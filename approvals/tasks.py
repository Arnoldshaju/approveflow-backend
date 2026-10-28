import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone

from approvals.models import ApprovalStep, PurchaseRequest, UserProfile

logger = logging.getLogger(__name__)
User = get_user_model()


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_purchase_request_submitted_notification(self, request_id):
    """
    Asynchronous task dispatched when a purchase request is submitted.
    Notifies the assigned reviewing manager that an approval request is pending.
    """
    try:
        pr = PurchaseRequest.objects.select_related(
            "requester", "requester__profile"
        ).get(pk=request_id)

        active_step = pr.steps.filter(is_active=True, status=ApprovalStep.Status.PENDING).first()
        if not active_step or not active_step.assigned_reviewer:
            logger.info("No assigned reviewer found for submitted request #%s", request_id)
            return {"status": "no_reviewer", "request_id": request_id}

        reviewer = active_step.assigned_reviewer
        requester_name = pr.requester.get_full_name() or pr.requester.username
        subject = f"[ApproveFlow] New Purchase Request Pending Approval: #{pr.id} - {pr.title}"
        message = (
            f"Hello {reviewer.first_name or reviewer.username},\n\n"
            f"A new purchase request has been submitted and awaits your review.\n\n"
            f"Request Details:\n"
            f"- Request ID: #{pr.id}\n"
            f"- Title: {pr.title}\n"
            f"- Requester: {requester_name}\n"
            f"- Category: {pr.get_category_display()}\n"
            f"- Amount: ₹{pr.amount:,.2f}\n"
            f"- Submission Time: {pr.submitted_at.strftime('%Y-%m-%d %H:%M:%S UTC') if pr.submitted_at else 'N/A'}\n\n"
            f"Please log in to ApproveFlow to review and decide on this request."
        )

        recipient_list = [reviewer.email] if reviewer.email else []
        if recipient_list:
            send_mail(
                subject=subject,
                message=message,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@approveflow.local"),
                recipient_list=recipient_list,
                fail_silently=True,
            )

        logger.info(
            "Submitted notification sent for request #%s to reviewer %s (%s)",
            pr.id,
            reviewer.username,
            reviewer.email,
        )
        return {
            "status": "sent",
            "request_id": pr.id,
            "reviewer_id": reviewer.id,
            "reviewer_email": reviewer.email,
        }

    except PurchaseRequest.DoesNotExist:
        logger.warning("PurchaseRequest #%s does not exist", request_id)
        return {"status": "not_found", "request_id": request_id}
    except Exception as exc:
        logger.error("Error sending submission notification for request #%s: %s", request_id, exc)
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_step_decision_notification(self, step_id, action, comments=""):
    """
    Asynchronous task dispatched when an approval step is actioned (APPROVED or REJECTED).
    Notifies the requester and/or the next level reviewer (e.g. Finance).
    """
    try:
        step = ApprovalStep.objects.select_related("request", "request__requester", "decided_by").get(
            pk=step_id
        )
        pr = step.request
        requester = pr.requester

        if action == "APPROVED":
            next_step = pr.steps.filter(is_active=True, status=ApprovalStep.Status.PENDING).first()
            if next_step:
                # Advancing to secondary review (e.g. Finance)
                subject = f"[ApproveFlow] Request #{pr.id} Approved by Manager — Advanced to {next_step.get_stage_display()}"
                body = (
                    f"Hello {requester.first_name or requester.username},\n\n"
                    f"Your purchase request #{pr.id} ({pr.title}) has been approved by your Manager "
                    f"and is now awaiting {next_step.get_stage_display()}.\n"
                )
                if comments:
                    body += f"Comments: {comments}\n"

                # Also notify Finance reviewers if unassigned
                finance_emails = list(
                    User.objects.filter(profile__role=UserProfile.Role.FINANCE, is_active=True)
                    .exclude(email="")
                    .values_list("email", flat=True)
                )
                if finance_emails:
                    send_mail(
                        subject=f"[ApproveFlow] Action Required: Request #{pr.id} Awaiting Finance Review",
                        message=(
                            f"Purchase request #{pr.id} (₹{pr.amount:,.2f}) has passed Manager review "
                            f"and requires Finance sign-off.\n"
                        ),
                        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@approveflow.local"),
                        recipient_list=finance_emails,
                        fail_silently=True,
                    )
            else:
                # Fully approved
                subject = f"[ApproveFlow] Request #{pr.id} Fully Approved!"
                body = (
                    f"Hello {requester.first_name or requester.username},\n\n"
                    f"Congratulations! Your purchase request #{pr.id} ({pr.title}) for ₹{pr.amount:,.2f} "
                    f"has been fully approved.\n"
                )
                if comments:
                    body += f"Final Comments: {comments}\n"

        else:
            # REJECTED
            subject = f"[ApproveFlow] Request #{pr.id} Rejected"
            body = (
                f"Hello {requester.first_name or requester.username},\n\n"
                f"Your purchase request #{pr.id} ({pr.title}) was rejected at the {step.get_stage_display()} stage.\n\n"
                f"Reason for rejection:\n{comments}\n"
            )

        if requester and requester.email:
            send_mail(
                subject=subject,
                message=body,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@approveflow.local"),
                recipient_list=[requester.email],
                fail_silently=True,
            )

        logger.info(
            "Step decision notification dispatched for step #%s (Action: %s)", step.id, action
        )
        return {
            "status": "sent",
            "step_id": step.id,
            "action": action,
            "request_status": pr.status,
        }

    except ApprovalStep.DoesNotExist:
        logger.warning("ApprovalStep #%s does not exist", step_id)
        return {"status": "not_found", "step_id": step_id}
    except Exception as exc:
        logger.error("Error sending decision notification for step #%s: %s", step_id, exc)
        raise self.retry(exc=exc)


@shared_task
def check_pending_approval_sla_reminders(hours_threshold=24):
    """
    Periodic task (scheduled via Celery Beat).
    Scans for approval steps that have been pending longer than hours_threshold
    and sends reminder emails to assigned or designated reviewers.
    """
    cutoff_time = timezone.now() - timedelta(hours=hours_threshold)
    overdue_steps = (
        ApprovalStep.objects.filter(
            is_active=True,
            status=ApprovalStep.Status.PENDING,
            request__submitted_at__lte=cutoff_time,
        )
        .select_related("request", "assigned_reviewer")
    )

    reminders_sent = 0
    for step in overdue_steps:
        recipients = []
        if step.assigned_reviewer and step.assigned_reviewer.email:
            recipients.append(step.assigned_reviewer.email)
        elif step.stage == ApprovalStep.Stage.FINANCE:
            recipients = list(
                User.objects.filter(profile__role=UserProfile.Role.FINANCE, is_active=True)
                .exclude(email="")
                .values_list("email", flat=True)
            )

        if recipients:
            send_mail(
                subject=f"[Reminder] Pending Approval Required for Request #{step.request_id}",
                message=(
                    f"Reminder: Purchase request #{step.request_id} ({step.request.title}) "
                    f"has been awaiting your {step.get_stage_display()} decision for more than {hours_threshold} hours.\n"
                    f"Amount: ₹{step.request.amount:,.2f}\n\n"
                    f"Please review this request as soon as possible."
                ),
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@approveflow.local"),
                recipient_list=recipients,
                fail_silently=True,
            )
            reminders_sent += len(recipients)

    logger.info("SLA check completed: %d reminder notifications dispatched", reminders_sent)
    return {"overdue_steps_count": overdue_steps.count(), "reminders_sent": reminders_sent}
