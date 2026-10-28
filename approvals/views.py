from decimal import Decimal
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from approvals.models import ApprovalStep, AuditLog, PurchaseRequest, SystemSetting, UserProfile
from approvals.permissions import IsAdmin, IsReviewerOrAdmin
from .serializers import (
    AdminUserSerializer,
    ApprovalStepSerializer,
    AuditLogSerializer,
    LoginSerializer,
    PurchaseRequestSerializer,
    ThresholdSettingSerializer,
)

User = get_user_model()



class HealthCheckAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            "status": "ok",
            "service": "ApproveFlow API",
            "version": "v1",
        })


class PurchaseRequestListCreateAPIView(APIView):
    def get(self, request):
        if request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        ):
            requests = (
                PurchaseRequest.objects.all()
                .select_related("requester")
                .order_by("-created_at")
            )
        else:
            requests = (
                PurchaseRequest.objects.filter(requester=request.user)
                .select_related("requester")
                .order_by("-created_at")
            )

        serializer = PurchaseRequestSerializer(requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PurchaseRequestSerializer(
            data=request.data,
            context={"request": request},
        )
        if serializer.is_valid():
            pr = serializer.save()
            AuditLog.log_action(
                request=pr,
                actor=request.user,
                action=AuditLog.Action.CREATED,
                from_status="",
                to_status=pr.status,
                notes="Draft purchase request created.",
            )
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )


PurchaseRequestCreateAPIView = PurchaseRequestListCreateAPIView


class PurchaseRequestDetailAPIView(APIView):
    def get_object(self, pk):
        try:
            return PurchaseRequest.objects.select_related("requester").get(pk=pk)
        except PurchaseRequest.DoesNotExist:
            return None

    def get(self, request, pk):
        pr = self.get_object(pk)
        if not pr:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
        if pr.requester != request.user and not is_admin:
            return Response(
                {"detail": "You do not have permission to view this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(PurchaseRequestSerializer(pr).data, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        pr = self.get_object(pk)
        if not pr:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
        if pr.requester != request.user and not is_admin:
            return Response(
                {"detail": "You do not have permission to edit this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = PurchaseRequestSerializer(
            pr,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        pr = self.get_object(pk)
        if not pr:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
        if pr.requester != request.user and not is_admin:
            return Response(
                {"detail": "You do not have permission to delete this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if pr.status != PurchaseRequest.Status.DRAFT:
            return Response(
                {"detail": "Only draft requests can be deleted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        pr.delete()
        return Response(
            {"detail": "Purchase request draft deleted successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )


class PurchaseRequestSubmitAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            pr = PurchaseRequest.objects.select_related("requester__profile__manager").get(pk=pk)
        except PurchaseRequest.DoesNotExist:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Only the requester can submit their request
        if pr.requester != request.user:
            return Response(
                {"detail": "You do not have permission to submit this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Only DRAFT requests can be submitted
        if pr.status != PurchaseRequest.Status.DRAFT:
            return Response(
                {"detail": "Only draft requests can be submitted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Requester must have an assigned manager
        requester_profile = getattr(request.user, "profile", None)
        if not requester_profile or not requester_profile.manager:
            return Response(
                {
                    "detail": "Cannot submit request without an assigned manager. Please contact your administrator."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        manager = requester_profile.manager

        with transaction.atomic():
            # 1. Snapshot current threshold at submission time
            active_threshold = SystemSetting.get_approval_threshold()
            pr.applied_threshold = active_threshold
            pr.status = PurchaseRequest.Status.PENDING
            pr.submitted_at = timezone.now()
            pr.save()

            # Clear any preexisting steps
            pr.steps.all().delete()

            # 2. Step 1: Manager Review (Always generated, is_active=True)
            ApprovalStep.objects.create(
                request=pr,
                stage=ApprovalStep.Stage.MANAGER,
                sequence=1,
                assigned_reviewer=manager,
                status=ApprovalStep.Status.PENDING,
                is_active=True,
            )

            # 3. Step 2: Finance Review (Generated if amount > applied_threshold, is_active=False until Step 1 approves)
            if pr.amount > active_threshold:
                ApprovalStep.objects.create(
                    request=pr,
                    stage=ApprovalStep.Stage.FINANCE,
                    sequence=2,
                    assigned_reviewer=None,
                    status=ApprovalStep.Status.PENDING,
                    is_active=False,
                )

            # Record audit entry for submission
            AuditLog.log_action(
                request=pr,
                actor=request.user,
                action=AuditLog.Action.SUBMITTED,
                from_status=PurchaseRequest.Status.DRAFT,
                to_status=PurchaseRequest.Status.PENDING,
                notes=f"Submitted for approval with snapshot threshold ₹{active_threshold}.",
            )

        serializer = PurchaseRequestSerializer(pr)
        return Response(
            {
                "message": "Purchase request submitted successfully.",
                "purchase_request": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class PendingApprovalsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsReviewerOrAdmin]

    def get(self, request):
        user = request.user
        role = getattr(getattr(user, "profile", None), "role", None)

        if user.is_superuser or role == UserProfile.Role.ADMIN:
            steps = ApprovalStep.objects.filter(
                is_active=True,
                status=ApprovalStep.Status.PENDING,
            )
        elif role == UserProfile.Role.MANAGER:
            steps = ApprovalStep.objects.filter(
                is_active=True,
                status=ApprovalStep.Status.PENDING,
                stage=ApprovalStep.Stage.MANAGER,
                assigned_reviewer=user,
            )
        elif role == UserProfile.Role.FINANCE:
            steps = ApprovalStep.objects.filter(
                is_active=True,
                status=ApprovalStep.Status.PENDING,
                stage=ApprovalStep.Stage.FINANCE,
            )
        else:
            steps = ApprovalStep.objects.none()

        steps = (
            steps.select_related("request", "request__requester", "assigned_reviewer", "decided_by")
            .order_by("created_at")
        )
        serializer = ApprovalStepSerializer(steps, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ApprovalStepApproveAPIView(APIView):
    permission_classes = [IsAuthenticated, IsReviewerOrAdmin]

    def post(self, request, pk):
        try:
            step = ApprovalStep.objects.select_related("request", "assigned_reviewer").get(pk=pk)
        except ApprovalStep.DoesNotExist:
            return Response(
                {"detail": "Approval step not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not step.is_active or step.status != ApprovalStep.Status.PENDING:
            return Response(
                {"detail": "This step is not currently awaiting decision."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        is_admin = user.is_superuser or (
            hasattr(user, "profile") and user.profile.role == UserProfile.Role.ADMIN
        )

        if step.stage == ApprovalStep.Stage.MANAGER:
            if step.assigned_reviewer != user and not is_admin:
                return Response(
                    {"detail": "You are not authorized to review this manager approval step."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        elif step.stage == ApprovalStep.Stage.FINANCE:
            is_finance = hasattr(user, "profile") and user.profile.role == UserProfile.Role.FINANCE
            if not is_finance and not is_admin:
                return Response(
                    {"detail": "Only Finance members can review this approval step."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        comments = request.data.get("comments", "").strip()

        with transaction.atomic():
            step.status = ApprovalStep.Status.APPROVED
            step.decided_by = user
            step.decided_at = timezone.now()
            step.is_active = False
            step.comments = comments
            step.save()

            next_step = ApprovalStep.objects.filter(
                request=step.request,
                sequence=step.sequence + 1,
            ).first()

            if next_step:
                next_step.is_active = True
                next_step.save()
                message = f"Step {step.sequence} approved. Request advanced to step {next_step.sequence} ({next_step.stage})."
            else:
                step.request.status = PurchaseRequest.Status.APPROVED
                step.request.save()
                message = "All approval steps completed. Purchase request approved."

            notes = f"Step {step.sequence} ({step.stage}) approved."
            if comments:
                notes += f" Comments: {comments}"
            AuditLog.log_action(
                request=step.request,
                actor=user,
                action=AuditLog.Action.STEP_APPROVED,
                from_status=PurchaseRequest.Status.PENDING,
                to_status=step.request.status,
                notes=notes,
            )

        return Response(
            {
                "message": message,
                "step": ApprovalStepSerializer(step).data,
                "request_status": step.request.status,
            },
            status=status.HTTP_200_OK,
        )


class ApprovalStepRejectAPIView(APIView):
    permission_classes = [IsAuthenticated, IsReviewerOrAdmin]

    def post(self, request, pk):
        try:
            step = ApprovalStep.objects.select_related("request", "assigned_reviewer").get(pk=pk)
        except ApprovalStep.DoesNotExist:
            return Response(
                {"detail": "Approval step not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if not step.is_active or step.status != ApprovalStep.Status.PENDING:
            return Response(
                {"detail": "This step is not currently awaiting decision."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        is_admin = user.is_superuser or (
            hasattr(user, "profile") and user.profile.role == UserProfile.Role.ADMIN
        )

        if step.stage == ApprovalStep.Stage.MANAGER:
            if step.assigned_reviewer != user and not is_admin:
                return Response(
                    {"detail": "You are not authorized to review this manager approval step."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        elif step.stage == ApprovalStep.Stage.FINANCE:
            is_finance = hasattr(user, "profile") and user.profile.role == UserProfile.Role.FINANCE
            if not is_finance and not is_admin:
                return Response(
                    {"detail": "Only Finance members can review this approval step."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        comments = request.data.get("comments", "").strip()
        if not comments:
            return Response(
                {"detail": "Rejection comments are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            step.status = ApprovalStep.Status.REJECTED
            step.decided_by = user
            step.decided_at = timezone.now()
            step.is_active = False
            step.comments = comments
            step.save()

            ApprovalStep.objects.filter(
                request=step.request,
                sequence__gt=step.sequence,
            ).update(
                status=ApprovalStep.Status.SKIPPED,
                is_active=False,
            )

            step.request.status = PurchaseRequest.Status.REJECTED
            step.request.save()

            notes = f"Step {step.sequence} ({step.stage}) rejected. Reason: {comments}"
            AuditLog.log_action(
                request=step.request,
                actor=user,
                action=AuditLog.Action.REJECTED,
                from_status=PurchaseRequest.Status.PENDING,
                to_status=PurchaseRequest.Status.REJECTED,
                notes=notes,
            )

        return Response(
            {
                "message": "Purchase request rejected.",
                "step": ApprovalStepSerializer(step).data,
                "request_status": step.request.status,
            },
            status=status.HTTP_200_OK,
        )


class PurchaseRequestHistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            pr = PurchaseRequest.objects.select_related("requester").get(pk=pk)
        except PurchaseRequest.DoesNotExist:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        user = request.user
        is_owner = pr.requester == user
        is_admin = user.is_superuser or (
            hasattr(user, "profile") and user.profile.role == UserProfile.Role.ADMIN
        )
        is_reviewer = hasattr(user, "profile") and user.profile.role in [
            UserProfile.Role.MANAGER,
            UserProfile.Role.FINANCE,
        ]

        if not (is_owner or is_admin or is_reviewer):
            return Response(
                {"detail": "You do not have permission to view the audit history for this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        logs = pr.audit_logs.select_related("actor").order_by("timestamp", "id")
        serializer = AuditLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "message": "Login successful.",
                "user": {
                    "id": user.id,
                    "username": user.get_username(),
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
            },
            status=status.HTTP_200_OK,
        )


class CurrentUserAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "username": user.get_username(),
            "email": user.email,
        })


class AdminUserListCreateAPIView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        users = (
            User.objects.all()
            .select_related("profile", "profile__manager")
            .order_by("id")
        )
        serializer = AdminUserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = AdminUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminUserDetailAPIView(APIView):
    permission_classes = [IsAdmin]

    def get_object(self, pk):
        try:
            return User.objects.select_related(
                "profile", "profile__manager"
            ).get(pk=pk)
        except User.DoesNotExist:
            return None

    def get(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(AdminUserSerializer(user).data, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = AdminUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = AdminUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminThresholdAPIView(APIView):
    permission_classes = [IsAdmin]

    def get_object(self):
        setting, _ = SystemSetting.objects.get_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )
        return setting

    def get(self, request):
        setting = self.get_object()
        serializer = ThresholdSettingSerializer(setting)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        setting = self.get_object()
        serializer = ThresholdSettingSerializer(
            setting,
            data=request.data,
            context={"request": request},
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        return self.put(request)




