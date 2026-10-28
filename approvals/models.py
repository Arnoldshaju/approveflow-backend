from decimal import Decimal
from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class PurchaseRequest(models.Model):
    class Status(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        PENDING = "PENDING", "Pending Approval"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"
        CANCELLED = "CANCELLED", "Cancelled"

    class Category(models.TextChoices):
        HARDWARE = "HARDWARE", "Hardware"
        SOFTWARE = "SOFTWARE", "Software License"
        TRAVEL = "TRAVEL", "Travel & Expense"
        OFFICE_SUPPLIES = "OFFICE_SUPPLIES", "Office Supplies"
        OTHER = "OTHER", "Other"

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="purchase_requests",
        null=True,
        blank=True,
        help_text="The employee who created this request.",
    )
    title = models.CharField(max_length=200)
    category = models.CharField(
        max_length=50,
        choices=Category.choices,
        default=Category.OTHER,
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
    )
    applied_threshold = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Threshold captured at submission time for policy stability.",
    )
    submitted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(amount__gt=0),
                name="positive_purchase_request_amount",
            ),
        ]

    def __str__(self):
        return f"{self.title} (₹{self.amount}) - {self.status}"


class UserProfile(models.Model):
    class Role(models.TextChoices):
        EMPLOYEE = "EMPLOYEE", "Employee"
        MANAGER = "MANAGER", "Manager"
        FINANCE = "FINANCE", "Finance"
        ADMIN = "ADMIN", "Admin"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.EMPLOYEE,
    )
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subordinates",
        help_text="The reviewing manager assigned to this employee.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.get_username()} ({self.role})"


class SystemSetting(models.Model):
    key = models.CharField(max_length=50, unique=True)
    value = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=Decimal("10000.00"),
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_settings",
    )

    def __str__(self):
        return f"{self.key}: {self.value}"

    @classmethod
    def get_approval_threshold(cls):
        setting, _ = cls.objects.get_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )
        return setting.value


class ApprovalStep(models.Model):
    class Stage(models.TextChoices):
        MANAGER = "MANAGER", "Manager Review"
        FINANCE = "FINANCE", "Finance Review"

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"
        SKIPPED = "SKIPPED", "Skipped"

    request = models.ForeignKey(
        PurchaseRequest,
        on_delete=models.CASCADE,
        related_name="steps",
    )
    stage = models.CharField(
        max_length=20,
        choices=Stage.choices,
    )
    sequence = models.PositiveIntegerField(default=1)
    assigned_reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_approval_steps",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    is_active = models.BooleanField(
        default=False,
        help_text="True if this step is currently pending action from the reviewer.",
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="decided_approval_steps",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    comments = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["sequence"]
        constraints = [
            models.UniqueConstraint(
                fields=["request", "sequence"],
                name="unique_step_per_request_sequence",
            ),
        ]

    def __str__(self):
        return f"Request #{self.request_id} - Step {self.sequence} ({self.stage}): {self.status}"


class AuditLog(models.Model):
    class Action(models.TextChoices):
        CREATED = "CREATED", "Created"
        SUBMITTED = "SUBMITTED", "Submitted"
        STEP_APPROVED = "STEP_APPROVED", "Step Approved"
        REJECTED = "REJECTED", "Rejected"
        CANCELLED = "CANCELLED", "Cancelled"

    request = models.ForeignKey(
        PurchaseRequest,
        on_delete=models.CASCADE,
        related_name="audit_logs",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    action = models.CharField(
        max_length=50,
        choices=Action.choices,
    )
    from_status = models.CharField(
        max_length=30,
        blank=True,
        default="",
    )
    to_status = models.CharField(
        max_length=30,
        blank=True,
        default="",
    )
    notes = models.TextField(blank=True, default="")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["timestamp", "id"]

    def __str__(self):
        return f"AuditLog #{self.id} - Request #{self.request_id} [{self.action}] by {self.actor}"

    @classmethod
    def log_action(cls, request, actor, action, from_status="", to_status="", notes=""):
        return cls.objects.create(
            request=request,
            actor=actor,
            action=action,
            from_status=from_status,
            to_status=to_status,
            notes=notes,
        )


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


