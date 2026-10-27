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


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


