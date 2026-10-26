from rest_framework.permissions import BasePermission
from approvals.models import UserProfile


class IsEmployee(BasePermission):
    """Allows access only to authenticated users with the EMPLOYEE role."""

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.EMPLOYEE
        )


class IsManager(BasePermission):
    """Allows access only to authenticated users with the MANAGER role."""

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.MANAGER
        )


class IsFinance(BasePermission):
    """Allows access only to authenticated users with the FINANCE role."""

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.FINANCE
        )


class IsAdmin(BasePermission):
    """Allows access only to authenticated users with the ADMIN role, staff, or superusers."""

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if request.user.is_superuser or request.user.is_staff:
            return True
        return bool(
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
