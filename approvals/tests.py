from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


class AuthenticationAndProfileTests(APITestCase):
    def setUp(self):
        self.username = "testuser"
        self.password = "SecurePass123!"
        self.email = "testuser@approveflow.com"
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            email=self.email,
        )

    def test_login_success(self):
        """Valid credentials return user details and JWT access + refresh tokens."""
        response = self.client.post(
            "/api/v1/login/",
            {"username": self.username, "password": self.password},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Login successful.")
        self.assertEqual(response.data["user"]["id"], self.user.id)
        self.assertEqual(response.data["user"]["username"], self.username)
        self.assertIn("tokens", response.data)
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])

    def test_login_invalid_credentials(self):
        """Invalid credentials return 400 Bad Request."""
        response = self.client.post(
            "/api/v1/login/",
            {"username": self.username, "password": "WrongPassword!"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)

    def test_token_refresh(self):
        """POST /api/v1/token/refresh/ returns a new access token given a valid refresh token."""
        login_response = self.client.post(
            "/api/v1/login/",
            {"username": self.username, "password": self.password},
        )
        refresh_token = login_response.data["tokens"]["refresh"]

        refresh_response = self.client.post(
            "/api/v1/token/refresh/",
            {"refresh": refresh_token},
        )
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", refresh_response.data)

    def test_me_authenticated(self):
        """GET /api/v1/me/ returns authenticated user ID, username, and email."""
        login_response = self.client.post(
            "/api/v1/login/",
            {"username": self.username, "password": self.password},
        )
        access_token = login_response.data["tokens"]["access"]

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        response = self.client.get("/api/v1/me/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data,
            {
                "id": self.user.id,
                "username": self.username,
                "email": self.email,
            },
        )

    def test_me_unauthenticated(self):
        """GET /api/v1/me/ without credentials returns 401 Unauthorized."""
        response = self.client.get("/api/v1/me/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_protected_purchase_requests_unauthenticated(self):
        """POST /api/v1/purchase-requests/ without credentials returns 401 Unauthorized."""
        response = self.client.post(
            "/api/v1/purchase-requests/",
            {"title": "Laptop", "amount": "50000.00"},
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_public_endpoints_accessible_without_jwt(self):
        """Public endpoints (/health/ and /statuses/) do not require authentication."""
        health_res = self.client.get("/api/v1/health/")
        self.assertEqual(health_res.status_code, status.HTTP_200_OK)
        self.assertEqual(health_res.data.get("status"), "ok")

        statuses_res = self.client.get("/api/v1/statuses/")
        self.assertEqual(statuses_res.status_code, status.HTTP_200_OK)
        self.assertIn("statuses", statuses_res.data)


class DummyRequest:
    def __init__(self, user):
        self.user = user


class RoleAndPermissionTests(APITestCase):
    def setUp(self):
        from approvals.models import UserProfile
        from approvals.permissions import (
            IsAdmin,
            IsEmployee,
            IsFinance,
            IsManager,
        )

        self.UserProfile = UserProfile
        self.IsEmployee = IsEmployee
        self.IsManager = IsManager
        self.IsFinance = IsFinance
        self.IsAdmin = IsAdmin

        self.employee = User.objects.create_user(
            username="emp1", password="Password123!", email="emp1@example.com"
        )
        self.manager = User.objects.create_user(
            username="mgr1", password="Password123!", email="mgr1@example.com"
        )
        self.manager.profile.role = UserProfile.Role.MANAGER
        self.manager.profile.save()

        self.finance = User.objects.create_user(
            username="fin1", password="Password123!", email="fin1@example.com"
        )
        self.finance.profile.role = UserProfile.Role.FINANCE
        self.finance.profile.save()

        self.admin = User.objects.create_user(
            username="adm1", password="Password123!", email="adm1@example.com"
        )
        self.admin.profile.role = UserProfile.Role.ADMIN
        self.admin.profile.save()

    def test_user_profile_created_automatically(self):
        """Newly created users automatically receive a UserProfile with EMPLOYEE role."""
        new_user = User.objects.create_user(
            username="newhire", password="Password123!"
        )
        self.assertTrue(hasattr(new_user, "profile"))
        self.assertEqual(new_user.profile.role, self.UserProfile.Role.EMPLOYEE)

    def test_manager_assignment_relationship(self):
        """An employee can be mapped to an assigned manager and queried via reverse relation."""
        self.employee.profile.manager = self.manager
        self.employee.profile.save()

        self.assertEqual(self.employee.profile.manager, self.manager)
        self.assertEqual(
            self.manager.subordinates.first().user,
            self.employee,
        )

    def test_is_employee_permission(self):
        """IsEmployee grants access only to users with EMPLOYEE role."""
        perm = self.IsEmployee()
        self.assertTrue(perm.has_permission(DummyRequest(self.employee), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.manager), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.finance), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.admin), None))

    def test_is_manager_permission(self):
        """IsManager grants access only to users with MANAGER role."""
        perm = self.IsManager()
        self.assertTrue(perm.has_permission(DummyRequest(self.manager), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.employee), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.finance), None))

    def test_is_finance_permission(self):
        """IsFinance grants access only to users with FINANCE role."""
        perm = self.IsFinance()
        self.assertTrue(perm.has_permission(DummyRequest(self.finance), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.employee), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.manager), None))

    def test_is_admin_permission(self):
        """IsAdmin grants access to ADMIN role and superusers, but not standard employees."""
        perm = self.IsAdmin()
        self.assertTrue(perm.has_permission(DummyRequest(self.admin), None))

        superuser = User.objects.create_superuser(
            username="root", password="Password123!", email="root@example.com"
        )
        self.assertTrue(perm.has_permission(DummyRequest(superuser), None))

        self.assertFalse(perm.has_permission(DummyRequest(self.employee), None))
        self.assertFalse(perm.has_permission(DummyRequest(self.manager), None))

    def test_unauthenticated_fails_all_role_permissions(self):
        """Unauthenticated requests are denied by all role permission classes."""
        from django.contrib.auth.models import AnonymousUser

        anon = AnonymousUser()
        for perm_class in [self.IsEmployee, self.IsManager, self.IsFinance, self.IsAdmin]:
            self.assertFalse(perm_class().has_permission(DummyRequest(anon), None))


