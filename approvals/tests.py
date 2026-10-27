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


class AdminUserManagementAPITests(APITestCase):
    def setUp(self):
        from approvals.models import UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.UserProfile = UserProfile

        # Admin user
        self.admin_user = User.objects.create_superuser(
            username="admin_boss",
            password="AdminPassword123!",
            email="admin@approveflow.com",
        )
        self.admin_user.profile.role = UserProfile.Role.ADMIN
        self.admin_user.profile.save()

        # Regular employee user
        self.employee_user = User.objects.create_user(
            username="regular_emp",
            password="EmpPassword123!",
            email="emp@approveflow.com",
        )
        self.employee_user.profile.role = UserProfile.Role.EMPLOYEE
        self.employee_user.profile.save()

        # JWT tokens
        self.admin_token = str(RefreshToken.for_user(self.admin_user).access_token)
        self.employee_token = str(RefreshToken.for_user(self.employee_user).access_token)

    def test_admin_can_list_users(self):
        """Admin can list all registered users with their roles and manager details."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.get("/api/v1/admin/users/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) >= 2)
        usernames = [u["username"] for u in response.data]
        self.assertIn("admin_boss", usernames)
        self.assertIn("regular_emp", usernames)

    def test_admin_can_create_user_with_role(self):
        """Admin can create a new user account with a specified role."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        payload = {
            "username": "sarah_manager",
            "password": "ManagerPass123!",
            "email": "sarah@approveflow.com",
            "role": "MANAGER",
        }
        response = self.client.post("/api/v1/admin/users/", payload)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], "sarah_manager")
        self.assertEqual(response.data["role"], "MANAGER")

        # Verify password and profile in database
        created_user = User.objects.get(username="sarah_manager")
        self.assertTrue(created_user.check_password("ManagerPass123!"))
        self.assertEqual(created_user.profile.role, self.UserProfile.Role.MANAGER)

    def test_admin_can_assign_manager_and_update_role(self):
        """Admin can update an employee's role and map them to a reviewing manager."""
        # Create a manager
        manager = User.objects.create_user(
            username="bob_mgr", password="Password123!"
        )
        manager.profile.role = self.UserProfile.Role.MANAGER
        manager.profile.save()

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        payload = {
            "role": "EMPLOYEE",
            "manager_id": manager.id,
        }
        response = self.client.patch(
            f"/api/v1/admin/users/{self.employee_user.id}/", payload
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.employee_user.refresh_from_db()
        self.assertEqual(self.employee_user.profile.manager, manager)
        self.assertEqual(response.data["manager"]["id"], manager.id)
        self.assertEqual(response.data["manager"]["username"], "bob_mgr")

    def test_non_admin_forbidden_from_admin_apis(self):
        """Employees receive 403 Forbidden when attempting to access admin user APIs."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.employee_token}")
        get_response = self.client.get("/api/v1/admin/users/")
        self.assertEqual(get_response.status_code, status.HTTP_403_FORBIDDEN)

        post_response = self.client.post(
            "/api/v1/admin/users/",
            {"username": "hacker", "password": "Password123!"},
        )
        self.assertEqual(post_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_rejected_with_401(self):
        """Unauthenticated requests to admin user APIs are rejected with 401 Unauthorized."""
        response = self.client.get("/api/v1/admin/users/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class AdminThresholdAPITests(APITestCase):
    def setUp(self):
        from approvals.models import SystemSetting, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.SystemSetting = SystemSetting

        # Create Admin
        self.admin = User.objects.create_superuser(
            username="threshold_admin",
            password="AdminPassword123!",
            email="threshold_admin@approveflow.com",
        )
        self.admin.profile.role = UserProfile.Role.ADMIN
        self.admin.profile.save()
        self.admin_token = str(RefreshToken.for_user(self.admin).access_token)

        # Create Employee
        self.employee = User.objects.create_user(
            username="regular_worker",
            password="EmpPassword123!",
            email="worker@approveflow.com",
        )
        self.employee.profile.role = UserProfile.Role.EMPLOYEE
        self.employee.profile.save()
        self.employee_token = str(RefreshToken.for_user(self.employee).access_token)

    def test_default_threshold_is_10000(self):
        """GET /api/v1/admin/threshold/ returns the default 10,000 threshold."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.get("/api/v1/admin/threshold/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["key"], "approval_threshold")
        self.assertEqual(response.data["threshold"], "10000.00")

    def test_admin_can_update_threshold_via_put(self):
        """Admin can update threshold via PUT and updated_by is recorded."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.put(
            "/api/v1/admin/threshold/",
            {"threshold": "15000.00"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["threshold"], "15000.00")
        self.assertEqual(response.data["updated_by"]["id"], self.admin.id)
        self.assertEqual(response.data["updated_by"]["username"], "threshold_admin")

        # Database verification
        from decimal import Decimal
        self.assertEqual(
            self.SystemSetting.get_approval_threshold(),
            Decimal("15000.00"),
        )

    def test_admin_can_update_threshold_via_patch(self):
        """Admin can update threshold via PATCH."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.patch(
            "/api/v1/admin/threshold/",
            {"threshold": "25000.50"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["threshold"], "25000.50")

    def test_zero_or_negative_threshold_rejected(self):
        """Setting threshold to <= 0 returns 400 Bad Request."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")

        res_zero = self.client.put("/api/v1/admin/threshold/", {"threshold": "0.00"})
        self.assertEqual(res_zero.status_code, status.HTTP_400_BAD_REQUEST)

        res_neg = self.client.put("/api/v1/admin/threshold/", {"threshold": "-500.00"})
        self.assertEqual(res_neg.status_code, status.HTTP_400_BAD_REQUEST)

    def test_non_admin_forbidden_from_threshold_api(self):
        """Employees receive 403 Forbidden when calling threshold API."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.employee_token}")

        get_res = self.client.get("/api/v1/admin/threshold/")
        self.assertEqual(get_res.status_code, status.HTTP_403_FORBIDDEN)

        put_res = self.client.put("/api/v1/admin/threshold/", {"threshold": "20000.00"})
        self.assertEqual(put_res.status_code, status.HTTP_403_FORBIDDEN)

    def test_unauthenticated_rejected_with_401(self):
        """Unauthenticated requests return 401 Unauthorized."""
        response = self.client.get("/api/v1/admin/threshold/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PurchaseRequestLifecycleAPITests(APITestCase):
    def setUp(self):
        from approvals.models import PurchaseRequest, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.PurchaseRequest = PurchaseRequest

        # Employee 1
        self.emp1 = User.objects.create_user(
            username="requester_one",
            password="EmpPassword123!",
            email="emp1@example.com",
        )
        self.emp1.profile.role = UserProfile.Role.EMPLOYEE
        self.emp1.profile.save()
        self.emp1_token = str(RefreshToken.for_user(self.emp1).access_token)

        # Employee 2
        self.emp2 = User.objects.create_user(
            username="requester_two",
            password="EmpPassword123!",
            email="emp2@example.com",
        )
        self.emp2.profile.role = UserProfile.Role.EMPLOYEE
        self.emp2.profile.save()
        self.emp2_token = str(RefreshToken.for_user(self.emp2).access_token)

        # Admin
        self.admin = User.objects.create_user(
            username="super_admin",
            password="AdminPassword123!",
            email="admin@example.com",
        )
        self.admin.profile.role = UserProfile.Role.ADMIN
        self.admin.profile.save()
        self.admin_token = str(RefreshToken.for_user(self.admin).access_token)

    def test_employee_creates_draft_purchase_request(self):
        """Creating a purchase request defaults to DRAFT status and sets requester to the user."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.post(
            "/api/v1/purchase-requests/",
            {
                "title": "MacBook Pro M3",
                "category": "HARDWARE",
                "amount": "2499.99",
                "description": "Upgraded development laptop.",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["status"], "DRAFT")
        self.assertEqual(response.data["title"], "MacBook Pro M3")
        self.assertEqual(response.data["category"], "HARDWARE")
        self.assertEqual(response.data["amount"], "2499.99")
        self.assertEqual(response.data["requester"]["id"], self.emp1.id)
        self.assertEqual(response.data["requester"]["username"], "requester_one")

        # Database verification
        req_id = response.data["id"]
        pr = self.PurchaseRequest.objects.get(id=req_id)
        self.assertEqual(pr.requester, self.emp1)
        self.assertEqual(pr.status, self.PurchaseRequest.Status.DRAFT)

    def test_employee_lists_own_requests_only(self):
        """Employees only see their own purchase requests in the list endpoint."""
        self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Desk Monitor",
            category="HARDWARE",
            amount="350.00",
        )
        self.PurchaseRequest.objects.create(
            requester=self.emp2,
            title="Office Chair",
            category="OFFICE_SUPPLIES",
            amount="450.00",
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.get("/api/v1/purchase-requests/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "Desk Monitor")

    def test_admin_lists_all_requests(self):
        """Admin users see all purchase requests across the organization."""
        self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Emp1 Monitor",
            amount="300.00",
        )
        self.PurchaseRequest.objects.create(
            requester=self.emp2,
            title="Emp2 Keyboard",
            amount="120.00",
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.get("/api/v1/purchase-requests/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_employee_can_view_own_detail(self):
        """Employee can retrieve the detail of their own purchase request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Software IDE License",
            category="SOFTWARE",
            amount="199.00",
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.get(f"/api/v1/purchase-requests/{pr.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["id"], pr.id)
        self.assertEqual(response.data["title"], "Software IDE License")

    def test_employee_forbidden_from_viewing_others_request(self):
        """Employee cannot retrieve another employee's purchase request detail."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Confidential Expense",
            amount="500.00",
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp2_token}")
        response = self.client.get(f"/api/v1/purchase-requests/{pr.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_employee_can_edit_draft_request_via_patch(self):
        """Employee can update fields of their draft request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Rough Draft Request",
            amount="100.00",
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.patch(
            f"/api/v1/purchase-requests/{pr.id}/",
            {"title": "Final Draft Request", "amount": "250.00"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "Final Draft Request")
        self.assertEqual(response.data["amount"], "250.00")

    def test_editing_locked_when_not_draft(self):
        """Attempting to edit a submitted or pending request returns 400 Bad Request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Submitted Request",
            amount="1000.00",
            status=self.PurchaseRequest.Status.PENDING,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.patch(
            f"/api/v1/purchase-requests/{pr.id}/",
            {"amount": "1200.00"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)
        self.assertIn("Only draft requests can be edited", str(response.data["detail"]))

    def test_employee_forbidden_from_editing_others_request(self):
        """Employee cannot edit another employee's request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Emp1 Request",
            amount="100.00",
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp2_token}")
        response = self.client.patch(
            f"/api/v1/purchase-requests/{pr.id}/",
            {"amount": "500.00"},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_zero_or_negative_amount_rejected(self):
        """Creating a purchase request with amount <= 0 returns 400 Bad Request."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")

        res_zero = self.client.post(
            "/api/v1/purchase-requests/",
            {"title": "Zero Item", "amount": "0.00"},
        )
        self.assertEqual(res_zero.status_code, status.HTTP_400_BAD_REQUEST)

        res_neg = self.client.post(
            "/api/v1/purchase-requests/",
            {"title": "Negative Item", "amount": "-50.00"},
        )
        self.assertEqual(res_neg.status_code, status.HTTP_400_BAD_REQUEST)

    def test_employee_can_delete_draft_request(self):
        """Employee can delete their own draft request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="Draft to Delete",
            amount="100.00",
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.delete(f"/api/v1/purchase-requests/{pr.id}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(self.PurchaseRequest.objects.filter(id=pr.id).exists())

    def test_deleting_non_draft_request_rejected(self):
        """Deleting a request that is not in DRAFT status returns 400 Bad Request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp1,
            title="In Flight Request",
            amount="100.00",
            status=self.PurchaseRequest.Status.PENDING,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp1_token}")
        response = self.client.delete(f"/api/v1/purchase-requests/{pr.id}/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(self.PurchaseRequest.objects.filter(id=pr.id).exists())





