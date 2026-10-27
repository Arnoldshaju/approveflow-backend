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


class RequestSubmissionAPITests(APITestCase):
    def setUp(self):
        from decimal import Decimal
        from approvals.models import ApprovalStep, PurchaseRequest, SystemSetting, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.Decimal = Decimal
        self.PurchaseRequest = PurchaseRequest
        self.ApprovalStep = ApprovalStep
        self.SystemSetting = SystemSetting

        # Manager
        self.manager = User.objects.create_user(
            username="reporting_manager",
            password="MgrPassword123!",
            email="manager@example.com",
        )
        self.manager.profile.role = UserProfile.Role.MANAGER
        self.manager.profile.save()

        # Employee with manager
        self.employee = User.objects.create_user(
            username="submitting_employee",
            password="EmpPassword123!",
            email="emp@example.com",
        )
        self.employee.profile.role = UserProfile.Role.EMPLOYEE
        self.employee.profile.manager = self.manager
        self.employee.profile.save()
        self.emp_token = str(RefreshToken.for_user(self.employee).access_token)

        # Another Employee without manager
        self.orphan_emp = User.objects.create_user(
            username="orphan_employee",
            password="EmpPassword123!",
            email="orphan@example.com",
        )
        self.orphan_emp.profile.role = UserProfile.Role.EMPLOYEE
        self.orphan_emp.profile.manager = None
        self.orphan_emp.profile.save()
        self.orphan_token = str(RefreshToken.for_user(self.orphan_emp).access_token)

        # Ensure default threshold is 10,000.00
        SystemSetting.objects.update_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )

    def test_submit_below_threshold_creates_single_manager_step(self):
        """Submitting an amount <= threshold generates only Step 1 (Manager Review)."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Desk Monitor",
            amount=self.Decimal("5000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Purchase request submitted successfully.")

        # Check request in DB
        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.PENDING)
        self.assertIsNotNone(pr.submitted_at)
        self.assertEqual(pr.applied_threshold, self.Decimal("10000.00"))

        # Verify steps: exactly 1 step
        steps = pr.steps.all().order_by("sequence")
        self.assertEqual(steps.count(), 1)
        step1 = steps[0]
        self.assertEqual(step1.sequence, 1)
        self.assertEqual(step1.stage, self.ApprovalStep.Stage.MANAGER)
        self.assertEqual(step1.assigned_reviewer, self.manager)
        self.assertEqual(step1.status, self.ApprovalStep.Status.PENDING)
        self.assertTrue(step1.is_active)

    def test_submit_above_threshold_creates_manager_and_finance_steps(self):
        """Submitting an amount > threshold generates Step 1 (Manager, active) and Step 2 (Finance, inactive)."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Enterprise Cloud Server",
            amount=self.Decimal("25000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check request
        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.PENDING)
        self.assertEqual(pr.applied_threshold, self.Decimal("10000.00"))

        # Verify steps: 2 steps
        steps = pr.steps.all().order_by("sequence")
        self.assertEqual(steps.count(), 2)

        # Step 1: Manager Review (active)
        step1 = steps[0]
        self.assertEqual(step1.sequence, 1)
        self.assertEqual(step1.stage, self.ApprovalStep.Stage.MANAGER)
        self.assertEqual(step1.assigned_reviewer, self.manager)
        self.assertTrue(step1.is_active)

        # Step 2: Finance Review (inactive until Step 1 approves)
        step2 = steps[1]
        self.assertEqual(step2.sequence, 2)
        self.assertEqual(step2.stage, self.ApprovalStep.Stage.FINANCE)
        self.assertIsNone(step2.assigned_reviewer)
        self.assertFalse(step2.is_active)

    def test_submit_without_assigned_manager_fails(self):
        """Submitting without an assigned manager returns 400 Bad Request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.orphan_emp,
            title="Orphan Request",
            amount=self.Decimal("1000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.orphan_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("manager", response.data["detail"].lower())

        # Request remains in draft
        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.DRAFT)
        self.assertEqual(pr.steps.count(), 0)

    def test_submit_already_submitted_request_fails(self):
        """Submitting a request that is not in DRAFT status returns 400 Bad Request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Already Pending Request",
            amount=self.Decimal("1000.00"),
            status=self.PurchaseRequest.Status.PENDING,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Only draft requests can be submitted", response.data["detail"])

    def test_submit_others_request_forbidden(self):
        """Submitting another user's request returns 403 Forbidden."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Employee 1 Request",
            amount=self.Decimal("1000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.orphan_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_policy_stability_snapshot_preserves_submission_threshold(self):
        """Threshold changes after submission do not alter applied_threshold on existing requests."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Snapshot Request",
            amount=self.Decimal("8000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        pr.refresh_from_db()
        self.assertEqual(pr.applied_threshold, self.Decimal("10000.00"))

        # Admin changes system threshold to 5,000.00
        setting = self.SystemSetting.objects.get(key="approval_threshold")
        setting.value = self.Decimal("5000.00")
        setting.save()

        # The previously submitted request still has 10,000.00 applied_threshold and 1 step
        pr.refresh_from_db()
        self.assertEqual(pr.applied_threshold, self.Decimal("10000.00"))
        self.assertEqual(pr.steps.count(), 1)


class ApprovalDecisionAPITests(APITestCase):
    def setUp(self):
        from decimal import Decimal
        from approvals.models import ApprovalStep, PurchaseRequest, SystemSetting, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.Decimal = Decimal
        self.PurchaseRequest = PurchaseRequest
        self.ApprovalStep = ApprovalStep
        self.SystemSetting = SystemSetting

        # Manager 1
        self.mgr1 = User.objects.create_user(
            username="mgr_alice",
            password="Password123!",
            email="alice@example.com",
        )
        self.mgr1.profile.role = UserProfile.Role.MANAGER
        self.mgr1.profile.save()
        self.mgr1_token = str(RefreshToken.for_user(self.mgr1).access_token)

        # Manager 2
        self.mgr2 = User.objects.create_user(
            username="mgr_bob",
            password="Password123!",
            email="bob@example.com",
        )
        self.mgr2.profile.role = UserProfile.Role.MANAGER
        self.mgr2.profile.save()
        self.mgr2_token = str(RefreshToken.for_user(self.mgr2).access_token)

        # Finance Reviewer
        self.fin_user = User.objects.create_user(
            username="fin_carol",
            password="Password123!",
            email="carol@example.com",
        )
        self.fin_user.profile.role = UserProfile.Role.FINANCE
        self.fin_user.profile.save()
        self.fin_token = str(RefreshToken.for_user(self.fin_user).access_token)

        # Employee assigned to Manager 1
        self.emp = User.objects.create_user(
            username="emp_dave",
            password="Password123!",
            email="dave@example.com",
        )
        self.emp.profile.role = UserProfile.Role.EMPLOYEE
        self.emp.profile.manager = self.mgr1
        self.emp.profile.save()
        self.emp_token = str(RefreshToken.for_user(self.emp).access_token)

        # Ensure default threshold is 10,000.00
        SystemSetting.objects.update_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )

    def test_manager_views_pending_queue(self):
        """Manager only sees active pending steps assigned to them."""
        # Request 1: assigned to mgr1
        pr1 = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Laptop",
            amount=self.Decimal("2000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr1.id}/submit/")

        # Request 2: step assigned to mgr2 directly
        pr2 = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Desk",
            amount=self.Decimal("500.00"),
            status=self.PurchaseRequest.Status.PENDING,
        )
        self.ApprovalStep.objects.create(
            request=pr2,
            stage=self.ApprovalStep.Stage.MANAGER,
            sequence=1,
            assigned_reviewer=self.mgr2,
            status=self.ApprovalStep.Status.PENDING,
            is_active=True,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr1_token}")
        response = self.client.get("/api/v1/approvals/pending/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["request_title"], "Laptop")

    def test_employee_forbidden_from_pending_queue(self):
        """Standard employees cannot access the pending approvals queue."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        response = self.client.get("/api/v1/approvals/pending/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_manager_approves_single_step_request(self):
        """Approving the only step transitions the purchase request to APPROVED."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Monitor",
            amount=self.Decimal("3000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step = pr.steps.get(sequence=1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr1_token}")
        response = self.client.post(
            f"/api/v1/approvals/steps/{step.id}/approve/",
            {"comments": "Approved for remote setup."},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["request_status"], "APPROVED")

        # Database checks
        step.refresh_from_db()
        self.assertEqual(step.status, self.ApprovalStep.Status.APPROVED)
        self.assertFalse(step.is_active)
        self.assertEqual(step.decided_by, self.mgr1)
        self.assertEqual(step.comments, "Approved for remote setup.")

        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.APPROVED)

    def test_manager_approves_multi_step_request_activates_finance(self):
        """Approving Step 1 in a multi-step request activates Step 2 (Finance)."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="High-End Workstation",
            amount=self.Decimal("25000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step1 = pr.steps.get(sequence=1)
        step2 = pr.steps.get(sequence=2)
        self.assertTrue(step1.is_active)
        self.assertFalse(step2.is_active)

        # Manager approves step 1
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr1_token}")
        response = self.client.post(
            f"/api/v1/approvals/steps/{step1.id}/approve/",
            {"comments": "Looks good from manager side."},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["request_status"], "PENDING")

        # Step 1 should now be approved and inactive
        step1.refresh_from_db()
        self.assertEqual(step1.status, self.ApprovalStep.Status.APPROVED)
        self.assertFalse(step1.is_active)

        # Step 2 (Finance) should now be active!
        step2.refresh_from_db()
        self.assertTrue(step2.is_active)
        self.assertEqual(step2.status, self.ApprovalStep.Status.PENDING)

        # Request status remains PENDING
        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.PENDING)

    def test_finance_approves_step_2_completes_request(self):
        """Finance member approving Step 2 marks the entire purchase request APPROVED."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Workstation",
            amount=self.Decimal("30000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step1 = pr.steps.get(sequence=1)
        step2 = pr.steps.get(sequence=2)

        # Manager approves Step 1
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr1_token}")
        self.client.post(f"/api/v1/approvals/steps/{step1.id}/approve/")

        # Finance approves Step 2
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.fin_token}")
        response = self.client.post(
            f"/api/v1/approvals/steps/{step2.id}/approve/",
            {"comments": "Finance budget verified."},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["request_status"], "APPROVED")

        # Final DB checks
        step2.refresh_from_db()
        self.assertEqual(step2.status, self.ApprovalStep.Status.APPROVED)
        self.assertEqual(step2.decided_by, self.fin_user)

        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.APPROVED)

    def test_manager_rejects_step_with_mandatory_comment(self):
        """Rejecting a step marks it REJECTED, skips subsequent steps, and marks request REJECTED."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Luxury Chair",
            amount=self.Decimal("15000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step1 = pr.steps.get(sequence=1)
        step2 = pr.steps.get(sequence=2)

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr1_token}")
        response = self.client.post(
            f"/api/v1/approvals/steps/{step1.id}/reject/",
            {"comments": "Item cost exceeds department travel and equipment policy."},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["request_status"], "REJECTED")

        # Step 1 is rejected
        step1.refresh_from_db()
        self.assertEqual(step1.status, self.ApprovalStep.Status.REJECTED)
        self.assertFalse(step1.is_active)
        self.assertEqual(step1.comments, "Item cost exceeds department travel and equipment policy.")

        # Step 2 is SKIPPED
        step2.refresh_from_db()
        self.assertEqual(step2.status, self.ApprovalStep.Status.SKIPPED)
        self.assertFalse(step2.is_active)

        # Entire request is REJECTED
        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.REJECTED)

    def test_rejection_without_comment_rejected_with_400(self):
        """Rejecting without providing a reason returns 400 Bad Request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Desk",
            amount=self.Decimal("2000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step1 = pr.steps.get(sequence=1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr1_token}")

        # Blank comments
        res1 = self.client.post(f"/api/v1/approvals/steps/{step1.id}/reject/", {"comments": "   "})
        self.assertEqual(res1.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("required", res1.data["detail"].lower())

        # Missing comments key
        res2 = self.client.post(f"/api/v1/approvals/steps/{step1.id}/reject/", {})
        self.assertEqual(res2.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unauthorized_manager_forbidden(self):
        """A manager not assigned to the step receives 403 Forbidden."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Headphones",
            amount=self.Decimal("200.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step1 = pr.steps.get(sequence=1)
        # mgr2 tries to approve mgr1's step
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.mgr2_token}")
        response = self.client.post(f"/api/v1/approvals/steps/{step1.id}/approve/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_inactive_step_cannot_be_approved(self):
        """Attempting to approve an inactive step (e.g. Finance step before Manager) returns 400."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Server",
            amount=self.Decimal("30000.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step2 = pr.steps.get(sequence=2)
        # Finance user tries to jump the gun and approve Step 2 while it's still inactive
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.fin_token}")
        response = self.client.post(f"/api/v1/approvals/steps/{step2.id}/approve/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)







