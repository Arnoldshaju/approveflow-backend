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


class AuditLoggingAPITests(APITestCase):
    def setUp(self):
        from decimal import Decimal
        from approvals.models import ApprovalStep, AuditLog, PurchaseRequest, SystemSetting, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.Decimal = Decimal
        self.PurchaseRequest = PurchaseRequest
        self.ApprovalStep = ApprovalStep
        self.AuditLog = AuditLog
        self.SystemSetting = SystemSetting

        # Manager
        self.manager = User.objects.create_user(
            username="audit_manager",
            password="Password123!",
            email="mgr@example.com",
        )
        self.manager.profile.role = UserProfile.Role.MANAGER
        self.manager.profile.save()
        self.manager_token = str(RefreshToken.for_user(self.manager).access_token)

        # Employee assigned to manager
        self.employee = User.objects.create_user(
            username="audit_employee",
            password="Password123!",
            email="emp@example.com",
        )
        self.employee.profile.role = UserProfile.Role.EMPLOYEE
        self.employee.profile.manager = self.manager
        self.employee.profile.save()
        self.emp_token = str(RefreshToken.for_user(self.employee).access_token)

        # Unrelated employee
        self.other_emp = User.objects.create_user(
            username="other_employee",
            password="Password123!",
            email="other@example.com",
        )
        self.other_emp.profile.role = UserProfile.Role.EMPLOYEE
        self.other_emp.profile.save()
        self.other_token = str(RefreshToken.for_user(self.other_emp).access_token)

        # Admin
        self.admin = User.objects.create_user(
            username="audit_admin",
            password="Password123!",
            email="admin@example.com",
        )
        self.admin.profile.role = UserProfile.Role.ADMIN
        self.admin.profile.save()
        self.admin_token = str(RefreshToken.for_user(self.admin).access_token)

        # Ensure default threshold
        SystemSetting.objects.update_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )

    def test_lifecycle_audit_trail_generation(self):
        """Audit logs are recorded across CREATED, SUBMITTED, and STEP_APPROVED."""
        # 1. Create Draft Request
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        create_res = self.client.post(
            "/api/v1/purchase-requests/",
            {
                "title": "Ergonomic Chair",
                "category": "OFFICE_SUPPLIES",
                "amount": "450.00",
                "description": "Ergonomic office setup.",
            },
        )
        self.assertEqual(create_res.status_code, status.HTTP_201_CREATED)
        pr_id = create_res.data["id"]

        pr = self.PurchaseRequest.objects.get(id=pr_id)
        logs = pr.audit_logs.all().order_by("timestamp", "id")
        self.assertEqual(logs.count(), 1)
        self.assertEqual(logs[0].action, self.AuditLog.Action.CREATED)
        self.assertEqual(logs[0].actor, self.employee)
        self.assertEqual(logs[0].to_status, self.PurchaseRequest.Status.DRAFT)

        # 2. Submit Request
        submit_res = self.client.post(f"/api/v1/purchase-requests/{pr_id}/submit/")
        self.assertEqual(submit_res.status_code, status.HTTP_200_OK)

        logs = pr.audit_logs.all().order_by("timestamp", "id")
        self.assertEqual(logs.count(), 2)
        self.assertEqual(logs[1].action, self.AuditLog.Action.SUBMITTED)
        self.assertEqual(logs[1].actor, self.employee)
        self.assertEqual(logs[1].from_status, self.PurchaseRequest.Status.DRAFT)
        self.assertEqual(logs[1].to_status, self.PurchaseRequest.Status.PENDING)

        # 3. Manager Approves Step 1
        step1 = pr.steps.get(sequence=1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.manager_token}")
        approve_res = self.client.post(
            f"/api/v1/approvals/steps/{step1.id}/approve/",
            {"comments": "Approved on budget."},
        )
        self.assertEqual(approve_res.status_code, status.HTTP_200_OK)

        logs = pr.audit_logs.all().order_by("timestamp", "id")
        self.assertEqual(logs.count(), 3)
        self.assertEqual(logs[2].action, self.AuditLog.Action.STEP_APPROVED)
        self.assertEqual(logs[2].actor, self.manager)
        self.assertEqual(logs[2].to_status, self.PurchaseRequest.Status.APPROVED)
        self.assertIn("Approved on budget", logs[2].notes)

    def test_rejection_audit_log_captures_mandatory_reason(self):
        """Rejecting records a REJECTED audit log containing the mandatory rejection reason."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Standing Desk",
            amount=self.Decimal("800.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        step1 = pr.steps.get(sequence=1)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.manager_token}")
        reject_res = self.client.post(
            f"/api/v1/approvals/steps/{step1.id}/reject/",
            {"comments": "Desk expense not permitted this quarter."},
        )
        self.assertEqual(reject_res.status_code, status.HTTP_200_OK)

        last_log = pr.audit_logs.latest("timestamp")
        self.assertEqual(last_log.action, self.AuditLog.Action.REJECTED)
        self.assertEqual(last_log.actor, self.manager)
        self.assertEqual(last_log.to_status, self.PurchaseRequest.Status.REJECTED)
        self.assertIn("Desk expense not permitted this quarter", last_log.notes)

    def test_requester_and_admin_can_retrieve_history(self):
        """Requester and Admin can fetch the chronological audit history."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        create_res = self.client.post(
            "/api/v1/purchase-requests/",
            {"title": "Keyboard", "amount": "120.00"},
        )
        pr_id = create_res.data["id"]
        self.client.post(f"/api/v1/purchase-requests/{pr_id}/submit/")

        # Requester retrieves history
        res_emp = self.client.get(f"/api/v1/purchase-requests/{pr_id}/history/")
        self.assertEqual(res_emp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res_emp.data), 2)
        self.assertEqual(res_emp.data[0]["action"], "CREATED")
        self.assertEqual(res_emp.data[1]["action"], "SUBMITTED")

        # Admin retrieves history
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        res_admin = self.client.get(f"/api/v1/purchase-requests/{pr_id}/history/")
        self.assertEqual(res_admin.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res_admin.data), 2)

    def test_unrelated_employee_forbidden_from_history(self):
        """Unrelated employees cannot view audit history for requests they do not own."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.employee,
            title="Private Request",
            amount=self.Decimal("500.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.other_token}")
        response = self.client.get(f"/api/v1/purchase-requests/{pr.id}/history/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class RequestCancellationAPITests(APITestCase):
    def setUp(self):
        from decimal import Decimal
        from approvals.models import ApprovalStep, AuditLog, PurchaseRequest, SystemSetting, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.Decimal = Decimal
        self.PurchaseRequest = PurchaseRequest
        self.ApprovalStep = ApprovalStep
        self.AuditLog = AuditLog

        # Manager
        self.mgr = User.objects.create_user(
            username="canc_mgr",
            password="Password123!",
            email="mgr@example.com",
        )
        self.mgr.profile.role = UserProfile.Role.MANAGER
        self.mgr.profile.save()

        # Employee
        self.emp = User.objects.create_user(
            username="canc_emp",
            password="Password123!",
            email="emp@example.com",
        )
        self.emp.profile.role = UserProfile.Role.EMPLOYEE
        self.emp.profile.manager = self.mgr
        self.emp.profile.save()
        self.emp_token = str(RefreshToken.for_user(self.emp).access_token)

        # Other employee
        self.other_emp = User.objects.create_user(
            username="canc_other",
            password="Password123!",
            email="other@example.com",
        )
        self.other_emp.profile.role = UserProfile.Role.EMPLOYEE
        self.other_emp.profile.save()
        self.other_token = str(RefreshToken.for_user(self.other_emp).access_token)

        # Admin
        self.admin = User.objects.create_user(
            username="canc_admin",
            password="Password123!",
            email="admin@example.com",
        )
        self.admin.profile.role = UserProfile.Role.ADMIN
        self.admin.profile.save()
        self.admin_token = str(RefreshToken.for_user(self.admin).access_token)

        SystemSetting.objects.update_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )

    def test_requester_can_cancel_pending_request(self):
        """Requester can cancel a pending request, invalidating approval steps and logging audit event."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Desk Fan",
            amount=self.Decimal("80.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        self.client.post(f"/api/v1/purchase-requests/{pr.id}/submit/")

        # Cancel request
        cancel_res = self.client.post(
            f"/api/v1/purchase-requests/{pr.id}/cancel/",
            {"reason": "Office temperature resolved."},
        )
        self.assertEqual(cancel_res.status_code, status.HTTP_200_OK)
        self.assertEqual(cancel_res.data["purchase_request"]["status"], "CANCELLED")

        # Database checks
        pr.refresh_from_db()
        self.assertEqual(pr.status, self.PurchaseRequest.Status.CANCELLED)

        # Steps must be skipped and inactive
        for step in pr.steps.all():
            self.assertFalse(step.is_active)
            self.assertEqual(step.status, self.ApprovalStep.Status.SKIPPED)

        # Audit log verified
        last_log = pr.audit_logs.latest("timestamp")
        self.assertEqual(last_log.action, self.AuditLog.Action.CANCELLED)
        self.assertEqual(last_log.actor, self.emp)
        self.assertIn("Office temperature resolved.", last_log.notes)

    def test_cancel_already_approved_request_fails(self):
        """Cannot cancel an approved request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Approved Item",
            amount=self.Decimal("200.00"),
            status=self.PurchaseRequest.Status.APPROVED,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/cancel/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unauthorized_user_cannot_cancel(self):
        """Another employee cannot cancel someone else's request."""
        pr = self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Secret Project Expense",
            amount=self.Decimal("500.00"),
            status=self.PurchaseRequest.Status.PENDING,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.other_token}")
        response = self.client.post(f"/api/v1/purchase-requests/{pr.id}/cancel/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class QueryFilterPaginationAPITests(APITestCase):
    def setUp(self):
        from decimal import Decimal
        from approvals.models import PurchaseRequest, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.Decimal = Decimal
        self.PurchaseRequest = PurchaseRequest

        self.user = User.objects.create_user(
            username="query_user",
            password="Password123!",
            email="query@example.com",
        )
        self.user.profile.role = UserProfile.Role.EMPLOYEE
        self.user.profile.save()
        self.token = str(RefreshToken.for_user(self.user).access_token)

        # Create diverse test requests
        self.pr1 = self.PurchaseRequest.objects.create(
            requester=self.user,
            title="Apple MacBook Pro",
            category="HARDWARE",
            amount=self.Decimal("2500.00"),
            status=self.PurchaseRequest.Status.APPROVED,
            description="High performance laptop.",
        )
        self.pr2 = self.PurchaseRequest.objects.create(
            requester=self.user,
            title="IntelliJ IDEA License",
            category="SOFTWARE",
            amount=self.Decimal("250.00"),
            status=self.PurchaseRequest.Status.PENDING,
            description="IDE license for development.",
        )
        self.pr3 = self.PurchaseRequest.objects.create(
            requester=self.user,
            title="Office Desk & Chair",
            category="OFFICE_SUPPLIES",
            amount=self.Decimal("450.00"),
            status=self.PurchaseRequest.Status.DRAFT,
            description="Furniture.",
        )

    def test_filter_by_status(self):
        """Can filter requests by status parameter."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.get("/api/v1/purchase-requests/?status=approved")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "Apple MacBook Pro")

    def test_filter_by_category(self):
        """Can filter requests by category parameter."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.get("/api/v1/purchase-requests/?category=software")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "IntelliJ IDEA License")

    def test_filter_by_amount_range(self):
        """Can filter requests by min_amount and max_amount."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.get("/api/v1/purchase-requests/?min_amount=300&max_amount=600")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "Office Desk & Chair")

    def test_search_keyword(self):
        """Can search requests across title and description."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.get("/api/v1/purchase-requests/?search=macbook")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["title"], "Apple MacBook Pro")

    def test_pagination_structure(self):
        """Querying with page parameter returns standard paginated format."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        response = self.client.get("/api/v1/purchase-requests/?page=1&page_size=2")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("count", response.data)
        self.assertIn("next", response.data)
        self.assertIn("results", response.data)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(len(response.data["results"]), 2)


class DashboardStatsAPITests(APITestCase):
    def setUp(self):
        from decimal import Decimal
        from approvals.models import ApprovalStep, PurchaseRequest, SystemSetting, UserProfile
        from rest_framework_simplejwt.tokens import RefreshToken

        self.Decimal = Decimal
        self.PurchaseRequest = PurchaseRequest
        self.ApprovalStep = ApprovalStep

        # Manager
        self.mgr = User.objects.create_user(
            username="stats_mgr",
            password="Password123!",
            email="mgr@example.com",
        )
        self.mgr.profile.role = UserProfile.Role.MANAGER
        self.mgr.profile.save()
        self.mgr_token = str(RefreshToken.for_user(self.mgr).access_token)

        # Employee
        self.emp = User.objects.create_user(
            username="stats_emp",
            password="Password123!",
            email="emp@example.com",
        )
        self.emp.profile.role = UserProfile.Role.EMPLOYEE
        self.emp.profile.manager = self.mgr
        self.emp.profile.save()
        self.emp_token = str(RefreshToken.for_user(self.emp).access_token)

        # Admin
        self.admin = User.objects.create_user(
            username="stats_admin",
            password="Password123!",
            email="admin@example.com",
        )
        self.admin.profile.role = UserProfile.Role.ADMIN
        self.admin.profile.save()
        self.admin_token = str(RefreshToken.for_user(self.admin).access_token)

        # Create requests
        self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Approved Laptop",
            amount=self.Decimal("2000.00"),
            status=self.PurchaseRequest.Status.APPROVED,
        )
        self.PurchaseRequest.objects.create(
            requester=self.emp,
            title="Draft Supplies",
            amount=self.Decimal("150.00"),
            status=self.PurchaseRequest.Status.DRAFT,
        )

    def test_employee_stats(self):
        """Employee retrieves their own request metrics."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.emp_token}")
        response = self.client.get("/api/v1/dashboard/stats/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["my_requests"]["total_requests"], 2)
        self.assertEqual(response.data["my_requests"]["approved_count"], 1)
        self.assertEqual(response.data["my_requests"]["draft_count"], 1)
        self.assertEqual(response.data["my_requests"]["total_approved_amount"], "2000.00")
        self.assertIsNone(response.data["organization_overview"])

    def test_admin_stats_includes_organization_overview(self):
        """Admin metrics include company-wide distribution."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.admin_token}")
        response = self.client.get("/api/v1/dashboard/stats/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data["organization_overview"])
        self.assertEqual(response.data["organization_overview"]["organization_total_requests"], 2)


from datetime import timedelta
from decimal import Decimal
from django.core import mail
from django.test import override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from approvals.models import ApprovalStep, PurchaseRequest, UserProfile
from approvals.tasks import (
    check_pending_approval_sla_reminders,
    send_purchase_request_submitted_notification,
    send_step_decision_notification,
)



@override_settings(CELERY_TASK_ALWAYS_EAGER=True, CELERY_TASK_EAGER_PROPAGATES=True)
class CeleryAsynchronousNotificationTests(APITestCase):
    def setUp(self):
        mail.outbox.clear()

        # Manager user
        self.manager = User.objects.create_user(
            username="celery_manager",
            password="Password123!",
            email="manager@company.local",
        )
        self.manager.profile.role = UserProfile.Role.MANAGER
        self.manager.profile.save()

        # Employee user mapped to manager
        self.employee = User.objects.create_user(
            username="celery_employee",
            password="Password123!",
            email="employee@company.local",
        )
        self.employee.profile.role = UserProfile.Role.EMPLOYEE
        self.employee.profile.manager = self.manager
        self.employee.profile.save()
        self.employee_token = str(RefreshToken.for_user(self.employee).access_token)
        self.manager_token = str(RefreshToken.for_user(self.manager).access_token)

        # Finance user
        self.finance = User.objects.create_user(
            username="celery_finance",
            password="Password123!",
            email="finance@company.local",
        )
        self.finance.profile.role = UserProfile.Role.FINANCE
        self.finance.profile.save()

        # Purchase Request
        self.pr = PurchaseRequest.objects.create(
            requester=self.employee,
            title="MacBook Pro M3",
            description="Workstation laptop upgrade",
            amount=Decimal("15000.00"),
            category=PurchaseRequest.Category.HARDWARE,
            status=PurchaseRequest.Status.PENDING,
            applied_threshold=Decimal("10000.00"),
            submitted_at=timezone.now(),
        )

        # Step 1: Manager Review (active)
        self.step_manager = ApprovalStep.objects.create(
            request=self.pr,
            stage=ApprovalStep.Stage.MANAGER,
            sequence=1,
            assigned_reviewer=self.manager,
            status=ApprovalStep.Status.PENDING,
            is_active=True,
        )

        # Step 2: Finance Review (inactive until manager approves)
        self.step_finance = ApprovalStep.objects.create(
            request=self.pr,
            stage=ApprovalStep.Stage.FINANCE,
            sequence=2,
            assigned_reviewer=None,
            status=ApprovalStep.Status.PENDING,
            is_active=False,
        )

    def test_submission_notification_task_sends_email_to_manager(self):
        """send_purchase_request_submitted_notification emails the assigned manager."""
        result = send_purchase_request_submitted_notification(self.pr.id)
        self.assertEqual(result["status"], "sent")
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn("celery_manager", email.body)
        self.assertIn(self.pr.title, email.subject)
        self.assertIn("manager@company.local", email.to)

    def test_step_approved_advancing_to_finance_notifies_requester_and_finance(self):
        """When manager approves a high-value request, finance and requester are notified."""
        self.step_manager.status = ApprovalStep.Status.APPROVED
        self.step_manager.is_active = False
        self.step_manager.save()
        self.step_finance.is_active = True
        self.step_finance.save()

        result = send_step_decision_notification(
            self.step_manager.id, "APPROVED", comments="Approved by manager"
        )
        self.assertEqual(result["status"], "sent")
        self.assertEqual(len(mail.outbox), 2)
        recipients = [m.to[0] for m in mail.outbox]
        self.assertIn("employee@company.local", recipients)
        self.assertIn("finance@company.local", recipients)

    def test_step_final_approved_notifies_requester(self):
        """When final step approves, requester receives confirmation email."""
        single_pr = PurchaseRequest.objects.create(
            requester=self.employee,
            title="Desk Monitor",
            amount=Decimal("300.00"),
            status=PurchaseRequest.Status.APPROVED,
            submitted_at=timezone.now(),
        )
        final_step = ApprovalStep.objects.create(
            request=single_pr,
            stage=ApprovalStep.Stage.MANAGER,
            sequence=1,
            assigned_reviewer=self.manager,
            status=ApprovalStep.Status.APPROVED,
            is_active=False,
        )

        result = send_step_decision_notification(
            final_step.id, "APPROVED", comments="Looks good"
        )
        self.assertEqual(result["status"], "sent")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("employee@company.local", mail.outbox[0].to)
        self.assertIn("Fully Approved", mail.outbox[0].subject)

    def test_step_rejected_notifies_requester_with_reason(self):
        """When a step is rejected, requester receives notification with the rejection reason."""
        self.step_manager.status = ApprovalStep.Status.REJECTED
        self.step_manager.is_active = False
        self.step_manager.save()
        self.pr.status = PurchaseRequest.Status.REJECTED
        self.pr.save()

        result = send_step_decision_notification(
            self.step_manager.id, "REJECTED", comments="Budget exhausted for this quarter."
        )
        self.assertEqual(result["status"], "sent")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("employee@company.local", mail.outbox[0].to)
        self.assertIn("Rejected", mail.outbox[0].subject)
        self.assertIn("Budget exhausted for this quarter.", mail.outbox[0].body)

    def test_check_pending_approval_sla_reminders(self):
        """Periodic SLA check emails reviewers for requests pending longer than threshold."""
        # Make pr submitted 30 hours ago
        self.pr.submitted_at = timezone.now() - timedelta(hours=30)
        self.pr.save()

        result = check_pending_approval_sla_reminders(hours_threshold=24)
        self.assertGreaterEqual(result["reminders_sent"], 1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("manager@company.local", mail.outbox[0].to)
        self.assertIn("[Reminder]", mail.outbox[0].subject)

    def test_api_submit_triggers_asynchronous_email(self):
        """Submitting a draft request through API dispatches notification email via on_commit."""
        draft = PurchaseRequest.objects.create(
            requester=self.employee,
            title="Office Chair",
            amount=Decimal("250.00"),
            status=PurchaseRequest.Status.DRAFT,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.employee_token}")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(f"/api/v1/purchase-requests/{draft.id}/submit/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("manager@company.local", mail.outbox[0].to)

    def test_api_decision_triggers_asynchronous_email(self):
        """Approving a step through API dispatches decision email via on_commit."""
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.manager_token}")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                f"/api/v1/approvals/steps/{self.step_manager.id}/approve/",
                {"comments": "Approved via API"},
                format="json",
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(mail.outbox), 1)










