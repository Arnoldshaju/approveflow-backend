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

