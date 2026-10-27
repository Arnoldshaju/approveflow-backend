from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from api_v1.statuses.views import StatusAPIView
from approvals.views import (
    AdminThresholdAPIView,
    AdminUserDetailAPIView,
    AdminUserListCreateAPIView,
    CurrentUserAPIView,
    HealthCheckAPIView,
    LoginAPIView,
    PurchaseRequestCreateAPIView,
    PurchaseRequestDetailAPIView,
    PurchaseRequestListCreateAPIView,
)

urlpatterns = [
    path("health/", HealthCheckAPIView.as_view(), name="health-check"),
    path("statuses/", StatusAPIView.as_view(), name="statuses"),
    path(
        "purchase-requests/",
        PurchaseRequestListCreateAPIView.as_view(),
        name="purchase-request-list-create",
    ),
    path(
        "purchase-requests/<int:pk>/",
        PurchaseRequestDetailAPIView.as_view(),
        name="purchase-request-detail",
    ),
    path("token/", TokenObtainPairView.as_view(), name="token-obtain-pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("login/", LoginAPIView.as_view(), name="login"),
    path("me/", CurrentUserAPIView.as_view(), name="current-user"),
    # Admin User & Role Management APIs
    path("admin/users/", AdminUserListCreateAPIView.as_view(), name="admin-user-list-create"),
    path("admin/users/<int:pk>/", AdminUserDetailAPIView.as_view(), name="admin-user-detail"),
    # Admin System Threshold Configuration
    path("admin/threshold/", AdminThresholdAPIView.as_view(), name="admin-threshold"),
]
