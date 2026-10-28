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
    ApprovalStepApproveAPIView,
    ApprovalStepRejectAPIView,
    CurrentUserAPIView,
    DashboardStatsAPIView,
    HealthCheckAPIView,
    LoginAPIView,
    PendingApprovalsAPIView,
    PurchaseRequestCancelAPIView,
    PurchaseRequestCreateAPIView,
    PurchaseRequestDetailAPIView,
    PurchaseRequestHistoryAPIView,
    PurchaseRequestListCreateAPIView,
    PurchaseRequestSubmitAPIView,
)

urlpatterns = [
    path("health/", HealthCheckAPIView.as_view(), name="health-check"),
    path("statuses/", StatusAPIView.as_view(), name="statuses"),
    path("dashboard/stats/", DashboardStatsAPIView.as_view(), name="dashboard-stats"),
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
    path(
        "purchase-requests/<int:pk>/submit/",
        PurchaseRequestSubmitAPIView.as_view(),
        name="purchase-request-submit",
    ),
    path(
        "purchase-requests/<int:pk>/cancel/",
        PurchaseRequestCancelAPIView.as_view(),
        name="purchase-request-cancel",
    ),
    path(
        "purchase-requests/<int:pk>/history/",
        PurchaseRequestHistoryAPIView.as_view(),
        name="purchase-request-history",
    ),
    # Approvals Workflow Decision APIs
    path("approvals/pending/", PendingApprovalsAPIView.as_view(), name="pending-approvals"),
    path("approvals/steps/<int:pk>/approve/", ApprovalStepApproveAPIView.as_view(), name="approval-step-approve"),
    path("approvals/steps/<int:pk>/reject/", ApprovalStepRejectAPIView.as_view(), name="approval-step-reject"),
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
