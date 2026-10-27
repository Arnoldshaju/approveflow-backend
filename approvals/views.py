from decimal import Decimal
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from approvals.models import PurchaseRequest, SystemSetting, UserProfile
from approvals.permissions import IsAdmin
from .serializers import (
    AdminUserSerializer,
    LoginSerializer,
    PurchaseRequestSerializer,
    ThresholdSettingSerializer,
)

User = get_user_model()



class HealthCheckAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            "status": "ok",
            "service": "ApproveFlow API",
            "version": "v1",
        })


class PurchaseRequestListCreateAPIView(APIView):
    def get(self, request):
        if request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        ):
            requests = (
                PurchaseRequest.objects.all()
                .select_related("requester")
                .order_by("-created_at")
            )
        else:
            requests = (
                PurchaseRequest.objects.filter(requester=request.user)
                .select_related("requester")
                .order_by("-created_at")
            )

        serializer = PurchaseRequestSerializer(requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PurchaseRequestSerializer(
            data=request.data,
            context={"request": request},
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )


PurchaseRequestCreateAPIView = PurchaseRequestListCreateAPIView


class PurchaseRequestDetailAPIView(APIView):
    def get_object(self, pk):
        try:
            return PurchaseRequest.objects.select_related("requester").get(pk=pk)
        except PurchaseRequest.DoesNotExist:
            return None

    def get(self, request, pk):
        pr = self.get_object(pk)
        if not pr:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
        if pr.requester != request.user and not is_admin:
            return Response(
                {"detail": "You do not have permission to view this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(PurchaseRequestSerializer(pr).data, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        pr = self.get_object(pk)
        if not pr:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
        if pr.requester != request.user and not is_admin:
            return Response(
                {"detail": "You do not have permission to edit this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = PurchaseRequestSerializer(
            pr,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        pr = self.get_object(pk)
        if not pr:
            return Response(
                {"detail": "Purchase request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        is_admin = request.user.is_superuser or (
            hasattr(request.user, "profile")
            and request.user.profile.role == UserProfile.Role.ADMIN
        )
        if pr.requester != request.user and not is_admin:
            return Response(
                {"detail": "You do not have permission to delete this request."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if pr.status != PurchaseRequest.Status.DRAFT:
            return Response(
                {"detail": "Only draft requests can be deleted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        pr.delete()
        return Response(
            {"detail": "Purchase request draft deleted successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "message": "Login successful.",
                "user": {
                    "id": user.id,
                    "username": user.get_username(),
                },
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
            },
            status=status.HTTP_200_OK,
        )


class CurrentUserAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "username": user.get_username(),
            "email": user.email,
        })


class AdminUserListCreateAPIView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        users = (
            User.objects.all()
            .select_related("profile", "profile__manager")
            .order_by("id")
        )
        serializer = AdminUserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = AdminUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminUserDetailAPIView(APIView):
    permission_classes = [IsAdmin]

    def get_object(self, pk):
        try:
            return User.objects.select_related(
                "profile", "profile__manager"
            ).get(pk=pk)
        except User.DoesNotExist:
            return None

    def get(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(AdminUserSerializer(user).data, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = AdminUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        user = self.get_object(pk)
        if not user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = AdminUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminThresholdAPIView(APIView):
    permission_classes = [IsAdmin]

    def get_object(self):
        setting, _ = SystemSetting.objects.get_or_create(
            key="approval_threshold",
            defaults={"value": Decimal("10000.00")},
        )
        return setting

    def get(self, request):
        setting = self.get_object()
        serializer = ThresholdSettingSerializer(setting)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        setting = self.get_object()
        serializer = ThresholdSettingSerializer(
            setting,
            data=request.data,
            context={"request": request},
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        return self.put(request)




