from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from approvals.permissions import IsAdmin
from .serializers import (
    AdminUserSerializer,
    LoginSerializer,
    PurchaseRequestSerializer,
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


class PurchaseRequestCreateAPIView(APIView):

    def post(self, request):
        serializer = PurchaseRequestSerializer(data=request.data)

        if serializer.is_valid():
            purchase_request = serializer.save()

            return Response(
                PurchaseRequestSerializer(purchase_request).data,
                status=status.HTTP_201_CREATED,
            )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
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



