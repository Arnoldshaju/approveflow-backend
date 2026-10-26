from django.contrib.auth import authenticate, get_user_model
from rest_framework import serializers

from .models import PurchaseRequest, UserProfile

User = get_user_model()


class AdminUserSerializer(serializers.ModelSerializer):
    role = serializers.ChoiceField(
        choices=UserProfile.Role.choices,
        default=UserProfile.Role.EMPLOYEE,
        required=False,
    )
    manager_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source="profile.manager",
        allow_null=True,
        required=False,
    )
    manager = serializers.SerializerMethodField()
    password = serializers.CharField(
        write_only=True,
        required=False,
        style={"input_type": "password"},
    )

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "password",
            "role",
            "manager_id",
            "manager",
            "is_active",
            "date_joined",
        ]
        read_only_fields = ["id", "date_joined", "manager"]

    def get_manager(self, obj):
        if hasattr(obj, "profile") and obj.profile.manager:
            return {
                "id": obj.profile.manager.id,
                "username": obj.profile.manager.get_username(),
            }
        return None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["role"] = (
            instance.profile.role
            if hasattr(instance, "profile")
            else UserProfile.Role.EMPLOYEE
        )
        return data

    def create(self, validated_data):
        role = validated_data.pop("role", UserProfile.Role.EMPLOYEE)
        profile_data = validated_data.pop("profile", {})
        manager = profile_data.get("manager", None)
        password = validated_data.pop("password", None)

        user = User(**validated_data)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()

        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = role
        profile.manager = manager
        profile.save()
        user.profile = profile

        return user

    def update(self, instance, validated_data):
        role = validated_data.pop("role", None)
        profile_data = validated_data.pop("profile", {})
        manager_provided = "manager" in profile_data
        manager = profile_data.get("manager", None)
        password = validated_data.pop("password", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)

        instance.save()

        profile, _ = UserProfile.objects.get_or_create(user=instance)
        if role is not None:
            profile.role = role
        if manager_provided:
            profile.manager = manager
        profile.save()
        instance.profile = profile

        return instance



class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )

    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")

        user = authenticate(
            request=self.context.get("request"),
            username=username,
            password=password,
        )

        if not user:
            raise serializers.ValidationError(
                {"detail": "Invalid username or password."}
            )

        if not user.is_active:
            raise serializers.ValidationError(
                {"detail": "This account is inactive."}
            )

        attrs["user"] = user
        return attrs



class PurchaseRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = PurchaseRequest
        fields = [
            "id",
            "title",
            "amount",
            "description",
            "status",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "status",
            "created_at",
        ]
