from django.contrib.auth import get_user_model
from django.core.validators import MaxLengthValidator, MinLengthValidator
from jwt.exceptions import InvalidTokenError
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class SocialLoginSerializer(serializers.Serializer):
    code = serializers.CharField(
        required=True, error_messages={"required": "OAuth 인증 코드가 필요합니다."}
    )


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # 변경: CustomUser -> User
        fields = [
            "id",
            "email",
            "nick_name",
            "profile_img",
            "provider",
            "is_adult",
            "is_created",
            "is_updated",
        ]
        read_only_fields = ["id", "provider", "is_adult", "is_created"]


class UserProfileSerializer(serializers.ModelSerializer):
    profile_img = serializers.ImageField(required=False)  # 파일 업로드 지원

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "nick_name",
            "profile_img",
            "provider",
            "is_adult",
            "is_created",
            "is_updated",
        ]
        read_only_fields = [
            "id",
            "provider",
            "is_adult",
            "is_created",
        ]

    def validate_nick_name(self, value):
        MinLengthValidator(2)(value)
        MaxLengthValidator(16)(value)
        return value


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        try:
            RefreshToken(attrs["refresh_token"])
            return attrs
        except Exception as e:
            raise serializers.ValidationError(str(e))


class NicknameCheckSerializer(serializers.Serializer):
    input_nick_name = serializers.CharField(required=True)
