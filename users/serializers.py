from django.contrib.auth import get_user_model
from django.core.validators import MaxLengthValidator, MinLengthValidator
from rest_framework import serializers
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken

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
    profile_img = serializers.URLField(required=False, allow_null=True)  # URL 반환

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "nick_name",
            "profile_img",
            "provider",
            "is_hidden",
            "is_created",
            "is_updated",
        )
        read_only_fields = (
            "id",
            "email",
            "provider",
            "is_hidden",
            "is_created",
            "is_updated",
        )

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


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        refresh_token = attrs.get("refresh")

        if not refresh_token:
            raise serializers.ValidationError({"error": "Refresh token is required."})

        try:
            # 토큰 구조 검증
            UntypedToken(refresh_token)
            # RefreshToken 인스턴스 생성 및 유효성 검증
            refresh = RefreshToken(refresh_token)
            refresh.verify()  # 서명 및 만료 검증

            # 새로운 액세스 토큰 생성
            new_access_token = str(refresh.access_token)
            print(
                f"New access token generated: {new_access_token[:10]}..."
            )  # 로깅 추가
            return {"access": new_access_token}

        except (TokenError, InvalidToken) as e:
            print(f"Token validation failed: {str(e)}")  # 로깅 추가
            raise serializers.ValidationError({"error": str(e)})
