from rest_framework import serializers

from users.models import CustomUser


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["nick_name", "profile_img"]
        extra_kwargs = {
            "nick_name": {"required": False},
            "profile_img": {"required": False},
        }
