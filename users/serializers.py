<<<<<<< HEAD
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import MinLengthValidator, MaxLengthValidator

User = get_user_model()

class SocialLoginSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, error_messages={'required': 'OAuth 인증 코드가 필요합니다.'})

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'nick_name', 'profile_img', 'provider', 'is_adult']
        read_only_fields = ['email', 'provider', 'is_adult']

    def validate_nick_name(self, value):
        MinLengthValidator(2)(value)
        MaxLengthValidator(16)(value)
        return value

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
=======
# from rest_framework import serializers
#
# from users.models import CustomUser
#
#
# class LogoutSerializer(serializers.Serializer):
#     refresh_token = serializers.CharField(required=True)
#
# class UserProfileUpdateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomUser
#         fields = ['nick_name', 'profile_img']
#         extra_kwargs = {
#             'nick_name': {'required': False},
#             'profile_img': {'required': False},
#         }
>>>>>>> 966e9f6b741aea6666e822501a7701a0ff394772
