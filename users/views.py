from django.contrib.auth import get_user_model
from django.http import HttpResponseNotAllowed
from django.utils import timezone
from rest_framework import generics, status, permissions
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiTypes, OpenApiResponse
from rest_framework.response import Response

from .models import CustomUser
from .oauth_mixins import KaKaoProviderInfoMixin, GoogleProviderInfoMixin, NaverProviderInfoMixin
from .serializers import LogoutSerializer, UserProfileSerializer, SocialLoginSerializer


from abc import abstractmethod
import requests
import os
import logging

logger = logging.getLogger(__name__)

User = get_user_model()

class BaseSocialLoginView(generics.RetrieveAPIView):
    permission_classes = [AllowAny]

    @abstractmethod
    def get_provider_info(self):
        pass

    @extend_schema(
        summary="소셜 로그인 URL 요청",
        description="소셜 로그인을 위한 인증 URL을 반환합니다.",
        responses={200: OpenApiTypes.OBJECT},
    )
    def retrieve(self, request, *args, **kwargs):
        provider_info = self.get_provider_info()

        if provider_info["name"] == "구글":
            auth_url = (
                f"{provider_info['authorization_url']}"
                f"?response_type=code"
                f"&client_id={provider_info['client_id']}"
                f"&redirect_uri={provider_info['callback_url']}"
                f"&scope=email%20profile"
                f"&access_type=offline"
            )
        else:
            auth_url = (
                f"{provider_info['authorization_url']}"
                f"&client_id={provider_info['client_id']}"
                f"&redirect_uri={provider_info['callback_url']}"
            )

        return Response({"auth_url": auth_url})

class KakaoLoginView(KaKaoProviderInfoMixin, BaseSocialLoginView):
    serializer_class = SocialLoginSerializer

    @extend_schema(
        summary="카카오 로그인 URL 요청",
        description="카카오 로그인을 위한 인증 URL을 반환합니다.",
        tags=["Kakao Social"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

class GoogleLoginView(GoogleProviderInfoMixin, BaseSocialLoginView):
    serializer_class = SocialLoginSerializer

    @extend_schema(
        summary="구글 로그인 URL 요청",
        description="구글 로그인을 위한 인증 URL을 반환합니다.",
        responses={200: OpenApiResponse(response={"auth_url": "string"})},
        tags=["Google Social"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

class NaverLoginView(NaverProviderInfoMixin, BaseSocialLoginView):
    serializer_class = SocialLoginSerializer

    @extend_schema(
        summary="네이버 로그인 URL 요청",
        description="네이버 로그인을 위한 인증 URL을 반환합니다.",
        tags=["Naver Social"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class OAuthCallbackView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = SocialLoginSerializer

    @abstractmethod
    def get_provider_info(self):
        pass

    @extend_schema(
        summary="OAuth 콜백 처리",
        description="소셜 로그인 인증 코드를 받아 사용자 정보를 조회하고 로그인 또는 회원가입을 처리합니다.",
        request=SocialLoginSerializer,
        parameters=[
            {
                'name': 'code',
                'in': 'query',
                'description': 'OAuth 인증 코드',
                'required': True,
                'type': 'string',
                'example': '0w57FBY27HJ6xCUZAcG7Z-QlFBUnT-qKlMLD2R7lmDJM06Bsvoj4BQAAAAQKPCJSAAABlM-9ooKGtS2__sNdBQ'
            }
        ],
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
    )
    def create(self, request, *args, **kwargs):
        logger.debug(f"Received data: {request.data}")  # request.GET 대신 request.data 로그 추가
        serializer = self.get_serializer(data=request.data)  # request.GET → request.data 변경
        if serializer.is_valid():
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def perform_create(self, serializer):
        code = serializer.validated_data['code']
        provider_info = self.get_provider_info()
        token_response = self.get_token(code, provider_info)

        if token_response.status_code != status.HTTP_200_OK:
            return Response(
                {"msg": f"{provider_info['name']} 서버로 부터 토큰을 받아오는데 실패하였습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = token_response.json().get("access_token")
        profile_response = self.get_profile(access_token, provider_info)

        if profile_response.status_code != status.HTTP_200_OK:
            return Response(
                {"msg": f"{provider_info['name']} 서버로 부터 프로필 데이터를 받아오는데 실패하였습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return self.login_process_user(self.request, profile_response.json(), provider_info)





class KakaoCallbackView(KaKaoProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="카카오 OAuth 콜백",
        description="카카오 소셜 로그인 콜백을 처리합니다.",
        tags=["Kakao Social"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

class GoogleCallbackView(GoogleProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="구글 OAuth 콜백",
        description="구글 소셜 로그인 콜백을 처리합니다.",
        tags=["Google Social"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

class NaverCallbackView(NaverProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="네이버 OAuth 콜백",
        description="네이버 소셜 로그인 콜백을 처리합니다.",
        tags=["Naver Social"],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

class LogoutView(generics.CreateAPIView):
    serializer_class = LogoutSerializer

    @extend_schema(
        summary="로그아웃 처리",
        description="로그아웃 처리합니다. 로그아웃과 동시에 token값은 blacklist에 보내서 다시 사용 불가",
        tags=["Logout"],
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.perform_create(serializer)

    def perform_create(self, serializer):
        try:
            refresh_token = serializer.validated_data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "로그아웃 되었습니다."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from django.http import HttpResponseNotAllowed
import os
from django.utils import timezone

from .serializers import UserProfileSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

class UserProfileView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer
    queryset = User.objects.all()

    def get_object(self):
        return self.request.user

    @extend_schema(
        summary="사용자 프로필 조회",
        description="인증된 사용자의 프로필 정보를 조회합니다.",
        responses={200: UserProfileSerializer},
        tags=["User Profile"],
    )
    def get(self, request, *args, **kwargs):  # GET 메서드 처리
        serializer = self.get_serializer(self.get_object())
        return Response(serializer.data)

    @extend_schema(
        summary="사용자 프로필 수정",
        description="인증된 사용자의 닉네임과 프로필 이미지를 수정합니다.",
        request=UserProfileSerializer,
        responses={200: UserProfileSerializer},
        tags=["User Profile"],
    )
    def post(self, request, *args, **kwargs):  # POST 메서드만 처리
        if request.method not in ['POST']:
            return HttpResponseNotAllowed(["POST"])

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def perform_update(self, serializer):
        user = self.request.user
        profile_img = self.request.FILES.get('profile_img')
        if profile_img:
            upload_dir = '/app/media/profile'
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, f"{user.id}_{profile_img.name}")

            with open(file_path, 'wb+') as destination:
                for chunk in profile_img.chunks():
                    destination.write(chunk)

            user.profile_img = f"/media/profile/{user.id}_{profile_img.name}"

        user.is_updated = timezone.now()
        user.save()
        serializer.save()
