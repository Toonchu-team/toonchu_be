import uuid

from django.contrib.auth import get_user_model
from django.http import HttpResponseNotAllowed
from django.utils import timezone
from rest_framework import generics, status, permissions
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import request
from drf_spectacular.utils import extend_schema, OpenApiTypes, OpenApiResponse

from .models import CustomUser
from .oauth_mixins import KaKaoProviderInfoMixin, GoogleProviderInfoMixin, NaverProviderInfoMixin
from .serializers import LogoutSerializer, UserProfileSerializer, SocialLoginSerializer, NicknameCheckSerializer

from abc import abstractmethod
import requests
import os
import logging

import datetime

import json


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

    def create(self, request, *args, **kwargs):
        # 🔥 1. 들어온 요청 데이터 확인
        print(f"📩 request.data: {request.data}")
        logger.debug(f"📩 request.data: {request.data}")

        # 🔥 2. 원본 요청 바디 확인 (혹시 JSON 파싱이 안 되는지 체크)
        try:
            raw_body = request.body.decode('utf-8')  # 바이너리 데이터를 문자열로 변환
            json_body = json.loads(raw_body)  # JSON 형식이면 파싱
            print(f"Raw JSON Payload: {json_body}")
            logger.debug(f"Raw JSON Payload: {json_body}")
        except json.JSONDecodeError:
            print("요청 바디가 JSON이 아닙니다.")
            logger.debug("요청 바디가 JSON이 아닙니다.")


        # 🔥 3. serializer 유효성 검사 진행
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # 🔥 4. 인가 코드가 정상적으로 들어왔는지 확인
            code = serializer.validated_data.get('code')
            print(f"💡 받은 인가 코드: {code}")
            logger.debug(f"💡 받은 인가 코드: {code}")

            # ✅ 5. 인가 코드로 access_token 요청
            provider_info = self.get_provider_info()
            token_response = self.get_token(code, provider_info)

            if token_response.status_code != status.HTTP_200_OK:
                logger.error(f"{provider_info['name']} 토큰 요청 실패: {token_response.text}")
                return Response(
                    {"msg": f"{provider_info['name']} 서버에서 토큰을 가져올 수 없습니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            access_token = token_response.json().get("access_token")
            if not access_token:
                logger.error(f"{provider_info['name']} 응답에서 access_token 없음: {token_response.json()}")
                return Response({"msg": "엑세스 토큰을 찾을 수 없습니다."}, status=status.HTTP_400_BAD_REQUEST)

            logger.debug(f"🔑 발급된 access_token: {access_token}")

            # ✅ 6. access_token을 사용하여 사용자 프로필 정보 요청
            profile_response = self.get_profile(access_token, provider_info)
            if profile_response.status_code != status.HTTP_200_OK:
                logger.error(f"{provider_info['name']} 프로필 요청 실패: {profile_response.text}")
                return Response(
                    {"msg": f"{provider_info['name']} 서버에서 사용자 정보를 가져올 수 없습니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user_data = profile_response.json()
            logger.debug(f"사용자 정보: {user_data}")

            # 7. 로그인 또는 회원가입 처리
            return self.login_process_user(request, user_data, provider_info)
        else:
            print(f"Serializer validation failed: {serializer.errors}")
            logger.debug(f"Serializer validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_provider_info(self):
        """
        각 OAuth 공급자에 대한 정보를 제공해야 합니다.
        하위 클래스에서 반드시 구현해야 합니다.
        """
        raise NotImplementedError

    def get_token(self, code, provider_info):
        """
        인가 코드를 사용해 access_token을 요청하는 함수
        """
        token_url = provider_info["token_url"]
        client_id = provider_info["client_id"]
        client_secret = provider_info["client_secret"]
        redirect_uri = provider_info["redirect_uri"]

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        }

        response = requests.post(token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        return response

    def get_profile(self, access_token, provider_info):
        """
        access_token을 사용하여 사용자 프로필을 요청하는 함수
        """
        profile_url = provider_info["profile_url"]
        headers = {"Authorization": f"Bearer {access_token}"}

        response = requests.get(profile_url, headers=headers)
        return response

    def login_process_user(self, request, profile_data, provider_info):
        """
        로그인 또는 회원가입 처리
        """
        email = profile_data.get("email")
        if not email:
            return Response({"msg": "이메일 정보가 없습니다."}, status=status.HTTP_400_BAD_REQUEST)

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "nick_name": profile_data.get("nickname") or f"User_{uuid.uuid4().hex[:6]}",  # 랜덤 닉네임 생성
                "profile_img": profile_data.get("profile_image"),
                "social_provider": provider_info["name"].lower(),
            },
        )

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),  # 클라이언트가 refresh token을 저장할 수 있도록 추가
                "user": {
                    "id": user.id,
                    "nick_name": user.nick_name,
                    "email": user.email,
                    "profile_image": user.profile_img,
                    "provider": provider_info["name"].lower(),
                },
            },
            status=status.HTTP_200_OK,
        )



class KakaoCallbackView(KaKaoProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="카카오 OAuth 콜백",
        description="카카오 소셜 로그인 콜백을 처리합니다.",
        tags=["Kakao Social"],
    )
    def get_token(self, code, provider_info):
        token_url = provider_info["token_url"]
        client_id = provider_info["client_id"]
        client_secret = provider_info["client_secret"]
        callback_url = provider_info["callback_url"]

        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback_url,
            "code": code,
        }


        return requests.post(token_url, data=data)

    def get_profile(self, access_token, provider_info):
        profile_url = provider_info["profile_url"]
        headers = {"Authorization": f"Bearer {access_token}"}
        return requests.get(profile_url, headers=headers)


class GoogleCallbackView(GoogleProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="구글 OAuth 콜백",
        description="구글 소셜 로그인 콜백을 처리합니다.",
        tags=["Google Social"],
    )
    def get_token(self, code, provider_info):
        token_url = provider_info["token_url"]
        client_id = provider_info["client_id"]
        client_secret = provider_info["client_secret"]
        callback_url = provider_info["callback_url"]

        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback_url,
            "code": code,
        }

        return requests.post(token_url, data=data)

    def get_profile(self, access_token, provider_info):
        profile_url = provider_info["profile_url"]
        headers = {"Authorization": f"Bearer {access_token}"}
        return requests.get(profile_url, headers=headers)


class NaverCallbackView(NaverProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="네이버 OAuth 콜백",
        description="네이버 소셜 로그인 콜백을 처리합니다.",
        tags=["Naver Social"],
    )
    def get_token(self, code, provider_info):
        token_url = provider_info["token_url"]
        client_id = provider_info["client_id"]
        client_secret = provider_info["client_secret"]
        callback_url = provider_info["callback_url"]

        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback_url,
            "code": code,
            "state": "YOUR_STATE_VALUE",  # 필요한 경우 state 값 추가
        }

        return requests.post(token_url, data=data)

    def get_profile(self, access_token, provider_info):
        profile_url = provider_info["profile_url"]
        headers = {"Authorization": f"Bearer {access_token}"}
        return requests.get(profile_url, headers=headers)



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
        data = serializer.data
        return Response(
            {"message": f"{data['nick_name']}의 정보가 정상적으로 반환되었습니다", "user": data},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        summary="사용자 프로필 수정",
        description="인증된 사용자의 닉네임과 프로필 이미지를 수정합니다.",
        request=UserProfileSerializer,
        responses={200: UserProfileSerializer},
        tags=["User Profile"],
    )
    def post(self, request, *args, **kwargs):  # POST 메서드만 처리
        if request.method not in ["POST"]:
            return HttpResponseNotAllowed(["POST"])

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        user_data = serializer.data
        return Response(
            {"message": "회원 정보가 수정되었습니다.", "user": user_data},
            status=status.HTTP_200_OK,
        )

    def perform_update(self, serializer):
        user = self.request.user
        profile_img = self.request.FILES.get("profile_img")
        if profile_img:
            upload_dir = "/app/media/profile"
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, f"{user.id}_{profile_img.name}")

            with open(file_path, "wb+") as destination:
                for chunk in profile_img.chunks():
                    destination.write(chunk)

            user.profile_img = f"/media/profile/{user.id}_{profile_img.name}"

        user.is_updated = timezone.now()
        user.save()
        serializer.save()


class UserWithdrawView(generics.GenericAPIView):
    serializer_class = NicknameCheckSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="회원 탈퇴 요청",
        description="회원 탈퇴 요청을 처리합니다. 닉네임 일치 여부를 확인하고, 50일 후 사용자 정보를 삭제합니다.",
        request=NicknameCheckSerializer,
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
        tags=["🚨🚨🚨 User Withdraw 🚨🚨🚨"],
    )


    def delete(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        input_nick_name = serializer.validated_data['input_nick_name']
        user = self.request.user

        if user.nick_name != input_nick_name:
            return Response({"message": "입력한 닉네임과 일치하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)

        user.withdraw_at = timezone.now()
        delete_date = timezone.now() + datetime.timedelta(days=50)
        user.is_active = False
        user.save()

        request_data = {"message": "계정탈퇴가 요청되었습니다. 50일후 사용자 정보는 완전히 삭제가 됩니다.", "deletion_date": delete_date}
        return Response({"data": request_data}, status=status.HTTP_200_OK)

