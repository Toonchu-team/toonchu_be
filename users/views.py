from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from abc import abstractmethod
from .models import Provider
from .oauth_mixins import KaKaoProviderInfoMixin, GoogleProviderInfoMixin, NaverProviderInfoMixin
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiTypes

User = get_user_model()

class BaseSocialLoginView(APIView):
    permission_classes = [AllowAny]

    @abstractmethod
    def get_provider_info(self):
        pass

    @extend_schema(
        summary="소셜 로그인 URL 요청",
        description="소셜 로그인을 위한 인증 URL을 반환합니다.",
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request):
        provider_info = self.get_provider_info()

        # Google의 경우 다르게 처리
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
            # 카카오와 네이버는 기존 방식 유지
            auth_url = (
                f"{provider_info['authorization_url']}"
                f"&client_id={provider_info['client_id']}"
                f"&redirect_uri={provider_info['callback_url']}"
            )

        return Response({"auth_url": auth_url})



class KakaoLoginView(KaKaoProviderInfoMixin, BaseSocialLoginView):
    @extend_schema(
        summary="카카오 로그인 URL 요청",
        description="카카오 로그인을 위한 인증 URL을 반환합니다.",
        tags=["Kakao Social"],
    )
    def get(self, request):
        return super().get(request)

class GoogleLoginView(GoogleProviderInfoMixin, BaseSocialLoginView):
    @extend_schema(
        summary="구글 로그인 URL 요청",
        description="구글 로그인을 위한 인증 URL을 반환합니다.",
        tags=["Google Social"],
    )
    def get(self, request):
        return super().get(request)

class NaverLoginView(NaverProviderInfoMixin, BaseSocialLoginView):
    @extend_schema(
        summary="네이버 로그인 URL 요청",
        description="네이버 로그인을 위한 인증 URL을 반환합니다.",
        tags=["Naver Social"],
    )
    def get(self, request):
        return super().get(request)



class OAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    @abstractmethod
    def get_provider_info(self):
        pass

    @extend_schema(
        summary="OAuth 콜백 처리",
        description="소셜 로그인 인증 코드를 받아 사용자 정보를 조회하고 로그인 또는 회원가입을 처리합니다.",
        parameters=[
            {
                'name': 'code',
                'in': 'query',
                'description': 'OAuth 인증 코드',
                'required': True,
                'type': 'string',
                'example': '0w57FBY27HJ6xCUZAcG7Z-QlFBUnT-qKlMLD2R7lmDJM06Bsvoj4BQAAAAQKPCJSAAABlM-9ooKGtS2__sNdBQ'     # 인가코드 입력예시
            }
        ],
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT,
        },
        examples=[
            OpenApiExample(
                'Successful login',
                description='인가코드를 통한 로그인 성공 응답',
                value={
                    "email": "user@example.com",
                    "nick_name": "User Nickname",
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                },
                response_only=True,
                status_codes=["200"]
            ),
            OpenApiExample(
                'Failed - No authorization code',
                description='인가코드가 없는 경우',
                value={
                    "msg": "인가코드가 필요합니다."
                },
                response_only=True,
                status_codes=["400"]
            ),
            OpenApiExample(
                'Failed - Token retrieval error',
                description='토큰 발급 실패',
                value={
                    "msg": "서버로 부터 토큰을 받아오는데 실패하였습니다."
                },
                response_only=True,
                status_codes=["400"]
            ),
            OpenApiExample(
                'Failed - Profile retrieval error',
                description='프로필 조회 실패',
                value={
                    "msg": "서버로 부터 프로필 데이터를 받아오는데 실패하였습니다."
                },
                response_only=True,
                status_codes=["400"]
            ),
        ]
    )

    # 인가 코드 확인
    def get(self, request, *args, **kwargs):
        code = request.GET.get("code")
        if not code:
            return Response({"msg": "인가코드가 필요합니다."}, status=status.HTTP_400_BAD_REQUEST)

        provider_info = self.get_provider_info()
        token_response = self.get_token(code, provider_info)        # 액세스 토큰 획득

        if token_response.status_code != status.HTTP_200_OK:
            return Response(
                {"msg": f"{provider_info['name']} 서버로 부터 토큰을 받아오는데 실패하였습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = token_response.json().get("access_token")
        profile_response = self.get_profile(access_token, provider_info)        # 사용자 프로필 정보 획득

        if profile_response.status_code != status.HTTP_200_OK:
            return Response(
                {"msg": f"{provider_info['name']} 서버로 부터 프로필 데이터를 받아오는데 실패하였습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 로그인 또는 회원가입 처리
        return self.login_process_user(request, profile_response.json(), provider_info)

    # 토큰 획득 메서드
    def get_token(self, code, provider_info):
        return requests.post(
            provider_info["token_url"],
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": provider_info["callback_url"],
                "client_id": provider_info["client_id"],
                "client_secret": provider_info["client_secret"],
            },
        )

    # 프로필 정보 획득 메서드
    def get_profile(self, access_token, provider_info):
        return requests.get(
            provider_info["profile_url"],
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
            },
        )

    # 로그인 또는 회원가입 처리 메서드
    def login_process_user(self, request, profile_res_data, provider_info):
        email, nick_name, provider_id = self.get_user_data(provider_info, profile_res_data)
        # 기존 사용자 확인 또는 새 사용자 생성
        try:
            provider = Provider.objects.get(provider=provider_info['name'].lower(), provider_id=provider_id)
            user = provider.user
        except Provider.DoesNotExist:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                user = User.objects.create_user(email=email, nick_name=nick_name)

            Provider.objects.create(
                user=user,
                provider=provider_info['name'].lower(),
                provider_id=provider_id,
                email=email
            )

        # JWT 토큰 생성 및 응답
        refresh_token = RefreshToken.for_user(user)
        response_data = {
            "email": user.email,
            "nick_name": user.nick_name,
            "access_token": str(refresh_token.access_token)
        }

        response = Response(response_data, status=status.HTTP_200_OK)
        response.set_cookie("refresh", str(refresh_token))

        return response


    # 소셜 플랫폼별 사용자 데이터 추출 메서드
    def get_user_data(self, provider_info, profile_res_data):
        if provider_info["name"] == "구글":
            email = profile_res_data.get(provider_info["email_field"])
            nick_name = profile_res_data.get(provider_info["nickname_field"])
            provider_id = profile_res_data.get("id")
        elif provider_info["name"] == "네이버":
            profile_data = profile_res_data.get("response")
            email = profile_data.get(provider_info["email_field"])
            nick_name = profile_data.get(provider_info["nickname_field"])
            provider_id = profile_data.get("id")
        elif provider_info["name"] == "카카오":
            account_data = profile_res_data.get("kakao_account")
            email = account_data.get(provider_info["email_field"])
            profile_data = account_data.get("profile")
            nick_name = profile_data.get(provider_info["nickname_field"])
            provider_id = profile_res_data.get("id")
        return email, nick_name, provider_id


# 각 소셜 플랫폼별 콜백 처리 뷰
class KakaoCallbackView(KaKaoProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="카카오 OAuth 콜백",
        description="카카오 소셜 로그인 콜백을 처리합니다.",
        tags=["Kakao Social"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class GoogleCallbackView(GoogleProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="구글 OAuth 콜백",
        description="구글 소셜 로그인 콜백을 처리합니다.",
        tags=["Google Social"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

class NaverCallbackView(NaverProviderInfoMixin, OAuthCallbackView):
    @extend_schema(
        summary="네이버 OAuth 콜백",
        description="네이버 소셜 로그인 콜백을 처리합니다.",
        tags=["Naver Social"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
