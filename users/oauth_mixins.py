from django.conf import settings


class KaKaoProviderInfoMixin:
    def get_provider_info(self):
        return {
            "name": "카카오",
            "callback_url": settings.KAKAO_CALLBACK_URL,
            "token_url": "https://kauth.kakao.com/oauth/token",
            "profile_url": "https://kapi.kakao.com/v2/user/me",
            "client_id": settings.KAKAO_CLIENT_ID,
            "client_secret": settings.KAKAO_CLIENT_SECRET,
            "email_field": "email",
            "nickname_field": "nickname",
            "profile_image_field": "profile_image_url",
            "authorization_url": "https://kauth.kakao.com/oauth/authorize?response_type=code",
        }


class GoogleProviderInfoMixin:
    def get_provider_info(self):
        return {
            "name": "구글",
            "callback_url": settings.GOOGLE_CALLBACK_URL.rstrip('/'),  # Remove trailing slash
            "token_url": "https://oauth2.googleapis.com/token",
            "profile_url": "https://www.googleapis.com/oauth2/v1/userinfo",
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "email_field": "email",
            "nickname_field": "name",
            "profile_image_field": "picture",
            "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        }

    def get_auth_url(self, provider_info):
        params = {
            'response_type': 'code',
            'client_id': provider_info['client_id'],
            'redirect_uri': provider_info['callback_url'],
            'scope': 'email profile',
            'access_type': 'offline',
            'include_granted_scopes': 'true',
            'state': 'state_parameter_passthrough_value'
        }
        return f"{provider_info['authorization_url']}?{'&'.join(f'{k}={v}' for k, v in params.items())}"


class NaverProviderInfoMixin:
    def get_provider_info(self):
        return {
            "name": "네이버",
            "callback_url": settings.NAVER_CALLBACK_URL,
            "token_url": "https://nid.naver.com/oauth2.0/token",
            "profile_url": "https://openapi.naver.com/v1/nid/me",
            "client_id": settings.NAVER_CLIENT_ID,
            "client_secret": settings.NAVER_CLIENT_SECRET,
            "email_field": "email",
            "nickname_field": "nickname",
            "profile_image_field": "profile_image",
            "authorization_url": "https://nid.naver.com/oauth2.0/authorize?response_type=code",
        }
