from django.contrib.auth.views import LogoutView
from django.urls import path

from .views import (  # GoogleCallbackView,; GoogleLoginView,; KakaoCallbackView,; KakaoLoginView,; LogoutView,; NaverCallbackView,; NaverLoginView,; UserProfileView,; UserWithdrawView,
    SocialLoginView,
)

urlpatterns = [
    # # Social Login URLs
    # path("login/kakao/", KakaoLoginView.as_view(), name="kakao-login"),
    # path("login/google/", GoogleLoginView.as_view(), name="google-login"),
    # path("login/naver/", NaverLoginView.as_view(), name="naver-login"),
    # # Social Callback URLs - GET 메소드 제거
    # path("callback/google/", GoogleCallbackView.as_view(), name="google-callback"),
    # path("callback/kakao/", KakaoCallbackView.as_view(), name="kakao-callback"),
    # path("callback/naver/", NaverCallbackView.as_view(), name="naver-callback"),
    # User Management URLs
    path("login/<str:provider>/", SocialLoginView.as_view(), name="social_login"),
    path("me/logout/", LogoutView.as_view(), name="logout"),
    # path("me/profile/update/", UserProfileView.as_view(), name="profile-update"),
    # path("me/profile/withdraw/", UserWithdrawView.as_view(), name="profile-withdraw"),
]
