from django.urls import path
from .views import (
    KakaoLoginView,
    GoogleLoginView,
    NaverLoginView,
    LogoutView,
    UserProfileView,
    NaverCallbackView,
    GoogleCallbackView,
    KakaoCallbackView
)

urlpatterns = [
    # Social Login URLs
    path('login/kakao/', KakaoLoginView.as_view(), name='kakao-login'),
    path('login/google/', GoogleLoginView.as_view(), name='google-login'),
    path('login/naver/', NaverLoginView.as_view(), name='naver-login'),

    # Social Callback URLs - GET 메소드 제거
    path('callback/google/', GoogleCallbackView.as_view(), name='google-callback'),
    path('callback/kakao/', KakaoCallbackView.as_view(), name='kakao-callback'),
    path('callback/naver/', NaverCallbackView.as_view(), name='naver-callback'),

    # User Management URLs
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/update/', UserProfileView.as_view(), name='profile-update'),
]