from django.urls import path
<<<<<<< HEAD
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
=======



# from .views import KakaoCallbackView, GoogleCallbackView, NaverCallbackView, NaverLoginView, GoogleLoginView, \
#     KakaoLoginView, LogoutView, UserProfileUpdateView

urlpatterns = [
    # path('oauth/kakao/callback/', KakaoCallbackView.as_view(), name='kakao-callback'),
    # path('oauth/google/callback/', GoogleCallbackView.as_view(), name='google-callback'),
    # path('oauth/naver/callback/', NaverCallbackView.as_view(), name='naver-callback'),
    #
    # path('login/kakao/', KakaoLoginView.as_view(), name='kakao-login'),
    # path('login/google/', GoogleLoginView.as_view(), name='google-login'),
    # path('login/naver/', NaverLoginView.as_view(), name='naver-login'),
    #
    # path('logout/', LogoutView.as_view(), name='logout'),
    #
    # path('profile/update/', UserProfileUpdateView.as_view(), name='user-profile-update'),
>>>>>>> 966e9f6b741aea6666e822501a7701a0ff394772
