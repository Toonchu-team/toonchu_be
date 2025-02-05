from django.urls import path


from .views import KakaoCallbackView, GoogleCallbackView, NaverCallbackView, NaverLoginView, GoogleLoginView, \
    KakaoLoginView, LogoutView, UserProfileUpdateView

urlpatterns = [
    path('oauth/kakao/callback/', KakaoCallbackView.as_view(), name='kakao-callback'),
    path('oauth/google/callback/', GoogleCallbackView.as_view(), name='google-callback'),
    path('oauth/naver/callback/', NaverCallbackView.as_view(), name='naver-callback'),

    path('login/kakao/', KakaoLoginView.as_view(), name='kakao-login'),
    path('login/google/', GoogleLoginView.as_view(), name='google-login'),
    path('login/naver/', NaverLoginView.as_view(), name='naver-login'),

    path('logout/', LogoutView.as_view(), name='logout'),

    path('profile/update/', UserProfileUpdateView.as_view(), name='user-profile-update'),
]
