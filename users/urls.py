from django.urls import path

from .views import (
    LogoutView,
    SocialLoginView,
    TokenRefreshView,
    UserProfileView,
    UserWithdrawView,
)

urlpatterns = [
    # Social Login URLs
    path("login/<str:provider>/", SocialLoginView.as_view(), name="social_login"),
    # Token refresh URL (Access Token 갱신 API)
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # User Management URLs
    path("me/logout/", LogoutView.as_view(), name="logout"),
    path("me/profile/update/", UserProfileView.as_view(), name="profile-update"),
    path("me/profile/withdraw/", UserWithdrawView.as_view(), name="profile-withdraw"),
]
