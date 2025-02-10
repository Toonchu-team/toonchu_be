from django.urls import path
from .views import WebtoonsView

urlpatterns = [
    path('request/', WebtoonsView.as_view(), name='webtoons-post'),
]