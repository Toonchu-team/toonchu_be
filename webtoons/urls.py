from django.urls import path

from .views import WebtoonView

urlpatterns = [
    path("request/", WebtoonView.as_view(), name="webtoons-post"),
]
