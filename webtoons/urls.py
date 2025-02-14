from django.urls import path

from .views import WebtoonSearchView, WebtoonView

urlpatterns = [
    path("", WebtoonView.as_view(), name="webtoons-post"),
    path("search", WebtoonSearchView.as_view(), name="webtoons-search"),
]
