from django.urls import path

from .views import WebtoonView, WebtoonSearchView

urlpatterns = [
    path("", WebtoonView.as_view(), name="webtoons-post"),
    path("search", WebtoonSearchView.as_view(), name="webtoons-search"),
]
