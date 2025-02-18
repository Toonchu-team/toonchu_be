from django.urls import path

from .views import (
    TagListView,
    TagSearchView,
    WebtoonSearchView,
    WebtoonView,
    WebtoonDayListView,
)

urlpatterns = [
    path("", WebtoonView.as_view(), name="webtoons-post"),
    path("search", WebtoonSearchView.as_view(), name="webtoons-search"),
    path("list/tag", TagSearchView.as_view(), name="webtoons-tag-list"),
    path("list/", WebtoonDayListView.as_view(), name="webtoons-day-list"),
    path("tag", TagListView.as_view(), name="webtoons-tag"),
]
