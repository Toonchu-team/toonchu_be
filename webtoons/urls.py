from django.urls import path

from .views import WebtoonSearchView, WebtoonView, TagListView, TagSearchView

urlpatterns = [
    path("", WebtoonView.as_view(), name="webtoons-post"),
    path("search", WebtoonSearchView.as_view(), name="webtoons-search"),
    path("search/tag", TagSearchView.as_view(), name="webtoons-tag-list"),
    path("tag", TagListView.as_view(), name="webtoons-tag"),
]
