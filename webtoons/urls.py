from django.urls import path

from .views import TagListView, TagSearchView, WebtoonSearchView, WebtoonView

urlpatterns = [
    path("", WebtoonView.as_view(), name="webtoons-post"),
    path("search", WebtoonSearchView.as_view(), name="webtoons-search"),
    path("search/tag", TagSearchView.as_view(), name="webtoons-tag-list"),
    path("tag", TagListView.as_view(), name="webtoons-tag"),
]
