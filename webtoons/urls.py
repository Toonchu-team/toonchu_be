from django.urls import path

from .views import (
    ListByTagView,
    ListView,
    SearchByIntegrateView,
    SearchByTagView,
    WebtoonApprovalView,
    WebtoonCreateView,
)

urlpatterns = [
    path("request/", WebtoonCreateView.as_view(), name="webtoons-create"),
    path("search", SearchByIntegrateView.as_view(), name="webtoons-search"),
    path("search/tag", SearchByTagView.as_view(), name="webtoons-tag-list"),
    path("list", ListView.as_view(), name="webtoons-sort"),
    path("tag", ListByTagView.as_view(), name="webtoons-tag"),
    path("<int:pk>/approve", WebtoonApprovalView.as_view(), name="webtoons-approve"),
]
