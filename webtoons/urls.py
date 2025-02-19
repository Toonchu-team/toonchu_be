from django.urls import path

from .views import (
    ListByTagView,
    SearchByTagView,
    SearchByIntegrateView,
    WebtoonCreateView,
    ListByDayView,
    ListView,

)

urlpatterns = [
    path("request/", WebtoonCreateView.as_view(), name="webtoons-create"),
    path("search", SearchByIntegrateView.as_view(), name="webtoons-search"),
    path("search/tag", SearchByTagView.as_view(), name="webtoons-tag-list"),
    path("list/", ListByDayView.as_view(), name="webtoons-day-list"),
    path("list", ListView.as_view(), name="webtoons-sort"),
    path("tag", ListByTagView.as_view(), name="webtoons-tag"),
]
