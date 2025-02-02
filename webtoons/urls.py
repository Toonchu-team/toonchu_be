from django.urls import path
from webtoons.views import TestView, get_all_webtoons

urlpatterns = [
    path('v1/test/', TestView.as_view(), name='test'),
    path('api/webtoons/all', get_all_webtoons, name='webtoons'),

]