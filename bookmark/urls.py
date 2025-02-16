from django.urls import path

from bookmark import views


urlpatterns = [
    path('', views.BookmarkListCreateView.as_view(), name='bookmark-list'),
]