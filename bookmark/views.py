from rest_framework import generics, status
from rest_framework.response import Response

from bookmark.models import Bookmark
from bookmark.serializers import BookmarkSerializer


class BookmarkListCreateView(generics.ListCreateAPIView):
    serializer_class = BookmarkSerializer

    def get_queryset(self):
        return Bookmark.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        webtoon_id = self.request.data.get("webtoon")
        existing_bookmarks = Bookmark.objects.filter(
            user=self.request.user, webtoon_id=webtoon_id
        )

        if existing_bookmarks:
            existing_bookmarks.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        serializer.save(user=self.request.user, webtoon_id=webtoon_id)
