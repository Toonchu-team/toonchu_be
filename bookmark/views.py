from django.db import transaction
from rest_framework import generics, status
from rest_framework.response import Response

from bookmark.models import Bookmark
from bookmark.serializers import BookmarkSerializer


class BookmarkListCreateView(generics.ListCreateAPIView):
    serializer_class = BookmarkSerializer

    def get_queryset(self):
        return Bookmark.objects.filter(user=self.request.user)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        webtoon_id = request.data.get("webtoon")
        if not webtoon_id:
            return Response(
                {"error": "Webtoon ID is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            existing_bookmark = Bookmark.objects.filter(
                user=request.user, webtoon_id=webtoon_id
            ).first()

            if existing_bookmark:
                existing_bookmark.delete()
                return Response(
                    {"message": "Bookmark removed successfully."},
                    status=status.HTTP_200_OK,
                )

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                serializer.data, status=status.HTTP_201_CREATED, headers=headers
            )

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
