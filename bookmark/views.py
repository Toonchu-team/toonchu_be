from django.db import transaction
from django.utils import timezone
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
            with transaction.atomic():
                existing_bookmark = (
                    Bookmark.objects.select_for_update()
                    .filter(user=request.user, webtoon_id=webtoon_id)
                    .first()
                )

                if existing_bookmark:
                    # 시간 기반 제어: 마지막 수정으로부터 5초 이내 요청은 무시(연속클릭 방지)
                    if (
                        timezone.now() - existing_bookmark.last_modified
                    ).total_seconds() < 5:
                        return Response(
                            {"error": "Action too frequent. Please try again later."},
                            status=status.HTTP_429_TOO_MANY_REQUESTS,
                        )
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
        serializer.save(user=self.request.user, last_modified=timezone.now())
