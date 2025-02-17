# from django.contrib.auth import get_user_model
# from django.utils import timezone
# from rest_framework.test import APITestCase
#
# from bookmark.models import Bookmark
#
# from .models import Webtoon
#
#
# class BookmarkTestCase(APITestCase):
#     def setUp(self):
#         self.user = get_user_model().objects.create_user(
#             # username='testuser',
#             email="test@example.com",
#             nick_name="TestNick",
#             password="testpass",
#         )
#         self.webtoon = Webtoon.objects.create(
#             title="Test Webtoon",
#             publication_day=timezone.now().date(),  # publication_day 값 제공
#         )
#         self.client.force_authenticate(user=self.user)
#         self.url = "/api/bookmarks/"
#
#     def test_create_bookmark(self):
#         response = self.client.post(self.url, {"webtoon": self.webtoon.id})
#         self.assertEqual(response.status_code, 201)
#         self.assertEqual(Bookmark.objects.count(), 1)
#         self.assertEqual(Bookmark.objects.get().webtoon, self.webtoon)
#
#     def test_list_bookmarks(self):
#         Bookmark.objects.create(user=self.user, webtoon=self.webtoon)
#         response = self.client.get(self.url)
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(len(response.data), 1)
#
#     def test_delete_bookmark(self):
#         bookmark = Bookmark.objects.create(user=self.user, webtoon=self.webtoon)
#         response = self.client.post(self.url, {"webtoon": self.webtoon.id})
#         self.assertEqual(response.status_code, 204)
#         self.assertEqual(Bookmark.objects.count(), 0)
