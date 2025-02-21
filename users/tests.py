# import io
# from unittest import mock
#
# from django.contrib.auth import get_user_model
# from django.core.files.uploadedfile import SimpleUploadedFile
# from django.urls import reverse
# from PIL import Image
# from rest_framework import status
# from rest_framework.test import APITestCase
# from rest_framework_simplejwt.tokens import AccessToken
#
# User = get_user_model()
#
#
# class UserProfileViewTest(APITestCase):
#     def setUp(self):
#         self.user = User.objects.create_user(
#             email="test@example.com", password="password123", nick_name="oldnickname"
#         )
#         self.access_token = str(AccessToken.for_user(self.user))
#         self.url = reverse("profile-update")
#
#     def test_get_user_profile(self):
#         response = self.client.get(
#             self.url, HTTP_AUTHORIZATION=f"Bearer {self.access_token}"
#         )
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data["user"]["nick_name"], "oldnickname")
#
#     @mock.patch("boto3.client")
#     def test_patch_user_profile(self, mock_s3_client):
#         mock_s3_client.return_value.upload_fileobj.return_value = None
#
#         # 유효한 1x1 PNG 이미지 생성
#         image_data = io.BytesIO()
#         image = Image.new("RGB", (1, 1), color="white")
#         image.save(image_data, format="PNG")
#         image_data.seek(0)
#
#         image_file = SimpleUploadedFile(
#             "test_image.png", image_data.getvalue(), content_type="image/png"
#         )
#
#         response = self.client.patch(
#             self.url,
#             {"nick_name": "newnickname", "profile_img": image_file},
#             format="multipart",
#             HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
#         )
#
#         print(response.data)  # 응답 데이터 출력
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertIn("user", response.data)
#         self.assertEqual(response.data["user"]["nick_name"], "newnickname")
