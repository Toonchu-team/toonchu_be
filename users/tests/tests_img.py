# # import io
# # from unittest import mock
# #
# # from django.contrib.auth import get_user_model
# # from django.core.files.uploadedfile import SimpleUploadedFile
# # from django.urls import reverse
# # from PIL import Image
# # from rest_framework import status
# # from rest_framework.test import APITestCase
# # from rest_framework_simplejwt.tokens import AccessToken
# #
# # User = get_user_model()
# #
# #
# # class UserProfileViewTest(APITestCase):
# #     def setUp(self):
# #         self.user = User.objects.create_user(
# #             email="test@example.com", password="password123", nick_name="oldnickname"
# #         )
# #         self.access_token = str(AccessToken.for_user(self.user))
# #         self.url = reverse("profile-update")
# #
# #     def test_get_user_profile(self):
# #         response = self.client.get(
# #             self.url, HTTP_AUTHORIZATION=f"Bearer {self.access_token}"
# #         )
# #         self.assertEqual(response.status_code, status.HTTP_200_OK)
# #         self.assertEqual(response.data["user"]["nick_name"], "oldnickname")
# #
# #     @mock.patch("boto3.client")
# #     def test_patch_user_profile(self, mock_s3_client):
# #         mock_s3_client.return_value.upload_fileobj.return_value = None
# #
# #         # 유효한 1x1 PNG 이미지 생성
# #         image_data = io.BytesIO()
# #         image = Image.new("RGB", (1, 1), color="white")
# #         image.save(image_data, format="PNG")
# #         image_data.seek(0)
# #
# #         image_file = SimpleUploadedFile(
# #             "test_image.jpg", image_data.getvalue(), content_type="image/png"
# #         )
# #
# #         response = self.client.patch(
# #             self.url,
# #             {"nick_name": "newnickname", "profile_img": image_file},
# #             format="multipart",
# #             HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
# #         )
# #
# #         print(response.data)  # 응답 데이터 출력
# #
# #         self.assertEqual(response.status_code, status.HTTP_200_OK)
# #         self.assertIn("user", response.data)
# #         self.assertEqual(response.data["user"]["nick_name"], "newnickname")
#
#
# from django.test import TestCase
# from django.core.files.uploadedfile import SimpleUploadedFile
# from users.models import CustomUser
# from rest_framework.test import APIClient
# import boto3
# from io import BytesIO
# import os
#
#
# class UserProfileViewTestCase(TestCase):
#     @classmethod
#     def setUpTestData(cls):
#         cls.user = CustomUser.objects.create_user(
#             email="test1@gmail.com", password="password", nick_name="Tester"
#         )
#
#     def setUp(self):
#         """APIClient 초기화 및 사용자 인증"""
#         self.client = APIClient()
#         self.client.force_authenticate(user=self.user)
#
#     def test_user_profile_get(self):
#         """사용자 프로필 조회 테스트"""
#         response = self.client.get("/users/me/profile/update/")
#         print(response.data)  # 응답 데이터 출력
#         self.assertEqual(response.status_code, 200)
#         self.assertEqual(response.data["user"]["nick_name"], self.user.nick_name)
#
#     def test_user_profile_patch_with_image(self):
#         """사용자 프로필 수정 테스트 (실제 NCP 연결 - 이미지 포함)"""
#         image_path = os.path.join(os.path.dirname(__file__), "../profile/test_image.jpg")
#         with open(image_path, "rb") as image_file:
#             image = SimpleUploadedFile("test_image.jpg", image_file.read(), content_type="image/png")
#             response = self.client.patch(
#                 "/users/me/profile/update/",
#                 {"nick_name": "ImageTest", "profile_img": image},
#                 format="multipart",
#             )
#         self.assertEqual(response.status_code, 200)
#
#         image_file = SimpleUploadedFile("test_image.jpg", image_content, content_type="image/png")
#
#         data = {"nick_name": "NewName", "profile_img": image_file}
#         response = self.client.patch("/users/me/profile/update/", data, format="multipart")
#
#         print(response.data)
#         self.assertEqual(response.status_code, 200)
#
#         self.user.refresh_from_db()
#         self.assertEqual(self.user.nick_name, "NewName")
#         self.assertEqual(self.user.is_hidden, 0)
#
#     def test_user_profile_patch_without_image(self):
#         """사용자 프로필 수정 테스트 (이미지 제외)"""
#         data = {"nick_name": "OnlyNameChange"}
#         response = self.client.patch("/users/me/profile/update/", data)  # format 제거
#
#         print(response.data)
#         self.assertEqual(response.status_code, 200)
#
#         self.user.refresh_from_db()
#         self.assertEqual(self.user.nick_name, "OnlyNameChange")
#         self.assertEqual(self.user.is_hidden, 0)
#
#     def tearDown(self):
#         """테스트 종료 후 업로드된 이미지 삭제 (NCP 연결 확인용)"""
#         if self.user.profile_img:
#             s3 = boto3.client(
#                 "s3",
#                 aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
#                 aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
#                 region_name=os.environ.get("AWS_S3_REGION_NAME"),
#             )
#             s3.delete_object(Bucket=os.environ.get("AWS_STORAGE_BUCKET_NAME"), Key=self.user.profile_img.name)
#
#


# import io
# import os
# from django.test import TestCase
# from django.core.files.uploadedfile import SimpleUploadedFile
# from rest_framework import status
# from rest_framework.test import APIClient
# from rest_framework_simplejwt.tokens import AccessToken
# from users.models import CustomUser
#
# class UserProfileViewTestCase(TestCase):
#     def setUp(self):
#         super().setUp()
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(
#             email="testuser@example.com", password="testpassword", nick_name="testuser"
#         )
#         self.token = str(AccessToken.for_user(self.user))
#         self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
#
#     def test_user_profile_patch_with_image(self):
#         """사용자 프로필 수정 테스트 (실제 NCP 연결 - 이미지 포함)"""
#         image_path = os.path.join(os.path.dirname(__file__), "test_image.jpg")
#         with open(os.path.join(os.path.dirname(__file__), 'test_image.jpg'), 'rb') as img_file:
#             image_content = img_file.read()
#
#             image = SimpleUploadedFile(
#                 name='test_image.jpg',
#                 content=img_file.read(),
#                 content_type='image/png'
#             )
#
#         data = {"profile_img": image}
#         response = self.client.patch("/users/me/profile/update/", data, format="multipart")
#
#         print("Image content length:", len(image_content))
#         print("Image name:", image.name)
#         print("Response status code:", response.status_code)
#         print("Response data:", response.data)
#
#         # self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

from django.core.files.uploadedfile import SimpleUploadedFile

from users.models import CustomUser

user = CustomUser.objects.first()
with open("users/tests/test_image.jpg", "rb") as img:
    user.profile_img.save(
        "test_image.jpg",
        SimpleUploadedFile("test_image.jpg", img.read(), content_type="image/jpg"),
    )
    user.save()

print(user.profile_img.url)  # 업로드된 이미지의 URL 확인
