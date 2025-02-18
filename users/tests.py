# from django.test import TestCase
# from django.urls import reverse
# from rest_framework.test import APIClient
# from rest_framework import status
# from django.contrib.auth import get_user_model
# from rest_framework_simplejwt.tokens import RefreshToken
#
# User = get_user_model()
#
# class LogoutViewTestCase(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.user = User.objects.create_user(
#             username='testuser',
#             email='testuser@example.com',
#             password='testpass123'
#         )
#         self.refresh = RefreshToken.for_user(self.user)
#         self.access_token = str(self.refresh.access_token)
#
#     def test_logout_success(self):
#         # 클라이언트에 인증 토큰 설정
#         self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
#
#         # 로그아웃 요청
#         response = self.client.post(reverse('logout'), {'refresh_token': str(self.refresh)})
#
#         # 응답 확인
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['message'], '로그아웃 되었습니다.')
#
#     def test_logout_no_token(self):
#         # 토큰 없이 로그아웃 요청
#         response = self.client.post(reverse('logout'))
#
#         # 응답 확인
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertEqual(response.data['error'], '리프레시 토큰이 제공되지 않았습니다.')
#
#     def test_logout_invalid_token(self):
#         # 잘못된 토큰으로 로그아웃 요청
#         response = self.client.post(reverse('logout'), {'refresh_token': 'invalid_token'})
#
#         # 응답 확인
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#         self.assertIn('error', response.data)
