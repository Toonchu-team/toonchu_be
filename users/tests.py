from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken


class SocialLoginTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch('users.serializers.requests.post')
    @patch('users.serializers.requests.get')
    def test_kakao_login(self, mock_get, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {'access_token': 'fake_token'}

        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'id': '12345',
            'kakao_account': {
                'email': 'test@example.com',
                'profile': {'nickname': 'Test User'}
            }
        }

        url = reverse('oauth-callback', kwargs={'provider': 'kakao'})
        response = self.client.get(url, {'code': 'fake_code'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertEqual(response.data['email'], 'test@example.com')
        self.assertEqual(response.data['nick_name'], 'Test User')

        # Verify that the user was created in the database
        self.assertTrue(CustomUser.objects.filter(email='test@example.com').exists())

# class UserProfileUpdateTests(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(
#             email='test@example.com',
#             nick_name='OldNickname',
#             provider='kakao'
#         )
#         self.client.force_authenticate(user=self.user)
#
#     def test_update_profile(self):
#         url = reverse('profile-update')
#         data = {'nick_name': 'NewNickname'}
#         response = self.client.post(url, data)
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['nick_name'], 'NewNickname')
#         self.user.refresh_from_db()
#         self.assertEqual(self.user.nick_name, 'NewNickname')
#
#
# class LogoutTests(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.user = CustomUser.objects.create_user(
#             email='test@example.com',
#             nick_name='TestUser',
#             provider='kakao'
#         )
#         self.client.force_authenticate(user=self.user)
#
#     @patch('rest_framework_simplejwt.tokens.RefreshToken.blacklist')
#     def test_logout(self, mock_blacklist):
#         url = reverse('logout')
#         refresh = RefreshToken.for_user(self.user)
#         response = self.client.post(url, {'refresh_token': str(refresh)})
#
#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['message'], '로그아웃 되었습니다.')
#         mock_blacklist.assert_called_once()
