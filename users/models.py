from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, nick_name, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        try:
            validate_email(email)
        except ValidationError:
            raise ValueError('Invalid email address')

        user = self.model(
            email=self.normalize_email(email),
            nick_name=nick_name,
            **extra_fields
        )

        user.set_unusable_password()  # set_un_user_password 대신 set_unusable_password 사용
        user.save(using=self._db)
        return user

    def create_superuser(self, email, nick_name):
        user = self.create_user(
            email,
            nick_name=nick_name,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user



class CustomUser(AbstractBaseUser, PermissionsMixin):

    PROVIDER_CHOICES = [
        ('google', 'Google'),
        ('naver', 'naver'),
        ('kakao', 'Kakao'),
    ]


    email = models.EmailField(unique=True)  # 이메일 정보
    nick_name = models.CharField(max_length=100, unique=True)  # 닉네임
    profile_img = models.ImageField(upload_to='profile', blank=True, null=True)  # 프로필 이미지
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)  # 제공사 이름
    is_adult = models.BooleanField(default=False)  # 성인 인증 여부
    is_staff = models.BooleanField(default=False)  # 관리자 여부
    is_updated = models.DateTimeField(null=True, blank=True)    #업데이트 시간
    is_created = models.DateTimeField(auto_now_add=True)

    def set_un_user_password(self):
        self.set_unusable_password()  # set_unusable_password사용 비밀번호 입력하여 로그인 하는 방식 제거 Oauth 이용한 소셜로그인 사용을 위해 추가


    objects = UserManager()

    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email
