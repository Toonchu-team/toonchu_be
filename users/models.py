from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, nick_name, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(
            email=self.normalize_email(email),
            nick_name=nick_name,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, nick_name, password=None):
        user = self.create_user(
            email,
            nick_name=nick_name,
            password=password,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)  # 이메일 정보
    nick_name = models.CharField(max_length=100, unique=True)  # 닉네임
    profile_img = models.ImageField(upload_to='profile', blank=True, null=True)  # 프로필 이미지
    is_adult = models.BooleanField(default=False)  # 성인 인증 여부
    is_staff = models.BooleanField(default=False)  # 관리자 여부
    last_login = models.DateTimeField(auto_now=True)  # 마지막 로그인 시간

    # groups와 user_permissions에 related_name 추가
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_groups',  # related_name으로 충돌 방지
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions',  # related_name으로 충돌 방지
        blank=True
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nick_name']

    def __str__(self):
        return self.email


class Provider(models.Model):
    PROVIDER_CHOICES = [
        ('google', 'Google'),
        ('naver', 'naver'),
        ('kakao', 'Kakao'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='providers')  # user 테이블과 연결
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)  # 제공사 이름
    provider_id = models.CharField(max_length=100)  # 제공사 ID
    email = models.EmailField()  # 사용자 이메일

    class Meta:
        unique_together = ('provider', 'provider_id')

    def __str__(self):
        return f"{self.user.email} - {self.provider}"

        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user