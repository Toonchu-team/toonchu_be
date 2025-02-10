"""
Django settings for config project.

Generated by 'django-admin startproject' using Django 5.1.5.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
from dotenv import dotenv_values

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# .env 파일 로드
ENV = dotenv_values(".env")

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = ENV.get("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition
CUSTOM_APPS = [
    "users",
    "webtoons",
]

SYSTEM_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
]

INSTALLED_APPS = CUSTOM_APPS + SYSTEM_APPS + THIRD_PARTY_APPS  # + ['corsheaders']

MIDDLEWARE = [
    # "corsheaders.middleware.CorsMiddleware", 설치가 안됨 잠시 주석처리함
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": ENV.get("DB_ENGINE"),
        "NAME": ENV.get("DB_NAME"),
        "USER": ENV.get("DB_USER"),
        "PASSWORD": ENV.get("DB_PASSWORD"),
        "HOST": ENV.get("DB_HOST"),
        "PORT": ENV.get("DB_PORT"),
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Swagger settings
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # # JWT 토큰 활성화 후 적용
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
}

# Swagger settings
SPECTACULAR_SETTINGS = {
    "TITLE": "toonchu",
    "DESCRIPTION": "toonchu",
    "VERSION": "1.0.0",
    "COMPONENT_SPLIT_REQUEST": True,  # 요청과 응답 스키마 분리
    "SERVE_INCLUDE_SCHEMA": False,  # 스키마 엔드포인트를 포함하지 않도록 설정
}  # '/api/schema/' 숨김처리

# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "ko-kr"

TIME_ZONE = "Asia/Seoul"

USE_I18N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Media files
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Custom user model
AUTH_USER_MODEL = "users.CustomUser"

SITE_ID = 1

LOGIN_REDIRECT_URL = "/"

# OAuth settings
KAKAO_CLIENT_ID = ENV.get("KAKAO_REST_API_KEY")  # 변경된 부분
KAKAO_CLIENT_SECRET = ENV.get("KAKAO_SECRET")
KAKAO_CALLBACK_URL = ENV.get("KAKAO_REDIRECT_URI")

GOOGLE_CLIENT_ID = ENV.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = ENV.get("GOOGLE_SECRET")
GOOGLE_CALLBACK_URL = ENV.get("GOOGLE_REDIRECT_URI")

NAVER_CLIENT_ID = ENV.get("NAVER_CLIENT_ID")
NAVER_CLIENT_SECRET = ENV.get("NAVER_SECRET")
NAVER_CALLBACK_URL = ENV.get("NAVER_REDIRECT_URI")

# http로 변경 (또는 .env 파일의 URL들을 https로 변경)
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"


CORS_ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",  # React, Vue 등의 프론트엔드 서버 주소
]
CORS_ALLOW_CREDENTIALS = True  # 인증정보 포함 허용

# GOOGLE_OAUTH2_SCOPE = ['email', 'profile']  # 새로운 설정 추가

CORS_ALLOW_ALL_ORIGINS = True  # 개발 환경에서만 사용
