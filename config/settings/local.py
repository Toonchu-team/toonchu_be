from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    ENV.get("DB_HOST"),
]


CORS_ALLOW_ALL_ORIGINS = True  # 개발 환경에서만 사용
