from config.settings.base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = [
    "toonchu-fe.vercel.app",
    "toonchu.com",
    ENV.get("DB_HOST"),
    "localhost",
    "api.toonchu.com",
    "www.toonchu.com",
]

# CORS 설정 (운영 환경)
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "https://toonchu-fe.vercel.app",
    "https://toonchu.com",
    "https://localhost:3000",
    "https://localhost:8000",
    "https://api.toonchu.com",
    "https://www.toonchu.com",
]
CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
CORS_ALLOW_HEADERS = ["*"]


#
# # # 보안 설정 추가
# SECURE_HSTS_SECONDS = 3600
# SECURE_SSL_REDIRECT = True
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True
