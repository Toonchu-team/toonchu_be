from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = [
    "https://toonchu-fe.vercel.app/",
    "http://be.toonchu.kro.kr/",
    ENV.get("DB_HOST"),
]


CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
CORS_ALLOW_HEADERS = ["content-type", "authorization", "x-csrf-token"]

# # 보안 설정 추가
SECURE_HSTS_SECONDS = 3600
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
            "datefmt": "%d/%b/%Y %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "console.info": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": True,
        },
        "console.error": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": True,
        },
        "logger.info": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "logger.warning": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
        "logger.error": {
            "level": "ERROR",
            "handlers": ["console"],
            "propagate": False,
        },
    },
}
