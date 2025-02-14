from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    ENV.get("DB_HOST"),
]


CORS_ALLOW_ALL_ORIGINS = True  # 개발 환경에서만 사용


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
