import os

import boto3

from .base import *

DEBUG = True

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    ENV.get("DB_HOST"),
    "www.toonchu.com",
]


CORS_ALLOW_ALL_ORIGINS = True  # 개발 환경에서만 사용

# 테스트 환경에서는 실행하지 않음
if ENV.get("DJANGO_ENV") != "test":
    bucket_name = ENV.get("NCP_STORAGE_BUCKET_NAME")
    if bucket_name:
        s3 = boto3.client(
            "s3",
            endpoint_url="https://kr.object.ncloudstorage.com",
            aws_access_key_id=ENV.get("NCP_ACCESS_KEY_ID"),
            aws_secret_access_key=ENV.get("NCP_SECRET_ACCESS_KEY"),
        )

        cors_configuration = {
            "CORSRules": [
                {
                    "AllowedOrigins": ["*"],
                    "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
                    "AllowedHeaders": ["*"],
                    "ExposeHeaders": [],
                    "MaxAgeSeconds": 3000,
                }
            ]
        }

        response = s3.put_bucket_cors(
            Bucket=bucket_name, CORSConfiguration=cors_configuration
        )
        print("CORS 설정 완료:", response)
    else:
        print("NCP_STORAGE_BUCKET_NAME 환경변수가 설정되지 않았습니다.")
