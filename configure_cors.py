import boto3
from dotenv import load_dotenv

from config.settings.base import ENV

# 환경 변수 로드
load_dotenv()

# Boto3 클라이언트 초기화
s3 = boto3.client(
    "s3",
    endpoint_url="https://kr.object.ncloudstorage.com",
    aws_access_key_id=ENV.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=ENV.get("AWS_SECRET_ACCESS_KEY"),
)

# CORS 설정 JSON
cors_configuration = {
    "CORSRules": [
        {
            "AllowedOrigins": ["*"],  # 필요한 경우 특정 도메인만 입력
            "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
            "AllowedHeaders": ["*"],
            "ExposeHeaders": [],
            "MaxAgeSeconds": 3000,
        }
    ]
}

# 버킷에 CORS 적용
bucket_name = ENV.get("AWS_STORAGE_BUCKET_NAME")
response = s3.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_configuration)

print("CORS 설정 완료:", response)
