import uuid

import boto3
from django.conf import settings

ACCESS_KEY = settings.NCP_ACCESS_KEY
SECRET_KEY = settings.NCP_SECRET_KEY
ENDPOINT_URL = settings.NCP_OBJECT_STORAGE_ENDPOINT
BUCKET_NAME = settings.BUCKET_NAME

s3_client = boto3.client(
    "s3",
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    endpoint_url=ENDPOINT_URL,
)


def upload_file_to_s3(request):
    if request.FILES.get("users"):
        file_obj = request.FILES["users"]

        # 파일명 중복 방지를 위해 UUID 추가
        file_name = f"users/profile/{uuid.uuid4()}_{file_obj.name}"

        try:
            # 파일을 Object Storage에 업로드
            s3_client.upload_fileobj(
                file_obj, BUCKET_NAME, file_name, ExtraArgs={"ACL": "public-read"}
            )

            # 업로드된 파일의 URL 생성
            file_url = f"{ENDPOINT_URL}/{BUCKET_NAME}/{file_name}"
        except Exception as e:
            raise ValueError(str(e))
        return file_url
    raise ValueError("프로필 이미지가 없습니다")
