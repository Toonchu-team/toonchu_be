import uuid
import boto3
from django.conf import settings
from django.http import JsonResponse
from dotenv import dotenv_values
from django.core.files import File

ENV = dotenv_values(".env")

def thumbnail_handler(request, existing_thumbnail=None):
    thumbnail_url = existing_thumbnail if existing_thumbnail else None

    try:
        if request.FILES.get("thumbnail"):
            folder_name = "webtoon/thumbnails"
            image = request.FILES.get("thumbnail")
        else:
            print("FILES.get ?, neither thumbnail nor file")
    except Exception as e:
        print(e)
        return JsonResponse({"error": str(e)}, status=400)

    if image:
        image: File
        endpoint_url = ENV.get("IMAGE_BUCKET_ENDPOINT")
        access_key = ENV.get("NCP_ACCESS_KEY")
        secret_key = ENV.get("NCP_SECRET_KEY")
        bucket_name = "toonchu"

        s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        image_id = str(uuid.uuid4())

        file_extension = image.name.split(".")[-1]
        image_name = f"{image_id}.{file_extension}"
        s3_key = f"{folder_name}/{image_name}"

        try:
            s3.upload_fileobj(image, bucket_name, s3_key)
            s3.put_object_acl(ACL="public-read", Bucket=bucket_name, Key=s3_key)
        except Exception as e:
            print(e)
            return None

        thumbnail_url = f"{endpoint_url}/{bucket_name}/{s3_key}"
        print("image_url out:", thumbnail_url)

    return thumbnail_url
