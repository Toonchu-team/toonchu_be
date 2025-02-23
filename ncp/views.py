from multiprocessing import context

import boto3
from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from .serializers import InputFileSerializer


def upload_file(s3_client, bucket_name, input_source, S3_key, file):
    # Check if folder (prefix) exists
    if not prefix_exists(s3_client, bucket_name, input_source):
        s3_client.put_object(Bucket=bucket_name, Key=f"{input_source}/")

    # Upload file to NCP Object Storage
    s3_client.put_object(
        Bucket=bucket_name,
        Key=S3_key,
        Body=file.read(),
    )
    file_url = f"https://kr.object.ncloudstorage.com/{bucket_name}/{S3_key}"
    return file_url


def prefix_exists(s3_client, bucket_name, prefix):
    try:
        response = s3_client.list_objects_v2(
            Bucket=bucket_name, Prefix=prefix, MaxKeys=1
        )
        return "Contents" in response
    except Exception as e:
        print(f"Error: {str(e)}")
        return False


class InputFile(APIView):
    @extend_schema(
        summary="Upload file to NCP Object Storage",
        description="Uploads file to NCP and returns the URL.",
        request={"multipart/form-data": InputFileSerializer},
    )
    def post(self, request):
        serializer = InputFileSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            input_source = serializer.validated_data["input_source"]
            file = serializer.validated_data["file"]
            user = str(request.user.uuid)

            region_name = "kr-standard"
            bucket_name = settings.NCP_BUCKET_NAME
            S3_key = ""

            s3_client = boto3.client(
                "s3",
                endpoint_url="https://kr.object.ncloudstorage.com",
                aws_access_key_id=settings.NCP_ACCESS_KEY,
                aws_secret_access_key=settings.NCP_SECRET_KEY,
                region_name=region_name,
            )

            if input_source == "profile":
                S3_key = f"{input_source}/{user}/{file.name}"
            elif input_source == "form_answer":
                form = serializer.validated_data["form_title"]
                question = serializer.validated_data["question_order"]
                option = serializer.validated_data["option_number"]
                S3_key = f"{input_source}/{form}/{question}/{option}/{user}/{file.name}"
            elif input_source == "form":
                form = serializer.validated_data["form_title"]
                question = serializer.validated_data["question_order"]
                option = serializer.validated_data["option_number"]
                S3_key = f"{input_source}/{form}/{question}/{option}/{file.name}"

            file_url = upload_file(s3_client, bucket_name, input_source, S3_key, file)
            return Response(
                {
                    "message": "File upload successful",
                    "file_name": file.name,
                    "file_size": file.size,
                    "input_source": input_source,
                    "file_url": file_url,
                },
                status=status.HTTP_200_OK,
            )
        else:
            print(serializer.errors)
            return Response(serializer.errors, status=400)
