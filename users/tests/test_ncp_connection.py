# import boto3
# import os
#
# def test_ncp_connection():
#     """로컬에서 NCP Object Storage 연결 테스트"""
#     try:
#         s3 = boto3.client(
#             "s3",
#             aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
#             aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
#             region_name=os.environ.get("AWS_S3_REGION_NAME"),
#         )
#
#         # 버킷 목록 확인
#         response = s3.list_buckets()
#         print("버킷 목록:", [bucket["Name"] for bucket in response["Buckets"]])
#
#         # 테스트 이미지 업로드
#         with open("sample_image.png", "rb") as image_file:
#             s3.upload_fileobj(image_file, os.environ.get("AWS_STORAGE_BUCKET_NAME"), "test/sample_image.png")
#             print("이미지 업로드 성공")
#
#         # 이미지 다운로드 확인
#         s3.download_file(os.environ.get("AWS_STORAGE_BUCKET_NAME"), "test/sample_image.png", "downloaded_image.png")
#         print("이미지 다운로드 성공")
#
#         # 업로드된 이미지 삭제
#         s3.delete_object(Bucket=os.environ.get("AWS_STORAGE_BUCKET_NAME"), Key="test/sample_image.png")
#         print("이미지 삭제 성공")
#
#     except Exception as e:
#         print(f"연결 실패: {e}")
#
#
# if __name__ == "__main__":
#     test_ncp_connection()


# import os
#
# import boto3
# from botocore.exceptions import EndpointConnectionError, NoCredentialsError
# from django.test import TestCase
#
# from config.settings.base import ENV
#
#
# class NCPConnectionTestCase(TestCase):
#     """
#     NCP Object Storage 연결 테스트
#     """
#
#     @classmethod
#     def setUpTestData(cls):
#         cls.endpoint_url = ENV.get("AWS_S3_ENDPOINT_URL")
#         cls.access_key = ENV.get("AWS_ACCESS_KEY_ID")
#         cls.secret_key = ENV.get("AWS_SECRET_ACCESS_KEY")
#         cls.bucket_name = ENV.get("AWS_STORAGE_BUCKET_NAME")
#
#     def test_ncp_connection(self):
#         """
#         NCP Object Storage 연결 여부 테스트
#         """
#         try:
#             # 클라이언트 초기화
#             s3 = boto3.client(
#                 "s3",
#                 endpoint_url=self.endpoint_url,
#                 aws_access_key_id=self.access_key,
#                 aws_secret_access_key=self.secret_key,
#             )
#
#             # 버킷 리스트 가져오기
#             response = s3.list_buckets()
#             bucket_names = [bucket["Name"] for bucket in response["Buckets"]]
#
#             # 버킷이 존재하는지 확인
#             self.assertIn(
#                 self.bucket_name,
#                 bucket_names,
#                 "Bucket not found in NCP Object Storage.",
#             )
#             print(" NCP Object Storage에 성공적으로 연결되었습니다!")
#
#         except NoCredentialsError:
#             self.fail(" 자격 증명이 제공되지 않았습니다.")
#         except EndpointConnectionError:
#             self.fail(" NCP Object Storage에 연결할 수 없습니다.")
#         except Exception as e:
#             self.fail(f" 예외 발생: {str(e)}")
