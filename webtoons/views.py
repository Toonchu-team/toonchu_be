from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from drf_spectacular.utils import extend_schema, OpenApiTypes, OpenApiResponse

from .serializers import WebtoonsSerializer, WebtoonTagSerializer, TagSerializer, ErrorResponseSerializer

import requests
import os

class WebtoonsView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary='웹툰 작품 등록',
        description='웹툰 작품을 등록 신청하는 API입니다.',
        tags=['Webtoons post'],
        request=WebtoonsSerializer,
        responses={
            201: WebtoonsSerializer,
            400: OpenApiTypes.OBJECT,
        }
    )

    def post(self, request):
        serializer = WebtoonsSerializer(data=request.data)
        if serializer.is_valid():
            webtoon = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)