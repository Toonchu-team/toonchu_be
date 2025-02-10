import json
from copy import deepcopy

from rest_framework.decorators import api_view
from rest_framework.generics import CreateAPIView
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from drf_spectacular.utils import extend_schema, OpenApiTypes, OpenApiResponse

from .serializers import WebtoonsSerializer, WebtoonTagSerializer, TagSerializer, ErrorResponseSerializer

import requests
import os

class WebtoonView(CreateAPIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = WebtoonsSerializer

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

    def create(self, request, *args, **kwargs):
        data = {key: value for key, value in request.data.items()}
        data['tags'] = json.loads(request.data['tags'])
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

