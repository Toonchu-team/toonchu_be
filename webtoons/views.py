import json
import os
from copy import deepcopy
from unicodedata import category

import requests
from django.db.models import Q
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    OpenApiTypes,
    extend_schema,
)
from rest_framework import permissions, status
from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Webtoon, Tag, WebtoonTag
from .serializers import (
    ErrorResponseSerializer,
    TagSerializer,
    WebtoonSearchSerializer,
    WebtoonsSerializer,
    WebtoonTagSerializer,
)


class WebtoonView(CreateAPIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = WebtoonsSerializer

    @extend_schema(
        summary="웹툰 작품 등록",
        description="웹툰 작품을 등록 신청하는 API입니다.",
        tags=["Webtoons post"],
        request=WebtoonsSerializer,
        responses={
            201: WebtoonsSerializer,
            400: OpenApiTypes.OBJECT,
        },
    )
    def create(self, request, *args, **kwargs):
        data = {key: value for key, value in request.data.items()}
        data["tags"] = json.loads(request.data["tags"])
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def get(self, request):
        webtoons = Webtoon.objects.all()
        serializer = WebtoonsSerializer(webtoons, many=True)
        return Response(serializer.data)


class WebtoonSearchView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        parameters=[
            OpenApiParameter(name="provider", description="웹툰 플랫폼", type=str),
            OpenApiParameter(name="tag", description="웹툰 태그", type=str),
            OpenApiParameter(name="term", description="검색어", type=str),
        ],
        summary="웹툰 검색",
        description="웹툰 검색 api입니다.",
        tags=["Webtoons Search"],
        request=WebtoonSearchSerializer,
        responses={
            200: WebtoonSearchSerializer(many=True),
            400: OpenApiTypes.OBJECT,
        },
    )
    def get(self, request):
        provider = request.query_params.get("provider", "")
        tags = request.query_params.getlist("tag")
        term = request.query_params.get("term", "")

        queryset = Webtoon.objects.all()

        if provider:
            queryset = queryset.filter(
                platform=provider
            )  # platform__iexact 사용 유무(정확할 일치가 필요 할지)

        if tags:
            queryset = queryset.filter(webtoon_tags__tag__tag_name__in=tags).distinct()

        if term:
            queryset = queryset.filter(
                Q(title__icontains=term) | Q(author__icontains=term)
            )

        queryset = queryset.prefetch_related("webtoon_tags__tag")

        serializer = WebtoonSearchSerializer(queryset, many=True)
        return Response(serializer.data)

class TagListView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="전체 태그 목록",
        description="태그 전체 목록 API",
        tags=["tags"],
        request=TagSerializer,
        parameters=[
            OpenApiParameter(name="category", description="카테고리 이름", type=str),
        ],
        responses={
            200: TagSerializer(many=True),
            400: OpenApiTypes.OBJECT,
        },
    )

    def get(self, request):
        category = request.GET.get("category")
        if category not in [choice[0] for choice in Tag.CATEGORY_CHOICES]:
            return Response({"error":"유효하지 않은 카테고리입니다"},status=status.HTTP_400_BAD_REQUEST)
        tags = Tag.objects.filter(category=category)
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)

class TagSearchView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        summary="태그 ID 별 기반 웸툰 검색",
        description="여러 태그 ID 기반으로 태그가 포함된 웹툰 검색",
        parameters=[
            OpenApiParameter(name="id", description="태그 아이디", type=int),
        ],
        request=WebtoonTagSerializer,
        responses={
            200: WebtoonTagSerializer(many=True),
            400: OpenApiTypes.OBJECT,
        }
    )

    def get(self, request):
        tag_id = request.GET.getlist("id")

        webtoons = Webtoon.objects.all()
        for tag_id in tag_id:
            try:
                tag_id = int(tag_id)
                tag = Tag.objects.get(id=tag_id)
                if tag:
                    webtoons = webtoons.filter(webtoon_tags__tag__id=tag_id)
            except Tag.DoesNotExist:
                return Response({"error":"유효하지 않은 ID입니다"},status=status.HTTP_400_BAD_REQUEST)
        serializer = WebtoonsSerializer(webtoons, many=True)
        return Response(serializer.data)