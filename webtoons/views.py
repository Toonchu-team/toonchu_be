import json
import os

import requests
from django.db.models import Count, Q
from drf_spectacular import openapi
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiTypes,
    extend_schema,
)
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import UpdateAPIView

from .models import Tag, Webtoon
from .serializers import (
    TagSerializer,
    WebtoonsSerializer,
    WebtoonTagSerializer,
)


class WebtoonCreateView(CreateAPIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = WebtoonsSerializer

    @extend_schema(
        summary="웹툰 작품 등록",
        description="웹툰 작품을 등록 신청하는 API입니다.",
        tags=["Webtoons"],
        request=WebtoonsSerializer,
        responses={
            201: WebtoonsSerializer,
            400: OpenApiTypes.OBJECT,
        },
    )
    def post(self, request, *args, **kwargs):
        data = {key: value for key, value in request.data.items()}
        data["tags"] = json.loads(request.data["tags"])
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )


class SearchByIntegrateView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="provider",
                description="웹툰 플랫폼",
                type=str,
                enum=["naver", "kakaowebtoon", "kakaopage", "others"],
            ),
            OpenApiParameter(name="tag", description="웹툰 태그", type=str),
            OpenApiParameter(name="term", description="검색어", type=str),
        ],
        summary="웹툰 검색",
        description="웹툰 통합 검색 api입니다. 플랫폼별, 태그별, 검색어로 검색합니다.",
        tags=["Webtoons Search"],
        request=WebtoonsSerializer,
        responses={
            200: WebtoonsSerializer(many=True),
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
            )  # platform__iexact 사용 유무(영어 대소문자관련 일치여부 확인용)

        if tags:
            queryset = queryset.filter(webtoon_tags__tag__tag_name__in=tags).distinct()

        if term:
            queryset = queryset.filter(
                Q(title__icontains=term) | Q(author__icontains=term)
            )

        queryset = queryset.prefetch_related("webtoon_tags__tag")

        serializer = WebtoonsSerializer(queryset, many=True)
        return Response(serializer.data)


class ListByTagView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="전체 태그 목록",
        description="태그 전체 목록 API",
        tags=["Webtoons list"],
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
            return Response(
                {"error": "유효하지 않은 카테고리입니다"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        tags = Tag.objects.filter(category=category)
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)


class SearchByTagView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="태그 ID 별 기반 웹툰 검색",
        description="여러 태그 ID 기반으로 태그가 포함된 웹툰 검색",
        tags=["Webtoons Search"],
        parameters=[
            OpenApiParameter(name="id", description="태그 아이디", type=int, many=True),
        ],
        request=WebtoonTagSerializer,
        responses={
            200: WebtoonsSerializer(many=True),
            400: OpenApiTypes.OBJECT,
        },
    )
    def get(self, request):
        tag_ids = request.GET.getlist("id")

        # webtoons/search/tag?id=1&id=3&....
        webtoons = Webtoon.objects.all()
        filtered_webtoons = (
            webtoons.filter(webtoon_tags__tag__id__in=tag_ids)
            .annotate(
                matching_tags=Count(
                    "webtoon_tags", filter=Q(webtoon_tags__tag__id__in=tag_ids)
                )
            )
            .filter(matching_tags=len(tag_ids))
        )
        # 웹툰과 연결 되어 있는 태그 수 카운팅

        # for tag_id in tag_id:
        #     try:
        #         tag_id = int(tag_id)
        #         tag = Tag.objects.get(id=tag_id)
        #         if tag:
        #             webtoons = webtoons.filter(webtoon_tags__tag__id=tag_id)
        #     except Tag.DoesNotExist:
        #         return Response({"error":"유효하지 않은 ID입니다"},status=status.HTTP_400_BAD_REQUEST)
        serializer = WebtoonsSerializer(filtered_webtoons, many=True)
        return Response(serializer.data)


class ListByDayView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="요일별/연재유무별 웹툰 리스트",
        description="요일별, 신작, 연재유무별 로 웹툰 리스트 표현",
        tags=["Webtoons list"],
        parameters=[
            OpenApiParameter(
                name="day",
                description="요일",
                type=str,
                enum=["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
            ),
            OpenApiParameter(
                name="status",
                description="신작/완결/전체",
                type=str,
                enum=["all", "new", "completed"],
            ),
        ],
        request=WebtoonsSerializer,
        responses={
            200: WebtoonsSerializer(many=True),
            400: OpenApiTypes.OBJECT,
        },
    )
    def get(self, request):
        day = request.query_params.get("day", "")
        status = request.query_params.get("status")
        queryset = Webtoon.objects.all()

        if day:
            queryset = queryset.filter(serial_day__iexact=day)

            if status == "new":
                queryset = queryset.filter(is_new=True)

            elif status == "completed":
                queryset = queryset.filter(is_completed=True)

        serializer = WebtoonsSerializer(queryset, many=True)
        return Response(serializer.data)


class ListView(APIView):
    permission_classes = [AllowAny]
    serializer_class = WebtoonsSerializer

    @extend_schema(
        summary="웹툰 정렬 리스트 Get",
        description="인기순, 조회순, 등록순, 연재일순(최신순) 정렬 api",
        tags=["Webtoons list"],
        parameters=[
            OpenApiParameter(
                name="sort",
                description="정렬할 순서 이름",
                type=str,
                enum=["popular", "view", "created", "latest"],
            ),
            OpenApiParameter(
                name="id",
                description="tag id (선택사항)",
                type=int,
                many=True,
            ),
        ],
    )
    def get(self, request):
        # 순서 정렬
        sort = self.request.query_params.get("sort", "popular")
        sort_mapping = {
            "popular": "-like_count",
            "view": "-view_count",
            "created": "-created_at",
            "latest": "-publication_day",
        }
        ordering = sort_mapping.get(sort, "-like_count")
        tag_ids = request.GET.getlist("tags.id")

        webtoons = Webtoon.objects.all()

        if tag_ids:
            webtoons = (
                Webtoon.objects.filter(tags__id__in=tag_ids)
                .annotate(
                    matching_tags=Count(
                        "webtoon_tags", filter=Q(webtoon_tags__tag__id__in=tag_ids)
                    )
                )
                .filter(matching_tags=len(tag_ids))
            )

        webtoons = webtoons.order_by(ordering)

        serializer = WebtoonsSerializer(webtoons, many=True)
        return Response(serializer.data)

class WebtoonApprovalView(UpdateAPIView):
    permission_classes = [AllowAny]
    queryset = Webtoon.objects.all()
    serializer_class = WebtoonsSerializer

    @extend_schema(
        summary="웹툰 등록 승인/거절 api",
        description="웹툰의 승인 상태를 변경하는 api",
        parameters=[
            OpenApiParameter(
                name="action",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="'approve' 또는 'reject'"
            )
        ],
        request=OpenApiTypes.NONE,
        responses={
            200: OpenApiTypes.OBJECT,
            400: OpenApiTypes.OBJECT
        }
    )

    def petch(self, request, pk):
        webtoon = self.get_object()
        action = request.data.get("action")

        action_mapping = {
            "approve": {"status":"approved", "message":"웹툰 등록이 완료됐다냥!"},
            "reject": {"status":"rejected", "message":"웹툰 등록 신청이 거절 됐다냥.."}
        }
        webtoon.approval_status = action_mapping[action]["status"]
        webtoon.save(update_fields=["approval_status"])

        return Response({"message":action_mapping[action]["message"]}, status=status.HTTP_200_OK)

    def get(self, request, pk):
        webtoon = self.get_object()
        serializer = WebtoonsSerializer(webtoon)
        return Response(serializer.data)