from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.decorators import api_view

from webtoons.models import WebtoonsSerializer, Webtoons


class TestView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response("Swagger 연동 테스트")

@swagger_auto_schema(
    method='GET',
    operation_description="웹툰 전체 조회",
    responses={
        status.HTTP_200_OK: openapi.Response(
            description="성공적으로 웹툰 목록을 조회함",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'webtoons': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'webtoons_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'title': openapi.Schema(type=openapi.TYPE_STRING),
                                'author': openapi.Schema(type=openapi.TYPE_STRING),
                                'description': openapi.Schema(type=openapi.TYPE_STRING),
                                'thumbnail': openapi.Schema(type=openapi.TYPE_STRING, formet=openapi.FORMAT_URI),
                                'age_rating': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'publication_day': openapi.Schema(type=openapi.TYPE_STRING, formet=openapi.FORMAT_DATE),
                                'is_completed': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'is_new': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                                'webtoon_url':openapi.Schema(type=openapi.TYPE_STRING, formet=openapi.FORMAT_URI),
                                'serial_day': openapi.Schema(type=openapi.TYPE_STRING),
                                'platform': openapi.Schema(type=openapi.TYPE_STRING),
                                'times': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'count': openapi.Schema(type=openapi.TYPE_INTEGER),
                            }
                        )
                    )
                }
            )
        ),
        status.HTTP_400_BAD_REQUEST: openapi.Response(
            description="잘못된 요청",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'code': openapi.Schema(type=openapi.TYPE_INTEGER),
                }
            )
        ),
    }
)
@api_view(['GET'])
def get_all_webtoons(request):
    try:
        webtoons = Webtoons.objects.all()
        serializer = WebtoonsSerializer(webtoons, many=True),
        return Response({"webtoons": serializer.data})
    except Exception as e:
        return Response({"message": "잘못된 요청", "code":400}, status=status.HTTP_400_BAD_REQUEST)

