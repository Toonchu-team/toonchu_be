from rest_framework import serializers
from drf_spectacular.utils import extend_schema_serializer, OpenApiExample
from .models import Webtoons, Tags, WebtoonTags

@extend_schema_serializer(
examples=[
        OpenApiExample(
            'Successful Creation',
            value={
                'id': 1,
                'title': '프론트개발자의 일상',
                'author': '감자전',
                'thumnail_url':"https://example.com/thumbnail.jpg",
                'description':'감자 같은 내 코드 and 프론트의 일상을 담은 이야기',
                'url': "https://webtoon-platform.com/webtoon/1",
                'platform':'네이버',
                'serial_day': '월요일,목요일',
                'serialization_cycle': '1주',
            },
            response_only=True,
            status_codes=['201'],
        ),
        OpenApiExample(
            'Bad Request',
            value={
                "massage": "Invalid input data",
            },
            response_only=True,
            status_codes=['400'],
        )
    ]
)

class WebtoonsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Webtoons
        fields = ['title','author','description','thumbnail','webtoon_url','platform', 'serial_day','serialization_cycle','created_at','updated_at']

    def create(self, validated_data):
        tags_name = self.initial_data.get('Tags', [])

        webtoon = Webtoons.objects.create(**validated_data)

        for tag_name in tags_name:
            tag, _ = Tags.objects.get_or_create(name=tag_name)
            WebtoonTags.objects.create(webtoon=webtoon, tag=tag)
        webtoon.save()
        return webtoon

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        return representation

class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tags
        fields = '__all__'

class WebtoonTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebtoonTags
        fields = '__all__'

class ErrorResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    code = serializers.IntegerField()