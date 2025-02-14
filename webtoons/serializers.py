from drf_spectacular.utils import OpenApiExample, extend_schema_serializer
from rest_framework import serializers

from webtoons.models import Tag, Webtoon, WebtoonTag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["id", "tag_name", "category"]

class WebtoonSearchSerializer(serializers.ModelSerializer):
    tags = TagSerializer(many=True, read_only=True)

    class Meta:
        model = Webtoon
        fields = [
            "id", "title", "author", "thumbnail", "platform", "tags"
        ]
    def get_tags(self, obj):
        return TagSerializer(obj.webtoon_tags.all().values("tag"), many=True).data

class WebtoonTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebtoonTag
        fields = "__all__"


class WebtoonsSerializer(serializers.ModelSerializer):
    tags = TagSerializer(many=True, required=False)

    class Meta:
        model = Webtoon
        fields = [
            "title",
            "author",
            "thumbnail",
            "webtoon_url",
            "publication_day",
            "platform",
            "serial_day",
            "serialization_cycle",
            "created_at",
            "updated_at",
            "tags",
        ]

    @extend_schema_serializer(
        examples=[
            OpenApiExample(
                "Successful Creation",
                value={
                    "id": 1,
                    "title": "프론트개발자의 일상",
                    "author": "감자전",
                    "thumnail_url": "https://example.com/thumbnail.jpg",
                    "url": "https://webtoon-platform.com/webtoon/1",
                    "platform": "네이버",
                    "publication_day": "2025-02-10",
                    "serial_day": "월요일,목요일",
                    "serialization_cycle": "1주",
                },
                response_only=True,
                status_codes=["201"],
            ),
            OpenApiExample(
                "Bad Request",
                value={
                    "massage": "Invalid input data",
                },
                response_only=True,
                status_codes=["400"],
            ),
        ]
    )

    def create(self, validated_data):
        tags = validated_data.pop("tags", [])
        webtoon = Webtoon.objects.create(**validated_data)

        if tags:
            tag_names = [tag["tag_name"] for tag in tags]
            existing_tags = [
                {"tag_name": tag.tags_name, "category": tag.category}
                for tag in Tag.objects.filter(tag_name__in=tag_names)
            ]

            new_tags = [tag for tag in tags if tag not in existing_tags]

            Tag.objects.bulk_create(
                [
                    Tag(tag_name=tag["tag_name"], category=tag["category"])
                    for tag in new_tags
                ]
            )  # 새 태그 생성

            # 최신 태그 리스트 가져오기 (새로 생성된 태그 포함)
            all_tags = [tag for tag in Tag.objects.filter(tag_name__in=tag_names)]

            # WebtoonTags 객체 리스트 생성 후 bulk_create
            WebtoonTag.objects.bulk_create(
                [WebtoonTag(webtoon=webtoon, tag=tag) for tag in all_tags]
            )

        return webtoon

    def to_representation(self, instance):
        data = super().to_representation(instance)
        tags = [webtoon_tag.tag for webtoon_tag in instance.webtoon_tags.all()]
        data["tags"] = TagSerializer(tags, many=True).data
        return data

class ErrorResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    code = serializers.IntegerField()
