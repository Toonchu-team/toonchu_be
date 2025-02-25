from drf_spectacular.utils import OpenApiExample, extend_schema_serializer
from rest_framework import serializers

from webtoons.models import Tag, Webtoon, WebtoonTag


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ["id", "tag_name", "category"]


class WebtoonTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebtoonTag
        fields = "__all__"




class WebtoonsSerializer(serializers.ModelSerializer):
    tags = TagSerializer(many=True, required=False)
    like_count = serializers.IntegerField(read_only=True)
    view_count = serializers.IntegerField(read_only=True)
    serial_day = serializers.MultipleChoiceField(
        choices=Webtoon.SERIAL_DAY_CHOICES, required=False
    )

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
            "is_new",
            "is_completed",
            "like_count",
            "view_count",
            "is_approved",
            "tags",
            "user",
        ]
        read_only_fields = ["like_count", "view_count", "is_approved","user"]

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
        webtoon = super().create(validated_data)
        # serial_day = validated_data.pop("serial_day", [])
        # if isinstance(serial_day, str):
        #     serial_day = serial_day.split(",")
        # elif not isinstance(serial_day, list):
        #     serial_day = []
        # validated_data["serial_day"] = ",".join(serial_day)
        # data["serial_day"] = instance.serial_day.split(",") if instance.serial_day else []
        #
        # validated_data["like_count"] = 0
        # validated_data["view_count"] = 0
        # webtoon = Webtoon.objects.create(**validated_data)

        if tags:
            tag_names = [tag["tag_name"] for tag in tags]

            # 기존 태그 조회 (딕셔너리로 변환하지 않음)
            existing_tags = {
                tag.tag_name: tag for tag in Tag.objects.filter(tag_name__in=tag_names)
            }

            # 새로운 태그만 필터링 (딕셔너리 비교 대신, 객체 비교)
            new_tags = [
                Tag(tag_name=tag["tag_name"], category=tag["category"])
                for tag in tags
                if tag["tag_name"] not in existing_tags
            ]

            # 새 태그 DB에 저장
            Tag.objects.bulk_create(new_tags)

            # 기존 + 새로운 태그 조회하여 저장
            all_tags = Tag.objects.filter(tag_name__in=tag_names)

            # WebtoonTag 객체 생성 후 bulk_create로 저장
            webtoon_tags = [WebtoonTag(webtoon=webtoon, tag=tag) for tag in all_tags]

            WebtoonTag.objects.bulk_create(webtoon_tags)

        return webtoon

    # def create(self, validated_data):
    #     tags = validated_data.pop("tags", [])
    #     webtoon = Webtoon.objects.create(**validated_data)
    #
    #     if tags:
    #         tag_names = [tag["tag_name"] for tag in tags]
    #         existing_tags = [
    #             {"tag_name": tag.tags_name, "category": tag.category}
    #             for tag in Tag.objects.filter(tag_name__in=tag_names)
    #         ]
    #
    #         new_tags = [tag for tag in tags if tag not in existing_tags]
    #
    #         Tag.objects.bulk_create(
    #             [
    #                 Tag(tag_name=tag["tag_name"], category=tag["category"])
    #                 for tag in new_tags
    #             ]
    #         )  # 새 태그 생성
    #
    #         # 최신 태그 리스트 가져오기 (새로 생성된 태그 포함)
    #         all_tags = [tag for tag in Tag.objects.filter(tag_name__in=tag_names)]
    #
    #         # WebtoonTags 객체 리스트 생성 후 bulk_create
    #         WebtoonTag.objects.bulk_create(
    #             [WebtoonTag(webtoon=webtoon, tag=tag) for tag in all_tags]
    #         )
    #
    #     return webtoon

    def to_representation(self, instance):
        data = super().to_representation(instance)
        tags = [webtoon_tag.tag for webtoon_tag in instance.webtoon_tags.all()]
        data["tags"] = TagSerializer(tags, many=True).data
        return data

class UserWebtoonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Webtoon
        exclude = ("user",)