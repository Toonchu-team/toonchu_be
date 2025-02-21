from django.db import models
from multiselectfield import MultiSelectField

from common.models import CommonModel
from users.models import CustomUser


class Webtoon(CommonModel):
    PLATFORM_CHOICES = [
        ("naver", "네이버"),
        ("kakaopage", "카카오페이지"),
        ("kakao", "카카오웹툰"),
        ("others", "기타"),
    ]
    CYCLE_CHOICES = [
        ("1weeks", "1주"),
        ("2weeks", "2주"),
        ("10days", "10일"),
        ("20days", "20일"),
        ("month", "한달"),
        ("etc", "기타"),
    ]
    SERIAL_DAY_CHOICES = [
        ("mon", "월요일"),
        ("tue", "화요일"),
        ("wed", "수요일"),
        ("thu", "목요일"),
        ("fri", "금요일"),
        ("sat", "토요일"),
        ("sun", "일요일"),
    ]
    APPROVAL_STATUS = [
        ("pending", "승인요청중"),
        ("approved", "승인됨"),
        ("rejected", "거절됨")
    ]
    title = models.CharField(max_length=100, null=False, blank=False)
    author = models.CharField(max_length=50, null=False, blank=False)
    thumbnail = models.ImageField(
        upload_to="webtoons/thumbnails", null=False, blank=False
    )
    age_rating = models.CharField(max_length=10)
    publication_day = models.DateField(null=False, blank=False)
    is_completed = models.BooleanField(default=False)
    is_new = models.BooleanField(default=True)
    webtoon_url = models.URLField(max_length=200, null=False, blank=False)
    platform = models.CharField(
        max_length=20, choices=PLATFORM_CHOICES, null=False, blank=False
    )
    serialization_cycle = models.CharField(
        max_length=20, choices=CYCLE_CHOICES, null=False, blank=False
    )
    serial_day = MultiSelectField(choices=SERIAL_DAY_CHOICES)
    view_count = models.PositiveIntegerField(default=0)
    like_count = models.PositiveIntegerField(default=0)
    is_approved = models.CharField(max_length=20, choices=APPROVAL_STATUS, default="pending")
    # user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)


class Tag(models.Model):
    CATEGORY_CHOICES = [
        ("genre", "장르"),
        ("matter", "소재"),
        ("atmosphere", "분위기"),
        ("relation", "관계"),
        ("job", "직업"),
        ("male character", "남캐"),
        ("female character", "여캐"),
        ("character", "캐릭터성"),
        ("top/bottom", "00공수"),
        ("etc", "기타"),
    ]
    tag_name = models.CharField(max_length=100)
    category = models.CharField(max_length=100, choices=CATEGORY_CHOICES)


class WebtoonTag(models.Model):
    webtoon = models.ForeignKey(
        Webtoon, on_delete=models.CASCADE, related_name="webtoon_tags"
    )
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)
