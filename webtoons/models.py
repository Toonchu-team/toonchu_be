from django.db import models

class Time(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Count(models.Model):
    view_count = models.IntegerField(default=0)
    like_count = models.IntegerField(default=0)

class Webtoons(models.Model):
    PLATFORM_CHOICES = [
        ('naver', '네이버'),
        ('kakaopage', '카카오페이지'),
        ('kakao', '카카오웹툰'),
    ]
    webtoons_id = models.IntegerField(primary_key=True)
    title = models.CharField(max_length=100)
    author = models.CharField(max_length=50)
    description = models.TextField()
    thumbnail = models.FileField(upload_to='webtoons/thumbnails')
    age_rating = models.CharField(max_length=10)
    publication_day = models.DateField()
    is_completed = models.BooleanField(default=False)
    is_new = models.BooleanField(default=True)
    webtoon_url = models.URLField(max_length=200)
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES)
    times = models.ForeignKey(Time, on_delete=models.CASCADE)
    count = models.ForeignKey(Count, on_delete=models.CASCADE)

class Tag(models.Model):
    CATEGORY_CHOICES = [
        ("genre","장르"),
        ("matter","소재"),
        ("atmosphere","분위기"),
        ("relation","관계"),
        ("job","직업"),
        ("male character","남캐"),
        ("female character", "여캐"),
        ("character","캐릭터성"),
        ("top/bottom","00공수"),
        ("etc","기타"),
    ]
    tags_id = models.IntegerField(primary_key=True)
    tags_name = models.CharField(max_length=20, unique=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)

class WebtoonTag(models.Model):
    webtoontags_id = models.IntegerField(primary_key=True)
    webtoons_id = models.ForeignKey(Webtoons, on_delete=models.CASCADE)
    tags_id = models.ForeignKey(Tag, on_delete=models.CASCADE)