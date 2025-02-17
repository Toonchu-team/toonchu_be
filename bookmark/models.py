from django.contrib.auth import get_user_model
from django.db import models

from users.models import CustomUser
from webtoons.models import Webtoon

user = get_user_model()


class Bookmark(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="bookmarks"
    )
    webtoon = models.ForeignKey(
        Webtoon, on_delete=models.CASCADE, related_name="bookmarks"
    )
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (
            ("user", "webtoon"),
        )  # 사용자가 같은 웹툰 중복 bookmark 방지

    def __str__(self):
        return f"{self.user.username}'s bookmark for {self.webtoon.title}"
