# Generated by Django 5.1.6 on 2025-02-26 11:49

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("bookmark", "0001_initial"),
        ("webtoons", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="bookmark",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="bookmarks",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="bookmark",
            name="webtoon",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="bookmarks",
                to="webtoons.webtoon",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="bookmark",
            unique_together={("user", "webtoon")},
        ),
    ]
