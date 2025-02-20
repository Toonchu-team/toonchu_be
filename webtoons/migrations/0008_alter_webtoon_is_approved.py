# Generated by Django 5.1.6 on 2025-02-21 14:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("webtoons", "0007_webtoon_is_approved"),
    ]

    operations = [
        migrations.AlterField(
            model_name="webtoon",
            name="is_approved",
            field=models.CharField(
                choices=[
                    ("pending", "승인요청중"),
                    ("approved", "승인됨"),
                    ("rejected", "거절됨"),
                ],
                default="pending",
                max_length=20,
            ),
        ),
    ]
