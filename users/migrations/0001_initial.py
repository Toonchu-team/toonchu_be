# Generated by Django 5.1.5 on 2025-02-12 15:58

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomUser",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                ("email", models.EmailField(max_length=254)),
                ("nick_name", models.CharField(max_length=100, unique=True)),
                (
                    "provider",
                    models.CharField(
                        choices=[
                            ("google", "Google"),
                            ("naver", "naver"),
                            ("kakao", "Kakao"),
                        ],
                        max_length=20,
                    ),
                ),
                (
                    "profile_img",
                    models.ImageField(blank=True, null=True, upload_to="profile"),
                ),
                ("is_adult", models.BooleanField(default=False)),
                ("is_staff", models.BooleanField(default=False)),
                ("is_updated", models.DateTimeField(blank=True, null=True)),
                ("is_created", models.DateTimeField(auto_now_add=True)),
                ("withdraw_at", models.DateTimeField(blank=True, null=True)),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "db_table": "users_customuser",
                "unique_together": {("email", "provider")},
            },
        ),
    ]
