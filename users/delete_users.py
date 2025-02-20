from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from users.models import CustomUser


def delete_withdrawn_users():
    deletion_date = timezone.now() - timedelta(days=50)
    users_to_delete = CustomUser.objects.filter(withdraw_at__lte=deletion_date)
    deleted_count = users_to_delete.count()
    users_to_delete.delete()
    print(f"{deleted_count} users have been deleted.")


class Command(BaseCommand):
    help = "50일 전에 탈퇴를 요청한 사용자 삭제"

    def handle(self, *args, **options):
        delete_withdrawn_users()
        self.stdout.write(self.style.SUCCESS("유저정보 삭제가 완료되었습니다"))
