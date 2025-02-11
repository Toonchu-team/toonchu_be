from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from users.models import CustomUser


class Command(BaseCommand):
    help = '50일 전에 탈퇴를 요청한 사용자 삭제'

    def handle(self, *args, **options):
        deletion_date = timezone.now() - timedelta(days=50)
        user_to_delete = CustomUser.objects.filter(withdraw_at__lte=deletion_date)
        deleted_count = user_to_delete.count()
        user_to_delete.delete()

        self.stdout.write(self.style.SUCCESS(f'{deleted_count} users have been deleted.'))