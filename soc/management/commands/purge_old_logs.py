from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from soc.models import LogEvent, Organization


class Command(BaseCommand):
    help = 'Purge old logs according to organization retention_days'

    def handle(self, *args, **options):
        total = 0
        for org in Organization.objects.all():
            cutoff = timezone.now() - timedelta(days=org.retention_days)
            deleted, _ = LogEvent.objects.filter(organization=org, ts__lt=cutoff).delete()
            total += deleted
        self.stdout.write(self.style.SUCCESS(f'Deleted {total} old log events'))
