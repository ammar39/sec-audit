from django.core.management.base import BaseCommand

from fintech.seed import seed_demo_data


class Command(BaseCommand):
    help = 'Seed local fake fintech data for the sec_audit demo.'

    def handle(self, *args, **options):
        summary = seed_demo_data()
        self.stdout.write(self.style.SUCCESS(str(summary)))
