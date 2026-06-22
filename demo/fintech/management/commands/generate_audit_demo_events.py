from django.core.management.base import BaseCommand

from fintech.seed import seed_demo_data
from fintech.traffic import generate_demo_events


class Command(BaseCommand):
    help = 'Generate fake fintech security/audit events for the Loki dashboard.'

    def add_arguments(self, parser):
        parser.add_argument('--batches', type=int, default=5)

    def handle(self, *args, **options):
        seed_demo_data()
        summary = generate_demo_events(batches=options['batches'])
        self.stdout.write(self.style.SUCCESS(str(summary)))
