from django.db import migrations


def seed_data(apps, schema_editor):
    from fintech.seed import seed_demo_data

    seed_demo_data()


class Migration(migrations.Migration):
    dependencies = [
        ('fintech', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_data),
    ]
