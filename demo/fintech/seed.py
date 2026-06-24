from decimal import Decimal

from django.contrib.auth import get_user_model

from fintech.models import Account, CustomerProfile


def seed_demo_data():
    User = get_user_model()
    maya, _ = User.objects.get_or_create(
        username='maya', defaults={'email': 'maya@example.test'}
    )
    maya.set_password('correct-demo-password')
    maya.save()

    # Superuser so the demo can sign into /admin/ and exercise the enforcement
    # PermanentBlock admin (create / revoke / list).
    analyst, _ = User.objects.get_or_create(
        username='risk-analyst',
        defaults={'email': 'risk@example.test', 'is_staff': True},
    )
    analyst.set_password('correct-demo-password')
    analyst.is_staff = True
    analyst.is_superuser = True
    analyst.save()

    CustomerProfile.objects.update_or_create(
        user=maya,
        defaults={
            'display_name': 'Maya Demo',
            'email': 'maya.demo@example.test',
            'phone': '+1-555-0100',
            'national_id': 'DEMO-NATIONAL-ID',
            'api_key': 'DEMO-API-KEY',
        },
    )
    Account.objects.update_or_create(
        account_id='acct-demo-1001',
        defaults={
            'owner': maya,
            'display_name': 'Operating Wallet',
            'account_number': 'DEMO-BANK-ACCOUNT-0001',
            'balance': Decimal('12850.75'),
            'currency': 'USD',
            'risk_tier': 'low',
            'is_flagged': False,
        },
    )
    Account.objects.update_or_create(
        account_id='acct-demo-2002',
        defaults={
            'owner': maya,
            'display_name': 'Treasury Reserve',
            'account_number': 'DEMO-BANK-ACCOUNT-0002',
            'balance': Decimal('88500.00'),
            'currency': 'USD',
            'risk_tier': 'medium',
            'is_flagged': False,
        },
    )
    Account.objects.update_or_create(
        account_id='acct-demo-4040',
        defaults={
            'owner': maya,
            'display_name': 'Flagged Review Account',
            'account_number': 'DEMO-BANK-ACCOUNT-4040',
            'balance': Decimal('2500.00'),
            'currency': 'USD',
            'risk_tier': 'critical',
            'is_flagged': True,
        },
    )
    return {'users': 2, 'accounts': Account.objects.count()}
