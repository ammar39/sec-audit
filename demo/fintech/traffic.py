from __future__ import annotations

import json

from django.test import Client

from fintech.seed import seed_demo_data


def generate_demo_events(request=None, *, batches: int = 3):
    seed_demo_data()
    client = Client(REMOTE_ADDR='127.0.0.1')
    proxy_client = Client(
        REMOTE_ADDR='203.0.113.10',
        HTTP_X_FORWARDED_FOR='198.51.100.77',
    )
    counts = {
        'account_views': 0,
        'transfers': 0,
        'high_risk_transfers': 0,
        'blocked_transfers': 0,
        'failed_logins': 0,
        'throttled_logins': 0,
        'suspicious_login_bursts': 0,
        'suspicious_proxy_requests': 0,
        'admin_actions': 0,
        'client_errors': 0,
        'profile_updates': 0,
    }

    for index in range(batches):
        client.get('/accounts/')
        counts['account_views'] += 1

        client.post(
            '/transfers/',
            json.dumps(
                {
                    'account_id': 'acct-demo-1001',
                    'amount': '125.50',
                    'currency': 'USD',
                    'destination_alias': f'Demo Vendor {index}',
                }
            ),
            content_type='application/json',
        )
        counts['transfers'] += 1

        client.post(
            '/transfers/high-risk/',
            json.dumps(
                {
                    'account_id': 'acct-demo-2002',
                    'amount': '25000.00',
                    'currency': 'USD',
                    'destination_alias': 'High Value Demo Recipient',
                }
            ),
            content_type='application/json',
        )
        counts['high_risk_transfers'] += 1

        client.post(
            '/transfers/blocked/',
            json.dumps({'amount': '75000.00', 'currency': 'USD'}),
            content_type='application/json',
        )
        counts['blocked_transfers'] += 1

        client.post(
            '/auth/login/suspicious/',
            json.dumps({'username': f'synthetic-attacker-{index}'}),
            content_type='application/json',
        )
        counts['failed_logins'] += 5
        counts['suspicious_login_bursts'] += 1

        client.post(
            '/auth/login/',
            json.dumps(
                {
                    'username': 'maya',
                    'password': 'correct-demo-password',
                }
            ),
            content_type='application/json',
        )
        counts['throttled_logins'] += 1

        client.post(
            '/profile/update/',
            json.dumps(
                {
                    'email': 'maya.demo@example.test',
                    'phone': '+1-555-0199',
                    'national_id': 'NID-987654321',
                    'api_key': 'never-log-this-api-key',
                    'token': 'never-log-this-token',
                    'bank_account_number': 'DEMO-BANK-ACCOUNT-0001',
                    'card_number': 'DEMO-CARD-REDACT-ME',
                }
            ),
            content_type='application/json',
        )
        counts['profile_updates'] += 1

        client.post(
            '/admin/risk-review/flag-account/',
            json.dumps(
                {
                    'account_id': 'acct-demo-2002',
                    'reason': 'Synthetic analyst action',
                }
            ),
            content_type='application/json',
        )
        counts['admin_actions'] += 1

        client.get('/accounts/missing-demo-account/')
        counts['client_errors'] += 1

        proxy_client.get('/accounts/')
        counts['suspicious_proxy_requests'] += 1

    return {'status': 'generated', 'counts': counts}
