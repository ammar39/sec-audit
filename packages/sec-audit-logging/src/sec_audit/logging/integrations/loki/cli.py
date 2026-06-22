from __future__ import annotations

import argparse
import secrets

from sec_audit.logging.integrations.loki.setup import copy_monitoring_assets


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Copy reusable Grafana Alloy / Loki / Grafana assets.',
    )
    parser.add_argument('target_dir', help='Directory to receive monitoring files.')
    parser.add_argument('--app-label', default='django-sec-audit')
    parser.add_argument('--environment', default='demo')
    parser.add_argument('--audit-log-path', default='../logs/sec-audit.jsonl')
    parser.add_argument('--grafana-admin-user', default='admin')
    parser.add_argument(
        '--grafana-admin-password',
        default=None,
        help='Grafana admin password; a strong one is generated if omitted.',
    )
    parser.add_argument('--dashboard-title', default='Sec Audit Monitoring')
    parser.add_argument('--overwrite', action='store_true')
    args = parser.parse_args(argv)

    password = args.grafana_admin_password
    generated = not password
    if generated:
        password = secrets.token_urlsafe(16)

    written = copy_monitoring_assets(
        args.target_dir,
        app_label=args.app_label,
        environment=args.environment,
        audit_log_path=args.audit_log_path,
        grafana_admin_user=args.grafana_admin_user,
        grafana_admin_password=password,
        dashboard_title=args.dashboard_title,
        overwrite=args.overwrite,
    )
    for path in written:
        print(path)
    print()
    print(
        '⚠️  LOCAL-ONLY monitoring stack — do not expose these ports or '
        'credentials publicly.'
    )
    print(f'Grafana login: {args.grafana_admin_user} / {password}')
    if generated:
        print(
            '(Generated Grafana admin password — store it now; it is not saved '
            'elsewhere.)'
        )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
