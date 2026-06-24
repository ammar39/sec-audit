import json
from importlib.resources import files

from sec_audit.logging.integrations.loki import copy_monitoring_assets


def test_loki_assets_exist_for_package_data():
    loki = files('sec_audit.logging.integrations.loki').joinpath('templates')
    assert (loki / 'README.md').exists()
    assert (loki / 'docker-compose.yml.template').exists()
    assert (loki / 'alloy' / 'config.alloy.template').exists()
    assert (loki / 'alloy' / 'config.stdout.alloy.template').exists()
    assert (loki / 'loki' / 'local-config.yml').exists()
    assert (loki / 'loki' / 'queries.md').exists()
    assert (loki / 'grafana' / 'provisioning' / 'datasources' / 'loki.yml').exists()
    assert (
        loki / 'grafana' / 'dashboards' / 'sec-audit-overview.json.template'
    ).exists()
    assert not (loki / 'otel-collector').exists()


def test_loki_init_copies_logging_only_assets(tmp_path):
    written = copy_monitoring_assets(
        tmp_path,
        app_label='test-app',
        environment='test',
        audit_log_path='../logs/audit.jsonl',
        dashboard_title='Test Dashboard',
    )
    assert written
    compose = (tmp_path / 'docker-compose.yml').read_text()
    alloy = (tmp_path / 'alloy' / 'config.alloy').read_text()
    dashboard = json.loads(
        (tmp_path / 'grafana' / 'dashboards' / 'sec-audit-overview.json').read_text()
    )
    queries = (tmp_path / 'loki' / 'queries.md').read_text()
    readme = (tmp_path / 'README.md').read_text()

    assert '../logs/audit.jsonl:/var/log/sec-audit/sec-audit.jsonl:ro' in compose
    assert 'grafana/alloy' in compose
    assert 'otel/opentelemetry-collector-contrib' not in compose
    assert 'grafana/promtail' not in compose
    assert 'otlphttp/loki' not in compose
    # ports bound to loopback only.
    assert '127.0.0.1:3100:3100' in compose
    assert '127.0.0.1:12345:12345' in compose
    assert '127.0.0.1:3000:3000' in compose
    # no hardcoded admin/admin password — a strong one is generated.
    assert 'GF_SECURITY_ADMIN_PASSWORD: admin' not in compose

    assert 'loki.source.file' in alloy
    assert 'loki.process' in alloy
    assert 'loki.write' in alloy
    # service_name is extracted from the record body, not a static label.
    assert 'service_name = "resource.\\"service.name\\""' in alloy
    assert 'service_name = "test-app"' not in alloy
    assert 'environment = "test"' in alloy
    assert 'event_type   = "event_type"' in alloy
    assert 'severity     = "severity"' in alloy

    stdout_alloy = (tmp_path / 'alloy' / 'config.stdout.alloy').read_text()
    assert 'loki.source.docker' in stdout_alloy
    assert 'loki.source.file' not in stdout_alloy
    assert 'service_name = "resource.\\"service.name\\""' in stdout_alloy
    assert 'service_name = "test-app"' not in stdout_alloy
    assert 'environment = "test"' in stdout_alloy

    assert dashboard['title'] == 'Test Dashboard'
    expressions = [
        target['expr']
        for panel in dashboard['panels']
        for target in panel.get('targets', [])
    ]
    assert any('{service_name="test-app"}' in expr for expr in expressions)
    assert all('audit.rule' not in expr for expr in expressions)
    # enforcement panels (audit.enforcement.*) are part of the shipped dashboard.
    assert any('audit.enforcement.blocked' in expr for expr in expressions)
    assert any('audit.enforcement.evaluation_failed' in expr for expr in expressions)
    assert any('audit.enforcement.alert' in expr for expr in expressions)

    assert 'service_name' in queries
    assert 'environment' in queries
    assert 'severity' in queries
    assert 'event_type' in queries
    assert 'audit.rule' not in queries
    # enforcement LogQL recipes ship in queries.md.
    assert 'audit.enforcement.blocked' in queries
    assert 'audit.enforcement.alert' in queries
    assert 'sec_audit.audit' in readme


def test_cli_generates_grafana_password_and_warns(tmp_path, capsys):
    from sec_audit.logging.integrations.loki.cli import main

    rc = main([str(tmp_path), '--overwrite'])
    assert rc == 0

    out = capsys.readouterr().out
    assert 'LOCAL-ONLY' in out
    assert 'Grafana login: admin /' in out

    compose = (tmp_path / 'docker-compose.yml').read_text()
    assert 'GF_SECURITY_ADMIN_PASSWORD: admin' not in compose


def test_loki_init_overwrite_replaces_existing_assets(tmp_path):
    (tmp_path / 'alloy').mkdir()
    (tmp_path / 'alloy' / 'config.alloy').write_text('old alloy config')

    copy_monitoring_assets(tmp_path, overwrite=True)

    assert (tmp_path / 'alloy' / 'config.alloy').exists()
    assert 'loki.source.file' in (tmp_path / 'alloy' / 'config.alloy').read_text()
