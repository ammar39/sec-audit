from __future__ import annotations

import secrets
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


@dataclass(frozen=True)
class LokiTemplateContext:
    app_label: str = 'django-sec-audit'
    environment: str = 'demo'
    audit_log_path: str = '../logs/sec-audit.jsonl'
    grafana_admin_user: str = 'admin'
    grafana_admin_password: str | None = None
    dashboard_title: str = 'Sec Audit Monitoring'

    def __post_init__(self) -> None:
        # Never render a hardcoded admin/admin credential. When the password is
        # unset, generate a strong one so even a LOCAL-ONLY stack is not shipped
        # with a default password.
        if not self.grafana_admin_password:
            object.__setattr__(
                self, 'grafana_admin_password', secrets.token_urlsafe(16)
            )

    def as_mapping(self) -> dict[str, str]:
        return {
            'APP_LABEL': self.app_label,
            'ENVIRONMENT': self.environment,
            'AUDIT_LOG_PATH': self.audit_log_path,
            'GRAFANA_ADMIN_USER': self.grafana_admin_user,
            'GRAFANA_ADMIN_PASSWORD': self.grafana_admin_password,
            'DASHBOARD_TITLE': self.dashboard_title,
        }


def copy_monitoring_assets(
    target_dir: str | Path,
    *,
    app_label: str = 'django-sec-audit',
    environment: str = 'demo',
    audit_log_path: str = '../logs/sec-audit.jsonl',
    grafana_admin_user: str = 'admin',
    grafana_admin_password: str | None = None,
    dashboard_title: str = 'Sec Audit Monitoring',
    overwrite: bool = False,
) -> list[Path]:
    """Render packaged Alloy / Loki / Grafana templates into ``target_dir``.

    The shipped pipeline is:

        sec_audit (stdout JSONL, or an audit file via RotatingFileHandler)
            -> OTel LogRecord JSONL
            -> Grafana Alloy
            -> Loki

    This helper only renders templates; it does not ship a Python Loki
    client. Runtime behavior lives in the Alloy River config. When
    ``grafana_admin_password`` is None a strong password is generated.
    """
    context = LokiTemplateContext(
        app_label=app_label,
        environment=environment,
        audit_log_path=audit_log_path,
        grafana_admin_user=grafana_admin_user,
        grafana_admin_password=grafana_admin_password,
        dashboard_title=dashboard_title,
    )
    target = Path(target_dir)
    package_root = resources.files('sec_audit.logging.integrations.loki')
    template_root = package_root / 'templates'
    written: list[Path] = []

    for resource in template_root.rglob('*'):
        if not resource.is_file():
            continue
        relative = Path(str(resource.relative_to(template_root)))
        destination = target / relative
        if destination.suffix == '.template':
            destination = destination.with_suffix('')
        if destination.exists() and not overwrite:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        text = resource.read_text()
        destination.write_text(_render(text, context.as_mapping()))
        written.append(destination)

    return written


def _render(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace('{{ ' + key + ' }}', value)
    return text


def remove_monitoring_assets(target_dir: str | Path) -> None:
    import shutil

    shutil.rmtree(target_dir)
