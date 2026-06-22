from __future__ import annotations

from django.conf import settings

from sec_audit.django.config import SecAuditSettings
from sec_audit.logging.formatters import JSONLLogFormatter


def audit_jsonl_formatter(**kwargs) -> JSONLLogFormatter:
    """Django ``LOGGING`` formatter factory wired with the resolved SEC_AUDIT config.

    Reference it from ``LOGGING`` via the dictConfig ``'()'`` key::

        'formatters': {
            'audit_jsonl': {'()': 'sec_audit.django.logging.formatters.audit_jsonl_formatter'},
        }

    Django evaluates this factory inside ``django.setup()`` — after settings are
    loaded but before app ``ready()`` — so reading ``settings.SEC_AUDIT`` here is
    safe. It must NOT touch the app registry (no ``get_runtime()``); it only parses
    configuration. Injecting ``config``/``limits`` at construction is what replaces
    the old post-construction formatter mutation.
    """
    config = SecAuditSettings.from_settings(settings)
    return JSONLLogFormatter(
        config=config.core,
        limits=config.logging.projection_limits,
        package_name='sec_audit.django',
        **kwargs,
    )
