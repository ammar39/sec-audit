from __future__ import annotations

import logging
import importlib.util
import threading
from dataclasses import dataclass

from django.core.exceptions import ImproperlyConfigured

from sec_audit.core.diagnostics import diagnostic_warning
from sec_audit.core.events import AuditEvent
from sec_audit.core.exceptions import AuditConfigurationError, AuditImportError
from sec_audit.core.imports import import_string
from sec_audit.django.config import SecAuditSettings
from sec_audit.logging import AuditPipeline, LoggingRuntime

AUDIT_LOGGER_NAME = 'sec_audit.audit'
_runtime: DjangoLoggingRuntime | None = None
_runtime_lock = threading.Lock()
__all__ = ['DjangoLoggingRuntime', 'get_runtime']


@dataclass(frozen=True)
class DjangoLoggingRuntime:
    config: SecAuditSettings
    logging: LoggingRuntime

    def record(self, event: AuditEvent, level: int) -> None:
        try:
            self.logging.emit_event(event, level)
        except Exception:
            diagnostic_warning('audit.emit_failed', 'Audit record emission failed')


def _build_runtime(settings_obj) -> DjangoLoggingRuntime:
    config = _from_django_settings(settings_obj)
    _validate_enabled_integrations(config)
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    logging_runtime = LoggingRuntime(
        audit_logger,
        core_config=config.core,
        logging_config=config.logging,
        pipeline=_build_pipeline(config),
    )
    # Handlers attached via Django's LOGGING dictConfig receive the resolved
    # CoreAuditConfig at construction through the ``audit_jsonl_formatter``
    # factory (sec_audit.django.logging.formatters), so no post-construction
    # formatter mutation is needed here.
    return DjangoLoggingRuntime(config=config, logging=logging_runtime)


def _validate_enabled_integrations(config: SecAuditSettings) -> None:
    if config.django.drf_enabled and importlib.util.find_spec('rest_framework') is None:
        raise ImproperlyConfigured(
            "SEC_AUDIT['django']['drf_enabled'] requires Django REST framework."
        )
    if (
        config.django.model_events_enabled
        and importlib.util.find_spec('auditlog') is None
    ):
        raise ImproperlyConfigured(
            "SEC_AUDIT['django']['model_events_enabled'] requires django-auditlog."
        )


def _build_pipeline(config: SecAuditSettings) -> AuditPipeline:
    return AuditPipeline.from_sequences(
        filters=_resolve_extensions(
            config.django.filters, "SEC_AUDIT['django']['filters']"
        ),
        enrichers=_resolve_extensions(
            config.django.enrichers, "SEC_AUDIT['django']['enrichers']"
        ),
    )


def _resolve_extensions(paths: tuple[object, ...], setting_name: str) -> tuple:
    resolved = []
    for path in paths:
        try:
            target = import_string(path) if isinstance(path, str) else path
        except AuditImportError as exc:
            raise ImproperlyConfigured(
                f'{setting_name} entry {path!r} could not be imported: {exc}'
            ) from exc
        resolved.append(target() if isinstance(target, type) else target)
    return tuple(resolved)


def _from_django_settings(settings_obj) -> SecAuditSettings:
    try:
        return SecAuditSettings.from_settings(settings_obj)
    except AuditConfigurationError as exc:
        raise ImproperlyConfigured(str(exc)) from exc


def _set_runtime(runtime: DjangoLoggingRuntime) -> None:
    global _runtime
    _runtime = runtime


def _reset_runtime() -> None:
    global _runtime
    _runtime = None


def get_runtime() -> DjangoLoggingRuntime:
    # Double-checked locking: the fast path reads the module global without the
    # lock; the lock only guards the one-time lazy build so two threads can't
    # both run _build_runtime and have the second silently clobber the first.
    runtime = _runtime
    if runtime is not None:
        return runtime
    with _runtime_lock:
        if _runtime is None:
            from django.conf import settings

            _set_runtime(_build_runtime(settings))
        return _runtime
