"""Django system checks for common sec-audit misconfigurations.

Registered from ``SecAuditConfig.ready()`` so ``manage.py check`` surfaces
problems (middleware missing/misordered, audit logger without a JSONL handler,
enabled integrations missing their dependency, body logging that silently
captures nothing) before they reach production.
"""

from __future__ import annotations

import importlib.util
import logging

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.django.config import SecAuditSettings
from sec_audit.logging.formatters import JSONLLogFormatter

AUDIT_MIDDLEWARE = 'sec_audit.django.middleware.AuditMiddleware'
SESSION_MIDDLEWARE = 'django.contrib.sessions.middleware.SessionMiddleware'
AUTH_MIDDLEWARE = 'django.contrib.auth.middleware.AuthenticationMiddleware'
AUDIT_LOGGER_NAME = 'sec_audit.audit'


def _parsed_settings():
    # Configuration errors fail the app at startup and are reported there; don't
    # double-report them as opaque check failures.
    try:
        return SecAuditSettings.from_settings(settings)
    except AuditConfigurationError:
        return None


@register(Tags.security)
def check_audit_middleware_installed(app_configs, **kwargs):
    middleware = list(getattr(settings, 'MIDDLEWARE', None) or [])
    if AUDIT_MIDDLEWARE in middleware:
        return []
    return [
        Error(
            'AuditMiddleware is not installed; HTTP events will not be audited.',
            hint=f"Add '{AUDIT_MIDDLEWARE}' to MIDDLEWARE.",
            id='sec_audit.E001',
        )
    ]


@register(Tags.security)
def check_audit_middleware_order(app_configs, **kwargs):
    middleware = list(getattr(settings, 'MIDDLEWARE', None) or [])
    if AUDIT_MIDDLEWARE not in middleware:
        return []  # absence is reported by E001
    audit_index = middleware.index(AUDIT_MIDDLEWARE)
    errors = []
    for name in (SESSION_MIDDLEWARE, AUTH_MIDDLEWARE):
        if name in middleware and middleware.index(name) > audit_index:
            errors.append(
                Error(
                    f'AuditMiddleware is ordered before {name}.',
                    hint=(
                        'Place AuditMiddleware after SessionMiddleware and '
                        'AuthenticationMiddleware so session id and user '
                        'identity are available when responses are recorded.'
                    ),
                    id='sec_audit.E002',
                )
            )
    return errors


@register(Tags.security)
def check_audit_logger_has_jsonl_handler(app_configs, **kwargs):
    if _has_jsonl_handler(logging.getLogger(AUDIT_LOGGER_NAME)):
        return []
    return [
        Warning(
            f"Logger '{AUDIT_LOGGER_NAME}' has no handler with a JSONL audit "
            'formatter; audit records will not be emitted in the canonical shape.',
            hint=(
                'Attach a handler whose formatter is built by the '
                "'sec_audit.django.logging.formatters.audit_jsonl_formatter' "
                'factory.'
            ),
            id='sec_audit.W003',
        )
    ]


def _has_jsonl_handler(logger) -> bool:
    current = logger
    while current is not None:
        for handler in current.handlers:
            if isinstance(getattr(handler, 'formatter', None), JSONLLogFormatter):
                return True
        if not current.propagate:
            break
        current = current.parent
    return False


@register(Tags.security)
def check_integration_dependencies(app_configs, **kwargs):
    config = _parsed_settings()
    if config is None:
        return []
    errors = []
    if config.django.drf_enabled and importlib.util.find_spec('rest_framework') is None:
        errors.append(
            Error(
                "SEC_AUDIT['django']['drf_enabled'] is True but Django REST "
                'framework is not installed.',
                hint='Install djangorestframework, or set drf_enabled to False.',
                id='sec_audit.E004',
            )
        )
    if (
        config.django.model_events_enabled
        and importlib.util.find_spec('auditlog') is None
    ):
        errors.append(
            Error(
                "SEC_AUDIT['django']['model_events_enabled'] is True but "
                'django-auditlog is not installed.',
                hint='Install django-auditlog, or set model_events_enabled to False.',
                id='sec_audit.E006',
            )
        )
    return errors


@register(Tags.security)
def check_body_logging_allowlist(app_configs, **kwargs):
    config = _parsed_settings()
    if config is None:
        return []
    if config.core.log_request_bodies and not config.core.body_field_allowlist:
        return [
            Warning(
                'log_request_bodies is True but body_field_allowlist is empty; '
                'no request body fields will be captured.',
                hint=(
                    'Add field names to body_field_allowlist, or set '
                    'log_request_bodies to False.'
                ),
                id='sec_audit.W005',
            )
        ]
    return []
