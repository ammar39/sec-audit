"""Django system checks for enforcement misconfiguration.

Registered from ``SecAuditEnforcementConfig.ready()`` so ``manage.py check``
surfaces a missing/misordered middleware, a missing app, an absent Redis URL, or
a fail-closed blast-radius BEFORE production.
"""

from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

from sec_audit.core.exceptions import AuditConfigurationError

from sec_audit.django_enforcement.config import DjangoEnforcementConfig

ENFORCEMENT_MIDDLEWARE = 'sec_audit.django_enforcement.middleware.EnforcementMiddleware'
AUDIT_MIDDLEWARE = 'sec_audit.django.middleware.AuditMiddleware'
ENFORCEMENT_APP = 'sec_audit.django_enforcement'


def _config():
    # Bad config raises at ready() and is reported there; don't double-report.
    try:
        return DjangoEnforcementConfig.from_settings(settings)
    except AuditConfigurationError:
        return None


@register(Tags.security)
def check_enforcement_middleware(app_configs, **kwargs):
    config = _config()
    if config is None or not config.enabled:
        return []
    middleware = list(getattr(settings, 'MIDDLEWARE', None) or [])
    if ENFORCEMENT_MIDDLEWARE not in middleware:
        return [
            Error(
                'EnforcementMiddleware is not installed but enforcement is enabled; '
                'ingress block checks will not run.',
                hint=f"Add '{ENFORCEMENT_MIDDLEWARE}' to MIDDLEWARE, above AuditMiddleware.",
                id='sec_audit_enforcement.E001',
            )
        ]
    if AUDIT_MIDDLEWARE in middleware and middleware.index(
        ENFORCEMENT_MIDDLEWARE
    ) > middleware.index(AUDIT_MIDDLEWARE):
        return [
            Error(
                'EnforcementMiddleware must be ordered above AuditMiddleware so the '
                'ingress block check short-circuits before audit work.',
                hint='Move EnforcementMiddleware before AuditMiddleware in MIDDLEWARE.',
                id='sec_audit_enforcement.E002',
            )
        ]
    return []


@register(Tags.security)
def check_enforcement_config(app_configs, **kwargs):
    config = _config()
    if config is None or not config.enabled:
        return []
    warnings = []
    installed = list(getattr(settings, 'INSTALLED_APPS', None) or [])
    if config.permanent_tier_enabled and ENFORCEMENT_APP not in installed:
        warnings.append(
            Warning(
                f"'{ENFORCEMENT_APP}' is not in INSTALLED_APPS but the permanent "
                'block tier is enabled; the PermanentBlock model/migrations will '
                'not load.',
                hint=f"Add '{ENFORCEMENT_APP}' to INSTALLED_APPS.",
                id='sec_audit_enforcement.W003',
            )
        )
    if not config.redis_url:
        warnings.append(
            Warning(
                'enforcement is enabled but redis_url is empty; the engine and '
                'block store fall back to per-process in-memory stores, which are '
                'incorrect on a multi-worker deployment.',
                hint="Set SEC_AUDIT_ENFORCEMENT['redis_url'].",
                id='sec_audit_enforcement.W004',
            )
        )
    if config.fail_closed_paths:
        warnings.append(
            Warning(
                'fail_closed_paths is configured: a store outage will DENY all '
                'traffic to those paths. Ensure this blast radius is intended.',
                hint='Confirm each fail-closed path is an explicit, audited choice.',
                id='sec_audit_enforcement.W005',
            )
        )
    return warnings
