"""Django system checks for enforcement misconfiguration.

Registered from ``SecAuditEnforcementConfig.ready()`` so ``manage.py check``
surfaces a missing/misordered middleware, a missing app, an absent Redis URL, or
a fail-closed blast-radius BEFORE production.
"""

from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.django.config import SecAuditSettings

from sec_audit.django_enforcement.config import DjangoEnforcementConfig

ENFORCEMENT_MIDDLEWARE = 'sec_audit.django_enforcement.middleware.EnforcementMiddleware'
AUDIT_MIDDLEWARE = 'sec_audit.django.middleware.AuditMiddleware'
SESSION_MIDDLEWARE = 'django.contrib.sessions.middleware.SessionMiddleware'
ENFORCEMENT_APP = 'sec_audit.django_enforcement'


def _config():
    # Bad config raises at ready() and is reported there; don't double-report.
    try:
        return DjangoEnforcementConfig.from_settings(settings)
    except AuditConfigurationError:
        return None


def _emit_session_id_enabled() -> bool:
    try:
        return bool(SecAuditSettings.from_settings(settings).django.emit_session_id)
    except AuditConfigurationError:
        return False


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


@register(Tags.security)
def check_session_enforcement_order(app_configs, **kwargs):
    """W007 — session blocks need SessionMiddleware to run before enforcement.

    When ``emit_session_id`` is on, the ingress check reads the audit-session id
    from ``request.session``; if ``EnforcementMiddleware`` runs before
    ``SessionMiddleware`` the session is unloaded at ingress and the session-scoped
    block silently drops.
    """
    config = _config()
    if config is None or not config.enabled:
        return []
    if not _emit_session_id_enabled():
        return []
    middleware = list(getattr(settings, 'MIDDLEWARE', None) or [])
    if ENFORCEMENT_MIDDLEWARE not in middleware:
        return []  # E001 already covers the missing-middleware case
    enf_index = middleware.index(ENFORCEMENT_MIDDLEWARE)
    if SESSION_MIDDLEWARE in middleware and enf_index > middleware.index(
        SESSION_MIDDLEWARE
    ):
        return []
    return [
        Warning(
            "SEC_AUDIT['django']['emit_session_id'] is True but EnforcementMiddleware "
            'is not ordered after SessionMiddleware; request.session is unloaded at '
            'ingress, so session-scoped blocks are never checked.',
            hint='Place EnforcementMiddleware after SessionMiddleware (and '
            'AuthenticationMiddleware) in MIDDLEWARE.',
            id='sec_audit_enforcement.W007',
        )
    ]
