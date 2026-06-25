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
# Eviction policies that can silently drop cached permanent-block keys.
_EVICTING_POLICY_PREFIXES = ('allkeys-', 'volatile-')


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
def check_redis_eviction_policy(app_configs, **kwargs):
    """W006 — warn when Redis may evict cached permanent-block keys.

    Best-effort and non-fatal: managed Redis (ElastiCache, Memorystore, Upstash)
    often disables ``CONFIG``, and ``manage.py check`` must not fail or hang when
    Redis is unreachable — so the whole probe is wrapped in a broad try/except.
    Correctness is preserved by the store (the warm sentinel carries ban
    membership), so this is purely an operator nudge to avoid the extra Postgres
    reads an evicting policy forces.
    """
    config = _config()
    if config is None or not config.enabled:
        return []
    if not (config.redis_url and config.permanent_tier_enabled):
        return []
    try:
        import redis

        client = redis.Redis.from_url(
            config.redis_url, socket_connect_timeout=1, socket_timeout=1
        )
        policy = str(
            (client.config_get('maxmemory-policy') or {}).get('maxmemory-policy', '')
        ).lower()
    except Exception:
        return []
    if not policy.startswith(_EVICTING_POLICY_PREFIXES):
        return []
    return [
        Warning(
            f"Redis maxmemory-policy is '{policy}': it can evict cached "
            'permanent-block keys. Bans stay correct (the store re-verifies against '
            'Postgres via the membership sentinel), but every eviction forces a '
            'Postgres read, and a ban list larger than the embed cap degrades to a '
            'per-request Postgres re-verify on matching scope types.',
            hint="Use 'noeviction' for the block store, or give it a dedicated Redis "
            'database/instance not subject to an allkeys-*/volatile-* policy.',
            id='sec_audit_enforcement.W006',
        )
    ]


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
