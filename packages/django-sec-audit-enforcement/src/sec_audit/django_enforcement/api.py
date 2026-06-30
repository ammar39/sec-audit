"""Programmatic block management — block/unblock/query a subject on demand.

These are the supported entry points for application code (views, signals,
Celery tasks, the shell) and for the admin to create or revoke blocks outside
the automatic rule-driven path. Every call goes through
``get_enforcement_runtime()`` so the Redis write-through cache and the
``audit.enforcement.*`` events stay consistent with rule-driven blocks.

A block written here is only *enforced* when ``SEC_AUDIT_ENFORCEMENT['enabled']``
is ``True`` and ``EnforcementMiddleware`` is installed; the runtime (and thus
these utils) is available regardless of the ``enabled`` flag.

Manual blocks reuse the existing event taxonomy with ``rule_name='manual'``
(``security_rule.name='manual'``) — no new schema fields are introduced.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from sec_audit.core.context import get_context
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.ip import resolve_client_ip
from sec_audit.django.logging.identity import _add_user_identity
from sec_audit.django.logging.routes import audit_route_info, resolve_request_match
from sec_audit.django.logging.sessions import get_audit_session_id
from sec_audit.django.runtime import get_runtime
from sec_audit.enforcement.blocks import BlockEntry, BlockScope
from sec_audit.rules.base import RuleMatch
from sec_audit.rules.engine import is_internal_event_type
from sec_audit.rules.triggers import MappingEventBuilder

from sec_audit.django_enforcement import emit as emit_mod
from sec_audit.django_enforcement.runtime import get_enforcement_runtime

# Standard scope fields auto-attached to a custom event from the ambient
# AuditContext (set per-request by AuditMiddleware) when the caller did not supply
# them. All five attribute names match the field keys 1:1.
_AMBIENT_FIELDS = ('srcip', 'session_id', 'request_id', 'route', 'route_name')

# Keys a fire_event payload may carry that are NOT schema fields but still map to
# something (the standard scope/correlation dimensions + their OTel aliases). A
# key matching neither these nor a declared schema field is silently dropped — so
# under a registered schema it is warned about (a likely typo).
_KNOWN_SCOPE_KEYS = frozenset(
    {
        'srcip',
        'session_id',
        'user_id',
        'username',
        'route',
        'route_name',
        'request_id',
        'event_type',
        'source.address',
        'session.id',
        'user.id',
        'http.route',
        'http.route_name',
    }
)

logger = logging.getLogger('sec_audit.enforcement')

USER_SCOPE = 'user'
IP_SCOPE = 'ip'
SESSION_SCOPE = 'session'
MANUAL_RULE_NAME = 'manual'

__all__ = [
    'USER_SCOPE',
    'IP_SCOPE',
    'SESSION_SCOPE',
    'MANUAL_RULE_NAME',
    'block_subject',
    'unblock_subject',
    'is_blocked',
    'list_active_blocks',
    'list_temp_blocks',
    'block_user',
    'unblock_user',
    'is_user_blocked',
    'list_blocked_users',
    'fire_event',
    'fields_from_request',
]


def _subject_id(value) -> str:
    """Resolve a subject to its scope value: a model instance's ``pk`` or ``str``."""
    pk = getattr(value, 'pk', None)
    return str(pk if pk is not None else value)


# ── Generic subject API ──────────────────────────────────────────────────────


def block_subject(
    scope_type: str,
    scope_value,
    *,
    reason: str = '',
    rule_name: str = MANUAL_RULE_NAME,
    ttl: int | None = None,
    status_code: int | None = None,
    message: str | None = None,
    metadata: dict | None = None,
    actor: str = '',
) -> BlockEntry:
    """Block ``scope_value`` under ``scope_type`` and emit ``block_applied``.

    ``ttl=None`` (default) writes a permanent block (Postgres source-of-truth +
    Redis write-through); a positive ``ttl`` writes a temp block (Redis-only).
    ``actor`` is recorded in the persisted block metadata.
    """
    runtime = get_enforcement_runtime()
    scope = BlockScope(scope_type, _subject_id(scope_value))
    if scope.scope_type == IP_SCOPE and ttl is None:
        # Operator override is allowed, but a permanent ip-scoped ban on shared
        # egress (NAT, mobile carrier) can lock out many users — surface it.
        logger.warning(
            'Permanent IP block requested for %s. A permanent ip-scoped ban on '
            'shared egress (NAT, mobile carrier) can lock out many users; '
            'consider a ttl or a user/session scope.',
            scope.scope_value,
        )
    meta = dict(metadata or {})
    if actor:
        meta.setdefault('actor', actor)
    entry = runtime.block_store.block(
        scope,
        reason=reason,
        rule_name=rule_name,
        status_code=status_code
        if status_code is not None
        else runtime.config.status_code,
        message=message if message is not None else runtime.config.message,
        ttl=ttl,
        metadata=meta,
    )
    kind = 'temp' if ttl is not None else 'permanent'
    runtime.emitter.emit(
        emit_mod.build_block_applied_event(
            entry,
            action_kind=kind,
            ttl=ttl,
            schema_version=runtime.schema_version,
        )
    )
    return entry


def unblock_subject(
    scope_type: str,
    scope_value,
    *,
    reason: str = '',
    revoked_by: str = '',
) -> int:
    """Revoke any active block for the subject; emit ``block_revoked`` if one was."""
    runtime = get_enforcement_runtime()
    scope = BlockScope(scope_type, _subject_id(scope_value))
    count = runtime.block_store.unblock(scope, reason=reason, revoked_by=revoked_by)
    if count:
        runtime.emitter.emit(
            emit_mod.build_block_revoked_event(
                scope,
                revoked_by=revoked_by,
                reason=reason,
                schema_version=runtime.schema_version,
            )
        )
    return count


def is_blocked(scope_type: str, scope_value) -> BlockEntry | None:
    """Return the active ``BlockEntry`` for the subject, or ``None`` if not blocked."""
    runtime = get_enforcement_runtime()
    scope = BlockScope(scope_type, _subject_id(scope_value))
    return runtime.block_store.get_active(scope)


def list_active_blocks(*, scope_type: str | None = None) -> list[BlockEntry]:
    """List durable active blocks, optionally filtered by ``scope_type``.

    Redis-only temp blocks are not enumerated (they auto-expire); this returns
    the permanent blocks that back operator-managed subjects.
    """
    runtime = get_enforcement_runtime()
    store = runtime.block_store
    entries = list(store.active_blocks()) if hasattr(store, 'active_blocks') else []
    if scope_type is not None:
        entries = [e for e in entries if e.scope.scope_type == scope_type]
    return entries


def list_temp_blocks(*, scope_type: str | None = None) -> list[BlockEntry]:
    """List active *temporary* (Redis-only, TTL-backed) blocks, optionally filtered."""
    runtime = get_enforcement_runtime()
    store = runtime.block_store
    entries = (
        list(store.active_temp_blocks()) if hasattr(store, 'active_temp_blocks') else []
    )
    if scope_type is not None:
        entries = [e for e in entries if e.scope.scope_type == scope_type]
    return entries


# ── User convenience wrappers ────────────────────────────────────────────────


def block_user(
    user, *, reason: str = '', ttl: int | None = None, actor: str = '', **kw
) -> BlockEntry:
    """Block a user (id or model instance). See :func:`block_subject`."""
    return block_subject(USER_SCOPE, user, reason=reason, ttl=ttl, actor=actor, **kw)


def unblock_user(user, *, reason: str = '', revoked_by: str = '') -> int:
    """Revoke a user's active block. See :func:`unblock_subject`."""
    return unblock_subject(USER_SCOPE, user, reason=reason, revoked_by=revoked_by)


def is_user_blocked(user) -> BlockEntry | None:
    """Return a user's active ``BlockEntry`` or ``None``. See :func:`is_blocked`."""
    return is_blocked(USER_SCOPE, user)


def list_blocked_users() -> list[BlockEntry]:
    """List active user-scoped blocks. See :func:`list_active_blocks`."""
    return list_active_blocks(scope_type=USER_SCOPE)


# ── Custom events ────────────────────────────────────────────────────────────


def fire_event(
    event_type: str,
    fields: Mapping[str, object] | None = None,
    *,
    trigger: str | None = None,
) -> list[RuleMatch]:
    """Fire a custom normalized event through the rule engine and return its matches.

    Application code (a view, a Celery task, a domain signal) calls this to push its
    own event into the SAME ``engine.evaluate`` → enforcement → emit path the built-in
    triggers use. Custom rules subscribe by ``Rule.event_types``; any match yields the
    usual ``audit.enforcement.*`` event and may apply a block — no new schema.

    ``fields`` are the normalized event attributes. ``trigger`` optionally selects a
    registered trigger's builder (otherwise a pass-through builder is used). The
    ``event_type`` must not use a reserved internal namespace (``audit.rule.*`` /
    ``audit.enforcement.*`` / ``audit.context.*``) — the engine skip-lists those, so a
    custom event using one would silently no-op.

    When called inside a request, the standard scope fields ``srcip``/``session_id``/
    ``request_id``/``route`` are auto-attached from the ambient ``AuditContext`` for
    any key the caller did not supply (explicit values always win). The ``user``
    dimension is not ambient — pass ``fields_from_request(request)`` for it.
    """
    if is_internal_event_type(event_type):
        raise AuditConfigurationError(
            f'fire_event event_type {event_type!r} uses a reserved internal namespace '
            '(audit.rule.*/audit.enforcement.*/audit.context.*).'
        )
    runtime = get_enforcement_runtime()
    if trigger is not None:
        registered = runtime.trigger_registry.by_name(trigger)
        if registered is None:
            raise AuditConfigurationError(f'Unknown trigger {trigger!r}.')
        builder = registered.builder
    else:
        builder = MappingEventBuilder()
    merged = _backfill_ambient_fields(dict(fields or {}))
    _warn_unmapped_keys(event_type, merged, runtime)
    rule_event = builder.build({**merged, 'event_type': event_type})
    return runtime.handle_event(rule_event)


def _warn_unmapped_keys(event_type: str, fields: Mapping, runtime) -> None:
    """Fail loud on a likely typo: a field that maps to nothing under a schema.

    Only checks event_types with a *registered* schema (unschematized fire_event
    calls keep their historical free-form behavior). A key that matches neither a
    declared schema field nor a known scope key is silently dropped by the
    whitelist/projection, so it is almost certainly a mistake — warn rather than
    swallow it.
    """
    schema = runtime.schema_registry.get(event_type)
    if schema is None:
        return
    declared = schema.field_names
    unmapped = sorted(
        k for k in fields if k not in declared and k not in _KNOWN_SCOPE_KEYS
    )
    if unmapped:
        logger.warning(
            'fire_event(%r): field key(s) %s match no declared schema field and no '
            'known scope key; they will be dropped (typo?).',
            event_type,
            unmapped,
        )


def _backfill_ambient_fields(fields: dict) -> dict:
    """Fill absent standard scope fields from the ambient ``AuditContext``.

    No-op outside a request (no context) or when the caller already supplied the
    key; explicit values always win. Only the four ambient dimensions are filled —
    ``user`` is resolved post-response and is never ambient (use
    :func:`fields_from_request`).
    """
    ctx = get_context()
    if ctx is None:
        return fields
    for name in _AMBIENT_FIELDS:
        if fields.get(name) in (None, ''):
            value = getattr(ctx, name, '')
            if value:
                fields[name] = value
    return fields


def fields_from_request(request) -> dict[str, object]:
    """Standard scope fields (srcip/session_id/user_id/route) from a Django request.

    Reuses the same resolvers the audit middleware uses, so the values match the
    event stream. Merge into ``fire_event`` fields to attach the full standard
    scopes — notably the ``user`` dimension, which the ambient backfill cannot
    provide (the middleware resolves the user only post-response)::

        fire_event('payment.attempted', {**fields_from_request(request), ...})
    """
    dj = get_runtime().config.django
    fields: dict[str, object] = {}
    client = resolve_client_ip(request.META, dj.trusted_proxy_config)
    if client.ip:
        fields['srcip'] = client.ip
    session_id = get_audit_session_id(request, enabled=dj.emit_session_id)
    if session_id:
        fields['session_id'] = session_id
    user = getattr(request, 'user', None)
    if user is not None and getattr(user, 'is_authenticated', False):
        _add_user_identity(fields, user)
    route_info = audit_route_info(request, match=resolve_request_match(request))
    if route_info.get('route_pattern'):
        fields['route'] = route_info['route_pattern']
    if route_info.get('route_name'):
        fields['route_name'] = route_info['route_name']
    return fields
