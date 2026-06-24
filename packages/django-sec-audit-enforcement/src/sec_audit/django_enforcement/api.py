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

from sec_audit.enforcement.blocks import BlockEntry, BlockScope

from sec_audit.django_enforcement import emit as emit_mod
from sec_audit.django_enforcement.runtime import get_enforcement_runtime

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
    'block_user',
    'unblock_user',
    'is_user_blocked',
    'list_blocked_users',
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
