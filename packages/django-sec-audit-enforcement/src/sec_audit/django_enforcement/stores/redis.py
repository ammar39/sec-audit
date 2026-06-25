"""Redis block store: all temp blocks + the read-through cache of permanent ones.

A backend error raises ``BlockStoreError`` (not a silent fail-open) so the
ingress check applies the configured fail mode — a block decision is a security
decision. Permanent entries are cached with a long refresh TTL, never a no-TTL
key (which managed Redis under an ``allkeys-*`` policy can silently evict,
unbanning an actor; and a heap of no-TTL keys under ``volatile-*`` can OOM).
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Sequence

import redis
from redis.exceptions import RedisError

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE, BlockEntry, BlockScope

from sec_audit.django_enforcement.stores.base import (
    BlockStoreError,
    entry_from_json,
    entry_to_json,
    now_utc,
    scope_redis_key,
)

_WARM_SUFFIX = ':blocks:warm'


class RedisBlockStore:
    demo_only = False

    def __init__(
        self,
        *,
        client=None,
        url: str | None = None,
        key_prefix: str = 'sec_audit',
        permanent_cache_ttl: int = 3600,
    ) -> None:
        if client is None:
            if not url:
                raise BlockStoreError('RedisBlockStore requires a client or url.')
            client = redis.Redis.from_url(url, decode_responses=True)
        self._client = client
        self.key_prefix = (key_prefix or 'sec_audit').strip(':')
        self.permanent_cache_ttl = int(permanent_cache_ttl)

    def _key(self, scope: BlockScope) -> str:
        return scope_redis_key(self.key_prefix, scope)

    @property
    def _warm_key(self) -> str:
        return f'{self.key_prefix}{_WARM_SUFFIX}'

    def block(
        self,
        scope: BlockScope,
        *,
        reason: str = '',
        rule_name: str = '',
        status_code: int = 429,
        message: str = DEFAULT_BLOCK_MESSAGE,
        ttl: int | None = None,
        metadata=None,
    ) -> BlockEntry:
        # The Redis layer never writes a no-TTL key: a None ttl falls back to the
        # permanent cache refresh TTL. Callers (TieredBlockStore) always pass an
        # explicit positive ttl; this guard is defensive.
        effective_ttl = int(ttl) if ttl is not None else self.permanent_cache_ttl
        now = now_utc()
        entry = BlockEntry(
            scope=scope,
            reason=reason,
            rule_name=rule_name,
            status_code=int(status_code),
            message=message,
            created_at=now,
            expires_at=now + timedelta(seconds=effective_ttl),
            metadata=metadata,
        )
        try:
            self._client.set(self._key(scope), entry_to_json(entry), ex=effective_ttl)
        except RedisError as exc:
            raise BlockStoreError('Redis block write failed.') from exc
        return entry

    def get_active(self, scope: BlockScope) -> BlockEntry | None:
        try:
            payload = self._client.get(self._key(scope))
        except RedisError as exc:
            raise BlockStoreError('Redis block read failed.') from exc
        return entry_from_json(_text(payload)) if payload else None

    def first_active(self, scopes: Sequence[BlockScope]) -> BlockEntry | None:
        scopes = tuple(scopes)
        if not scopes:
            return None
        try:
            # One round trip over the candidate keys; Redis TTL handles expiry,
            # so a missing/expired key just returns nil.
            values = self._client.mget([self._key(scope) for scope in scopes])
        except RedisError as exc:
            raise BlockStoreError('Redis block lookup failed.') from exc
        for value in values:
            if value:
                return entry_from_json(_text(value))
        return None

    def unblock(self, scope: BlockScope, *, reason: str = '') -> int:
        try:
            return int(self._client.delete(self._key(scope)))
        except RedisError as exc:
            raise BlockStoreError('Redis block delete failed.') from exc

    # --- warm-sentinel helpers (used by TieredBlockStore) ---
    #
    # The warm key holds a JSON payload describing the active permanent bans
    # (``TieredBlockStore`` owns its shape). This layer only serializes/reads it.

    def read_warm(self) -> dict | None:
        """Return the parsed warm payload, or ``None`` if absent (cold).

        The payload is written only by ``TieredBlockStore`` (which owns its shape),
        so a value that is not the JSON object we write means our own writer is
        broken or a foreign process is using the key — raise rather than silently
        degrade to a re-verify that would mask the bug.
        """
        try:
            raw = self._client.get(self._warm_key)
        except RedisError as exc:
            raise BlockStoreError('Redis warm read failed.') from exc
        if raw is None:
            return None
        try:
            data = json.loads(_text(raw))
        except (ValueError, TypeError) as exc:
            raise BlockStoreError('Malformed warm sentinel (not JSON).') from exc
        if not isinstance(data, dict):
            raise BlockStoreError('Malformed warm sentinel (not an object).')
        return data

    def mark_warm(self, ttl: int, data: dict) -> None:
        try:
            self._client.set(self._warm_key, json.dumps(data), ex=int(ttl))
        except RedisError as exc:
            raise BlockStoreError('Redis warm mark failed.') from exc

    def clear_warm(self) -> None:
        try:
            self._client.delete(self._warm_key)
        except RedisError as exc:
            raise BlockStoreError('Redis warm clear failed.') from exc


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return str(value)
