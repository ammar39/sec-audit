"""The composed store the enforcer and middleware actually talk to.

Routing:
- temp block (``ttl`` is a positive int)  -> Redis only.
- permanent block (``ttl is None``)       -> Postgres (source of truth) +
  write-through Redis cache (long refresh TTL).

``first_active`` must not put a Postgres query on every non-blocked request. A
**warm sentinel** key in Redis means "the cache holds all active permanent
scopes": while it is present a Redis miss is authoritative *not blocked* and
Postgres is never consulted. The sentinel is absent only on cold start or after
a Redis flush/eviction, when Postgres is read once to re-warm the cache — which
is also the durability guarantee for permanent bans.
"""

from __future__ import annotations

from typing import Sequence

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE, BlockEntry, BlockScope

from sec_audit.django_enforcement.stores.postgres import PostgresBlockStore
from sec_audit.django_enforcement.stores.redis import RedisBlockStore


class TieredBlockStore:
    def __init__(
        self,
        *,
        redis_store: RedisBlockStore,
        postgres_store: PostgresBlockStore | None = None,
        permanent_cache_ttl: int = 3600,
    ) -> None:
        self._redis = redis_store
        self._pg = postgres_store
        self.permanent_cache_ttl = int(permanent_cache_ttl)

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
        kwargs = dict(
            reason=reason,
            rule_name=rule_name,
            status_code=status_code,
            message=message,
            metadata=metadata,
        )
        if ttl is not None:
            # Temp block: Redis only, never touches Postgres.
            return self._redis.block(scope, ttl=int(ttl), **kwargs)
        # Permanent block.
        if self._pg is not None:
            entry = self._pg.block(scope, ttl=None, **kwargs)
            self._cache_permanent(entry)
            return entry
        # No durable tier configured: degrade to a long-lived Redis entry.
        return self._redis.block(scope, ttl=self.permanent_cache_ttl, **kwargs)

    def get_active(self, scope: BlockScope) -> BlockEntry | None:
        hit = self._redis.get_active(scope)
        if hit is not None:
            return hit
        if self._pg is None or self._redis.is_warm():
            return None
        self._rewarm()
        return self._redis.get_active(scope)

    def first_active(self, scopes: Sequence[BlockScope]) -> BlockEntry | None:
        hit = self._redis.first_active(scopes)  # one MGET round trip
        if hit is not None:
            return hit
        if self._pg is None or self._redis.is_warm():
            return None
        # Cold start or post-flush: re-warm from Postgres, then answer.
        self._rewarm()
        return self._redis.first_active(scopes)

    def unblock(
        self, scope: BlockScope, *, reason: str = '', revoked_by: str = ''
    ) -> int:
        count = self._redis.unblock(scope, reason=reason)
        if self._pg is not None:
            count += self._pg.unblock(scope, reason=reason, revoked_by=revoked_by)
        return count

    def _cache_permanent(self, entry: BlockEntry) -> None:
        # Write-through: Postgres already holds the source of truth, so a cache
        # write failure is non-fatal (read-through re-warms on miss).
        from sec_audit.django_enforcement.stores.base import BlockStoreError

        try:
            self._cache_entry(entry)
        except BlockStoreError:
            pass

    def _rewarm(self) -> None:
        for entry in self._pg.active_blocks():
            self._cache_entry(entry)
        # Mark warm even when there are zero active blocks, so a non-blocked
        # system stops querying Postgres on every request after the first.
        self._redis.mark_warm(self.permanent_cache_ttl)

    def _cache_entry(self, entry: BlockEntry) -> None:
        self._redis.block(
            entry.scope,
            reason=entry.reason,
            rule_name=entry.rule_name,
            status_code=entry.status_code,
            message=entry.message,
            ttl=self.permanent_cache_ttl,
            metadata=dict(entry.metadata or {}),
        )
