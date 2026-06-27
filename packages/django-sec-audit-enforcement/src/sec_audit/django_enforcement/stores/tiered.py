"""The composed store the enforcer and middleware actually talk to.

Routing:
- temp block (``ttl`` is a positive int)  -> Redis only.
- permanent block (``ttl is None``)       -> Postgres (source of truth) +
  write-through Redis cache (long refresh TTL).

``first_active`` must not put a Postgres query on every non-blocked request. The
cache only ever holds keys for *actually-blocked* actors, so a normal request
always misses — and that miss must stay O(1) with no Postgres read. A **warm
sentinel** key carries the authoritative *membership set* of active permanent
bans (``(scope_type, scope_value)`` pairs); while it is present a Redis miss is
answered from the sentinel itself, no Postgres. This stays correct under an
``allkeys-*`` eviction policy: eviction can take an individual block key (the
sentinel, read on every miss, stays hot), but membership lives in the sentinel,
so a banned-but-evicted actor is still detected and the block entry re-fetched
from Postgres on the spot. If the sentinel itself is evicted the read goes cold
and re-warms from Postgres — also the durability guarantee for permanent bans.
When the active-ban list exceeds ``_WARM_EMBED_CAP`` the sentinel cannot embed
every pair; it falls back to a count + scope-type summary, and a warm miss whose
scope type matches re-verifies against Postgres.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE, BlockEntry, BlockScope

from sec_audit.django_enforcement.stores.postgres import PostgresBlockStore
from sec_audit.django_enforcement.stores.redis import RedisBlockStore

# Above this many active permanent bans the sentinel stops embedding the full
# membership set (to bound its size + per-miss transfer) and degrades to the
# count/scope-type re-verify path.
_WARM_EMBED_CAP = 1000


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
            # Invalidate the membership sentinel so the next miss re-warms and
            # includes this new ban (in-place set mutation would be racy).
            self._invalidate_warm()
            return entry
        # No durable tier configured: degrade to a long-lived Redis entry.
        return self._redis.block(scope, ttl=self.permanent_cache_ttl, **kwargs)

    def get_active(self, scope: BlockScope) -> BlockEntry | None:
        hit = self._redis.get_active(scope)
        if hit is not None:
            return hit
        if self._pg is None:
            return None
        return self._answer_warm_miss((scope,))

    def first_active(self, scopes: Sequence[BlockScope]) -> BlockEntry | None:
        scopes = tuple(scopes)
        hit = self._redis.first_active(scopes)  # one MGET round trip
        if hit is not None:
            return hit
        if self._pg is None or not scopes:
            return None
        return self._answer_warm_miss(scopes)

    def _answer_warm_miss(self, scopes: Sequence[BlockScope]) -> BlockEntry | None:
        """Resolve a Redis cache miss using the warm membership sentinel."""
        from sec_audit.django_enforcement.stores.base import BlockStoreError

        warm = self._redis.read_warm()
        if warm is None:
            # Cold start or post-flush: re-warm from Postgres, then answer.
            self._rewarm()
            return self._redis.first_active(scopes)
        if 'members' in warm:
            # Authoritative membership: non-banned traffic is answered with zero
            # Postgres reads. Only a genuinely-banned actor whose block key was
            # evicted falls through to a single Postgres fetch (and re-cache).
            members = _member_set(warm['members'])
            for scope in scopes:
                if (scope.scope_type, scope.scope_value) in members:
                    entry = self._pg.get_active(scope)
                    if entry is not None:
                        self._cache_permanent(entry)
                        return entry
            return None
        if warm.get('truncated'):
            # Ban list exceeded the embed cap: membership not embedded. Re-verify
            # the candidate scopes whose type matches an active ban against Postgres.
            allowed = set(warm.get('types') or ())
            candidates = [s for s in scopes if s.scope_type in allowed]
            if not candidates:
                return None
            hit = self._pg.first_active(candidates)
            if hit is not None:
                self._cache_permanent(hit)
            return hit
        # Neither shape: a broken writer or a foreign process wrote our key.
        # Surface it (the middleware applies its fail mode) rather than degrade.
        raise BlockStoreError(f'Malformed warm sentinel keys: {sorted(warm)!r}')

    def unblock(
        self, scope: BlockScope, *, reason: str = '', revoked_by: str = ''
    ) -> int:
        count = self._redis.unblock(scope, reason=reason)
        if self._pg is not None:
            count += self._pg.unblock(scope, reason=reason, revoked_by=revoked_by)
            # Drop the membership sentinel so a revoked ban leaves it on re-warm.
            self._invalidate_warm()
        return count

    def active_blocks(self) -> Iterable[BlockEntry]:
        # Durable (permanent) blocks only — the Postgres tier is the source of
        # truth. Redis-only temp blocks are not enumerated here (use
        # ``active_temp_blocks`` for those).
        if self._pg is None:
            return []
        return list(self._pg.active_blocks())

    def active_temp_blocks(self) -> list[BlockEntry]:
        # Active temp (Redis-only) blocks: every live Redis block key minus the
        # permanent membership (whose write-through cache entries share the same
        # key scheme). Deliberately crosses the "temp blocks aren't enumerated"
        # boundary for the operator block-manager UI; it costs a SCAN, so it is
        # only invoked on demand from that page, never on the request path. With
        # no durable tier, permanent blocks degrade to long-lived Redis entries
        # indistinguishable from temp ones, so all Redis blocks are returned.
        redis_entries = self._redis.scan_blocks()
        if self._pg is None:
            return redis_entries
        permanent = {
            (e.scope.scope_type, e.scope.scope_value) for e in self._pg.active_blocks()
        }
        return [
            e
            for e in redis_entries
            if (e.scope.scope_type, e.scope.scope_value) not in permanent
        ]

    def _cache_permanent(self, entry: BlockEntry) -> None:
        # Write-through: Postgres already holds the source of truth, so a cache
        # write failure is non-fatal (read-through re-warms on miss).
        from sec_audit.django_enforcement.stores.base import BlockStoreError

        try:
            self._cache_entry(entry)
        except BlockStoreError:
            pass

    def _rewarm(self) -> None:
        members: list[tuple[str, str]] = []
        types: set[str] = set()
        for entry in self._pg.active_blocks():
            self._cache_entry(entry)
            members.append((entry.scope.scope_type, entry.scope.scope_value))
            types.add(entry.scope.scope_type)
        # Mark warm even when there are zero active blocks, so a non-blocked
        # system stops querying Postgres on every request after the first.
        self._redis.mark_warm(self.permanent_cache_ttl, _warm_payload(members, types))

    def _invalidate_warm(self) -> None:
        # Best-effort, like _cache_permanent: a transient failure self-heals on the
        # next cold read. A down Redis errors the read path (fail mode) before this
        # matters, and the write-through SET would have failed too, so they stay
        # consistent.
        from sec_audit.django_enforcement.stores.base import BlockStoreError

        try:
            self._redis.clear_warm()
        except BlockStoreError:
            pass

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


def _warm_payload(members: Sequence[tuple[str, str]], types: Iterable[str]) -> dict:
    """Build the warm-sentinel payload: full membership when small, else a summary."""
    members = list(members)
    if len(members) <= _WARM_EMBED_CAP:
        return {'v': 2, 'members': [[t, v] for t, v in members]}
    return {'v': 2, 'truncated': True, 'count': len(members), 'types': sorted(types)}


def _member_set(members) -> set[tuple[str, str]]:
    """The embedded ``(scope_type, scope_value)`` membership set."""
    return {(str(scope_type), str(value)) for scope_type, value in members}
