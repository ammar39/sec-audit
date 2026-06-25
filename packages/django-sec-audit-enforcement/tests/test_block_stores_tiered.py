import json

import pytest
from sec_audit.enforcement.blocks import BlockScope

from sec_audit.django_enforcement.models import PermanentBlock
from sec_audit.django_enforcement.stores import (
    BlockStoreError,
    PostgresBlockStore,
    RedisBlockStore,
    TieredBlockStore,
)
from sec_audit.django_enforcement.stores import tiered as tiered_mod

pytestmark = pytest.mark.django_db

_WARM_KEY = 'sec_audit:blocks:warm'


class _CountingPg(PostgresBlockStore):
    def __init__(self):
        super().__init__()
        self.first_active_calls = 0
        self.active_blocks_calls = 0
        self.get_active_calls = 0

    def first_active(self, scopes):
        self.first_active_calls += 1
        return super().first_active(scopes)

    def get_active(self, scope):
        self.get_active_calls += 1
        return super().get_active(scope)

    def active_blocks(self):
        self.active_blocks_calls += 1
        return super().active_blocks()

    @property
    def total_calls(self):
        return (
            self.first_active_calls + self.get_active_calls + self.active_blocks_calls
        )


def _tiered(redis_client, pg=None):
    return TieredBlockStore(
        redis_store=RedisBlockStore(client=redis_client, key_prefix='sec_audit'),
        postgres_store=pg if pg is not None else PostgresBlockStore(),
        permanent_cache_ttl=3600,
    )


def test_temp_block_never_touches_postgres(redis_client):
    store = _tiered(redis_client)
    ip = BlockScope('ip', '1.2.3.4')
    store.block(ip, ttl=300)
    assert PermanentBlock.objects.count() == 0  # temp = Redis only
    assert redis_client.ttl('sec_audit:block:ip:1.2.3.4') > 0


def test_permanent_block_writes_postgres_and_cache(redis_client):
    store = _tiered(redis_client)
    user = BlockScope('user', '42')
    store.block(user, ttl=None, status_code=403, message='banned')
    assert (
        PermanentBlock.objects.filter(
            scope_type='user', scope_value='42', revoked_at__isnull=True
        ).count()
        == 1
    )
    # cache populated with a positive (refresh) TTL, never no-TTL
    assert 0 < redis_client.ttl('sec_audit:block:user:42') <= 3600


def test_permanent_durable_across_redis_flush(redis_client):
    pg = _CountingPg()
    store = _tiered(redis_client, pg=pg)
    user = BlockScope('user', '42')
    store.block(user, ttl=None)
    redis_client.flushall()  # cache + warm sentinel gone
    hit = store.first_active([user])  # Postgres read-through re-warms
    assert hit is not None and hit.scope == user
    # cache re-warmed with a positive TTL
    assert 0 < redis_client.ttl('sec_audit:block:user:42') <= 3600


def test_warm_cache_does_not_query_postgres_for_non_blocked(redis_client):
    pg = _CountingPg()
    store = _tiered(redis_client, pg=pg)
    unknown = BlockScope('ip', '8.8.8.8')
    # First call is cold -> one PG read to warm.
    assert store.first_active([unknown]) is None
    calls_after_warm = pg.first_active_calls + pg.active_blocks_calls
    # Subsequent non-blocked lookups must not hit Postgres while warm.
    for _ in range(5):
        assert store.first_active([unknown]) is None
    assert pg.first_active_calls + pg.active_blocks_calls == calls_after_warm


def test_unblock_clears_both_tiers(redis_client):
    store = _tiered(redis_client)
    user = BlockScope('user', '42')
    store.block(user, ttl=None)
    assert store.unblock(user, reason='x') >= 1
    assert redis_client.get('sec_audit:block:user:42') is None
    assert PermanentBlock.objects.get(scope_type='user', scope_value='42').revoked_at


def test_active_blocks_returns_permanent_rows_only(redis_client):
    store = _tiered(redis_client)
    store.block(BlockScope('user', '42'), ttl=None)
    store.block(BlockScope('ip', '1.2.3.4'), ttl=300)  # temp = Redis only
    listed = {(e.scope.scope_type, e.scope.scope_value) for e in store.active_blocks()}
    assert listed == {('user', '42')}  # temp block not enumerated


def test_active_blocks_empty_without_postgres(redis_client):
    store = TieredBlockStore(
        redis_store=RedisBlockStore(client=redis_client, key_prefix='sec_audit'),
        postgres_store=None,
        permanent_cache_ttl=3600,
    )
    store.block(BlockScope('user', '42'), ttl=None)  # degrades to long Redis entry
    assert list(store.active_blocks()) == []


# --- Bug 2: permanent bans survive Redis key eviction under a warm sentinel ---


def _warm(store, redis_client):
    """Force a warm sentinel by reading a non-banned scope (cold -> re-warm)."""
    store.first_active([BlockScope('ip', '0.0.0.0')])
    assert redis_client.get(_WARM_KEY) is not None


def test_permanent_ban_survives_block_key_eviction(redis_client):
    pg = _CountingPg()
    store = _tiered(redis_client, pg=pg)
    user = BlockScope('user', '42')
    store.block(user, ttl=None)  # invalidates the sentinel
    _warm(store, redis_client)  # membership sentinel now embeds user:42
    redis_client.delete('sec_audit:block:user:42')  # simulate LRU eviction
    hit = store.first_active([user])  # old code returned None here
    assert hit is not None and hit.scope == user
    # the evicted key is re-cached on the spot
    assert 0 < redis_client.ttl('sec_audit:block:user:42') <= 3600


def test_get_active_survives_block_key_eviction(redis_client):
    # is_blocked()/admin block_status route through get_active — must also survive.
    pg = _CountingPg()
    store = _tiered(redis_client, pg=pg)
    user = BlockScope('user', '42')
    store.block(user, ttl=None)
    _warm(store, redis_client)
    redis_client.delete('sec_audit:block:user:42')
    assert store.get_active(user) is not None


def test_non_banned_traffic_never_hits_postgres_while_a_ban_exists(redis_client):
    # The review's core concern: with a ban present + warm, non-banned requests
    # must be answered from the membership sentinel with ZERO Postgres reads.
    pg = _CountingPg()
    store = _tiered(redis_client, pg=pg)
    store.block(BlockScope('user', '42'), ttl=None)
    _warm(store, redis_client)
    baseline = pg.total_calls
    for _ in range(5):
        assert store.first_active([BlockScope('user', '99')]) is None
        assert store.first_active([BlockScope('ip', '8.8.8.8')]) is None
    assert pg.total_calls == baseline  # no PG round trips for non-banned traffic


def test_sentinel_invalidated_on_permanent_block_and_unblock(redis_client):
    store = _tiered(redis_client)
    _warm(store, redis_client)
    store.block(BlockScope('user', '42'), ttl=None)
    assert redis_client.get(_WARM_KEY) is None  # block creation drops the sentinel
    _warm(store, redis_client)
    store.unblock(BlockScope('user', '42'))
    assert redis_client.get(_WARM_KEY) is None  # revoke drops it too


def test_non_object_warm_sentinel_raises(redis_client):
    # A value that is not the JSON object we write can only be a broken writer or
    # a foreign process on our key — surface it, never silently degrade.
    store = _tiered(redis_client)
    user = BlockScope('user', '42')
    store.block(user, ttl=None)
    redis_client.set(_WARM_KEY, '1')  # valid JSON, but not our object shape
    redis_client.delete('sec_audit:block:user:42')
    with pytest.raises(BlockStoreError):
        store.first_active([user])


def test_unknown_shape_warm_sentinel_raises(redis_client):
    # A dict that is neither a membership nor a truncated payload is corrupt.
    store = _tiered(redis_client)
    user = BlockScope('user', '42')
    store.block(user, ttl=None)
    redis_client.set(_WARM_KEY, '{"v": 2}')  # no members, not truncated
    redis_client.delete('sec_audit:block:user:42')
    with pytest.raises(BlockStoreError):
        store.first_active([user])


def test_rewarm_embeds_membership_pairs(redis_client):
    store = _tiered(redis_client)
    store.block(BlockScope('user', '42'), ttl=None)
    store.block(BlockScope('session', 'abc'), ttl=None)
    _warm(store, redis_client)  # cold -> re-warm writes the membership payload
    payload = json.loads(redis_client.get(_WARM_KEY))
    members = {tuple(pair) for pair in payload['members']}
    assert members == {('user', '42'), ('session', 'abc')}


def test_truncated_sentinel_falls_back_to_postgres_reverify(redis_client, monkeypatch):
    monkeypatch.setattr(tiered_mod, '_WARM_EMBED_CAP', 1)  # force truncation
    pg = _CountingPg()
    store = _tiered(redis_client, pg=pg)
    store.block(BlockScope('user', '42'), ttl=None)
    store.block(BlockScope('user', '43'), ttl=None)
    _warm(store, redis_client)
    payload = json.loads(redis_client.get(_WARM_KEY))
    assert payload['truncated'] is True and payload['count'] == 2
    redis_client.delete('sec_audit:block:user:42')  # evict one
    # matching scope type -> re-verified against Postgres
    assert store.first_active([BlockScope('user', '42')]) is not None
    # non-matching scope type -> short-circuits without a Postgres re-verify
    before = pg.first_active_calls
    assert store.first_active([BlockScope('ip', '8.8.8.8')]) is None
    assert pg.first_active_calls == before
