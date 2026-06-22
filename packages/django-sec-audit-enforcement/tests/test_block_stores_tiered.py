import pytest
from sec_audit.enforcement.blocks import BlockScope

from sec_audit.django_enforcement.models import PermanentBlock
from sec_audit.django_enforcement.stores import (
    PostgresBlockStore,
    RedisBlockStore,
    TieredBlockStore,
)

pytestmark = pytest.mark.django_db


class _CountingPg(PostgresBlockStore):
    def __init__(self):
        super().__init__()
        self.first_active_calls = 0
        self.active_blocks_calls = 0

    def first_active(self, scopes):
        self.first_active_calls += 1
        return super().first_active(scopes)

    def active_blocks(self):
        self.active_blocks_calls += 1
        return super().active_blocks()


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
