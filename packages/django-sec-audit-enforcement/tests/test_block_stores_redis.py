import fakeredis
import pytest
from sec_audit.enforcement.blocks import BlockScope

from sec_audit.django_enforcement.stores import BlockStoreError, RedisBlockStore


def _store(client):
    return RedisBlockStore(client=client, key_prefix='sec_audit')


def test_block_first_active_single_mget(redis_client):
    store = _store(redis_client)
    ip = BlockScope('ip', '1.2.3.4')
    store.block(ip, ttl=300, status_code=429, message='nope')
    hit = store.first_active([BlockScope('user', '7'), ip])
    assert hit is not None and hit.scope == ip and hit.message == 'nope'
    assert store.get_active(ip) is not None
    assert store.first_active([BlockScope('user', '7')]) is None


def test_temp_block_sets_ttl_key(redis_client):
    store = _store(redis_client)
    ip = BlockScope('ip', '1.2.3.4')
    store.block(ip, ttl=5)
    ttl = redis_client.ttl('sec_audit:block:ip:1.2.3.4')
    assert 0 < ttl <= 5  # never a no-TTL (-1) key


def test_permanent_cache_never_no_ttl(redis_client):
    # ttl=None must not write a no-TTL key; it falls back to permanent_cache_ttl.
    store = RedisBlockStore(client=redis_client, permanent_cache_ttl=3600)
    ip = BlockScope('ip', '1.2.3.4')
    store.block(ip, ttl=None)
    ttl = redis_client.ttl('sec_audit:block:ip:1.2.3.4')
    assert 0 < ttl <= 3600


def test_unblock_deletes(redis_client):
    store = _store(redis_client)
    ip = BlockScope('ip', '1.2.3.4')
    store.block(ip, ttl=300)
    assert store.unblock(ip) == 1
    assert store.get_active(ip) is None


def test_multi_worker_visibility():
    # Two client handles on one server == two Gunicorn workers sharing Redis.
    server = fakeredis.FakeServer()
    c1 = fakeredis.FakeStrictRedis(server=server, decode_responses=True)
    c2 = fakeredis.FakeStrictRedis(server=server, decode_responses=True)
    ip = BlockScope('ip', '1.2.3.4')
    _store(c1).block(ip, ttl=300)
    assert _store(c2).get_active(ip) is not None


def test_backend_error_raises_block_store_error():
    class _Broken:
        def mget(self, *a, **k):
            raise __import__('redis').exceptions.ConnectionError('down')

    store = RedisBlockStore(client=_Broken(), key_prefix='sec_audit')
    with pytest.raises(BlockStoreError):
        store.first_active([BlockScope('ip', '1.2.3.4')])
