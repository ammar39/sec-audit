"""Redis counter/history store behaviour against fakeredis[lua]."""

import threading

import pytest

pytest.importorskip('redis')
fakeredis = pytest.importorskip('fakeredis')

from sec_audit.rules.history import ScopeKey  # noqa: E402
from sec_audit.rules.stores.redis import (  # noqa: E402
    RedisCounterStore,
    RedisEventHistoryStore,
)


def _client():
    return fakeredis.FakeStrictRedis(decode_responses=True)


def test_counter_incr_sets_ttl_and_counts():
    client = _client()
    store = RedisCounterStore(client=client, key_prefix='sec_audit')
    assert store.incr('k', ttl=300) == 1
    assert store.incr('k', ttl=300) == 2
    # Atomic INCR+EXPIRE: the key always carries a TTL, never -1 (no-expiry).
    assert client.pttl('sec_audit:counter:k') > 0
    assert store.get_int('k') == 2


def test_counter_atomicity_under_threads_keeps_ttl():
    server = fakeredis.FakeServer()

    def worker():
        store = RedisCounterStore(
            client=fakeredis.FakeStrictRedis(server=server, decode_responses=True),
            key_prefix='sec_audit',
        )
        for _ in range(50):
            store.incr('rate', ttl=300)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    client = fakeredis.FakeStrictRedis(server=server, decode_responses=True)
    assert int(client.get('sec_audit:counter:rate')) == 8 * 50
    assert client.pttl('sec_audit:counter:rate') > 0  # never lost its TTL


def test_counter_multi_worker_visibility():
    server = fakeredis.FakeServer()
    a = RedisCounterStore(
        client=fakeredis.FakeStrictRedis(server=server, decode_responses=True),
        key_prefix='sec_audit',
    )
    b = RedisCounterStore(
        client=fakeredis.FakeStrictRedis(server=server, decode_responses=True),
        key_prefix='sec_audit',
    )
    a.incr('shared', ttl=300)
    assert b.get_int('shared') == 1  # one worker's write visible to another


def test_history_append_query_window_and_ttl():
    client = _client()
    store = RedisEventHistoryStore(
        client=client, key_prefix='sec_audit', max_events_per_key=5, window_seconds=3600
    )
    sk = ScopeKey('ip', '1.2.3.4')
    store.append(
        {'event_type': 'auth.login.failed'}, scope_keys=[sk], recorded_at=1000.0
    )
    store.append(
        {'event_type': 'auth.login.failed'}, scope_keys=[sk], recorded_at=1001.0
    )
    rows = store.query(scope_key='ip:1.2.3.4', event_types=None, since=999.0, limit=10)
    assert [r['recorded_at'] for r in rows] == [1001.0, 1000.0]  # newest first
    assert client.pttl('sec_audit:hist:ip:1.2.3.4') > 0
    # since is exclusive + event_type filter
    rows2 = store.query(
        scope_key='ip:1.2.3.4',
        event_types={'auth.login.failed'},
        since=1000.0,
        limit=10,
    )
    assert [r['recorded_at'] for r in rows2] == [1001.0]


def test_history_equal_timestamp_members_do_not_collide():
    client = _client()
    store = RedisEventHistoryStore(client=client, key_prefix='sec_audit')
    sk = ScopeKey('ip', '1.2.3.4')
    # Two events at the SAME score must both survive (unique member ids).
    store.append({'event_type': 'a'}, scope_keys=[sk], recorded_at=1000.0)
    store.append({'event_type': 'b'}, scope_keys=[sk], recorded_at=1000.0)
    rows = store.query(scope_key='ip:1.2.3.4', event_types=None, since=0.0, limit=10)
    assert len(rows) == 2
