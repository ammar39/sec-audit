from datetime import datetime, timedelta, timezone

from sec_audit.enforcement.blocks import BlockScope

from sec_audit.django_enforcement.stores import MemoryBlockStore


class _Clock:
    def __init__(self, start):
        self.now = start

    def __call__(self):
        return self.now


def test_block_get_first_unblock():
    store = MemoryBlockStore()
    ip = BlockScope('ip', '1.2.3.4')
    user = BlockScope('user', '42')
    entry = store.block(ip, reason='r', rule_name='rule', status_code=429)
    assert entry.scope == ip
    assert store.get_active(ip) is not None
    # precedence: user first, then ip — only ip is active
    assert store.first_active([user, ip]).scope == ip
    assert store.unblock(ip) == 1
    assert store.get_active(ip) is None
    assert store.unblock(ip) == 0


def test_temp_block_expires_lazily():
    clock = _Clock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    store = MemoryBlockStore(clock=clock)
    ip = BlockScope('ip', '1.2.3.4')
    store.block(ip, ttl=300)
    assert store.get_active(ip) is not None
    clock.now += timedelta(seconds=301)
    assert store.get_active(ip) is None  # expired on read


def test_permanent_block_has_no_expiry():
    store = MemoryBlockStore()
    ip = BlockScope('ip', '9.9.9.9')
    entry = store.block(ip, ttl=None)
    assert entry.expires_at is None


def test_active_blocks_lists_permanent_only():
    store = MemoryBlockStore()
    store.block(BlockScope('user', '1'), ttl=None)  # permanent
    store.block(BlockScope('ip', '2.2.2.2'), ttl=300)  # temp -> not in active_blocks
    scopes = {(e.scope.scope_type, e.scope.scope_value) for e in store.active_blocks()}
    assert scopes == {('user', '1')}  # durable/permanent only (matches tiered store)


def test_active_blocks_excludes_expired():
    clock = _Clock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    store = MemoryBlockStore(clock=clock)
    store.block(BlockScope('ip', '1.1.1.1'), ttl=300)
    clock.now += timedelta(seconds=301)
    assert list(store.active_blocks()) == []


def test_active_temp_blocks_only_lists_ttl_blocks():
    store = MemoryBlockStore()
    store.block(BlockScope('user', '1'), ttl=None)  # permanent
    store.block(BlockScope('ip', '2.2.2.2'), ttl=300)  # temp
    scopes = {
        (e.scope.scope_type, e.scope.scope_value) for e in store.active_temp_blocks()
    }
    assert scopes == {('ip', '2.2.2.2')}  # permanent excluded


def test_active_temp_blocks_excludes_expired():
    clock = _Clock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    store = MemoryBlockStore(clock=clock)
    store.block(BlockScope('ip', '1.1.1.1'), ttl=300)
    clock.now += timedelta(seconds=301)
    assert list(store.active_temp_blocks()) == []


def test_unblock_accepts_revoked_by():
    store = MemoryBlockStore()
    ip = BlockScope('ip', '3.3.3.3')
    store.block(ip)
    assert store.unblock(ip, reason='x', revoked_by='root') == 1
