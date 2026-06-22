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
