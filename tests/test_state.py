from sec_audit.rules.config import RulesAuditConfig
from sec_audit.rules.stores import (
    DEFAULT_MEMORY_COUNTER_STORE,
    MemoryCounterStore,
    build_counter_store,
)


def test_memory_counter_store_api_and_fixed_window_ttl():
    now = [0.0]
    store = MemoryCounterStore(clock=lambda: now[0])

    assert store.incr('counter', amount=2, ttl=10) == 2
    now[0] = 5.0
    assert store.incr('counter', amount=2, ttl=10) == 4
    assert store.get_int('counter') == 4
    now[0] = 11.0
    assert store.get('counter') is None

    store.set('value', 12.5, ttl=5)
    assert store.get('value') == '12.5'
    assert store.get_int('missing', default=7) == 7
    store.expire('value', 1)
    now[0] = 12.1
    assert store.get('value') is None
    store.set('delete-me', 'yes')
    store.delete('delete-me')
    assert store.get('delete-me') is None


def test_build_counter_store_defaults_to_memory():
    store = build_counter_store(RulesAuditConfig())

    assert isinstance(store, MemoryCounterStore)
    assert (
        RulesAuditConfig().rules_counter_store_backend == DEFAULT_MEMORY_COUNTER_STORE
    )


def test_build_counter_store_uses_existing_store():
    existing = MemoryCounterStore()
    store = build_counter_store(RulesAuditConfig(rules_counter_store=existing))

    assert store is existing
