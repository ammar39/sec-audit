from sec_audit.rules.stores.counters import (
    DEFAULT_MEMORY_COUNTER_STORE,
    CounterStore,
    MemoryCounterStore,
    build_counter_store,
)
from sec_audit.rules.stores.history import EventHistoryStore, MemoryEventHistoryStore
from sec_audit.rules.stores.history import (
    DEFAULT_MEMORY_HISTORY_STORE,
    build_history_store,
)
from sec_audit.rules.history import ScopeKey

# Dotted import paths for the Redis-backed stores. Exposed as strings (not
# imported) so ``import sec_audit.rules`` never pulls ``redis``; the factories
# resolve them lazily via ``import_string`` only when configuration selects them.
DEFAULT_REDIS_COUNTER_STORE = 'sec_audit.rules.stores.redis.RedisCounterStore'
DEFAULT_REDIS_HISTORY_STORE = 'sec_audit.rules.stores.redis.RedisEventHistoryStore'

__all__ = [
    'CounterStore',
    'DEFAULT_MEMORY_COUNTER_STORE',
    'DEFAULT_MEMORY_HISTORY_STORE',
    'DEFAULT_REDIS_COUNTER_STORE',
    'DEFAULT_REDIS_HISTORY_STORE',
    'EventHistoryStore',
    'MemoryCounterStore',
    'MemoryEventHistoryStore',
    'ScopeKey',
    'build_counter_store',
    'build_history_store',
]
