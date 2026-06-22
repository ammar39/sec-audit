from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Protocol

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string


DEFAULT_MEMORY_COUNTER_STORE = 'sec_audit.rules.stores.memory.MemoryCounterStore'


class CounterStore(Protocol):
    def incr(self, key: str, *, amount: int = 1, ttl: int | None = None) -> int: ...

    def get_int(self, key: str, *, default: int = 0) -> int: ...

    def set(self, key: str, value, *, ttl: int | None = None) -> None: ...

    def delete(self, key: str) -> None: ...

    def expire(self, key: str, ttl: int) -> None: ...


class MemoryCounterStore:
    demo_only = True

    def __init__(
        self,
        *,
        config=None,
        key_prefix: str | None = None,
        max_keys: int | None = None,
        clock=time.time,
    ) -> None:
        if config is not None:
            if key_prefix is None:
                key_prefix = getattr(config, 'state_key_prefix', 'sec_audit')
            if max_keys is None:
                max_keys = getattr(config, 'rule_engine_max_keys', 10_000)
        self.key_prefix = (key_prefix or 'sec_audit').strip(':')
        self.max_keys = int(max_keys if max_keys is not None else 10_000)
        self.clock = clock
        self.lock = threading.Lock()
        self._values: OrderedDict[str, tuple[str, float | None]] = OrderedDict()
        self._writes_since_prune = 0
        self._prune_interval = 256

    def incr(self, key: str, *, amount: int = 1, ttl: int | None = None) -> int:
        prefixed = self._key(key)
        with self.lock:
            self._maybe_prune()
            existing = self._values.get(prefixed)
            expires_at = None
            if existing is None:
                value = int(amount)
                if ttl is not None:
                    expires_at = self.clock() + int(ttl)
            else:
                current, expires_at = existing
                try:
                    value = int(current) + int(amount)
                except (TypeError, ValueError):
                    value = int(amount)
            self._values[prefixed] = (str(value), expires_at)
            self._values.move_to_end(prefixed)
            self._evict()
            return value

    def get(self, key: str) -> str | None:
        prefixed = self._key(key)
        with self.lock:
            if self._is_expired(prefixed):
                self._values.pop(prefixed, None)
                return None
            item = self._values.get(prefixed)
            if item is None:
                return None
            self._values.move_to_end(prefixed)
            return item[0]

    def get_int(self, key: str, *, default: int = 0) -> int:
        value = self.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def set(
        self, key: str, value: str | int | float, *, ttl: int | None = None
    ) -> None:
        prefixed = self._key(key)
        expires_at = self.clock() + int(ttl) if ttl is not None else None
        with self.lock:
            self._maybe_prune()
            self._values[prefixed] = (str(value), expires_at)
            self._values.move_to_end(prefixed)
            self._evict()

    def delete(self, key: str) -> None:
        with self.lock:
            self._values.pop(self._key(key), None)

    def expire(self, key: str, ttl: int) -> None:
        prefixed = self._key(key)
        with self.lock:
            if self._is_expired(prefixed):
                self._values.pop(prefixed, None)
                return
            item = self._values.get(prefixed)
            if item is not None:
                self._values[prefixed] = (item[0], self.clock() + int(ttl))
                self._values.move_to_end(prefixed)

    def _key(self, key: str) -> str:
        return f'{self.key_prefix}:{key}' if self.key_prefix else key

    def _is_expired(self, key: str) -> bool:
        item = self._values.get(key)
        return item is not None and item[1] is not None and item[1] <= self.clock()

    def _maybe_prune(self) -> None:
        # Amortize the O(n) sweep: a full scan on every write serializes all
        # threads behind a linear pass under the lock. Reads still drop expired
        # keys lazily (get/get_int/expire), so deferring the bulk sweep never
        # returns a stale value.
        self._writes_since_prune += 1
        if self._writes_since_prune >= self._prune_interval:
            self._writes_since_prune = 0
            self._prune()

    def _prune(self) -> None:
        for key in list(self._values):
            if self._is_expired(key):
                self._values.pop(key, None)

    def _evict(self) -> None:
        while len(self._values) > self.max_keys:
            self._values.popitem(last=False)


def build_counter_store(config) -> CounterStore:
    existing = getattr(config, 'rules_counter_store', None)
    if existing is not None:
        return existing
    backend = getattr(
        config, 'rules_counter_store_backend', DEFAULT_MEMORY_COUNTER_STORE
    )
    target = import_string(str(backend))
    try:
        return target(config=config)
    except Exception as exc:
        raise AuditConfigurationError(
            f'Failed to initialize counter store {backend!r}: {exc}'
        ) from exc
