from __future__ import annotations

import threading
from collections import defaultdict
from typing import Mapping, Protocol, Sequence

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string
from sec_audit.rules.history import ScopeKey

DEFAULT_MEMORY_HISTORY_STORE = 'sec_audit.rules.stores.memory.MemoryEventHistoryStore'


class EventHistoryStore(Protocol):
    def append(
        self,
        event_summary: Mapping[str, object],
        *,
        scope_keys: Sequence[ScopeKey],
        recorded_at: float,
    ) -> None: ...

    def query(
        self,
        *,
        scope_key: str,
        event_types: set[str] | None,
        since: float,
        limit: int,
    ) -> Sequence[Mapping[str, object]]: ...


class MemoryEventHistoryStore:
    demo_only = True

    def __init__(
        self,
        *,
        config=None,
        max_keys: int | None = None,
        max_events_per_key: int | None = None,
    ) -> None:
        if config is not None and max_keys is None:
            max_keys = getattr(config, 'history_max_keys', 10_000)
        if config is not None and max_events_per_key is None:
            max_events_per_key = getattr(config, 'history_max_events_per_key', 100)
        self.max_keys = int(max_keys if max_keys is not None else 10_000)
        self.max_events_per_key = int(
            max_events_per_key if max_events_per_key is not None else 100
        )
        self.lock = threading.Lock()
        self._events: dict[str, list[Mapping[str, object]]] = defaultdict(list)

    def append(
        self,
        event_summary: Mapping[str, object],
        *,
        scope_keys: Sequence[ScopeKey],
        recorded_at: float,
    ) -> None:
        entry = dict(event_summary)
        entry['recorded_at'] = float(recorded_at)
        with self.lock:
            for scope_key in scope_keys:
                key = scope_key.as_string()
                self._events[key].append(dict(entry))
                self._events[key] = self._events[key][-self.max_events_per_key :]
            self._evict()

    def query(
        self,
        *,
        scope_key: str,
        event_types: set[str] | None,
        since: float,
        limit: int,
    ) -> Sequence[Mapping[str, object]]:
        with self.lock:
            rows = list(self._events.get(scope_key, ()))
        matches = [
            dict(row)
            for row in rows
            if float(row.get('recorded_at', 0.0)) > float(since)
            and (event_types is None or str(row.get('event_type') or '') in event_types)
        ]
        return list(reversed(matches))[: int(limit)]

    def _evict(self) -> None:
        while len(self._events) > self.max_keys:
            first_key = next(iter(self._events))
            self._events.pop(first_key, None)


def build_history_store(config) -> EventHistoryStore | None:
    existing = getattr(config, 'rules_history_store', None)
    if existing is None:
        return None
    if not isinstance(existing, str):
        return existing
    target = import_string(existing)
    try:
        return target(config=config)
    except Exception as exc:
        raise AuditConfigurationError(
            f'Failed to initialize event history store {existing!r}: {exc}'
        ) from exc
