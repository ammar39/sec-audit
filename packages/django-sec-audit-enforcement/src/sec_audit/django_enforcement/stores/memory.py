"""In-process block store for tests and single-process dev (``demo_only``)."""

from __future__ import annotations

import threading
from datetime import timedelta
from typing import Callable, Iterable, Sequence

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE, BlockEntry, BlockScope

from sec_audit.django_enforcement.stores.base import now_utc


class MemoryBlockStore:
    demo_only = True

    def __init__(self, *, clock: Callable[[], object] = now_utc) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._blocks: dict[str, BlockEntry] = {}

    @staticmethod
    def _key(scope: BlockScope) -> str:
        return f'{scope.scope_type}:{scope.scope_value}'

    def block(
        self,
        scope: BlockScope,
        *,
        reason: str = '',
        rule_name: str = '',
        status_code: int = 429,
        message: str = DEFAULT_BLOCK_MESSAGE,
        ttl: int | None = None,
        metadata=None,
    ) -> BlockEntry:
        now = self._clock()
        expires_at = now + timedelta(seconds=int(ttl)) if ttl is not None else None
        entry = BlockEntry(
            scope=scope,
            reason=reason,
            rule_name=rule_name,
            status_code=int(status_code),
            message=message,
            created_at=now,
            expires_at=expires_at,
            metadata=metadata,
        )
        with self._lock:
            self._blocks[self._key(scope)] = entry
        return entry

    def unblock(
        self, scope: BlockScope, *, reason: str = '', revoked_by: str = ''
    ) -> int:
        # ``revoked_by`` is accepted for store-interface uniformity; the in-memory
        # store keeps no audit columns, so it is ignored.
        with self._lock:
            return 1 if self._blocks.pop(self._key(scope), None) is not None else 0

    def active_blocks(self) -> Iterable[BlockEntry]:
        with self._lock:
            return [
                entry for entry in self._blocks.values() if not self._expired(entry)
            ]

    def get_active(self, scope: BlockScope) -> BlockEntry | None:
        with self._lock:
            entry = self._blocks.get(self._key(scope))
            if entry is None:
                return None
            if self._expired(entry):
                self._blocks.pop(self._key(scope), None)
                return None
            return entry

    def first_active(self, scopes: Sequence[BlockScope]) -> BlockEntry | None:
        for scope in scopes:
            entry = self.get_active(scope)
            if entry is not None:
                return entry
        return None

    def _expired(self, entry: BlockEntry) -> bool:
        return entry.expires_at is not None and entry.expires_at <= self._clock()
