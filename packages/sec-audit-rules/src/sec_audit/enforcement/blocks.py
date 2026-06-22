from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence

DEFAULT_BLOCK_MESSAGE = 'Request blocked by audit enforcement policy'


@dataclass(frozen=True)
class BlockScope:
    scope_type: str
    scope_value: str

    def __post_init__(self) -> None:
        scope_type = str(self.scope_type).strip()
        scope_value = str(self.scope_value).strip()
        if not scope_type:
            raise ValueError('scope_type cannot be empty.')
        if not scope_value:
            raise ValueError('scope_value cannot be empty.')
        object.__setattr__(self, 'scope_type', scope_type)
        object.__setattr__(self, 'scope_value', scope_value)


@dataclass(frozen=True)
class BlockEntry:
    scope: BlockScope
    reason: str = ''
    rule_name: str = ''
    status_code: int = 429
    message: str = DEFAULT_BLOCK_MESSAGE
    created_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    metadata: Mapping[str, object] | None = field(default=None)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, 'metadata', MappingProxyType(dict(self.metadata or {}))
        )


class BlockStore(Protocol):
    def block(
        self,
        scope: BlockScope,
        *,
        reason: str = '',
        rule_name: str = '',
        status_code: int = 429,
        message: str = DEFAULT_BLOCK_MESSAGE,
        ttl: int | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> BlockEntry: ...

    def unblock(self, scope: BlockScope, *, reason: str = '') -> int: ...

    def get_active(self, scope: BlockScope) -> BlockEntry | None: ...

    def first_active(self, scopes: Sequence[BlockScope]) -> BlockEntry | None: ...
