"""Shared helpers for the block stores: error type, key scheme, (de)serialization."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Mapping

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE, BlockEntry, BlockScope


class BlockStoreError(Exception):
    """A block-store backend (Redis/Postgres) was unreachable or errored.

    Raised so the ingress check can apply the configured fail mode (open or
    closed) for the path rather than crashing the request — a store outage is a
    security decision, unlike a detection-quality degradation which fails open
    silently in the counter/history stores.
    """


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def scope_redis_key(prefix: str, scope: BlockScope) -> str:
    return f'{prefix}:block:{scope.scope_type}:{scope.scope_value}'


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_iso(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def entry_to_json(entry: BlockEntry) -> str:
    return json.dumps(
        {
            'scope_type': entry.scope.scope_type,
            'scope_value': entry.scope.scope_value,
            'reason': entry.reason,
            'rule_name': entry.rule_name,
            'status_code': int(entry.status_code),
            'message': entry.message,
            'created_at': _iso(entry.created_at),
            'expires_at': _iso(entry.expires_at),
            'metadata': dict(entry.metadata or {}),
        },
        default=str,
    )


def entry_from_json(payload: str) -> BlockEntry:
    data = json.loads(payload)
    return BlockEntry(
        scope=BlockScope(
            scope_type=str(data['scope_type']),
            scope_value=str(data['scope_value']),
        ),
        reason=str(data.get('reason') or ''),
        rule_name=str(data.get('rule_name') or ''),
        status_code=int(data.get('status_code') or 429),
        message=str(data.get('message') or DEFAULT_BLOCK_MESSAGE),
        created_at=_parse_iso(data.get('created_at')),
        expires_at=_parse_iso(data.get('expires_at')),
        metadata=data.get('metadata')
        if isinstance(data.get('metadata'), Mapping)
        else {},
    )
