from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

from sec_audit.core.config import DEFAULT_SENSITIVE_KEYS
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.scrubbers import scrub

TRUNCATED = '[TRUNCATED]'
CIRCULAR = '[CIRCULAR]'
MIN_RECORD_BYTES = 1024


class ProjectionError(ValueError):
    pass


@dataclass(frozen=True)
class ProjectionLimits:
    max_depth: int = 8
    max_mapping_entries: int = 100
    max_sequence_length: int = 100
    max_string_length: int = 4096
    max_attributes: int = 128
    max_bytes: int = 64
    max_record_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        # Limits are public configuration; reject invalid values eagerly so the
        # first ``project_attributes`` call is not where an operator discovers a
        # negative or zero cap. ``bool`` is an ``int`` subclass, exclude it.
        for name in (
            'max_depth',
            'max_mapping_entries',
            'max_sequence_length',
            'max_string_length',
            'max_attributes',
            'max_bytes',
            'max_record_bytes',
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise AuditConfigurationError(f'{name} must be an int.')
            if value <= 0:
                raise AuditConfigurationError(f'{name} must be greater than 0.')
        if self.max_record_bytes < MIN_RECORD_BYTES:
            raise AuditConfigurationError(
                f'max_record_bytes must be at least {MIN_RECORD_BYTES}.'
            )


def freeze_value(value: object, *, cycle_marker: str = CIRCULAR) -> object:
    return _freeze(value, active=set(), cycle_marker=cycle_marker)


def project_value(
    value: object,
    *,
    limits: ProjectionLimits | None = None,
    strict: bool = False,
) -> object:
    return _project(
        value,
        limits=limits or ProjectionLimits(),
        strict=strict,
        depth=0,
        active=set(),
    )


def project_attributes(
    attributes: Mapping[str, object],
    *,
    limits: ProjectionLimits | None = None,
    strict: bool = True,
) -> dict[str, object]:
    limits = limits or ProjectionLimits()
    projected = _project_mapping(
        attributes,
        limits=limits,
        strict=strict,
        depth=0,
        active=set(),
        max_items=limits.max_attributes,
    )
    return dict(projected)


def safe_metadata_projection(
    metadata: Mapping[str, object] | None,
    *,
    sensitive_keys=DEFAULT_SENSITIVE_KEYS,
    value_patterns=(),
    max_depth: int = 5,
    max_items: int = 50,
    max_string_length: int = 1000,
) -> dict[str, object]:
    scrubbed = scrub(
        dict(metadata or {}),
        sensitive_keys=sensitive_keys,
        value_patterns=value_patterns,
    )
    return project_attributes(
        scrubbed,
        limits=ProjectionLimits(
            max_depth=max_depth,
            max_mapping_entries=max_items,
            max_sequence_length=max_items,
            max_string_length=max_string_length,
            max_attributes=max_items,
        ),
    )


def _freeze(value: object, *, active: set[int], cycle_marker: str) -> object:
    if isinstance(value, Mapping):
        obj_id = id(value)
        if obj_id in active:
            return cycle_marker
        active.add(obj_id)
        try:
            return MappingProxyType(
                {
                    str(key): _freeze(item, active=active, cycle_marker=cycle_marker)
                    for key, item in value.items()
                }
            )
        finally:
            active.discard(obj_id)
    if isinstance(value, (set, frozenset)):
        # Audit attributes must be JSON-compatible. ``set``/``frozenset`` have
        # no guaranteed iteration order, so converting them to a tuple would
        # serialize differently across processes; reject instead of silently
        # coercing. Callers must pass ``list`` or ``tuple``.
        raise ProjectionError(
            'set/frozenset are not valid audit values; use list or tuple.'
        )
    if isinstance(value, (list, tuple)):
        obj_id = id(value)
        if obj_id in active:
            return cycle_marker
        active.add(obj_id)
        try:
            return tuple(
                _freeze(item, active=active, cycle_marker=cycle_marker)
                for item in value
            )
        finally:
            active.discard(obj_id)
    return value


def _project(
    value: object,
    *,
    limits: ProjectionLimits,
    strict: bool,
    depth: int,
    active: set[int],
) -> object:
    if depth >= limits.max_depth:
        return TRUNCATED
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        if strict:
            raise ProjectionError('Non-finite floats are not valid JSON values.')
        return str(value)
    if isinstance(value, str):
        return _limit_string(value, limits.max_string_length)
    if isinstance(value, bytes):
        return _bytes_projection(value, limits.max_bytes)
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, (UUID, Decimal, Path)):
        return str(value)
    if isinstance(value, Enum):
        return project_value(value.value, limits=limits, strict=strict)
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(value)
    if isinstance(value, Mapping):
        return _project_mapping(
            value,
            limits=limits,
            strict=strict,
            depth=depth,
            active=active,
            max_items=limits.max_mapping_entries,
        )
    if isinstance(value, (set, frozenset)):
        # Audit attributes must be JSON-compatible: sets have no guaranteed
        # iteration order, so the same logical event would serialize
        # differently across processes. Reject rather than coerce; callers must
        # pass list or tuple.
        if strict:
            raise ProjectionError(
                'set/frozenset are not valid audit values; use list or tuple.'
            )
        return f'<unserializable:{type(value).__module__}.{type(value).__name__}>'
    if isinstance(value, (list, tuple)):
        return _project_sequence(
            value,
            limits=limits,
            strict=strict,
            depth=depth,
            active=active,
        )
    if strict:
        raise ProjectionError(f'Unsupported projection value: {type(value).__name__}')
    return f'<unserializable:{type(value).__module__}.{type(value).__name__}>'


def _project_mapping(
    value: Mapping[object, object],
    *,
    limits: ProjectionLimits,
    strict: bool,
    depth: int,
    active: set[int],
    max_items: int,
) -> dict[str, object]:
    obj_id = id(value)
    if obj_id in active:
        return {'_truncated': CIRCULAR}
    active.add(obj_id)
    try:
        projected = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= max_items:
                projected['_truncated'] = TRUNCATED
                break
            # Every mapping key is ordinary application data. There is no
            # envelope unwrapping: names like ``event``/``raw_event`` are
            # preserved verbatim, nested or top-level.
            key = str(key)
            projected[_limit_string(key, limits.max_string_length)] = _project(
                item,
                limits=limits,
                strict=strict,
                depth=depth + 1,
                active=active,
            )
        return projected
    finally:
        active.discard(obj_id)


def _project_sequence(
    value: Sequence[object] | set[object] | frozenset[object],
    *,
    limits: ProjectionLimits,
    strict: bool,
    depth: int,
    active: set[int],
) -> list[object]:
    obj_id = id(value)
    if obj_id in active:
        return [CIRCULAR]
    active.add(obj_id)
    try:
        items = list(value)
        projected = [
            _project(
                item,
                limits=limits,
                strict=strict,
                depth=depth + 1,
                active=active,
            )
            for item in items[: limits.max_sequence_length]
        ]
        if len(items) > limits.max_sequence_length:
            projected.append(TRUNCATED)
        return projected
    finally:
        active.discard(obj_id)


def _bytes_projection(value: bytes, max_bytes: int) -> dict[str, object]:
    truncated = len(value) > max_bytes
    raw = value[:max_bytes]
    return {
        'encoding': 'base64',
        'size': len(value),
        'data': base64.b64encode(raw).decode('ascii'),
        'truncated': truncated,
    }


def _limit_string(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return f'{value[:max_length]}{TRUNCATED}'
