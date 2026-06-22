from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
import math
from types import MappingProxyType

from sec_audit.core.exceptions import AuditConfigurationError


def _validate_nanos(name: str, value: object) -> int:
    # ``bool`` is an ``int`` subclass; reject it so True/False never reach the
    # wire as a timestamp.
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditConfigurationError(f'{name} must be an int.')
    if value < 0:
        raise AuditConfigurationError(f'{name} must be non-negative.')
    return value


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    schema_version: str
    body: str
    attributes: Mapping[str, object]
    timestamp_ns: int = field(default_factory=time.time_ns)
    observed_timestamp_ns: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, str) or not self.event_type:
            raise AuditConfigurationError('event_type is required and must be a str.')
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise AuditConfigurationError(
                'schema_version is required and must be a str.'
            )
        if not isinstance(self.body, str):
            raise AuditConfigurationError('body must be a str.')
        timestamp_ns = _validate_nanos('timestamp_ns', self.timestamp_ns)
        observed = self.observed_timestamp_ns
        if observed is not None:
            observed = _validate_nanos('observed_timestamp_ns', observed)
        frozen = _canonicalize_attributes(
            self.event_type,
            self.schema_version,
            self.attributes,
        )
        object.__setattr__(self, 'event_type', self.event_type)
        object.__setattr__(self, 'schema_version', self.schema_version)
        object.__setattr__(self, 'body', self.body)
        object.__setattr__(self, 'attributes', frozen)
        object.__setattr__(self, 'timestamp_ns', timestamp_ns)
        object.__setattr__(self, 'observed_timestamp_ns', observed)

    def observed(self, observed_timestamp_ns: int | None = None) -> 'AuditEvent':
        resolved = (
            observed_timestamp_ns
            if observed_timestamp_ns is not None
            else time.time_ns()
        )
        resolved = _validate_nanos('observed_timestamp_ns', resolved)
        # Stamp the observed timestamp without dataclasses.replace(): replace()
        # reconstructs the event, re-running __post_init__ -> _canonicalize_
        # attributes over every attribute on each emission. The source event is
        # already validated and its attributes already frozen, so copy them
        # verbatim and validate only the new timestamp. object.__new__ skips
        # __init__/__post_init__; object.__setattr__ writes through the freeze.
        new = object.__new__(AuditEvent)
        object.__setattr__(new, 'event_type', self.event_type)
        object.__setattr__(new, 'schema_version', self.schema_version)
        object.__setattr__(new, 'body', self.body)
        object.__setattr__(new, 'attributes', self.attributes)
        object.__setattr__(new, 'timestamp_ns', self.timestamp_ns)
        object.__setattr__(new, 'observed_timestamp_ns', resolved)
        return new


def _canonicalize_attributes(
    event_type: str,
    schema_version: str,
    attributes: Mapping[str, object],
) -> Mapping[str, object]:
    if not isinstance(attributes, Mapping):
        raise AuditConfigurationError('attributes must be a mapping.')
    data = _canonicalize_mapping(
        attributes,
        path='attributes',
        active=set(),
    )
    _validate_authoritative_field(data, 'event_type', event_type)
    _validate_authoritative_field(data, 'schema_version', schema_version)
    merged = dict(data)
    merged['event_type'] = event_type
    merged['schema_version'] = schema_version
    return MappingProxyType(merged)


def _validate_authoritative_field(
    attributes: Mapping[str, object],
    key: str,
    expected: str,
) -> None:
    value = attributes.get(key)
    if value is not None and value != expected:
        raise AuditConfigurationError(
            f'attributes[{key!r}] conflicts with the AuditEvent {key}.'
        )


def _canonicalize_value(value: object, *, path: str, active: set[int]) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        if value != value:
            kind = 'NaN'
        else:
            kind = 'infinite'
        raise AuditConfigurationError(
            f'{path} is {kind}; audit events must be JSON-compatible.'
        )
    if isinstance(value, (bytes, bytearray)):
        raise AuditConfigurationError(f'{path} must not be bytes.')
    if isinstance(value, (set, frozenset)):
        raise AuditConfigurationError(
            f'{path} must not be a set/frozenset; use list or tuple.'
        )
    if isinstance(value, Mapping):
        return _canonicalize_mapping(value, path=path, active=active)
    if isinstance(value, (list, tuple)):
        return _canonicalize_sequence(value, path=path, active=active)
    raise AuditConfigurationError(
        f'{path} has unsupported value type {type(value).__name__}.'
    )


def _canonicalize_mapping(
    value: Mapping[object, object],
    *,
    path: str,
    active: set[int],
) -> Mapping[str, object]:
    obj_id = id(value)
    if obj_id in active:
        raise AuditConfigurationError(f'{path} contains a cycle.')
    active.add(obj_id)
    try:
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditConfigurationError(f'{path} contains a non-string key.')
            if key in frozen:
                raise AuditConfigurationError(f'{path} contains duplicate key {key!r}.')
            frozen[key] = _canonicalize_value(
                item,
                path=f'{path}.{key}',
                active=active,
            )
        return MappingProxyType(frozen)
    finally:
        active.discard(obj_id)


def _canonicalize_sequence(
    value: list[object] | tuple[object, ...],
    *,
    path: str,
    active: set[int],
) -> tuple[object, ...]:
    obj_id = id(value)
    if obj_id in active:
        raise AuditConfigurationError(f'{path} contains a cycle.')
    active.add(obj_id)
    try:
        return tuple(
            _canonicalize_value(item, path=f'{path}[{index}]', active=active)
            for index, item in enumerate(value)
        )
    finally:
        active.discard(obj_id)


__all__ = ['AuditEvent']
