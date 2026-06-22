"""Builders for the four ``audit.enforcement.*`` OTel events + the emitter.

Builders return ``(AuditEvent, level)``. The stdlib logging ``level`` drives the
OTel severity number the formatter writes (WARN 13 / ERROR 17 / INFO 9), per the
event taxonomy. ``body`` is the event-type string only — all scope/rule/ttl
context goes in ``attributes`` (OTel guidance: ``body`` is a human display
message, not structured data). Scrubbing and the 4 KB bound are applied by the
existing emit pipeline when these ride ``DjangoLoggingRuntime.record`` — no new
scrubbing code here.
"""

from __future__ import annotations

import logging
from typing import Callable

from sec_audit.core.events import AuditEvent

BLOCKED = 'audit.enforcement.blocked'
BLOCK_APPLIED = 'audit.enforcement.block_applied'
BLOCK_REVOKED = 'audit.enforcement.block_revoked'
EVALUATION_FAILED = 'audit.enforcement.evaluation_failed'


def _attrs(items: dict) -> dict:
    return {key: value for key, value in items.items() if value not in (None, '')}


def _event(event_type: str, schema_version: str, attributes: dict) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        schema_version=schema_version,
        body=event_type,
        attributes=attributes,
    )


def build_blocked_event(entry, *, schema_version: str):
    attrs = _attrs(
        {
            'scope.type': entry.scope.scope_type,
            'scope.value': entry.scope.scope_value,
            'security_rule.name': entry.rule_name,
            'enforcement.action': 'blocked',
            'http.response.status_code': int(entry.status_code),
        }
    )
    return _event(BLOCKED, schema_version, attrs), logging.WARNING


def build_block_applied_event(entry, *, action_kind: str, ttl, schema_version: str):
    attrs = _attrs(
        {
            'scope.type': entry.scope.scope_type,
            'scope.value': entry.scope.scope_value,
            'security_rule.name': entry.rule_name,
            'enforcement.action': action_kind,  # 'temp' | 'permanent'
            'enforcement.ttl': int(ttl) if ttl is not None else None,
            'enforcement.expires_at': (
                entry.expires_at.isoformat() if entry.expires_at else None
            ),
        }
    )
    return _event(BLOCK_APPLIED, schema_version, attrs), logging.WARNING


def build_block_revoked_event(
    scope, *, revoked_by: str, reason: str, schema_version: str
):
    attrs = _attrs(
        {
            'scope.type': scope.scope_type,
            'scope.value': scope.scope_value,
            'enforcement.revoked_by': revoked_by,
            'enforcement.reason': reason,
        }
    )
    return _event(BLOCK_REVOKED, schema_version, attrs), logging.INFO


def build_evaluation_failed_event(*, fail_mode: str, error, schema_version: str):
    attrs = _attrs(
        {
            'enforcement.fail_mode': fail_mode,
            # class name only — never the message, which can carry PII.
            'error.type': type(error).__name__,
        }
    )
    return _event(EVALUATION_FAILED, schema_version, attrs), logging.ERROR


class EnforcementEmitter:
    """Routes a built ``(AuditEvent, level)`` through the audit logging runtime."""

    def __init__(self, record: Callable[[AuditEvent, int], None]) -> None:
        self._record = record

    def emit(self, built) -> None:
        event, level = built
        self._record(event, level)
