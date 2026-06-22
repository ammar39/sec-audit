"""Ingress synthetic event. The egress path consumes emitted ``AuditEvent``s
directly via ``RuleEvent.from_mapping`` in the consumer — no dict projection."""

from __future__ import annotations

from typing import Mapping

from sec_audit.rules.events import RuleEvent

PRE_REQUEST_EVENT = 'audit.http.request.pre'


def synthesize_pre_request_event(payload: Mapping[str, object]) -> RuleEvent:
    """Build the pre-request event so ``safe_for_enforcement`` rules
    (``LoginThrottleRule``/``RepeatedRouteRule``) can fire on ingress."""
    return RuleEvent.from_mapping({**dict(payload), 'event_type': PRE_REQUEST_EVENT})
