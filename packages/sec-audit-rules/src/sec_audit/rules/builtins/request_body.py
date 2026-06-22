from __future__ import annotations

import re
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation

from sec_audit.rules.base import Rule, RuleContext, RuleMatch, make_match
from sec_audit.rules.events import RuleEvent


class RequestBodyThresholdRule(Rule):
    name = 'request_body_threshold'
    severity = 8
    event_types = {'audit.http.request.pre'}
    safe_for_enforcement = True

    def __init__(
        self,
        *,
        field: str = 'amount',
        threshold: str | int | float | Decimal = '10000',
        paths: Sequence[str] = (),
        severity: int | None = None,
        message: str = 'Request body numeric threshold exceeded',
        tags: Sequence[str] = ('request', 'threshold'),
        decision: str | None = 'block',
    ) -> None:
        self.field = str(field)
        self.threshold = Decimal(str(threshold))
        self.paths = tuple(re.compile(path) for path in paths)
        if severity is not None:
            self.severity = int(severity)
        self.message = str(message)
        self.tags = tuple(str(tag) for tag in tags)
        self.decision = decision

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        path = event.url.path
        if self.paths and not any(pattern.search(path) for pattern in self.paths):
            return None
        body = event.request.body
        if not isinstance(body, dict):
            return None
        value = _decimal(body.get(self.field))
        if value is None or value <= self.threshold:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message=self.message,
            event=event,
            tags=self.tags,
            metadata={
                'field': self.field,
                'value': str(value),
                'threshold': str(self.threshold),
            },
            decision=self.decision,
        )


def _decimal(value: object) -> Decimal | None:
    if value in (None, ''):
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
