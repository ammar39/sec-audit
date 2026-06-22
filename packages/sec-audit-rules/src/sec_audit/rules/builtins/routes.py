from __future__ import annotations

import re
from collections.abc import Sequence

from sec_audit.rules.base import Rule, RuleContext, RuleMatch, make_match
from sec_audit.rules.events import RuleEvent


def _state_key(*parts: str) -> str:
    return ':'.join(part.replace(':', '_') for part in parts)


class RepeatedRouteRule(Rule):
    name = 'repeated_route'
    severity = 7
    event_types = {'audit.http.request.pre'}
    safe_for_enforcement = True

    def __init__(
        self,
        *,
        threshold: int = 10,
        window_seconds: int = 300,
        paths: Sequence[str] = (),
        severity: int | None = None,
        message: str = 'Repeated requests to a monitored route',
        tags: Sequence[str] = ('http', 'route-abuse'),
        decision: str | None = 'temp_block',
        block_ttl: int | None = None,
    ) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        self.paths = tuple(re.compile(path) for path in paths)
        if severity is not None:
            self.severity = int(severity)
        self.message = str(message)
        self.tags = tuple(str(tag) for tag in tags)
        self.decision = decision
        self.block_ttl = block_ttl

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        path = event.url.path
        if self.paths and not any(pattern.search(path) for pattern in self.paths):
            return None
        srcip = event.source.address
        route = _route_key(event)
        if not srcip or not route:
            return None
        key = _state_key('rules', self.name, srcip, route)
        count = ctx.counters.incr(key, ttl=self.window_seconds)
        if count < self.threshold:
            return None
        metadata = {'request_count': count, 'route': route}
        if self.block_ttl is not None:
            metadata['block_ttl'] = int(self.block_ttl)
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message=self.message,
            event=event,
            tags=self.tags,
            metadata=metadata,
            decision=self.decision,
        )


def _route_key(event: RuleEvent) -> str:
    return (
        str(event.field('route_name') or '')
        or str(event.field('route_pattern') or '')
        or event.url.path
    ).strip()
