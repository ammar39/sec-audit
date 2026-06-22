from __future__ import annotations

from sec_audit.rules.base import Rule, RuleContext, RuleMatch, make_match
from sec_audit.rules.events import RuleEvent


def _state_key(*parts: str) -> str:
    return ':'.join(part.replace(':', '_') for part in parts)


class RepeatedClientErrorRule(Rule):
    name = 'repeated_client_error'
    severity = 6
    event_types = {'http.response.client_error'}
    safe_for_enforcement = False

    def __init__(self, *, threshold: int = 20, window_seconds: int = 300) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        srcip = event.source.address
        if not srcip:
            return None
        count = ctx.counters.incr(
            _state_key('rules', 'repeated_client_error', 'errors', srcip),
            ttl=self.window_seconds,
        )
        if count < self.threshold:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='Repeated HTTP client errors from source IP',
            event=event,
            tags=('http', 'scan'),
            metadata={'error_count': count},
        )
