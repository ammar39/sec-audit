from __future__ import annotations

from collections.abc import Sequence

from sec_audit.rules.base import (
    ContextRequirements,
    Rule,
    RuleContext,
    RuleMatch,
    make_match,
)
from sec_audit.rules.events import RuleEvent

_HTTP_RESPONSE_EVENTS = {
    'http.response.success',
    'http.response.redirect',
    'http.response.client_error',
    'http.response.server_error',
}


class ResourceEnumerationRule(Rule):
    """Detect one source IP touching many distinct resources under one route.

    Demonstrates rule-contributed history attributes: the system retains only the
    collapsed ``route_pattern`` (every ``/admin/users/<uuid>/`` looks alike), so the
    rule persists its own ``{route, path}`` per request via ``history_attributes``
    and counts distinct concrete paths under the *same* route template per IP. That
    distinguishes enumeration of one collection from normal browsing across
    different endpoints.
    """

    name = 'resource_enumeration'
    severity = 7
    event_types = _HTTP_RESPONSE_EVENTS
    safe_for_enforcement = False
    context = ContextRequirements(
        scopes={'ip'},
        event_types=_HTTP_RESPONSE_EVENTS,
        window_seconds=300,
        max_events=100,
    )

    def __init__(
        self,
        *,
        threshold: int = 20,
        window_seconds: int = 300,
        severity: int | None = None,
        message: str = 'Many distinct resources accessed under one route',
        tags: Sequence[str] = ('http', 'enumeration'),
        decision: str | None = None,
    ) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        if severity is not None:
            self.severity = int(severity)
        self.message = str(message)
        self.tags = tuple(str(tag) for tag in tags)
        self.decision = decision

    @staticmethod
    def _route_and_path(event: RuleEvent) -> tuple[str, str]:
        route = str(event.field('route_pattern') or event.field('route') or '')
        path = str(event.url.path or '')
        return (route, path) if (route and path) else ('', '')

    def history_attributes(
        self, event: RuleEvent, ctx: RuleContext
    ) -> dict[str, object] | None:
        route, path = self._route_and_path(event)
        if not route:
            return None
        return {'route': route, 'path': path}

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        route, path = self._route_and_path(event)
        if not route or ctx.history is None:
            return None
        distinct = {path}
        for row in ctx.history.events('ip', window_seconds=self.window_seconds):
            attrs = row.get('rule_attrs')
            if not isinstance(attrs, dict):
                continue
            mine = attrs.get(self.name)
            if not isinstance(mine, dict) or mine.get('route') != route:
                continue
            seen_path = mine.get('path')
            if seen_path:
                distinct.add(str(seen_path))
        if len(distinct) < self.threshold:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message=self.message,
            event=event,
            tags=self.tags,
            metadata={'distinct_paths': len(distinct), 'route': route},
            decision=self.decision,
        )
