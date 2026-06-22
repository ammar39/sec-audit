from __future__ import annotations

import re
from collections.abc import Sequence

from sec_audit.rules.base import Rule, RuleContext, RuleMatch, make_match
from sec_audit.rules.events import RuleEvent


def _state_key(*parts: str) -> str:
    return ':'.join(part.replace(':', '_') for part in parts)


def _login_failures_key(srcip: str) -> str:
    return _state_key('rules', 'brute_force_login', 'failures', srcip)


class BruteForceLoginRule(Rule):
    name = 'brute_force_login'
    severity = 8
    event_types = {'auth.login.failed', 'auth.login.success'}
    safe_for_enforcement = False

    def __init__(self, *, threshold: int = 5, window_seconds: int = 300) -> None:
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        srcip = event.source.address
        username = event.actor.name or str(event.field('username') or '')
        if not srcip:
            return None
        if event.event_type == 'auth.login.success':
            ctx.counters.delete(_login_failures_key(srcip))
            return None
        count = ctx.counters.incr(
            _login_failures_key(srcip),
            ttl=self.window_seconds,
        )
        if count < self.threshold:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='Repeated login failures detected',
            event=event,
            tags=('auth', 'bruteforce'),
            metadata={'failure_count': count, 'username': username},
        )


class LoginThrottleRule(Rule):
    name = 'login_throttle'
    severity = 8
    event_types = {'audit.http.request.pre'}
    safe_for_enforcement = True

    def __init__(
        self,
        *,
        threshold: int = 5,
        paths: Sequence[str] = (r'/login',),
    ) -> None:
        self.threshold = int(threshold)
        self.paths = tuple(re.compile(path) for path in paths)

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        path = event.url.path
        if self.paths and not any(pattern.search(path) for pattern in self.paths):
            return None
        srcip = event.source.address
        if not srcip:
            return None
        count = ctx.counters.get_int(_login_failures_key(srcip))
        if count < self.threshold:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='Login temporarily throttled after repeated failures',
            event=event,
            tags=('auth', 'throttle'),
            metadata={'failure_count': count},
            decision='block',
        )
