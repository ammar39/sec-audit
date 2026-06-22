from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

from sec_audit.rules.base import Rule, RuleContext, RuleMatch, make_match
from sec_audit.rules.events import RuleEvent

_TOKEN_SPLIT_RE = re.compile(r'[,;\s=]+')


class SuspiciousProxyHeaderRule(Rule):
    name = 'suspicious_proxy_header'
    severity = 6
    event_types = None

    def __init__(self, *, safe_for_enforcement: bool = False) -> None:
        self.safe_for_enforcement = safe_for_enforcement

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        if event.proxy.trusted_route:
            return None
        headers = event.proxy.headers
        if not headers:
            return None
        suspicious = _suspicious_headers(headers, event.source.address)
        if not suspicious:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='Proxy headers claimed a different client identity',
            event=event,
            tags=('proxy', 'spoofing'),
            metadata={
                'header_count': len(headers),
                'suspicious_headers': suspicious,
            },
        )


def _suspicious_headers(headers: Mapping[str, object], srcip: str) -> tuple[str, ...]:
    source = _ip(srcip)
    suspicious = []
    for name, value in headers.items():
        tokens = tuple(_ip_tokens(value))
        if not tokens:
            if str(value or '').strip():
                suspicious.append(str(name))
            continue
        if source is None or any(token != source for token in tokens):
            suspicious.append(str(name))
    return tuple(sorted(suspicious))


def _ip_tokens(value: object):
    for token in _TOKEN_SPLIT_RE.split(str(value or '')):
        parsed = _ip(token.strip(' "\'[]'))
        if parsed is not None:
            yield parsed


def _ip(value: object):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None
