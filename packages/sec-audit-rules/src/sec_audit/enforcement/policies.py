from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from sec_audit.rules.base import RuleMatch
from sec_audit.rules.events import RuleEvent


@dataclass(frozen=True)
class EnforcementDecision:
    allowed: bool = True
    status_code: int = 429
    message: str = 'Request blocked by audit enforcement policy'
    reason: str | None = None


class EnforcementPolicy(Protocol):
    def decide(
        self,
        event: RuleEvent | Mapping[str, object],
        matches: Sequence[RuleMatch],
    ) -> EnforcementDecision: ...


def highest_severity_match(matches: Sequence[RuleMatch]) -> RuleMatch | None:
    best = None
    for match in matches:
        if best is None or match.severity > best.severity:
            best = match
    return best


class SeverityEnforcementPolicy:
    def __init__(
        self,
        *,
        block_severity: int | None = 8,
        status_code: int = 429,
        message: str = 'Request blocked by audit enforcement policy',
    ) -> None:
        self.block_severity = (
            int(block_severity) if block_severity is not None else None
        )
        self.status_code = int(status_code)
        self.message = message

    def decide(
        self,
        event: RuleEvent | Mapping[str, object],
        matches: Sequence[RuleMatch],
    ) -> EnforcementDecision:
        if self.block_severity is None:
            return EnforcementDecision()
        triggering = highest_severity_match(
            [match for match in matches if match.severity >= self.block_severity]
        )
        if triggering is None:
            return EnforcementDecision()
        return EnforcementDecision(
            allowed=False,
            status_code=self.status_code,
            message=self.message,
            reason=triggering.rule_name,
        )
