from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from sec_audit.rules.events import RuleEvent
from sec_audit.rules.history import ScopeKey
from sec_audit.rules.stores.counters import CounterStore


@dataclass(frozen=True)
class RuleMatch:
    rule_name: str
    severity: int
    matched_at: float
    message: str
    event_type: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    srcip: str | None = None
    decision: str | None = None
    subject: str | None = None
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, 'metadata', MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class ContextRequirements:
    scopes: frozenset[str]
    event_types: frozenset[str] | None = None
    window_seconds: int = 900
    max_events: int = 100

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            'scopes',
            frozenset(str(scope) for scope in self.scopes),
        )
        if self.event_types is not None:
            object.__setattr__(
                self,
                'event_types',
                frozenset(str(event_type) for event_type in self.event_types),
            )
        object.__setattr__(self, 'window_seconds', int(self.window_seconds))
        object.__setattr__(self, 'max_events', int(self.max_events))
        if self.window_seconds <= 0:
            raise ValueError('window_seconds must be positive.')
        if self.max_events <= 0:
            raise ValueError('max_events must be positive.')


@dataclass(frozen=True)
class RuleContext:
    now: float
    counters: CounterStore
    history: 'ScopedHistoryReader | None'
    config: Mapping[str, Any]


class Rule:
    name: str = ''
    severity: int = 1
    event_types: set[str] | None = None
    safe_for_enforcement: bool = False
    context: ContextRequirements | None = None

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        raise NotImplementedError

    def history_attributes(
        self, event: RuleEvent, ctx: RuleContext
    ) -> Mapping[str, object] | None:
        """Attributes this rule wants persisted alongside the event in history.

        Returned values are stored under this rule's own namespace
        (``rule_attrs[<name>]``) in the per-event history summary, so later events
        in the same scope window can read them back for correlation — including
        derived data the system does not otherwise carry (e.g. an extracted
        resource id or a computed fingerprint).

        Must be a pure detector method: no side effects. The engine owns the write
        and coerces the returned mapping for serialization, but does NOT scrub it —
        the rule is trusted to choose what it persists. Default contributes nothing.

        SECURITY: because the engine does not scrub these values, they must NOT
        carry secrets or PII. The history store (e.g. Redis) is a separate
        retention/exposure surface from the scrubbed log stream, and later events
        in the same scope window read these values back. Persist only derived,
        non-sensitive correlation data (ids, fingerprints, route templates) — never
        raw request data that could contain credentials, tokens, or personal data.
        """
        return None


class ScopedHistoryReader:
    def __init__(
        self,
        *,
        store,
        scope_keys: Sequence[ScopeKey],
        requirements: ContextRequirements | None,
        now: float,
    ) -> None:
        self.store = store
        self.scope_keys = {}
        for scope_key in scope_keys:
            self.scope_keys.setdefault(scope_key.scope, []).append(
                scope_key.as_string()
            )
        self.requirements = requirements
        self.now = float(now)

    def events(
        self,
        scope: str,
        *,
        event_type: str | None = None,
        event_types: set[str] | None = None,
        since: float | None = None,
        limit: int | None = None,
        window_seconds: int | None = None,
    ) -> Sequence[Mapping[str, object]]:
        scope = str(scope)
        self._ensure_scope_allowed(scope)
        if self.store is None:
            return ()
        scope_keys = self.scope_keys.get(scope, ())
        if not scope_keys:
            return ()
        selected_types = self._bounded_event_types(
            event_type=event_type, event_types=event_types
        )
        selected_limit = self._bounded_limit(limit)
        if selected_limit <= 0:
            return ()
        selected_since = self._bounded_since(since=since, window_seconds=window_seconds)
        rows = []
        try:
            for scope_key in scope_keys:
                rows.extend(
                    self.store.query(
                        scope_key=scope_key,
                        event_types=selected_types,
                        since=selected_since,
                        limit=selected_limit,
                    )
                )
        except Exception:
            return ()
        rows.sort(key=lambda row: float(row.get('recorded_at', 0.0)), reverse=True)
        return rows[:selected_limit]

    def count(
        self,
        scope: str,
        *,
        event_type: str | None = None,
        event_types: set[str] | None = None,
        window_seconds: int | None = None,
    ) -> int:
        # Materializes the matching window to count it. This is intentional and
        # bounded: events() caps results at the rule's max_events (<=100), and
        # the EventHistoryStore protocol exposes no count primitive, so an O(1)
        # count path would be a breaking protocol change for negligible gain.
        return len(
            self.events(
                scope,
                event_type=event_type,
                event_types=event_types,
                window_seconds=window_seconds,
            )
        )

    def _ensure_scope_allowed(self, scope: str) -> None:
        if self.requirements is None:
            raise ValueError(f'Rule did not declare history scope {scope!r}.')
        if scope not in self.requirements.scopes:
            raise ValueError(f'Rule did not declare history scope {scope!r}.')

    def _bounded_event_types(
        self,
        *,
        event_type: str | None,
        event_types: set[str] | None,
    ) -> set[str] | None:
        requested = set(event_types or ())
        if event_type is not None:
            requested.add(str(event_type))
        required = self.requirements.event_types if self.requirements else None
        if required is None:
            return requested or None
        if not requested:
            return set(required)
        return set(required).intersection(requested)

    def _bounded_limit(self, limit: int | None) -> int:
        max_events = self.requirements.max_events if self.requirements else 100
        return min(max_events, int(limit) if limit is not None else max_events)

    def _bounded_since(
        self, *, since: float | None, window_seconds: int | None
    ) -> float:
        max_window = self.requirements.window_seconds if self.requirements else 900
        selected_window = min(
            max_window,
            int(window_seconds) if window_seconds is not None else max_window,
        )
        lower_bound = self.now - selected_window
        if since is None:
            return lower_bound
        return max(float(since), lower_bound)


ScopeContext = ScopedHistoryReader


def event_field(event: RuleEvent, name: str, default: object = '') -> object:
    return event.field(name, default)


def make_match(
    *,
    rule_name: str,
    severity: int,
    now: float,
    message: str,
    event: RuleEvent,
    tags: Sequence[str] = (),
    metadata: Mapping[str, object] | None = None,
    decision: str | None = None,
    subject: str | None = None,
) -> RuleMatch:
    return RuleMatch(
        rule_name=rule_name,
        severity=severity,
        matched_at=now,
        message=message,
        event_type=event.event_type or None,
        request_id=event.request_id or None,
        session_id=event.session_id or None,
        srcip=event.source.address or None,
        decision=decision,
        subject=subject,
        tags=tuple(tags),
        metadata=metadata or {},
    )
