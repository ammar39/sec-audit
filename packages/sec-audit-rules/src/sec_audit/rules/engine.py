from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Callable

from sec_audit.core.clock import utc_timestamp
from sec_audit.rules.base import (
    ContextRequirements,
    Rule,
    RuleContext,
    RuleMatch,
    ScopedHistoryReader,
)
from sec_audit.rules.events import RuleEvent, create_history_summary
from sec_audit.rules.history import (
    HistoryScopeExtractor,
    ScopeKey,
    build_history_scope_extractors,
    extract_scope_keys,
)
from sec_audit.rules.stores.counters import CounterStore

logger = logging.getLogger('sec_audit.rules')

_INTERNAL_EVENT_PREFIXES = (
    'audit.rule.',
    'audit.enforcement.',
    'audit.context.',
)


@dataclass(frozen=True)
class _EvaluationContext:
    rule_event: RuleEvent
    now: float
    summary: Mapping[str, object]
    scope_keys: Sequence[ScopeKey]


class RuleEngine:
    def __init__(
        self,
        rules: Sequence[Rule],
        *,
        counters: CounterStore,
        history=None,
        config: Mapping[str, object] | None = None,
        clock: Callable[[], float] = utc_timestamp,
        result_sinks: Sequence[object] = (),
        history_extractors: Sequence[HistoryScopeExtractor] | None = None,
        sensitive_keys: Sequence[str] | None = None,
        value_patterns: Sequence[object] = (),
        fail_open: bool = True,
    ) -> None:
        if counters is None:
            raise ValueError('RuleEngine requires an explicit CounterStore.')
        self.rules = tuple(rules)
        self.counters = counters
        self.history = history
        self.config = dict(config or {})
        self.clock = clock
        self.result_sinks = tuple(result_sinks)
        self.history_extractors = tuple(
            history_extractors or build_history_scope_extractors()
        )
        self.sensitive_keys = tuple(sensitive_keys or ())
        self.value_patterns = tuple(value_patterns)
        self.fail_open = bool(fail_open)

    def evaluate(
        self,
        event: RuleEvent | Mapping[str, object],
        *,
        enforcement_only: bool = False,
    ) -> list[RuleMatch]:
        rule_event = RuleEvent.from_mapping(event)
        if self._is_internal_event(rule_event):
            return []
        try:
            ctx = self._build_evaluation_context(rule_event)
        except Exception:
            # Whole-evaluation loss for this event (no rules ran). DEBUG keeps
            # exc_info for diagnosis; WARNING surfaces the degradation to
            # operators running normal log levels.
            logger.debug('Failed to build audit rule context', exc_info=True)
            logger.warning(
                'Audit rule evaluation skipped for event %r: context build failed '
                '(fail_open=%s).',
                rule_event.event_type,
                self.fail_open,
            )
            if not self.fail_open:
                raise
            return []
        matches = self._run_rules(ctx, enforcement_only)
        self._persist_matches(matches)
        self._append_history(ctx.summary, ctx.scope_keys, recorded_at=ctx.now)
        return matches

    def _is_internal_event(self, rule_event: RuleEvent) -> bool:
        return rule_event.event_type.startswith(_INTERNAL_EVENT_PREFIXES)

    def _build_evaluation_context(self, rule_event: RuleEvent) -> _EvaluationContext:
        now = self.clock()
        kwargs = {'value_patterns': self.value_patterns}
        if self.sensitive_keys:
            kwargs['sensitive_keys'] = self.sensitive_keys
        summary = dict(create_history_summary(rule_event, **kwargs))
        scope_keys = extract_scope_keys(summary, self.history_extractors)
        return _EvaluationContext(
            rule_event=rule_event,
            now=now,
            summary=summary,
            scope_keys=scope_keys,
        )

    def _run_rules(
        self, ctx: _EvaluationContext, enforcement_only: bool
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if not self._rule_applies(rule, ctx.rule_event, enforcement_only):
                continue
            match = self._evaluate_rule(rule, ctx, enforcement_only)
            if match is not None:
                matches.append(match)
        return matches

    def _rule_applies(
        self, rule: Rule, rule_event: RuleEvent, enforcement_only: bool
    ) -> bool:
        if enforcement_only and not getattr(rule, 'safe_for_enforcement', False):
            return False
        allowed_types = getattr(rule, 'event_types', None)
        if allowed_types and rule_event.event_type not in allowed_types:
            return False
        return True

    def _evaluate_rule(
        self, rule: Rule, ctx: _EvaluationContext, enforcement_only: bool
    ) -> RuleMatch | None:
        try:
            self._ensure_requested_context(rule)
            rule_ctx = self._build_context(rule, ctx)
            match = rule.evaluate(ctx.rule_event, rule_ctx)
        except Exception:
            logger.debug(
                'Audit rule failed: %s',
                getattr(rule, 'name', rule),
                exc_info=True,
            )
            if enforcement_only and not self.fail_open:
                raise
            return None
        return self._validate_match(rule, match)

    def _build_context(self, rule: Rule, ctx: _EvaluationContext) -> RuleContext:
        return RuleContext(
            now=ctx.now,
            counters=self.counters,
            history=ScopedHistoryReader(
                store=self.history,
                scope_keys=ctx.scope_keys,
                requirements=getattr(rule, 'context', None),
                now=ctx.now,
            ),
            config=self.config,
        )

    def _validate_match(self, rule: Rule, match: object) -> RuleMatch | None:
        if match is None:
            return None
        if not isinstance(match, RuleMatch):
            logger.debug(
                'Audit rule %r returned %r; expected RuleMatch or None.',
                getattr(rule, 'name', rule),
                type(match).__name__,
            )
            if not self.fail_open:
                raise TypeError(
                    f'Rule {getattr(rule, "name", rule)!r} returned '
                    f'{type(match).__name__}; expected RuleMatch or None.'
                )
            return None
        return match

    def _persist_matches(self, matches: Sequence[RuleMatch]) -> None:
        for sink in self.result_sinks:
            for match in matches:
                try:
                    sink.persist(match)
                except Exception:
                    # Data loss: a match was not recorded. DEBUG keeps exc_info;
                    # WARNING surfaces it.
                    logger.debug('Failed to persist audit rule match', exc_info=True)
                    logger.warning(
                        'Failed to persist audit rule match %r to sink %r.',
                        getattr(match, 'rule_name', match),
                        type(sink).__name__,
                    )

    def _ensure_requested_context(self, rule: Rule) -> None:
        context = getattr(rule, 'context', None)
        if context is not None and not isinstance(context, ContextRequirements):
            raise TypeError(f'Rule {rule.name!r} has invalid context requirements.')

    def _append_history(self, summary, scope_keys, *, recorded_at: float) -> None:
        if self.history is None or not scope_keys:
            return
        try:
            self.history.append(
                summary,
                scope_keys=scope_keys,
                recorded_at=recorded_at,
            )
        except Exception:
            # Data loss: future scope-keyed history queries will miss this
            # event. DEBUG keeps exc_info; WARNING surfaces it.
            logger.debug('Failed to append audit event history', exc_info=True)
            logger.warning(
                'Failed to append audit event history for %d scope key(s).',
                len(scope_keys),
            )
