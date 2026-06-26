import importlib
import logging
import sys

import pytest

from sec_audit.rules import (
    BruteForceLoginRule,
    LoginThrottleRule,
    RepeatedClientErrorRule,
    RepeatedRouteRule,
    RequestBodyThresholdRule,
    Rule,
    RuleContext,
    RuleEngine,
    RuleEvent,
    RuleMatch,
    SensitiveFieldChangeRule,
    SuspiciousProxyHeaderRule,
)
from sec_audit.rules.engine import _EvaluationContext
from sec_audit.rules.stores import MemoryCounterStore, MemoryEventHistoryStore


def test_rule_event_freezes_sets_deterministically():
    # #N2: a set field is frozen to a stably-ordered tuple (set iteration order
    # is PYTHONHASHSEED-dependent), so history summaries stay deterministic.
    event = RuleEvent('x', {'tags': {'c', 'a', 'b'}})
    assert event.fields['tags'] == ('a', 'b', 'c')


def test_rule_match_metadata_is_immutable_and_copied():
    original = {'count': 1}
    match = RuleMatch('r', 1, 1.0, 'm', metadata=original)
    original['count'] = 2
    assert match.metadata['count'] == 1
    with pytest.raises(TypeError):
        match.metadata['count'] = 3


def test_rules_package_import_does_not_import_sec_audit_logging():
    modules = {
        name: module
        for name, module in sys.modules.items()
        if name == 'sec_audit'
        or name.startswith(('sec_audit.rules', 'sec_audit.logging'))
    }
    for name in modules:
        sys.modules.pop(name, None)

    try:
        importlib.import_module('sec_audit.rules')

        assert not any(name.startswith('sec_audit.logging') for name in sys.modules)
    finally:
        for name in list(sys.modules):
            if name == 'sec_audit' or name.startswith(
                ('sec_audit.rules', 'sec_audit.logging')
            ):
                sys.modules.pop(name, None)
        sys.modules.update(modules)


def test_rule_engine_filters_and_calls_clock_once(caplog):
    calls = []

    class SafeRule(Rule):
        name = 'safe'
        severity = 5
        event_types = {'audit.http.request.pre'}
        safe_for_enforcement = True

        def evaluate(self, event: RuleEvent, ctx: RuleContext):
            calls.append(ctx.now)
            return RuleMatch(self.name, self.severity, ctx.now, 'ok')

    class NoisyRule(Rule):
        name = 'noisy'
        safe_for_enforcement = True

        def evaluate(self, event: RuleEvent, ctx: RuleContext):
            raise RuntimeError('boom')

    clock_calls = []

    def clock():
        clock_calls.append(True)
        return 123.0

    engine = RuleEngine(
        [SafeRule(), NoisyRule()], counters=MemoryCounterStore(), clock=clock
    )
    matches = engine.evaluate(
        {'event_type': 'audit.http.request.pre'}, enforcement_only=True
    )
    assert len(matches) == 1
    assert calls == [123.0]
    assert len(clock_calls) == 1


def test_rule_engine_skips_recursive_events_without_clock():
    def clock():
        raise AssertionError('clock should not be called')

    engine = RuleEngine([], counters=MemoryCounterStore(), clock=clock)
    assert engine.evaluate({'event_type': 'audit.rule.match'}) == []
    assert engine.evaluate({'event_type': 'audit.enforcement.block'}) == []


def test_brute_force_and_login_throttle_share_explicit_counter_store():
    store = MemoryCounterStore()
    brute = BruteForceLoginRule(threshold=2, window_seconds=60)
    throttle = LoginThrottleRule(threshold=2, paths=(r'/login',))
    engine = RuleEngine([brute, throttle], counters=store)

    first = {'event_type': 'auth.login.failed', 'srcip': '10.0.0.1', 'username': 'a'}
    assert engine.evaluate(first) == []
    assert (
        engine.evaluate(
            {
                'event_type': 'audit.http.request.pre',
                'srcip': '10.0.0.1',
                'path': '/login',
            },
            enforcement_only=True,
        )
        == []
    )

    second = {'event_type': 'auth.login.failed', 'srcip': '10.0.0.1', 'username': 'b'}
    assert engine.evaluate(second)[0].rule_name == 'brute_force_login'
    match = engine.evaluate(
        {'event_type': 'audit.http.request.pre', 'srcip': '10.0.0.1', 'path': '/login'},
        enforcement_only=True,
    )[0]
    assert match.rule_name == 'login_throttle'
    assert brute.safe_for_enforcement is False
    assert throttle.safe_for_enforcement is True


def test_repeated_client_error_uses_context_counter_store():
    store = MemoryCounterStore()
    rule = RepeatedClientErrorRule(threshold=2, window_seconds=60)
    engine = RuleEngine([rule], counters=store)
    event = {'event_type': 'http.response.client_error', 'srcip': '10.0.0.2'}

    assert engine.evaluate(event) == []
    assert engine.evaluate(event)[0].rule_name == 'repeated_client_error'


def test_request_body_threshold_rule_blocks_matching_body_amount():
    rule = RequestBodyThresholdRule(
        field='amount',
        threshold='1000',
        paths=(r'^/transfers/$',),
        message='Transfer limit exceeded',
    )
    engine = RuleEngine([rule], counters=MemoryCounterStore(), clock=lambda: 10)

    assert (
        engine.evaluate(
            {
                'event_type': 'audit.http.request.pre',
                'path': '/profile/update/',
                'body': {'amount': '2000.00'},
            },
            enforcement_only=True,
        )
        == []
    )
    match = engine.evaluate(
        {
            'event_type': 'audit.http.request.pre',
            'path': '/transfers/',
            'body': {'amount': '2000.00'},
        },
        enforcement_only=True,
    )[0]

    assert match.rule_name == 'request_body_threshold'
    assert match.decision == 'block'
    assert match.metadata['field'] == 'amount'
    with pytest.raises(TypeError):
        match.metadata['field'] = 'other'


def test_suspicious_proxy_header_rule_distinguishes_spoofed_identity():
    rule = SuspiciousProxyHeaderRule()
    engine = RuleEngine([rule], counters=MemoryCounterStore(), clock=lambda: 10)

    assert (
        engine.evaluate(
            {
                'event_type': 'audit.http.request.pre',
                'srcip': '198.51.100.88',
                'trusted_route': True,
                'proxy_headers': {'X-Forwarded-For': '203.0.113.200'},
            }
        )
        == []
    )
    assert (
        engine.evaluate(
            {
                'event_type': 'audit.http.request.pre',
                'srcip': '198.51.100.88',
                'proxy_headers': {'X-Forwarded-For': '198.51.100.88'},
            }
        )
        == []
    )

    match = engine.evaluate(
        {
            'event_type': 'audit.http.request.pre',
            'srcip': '198.51.100.88',
            'proxy_headers': {'X-Forwarded-For': '203.0.113.200'},
        }
    )[0]

    assert match.rule_name == 'suspicious_proxy_header'
    assert match.metadata['suspicious_headers'] == ('X-Forwarded-For',)


def test_suspicious_proxy_header_rule_matches_forwarded_token_syntax():
    rule = SuspiciousProxyHeaderRule()
    engine = RuleEngine([rule], counters=MemoryCounterStore(), clock=lambda: 10)

    assert (
        engine.evaluate(
            {
                'event_type': 'audit.http.request.pre',
                'srcip': '198.51.100.88',
                'proxy_headers': {'Forwarded': 'for=198.51.100.88; proto=https'},
            }
        )
        == []
    )

    match = engine.evaluate(
        {
            'event_type': 'audit.http.request.pre',
            'srcip': '198.51.100.88',
            'proxy_headers': {
                'Forwarded': 'for=198.51.100.88; proto=https, for=203.0.113.200'
            },
        }
    )[0]

    assert match.rule_name == 'suspicious_proxy_header'
    assert match.metadata['suspicious_headers'] == ('Forwarded',)


def test_sensitive_field_change_rule_matches_configured_model_fields():
    rule = SensitiveFieldChangeRule(
        fields=('api_key', 'national_id'),
        model_labels=('fintech.customerprofile',),
    )
    engine = RuleEngine([rule], counters=MemoryCounterStore(), clock=lambda: 10)

    assert (
        engine.evaluate(
            {
                'event_type': 'model.update',
                'model_label': 'fintech.account',
                'changed_fields': ('api_key',),
            }
        )
        == []
    )
    match = engine.evaluate(
        {
            'event_type': 'model.update',
            'model_label': 'fintech.customerprofile',
            'object_id': '1',
            'changed_fields': ('email', 'api_key'),
        }
    )[0]

    assert rule.safe_for_enforcement is False
    assert match.rule_name == 'sensitive_field_change'
    assert match.subject == '1'
    assert match.metadata['changed_fields'] == ('api_key',)


def test_repeated_route_rule_counts_by_ip_and_route_for_enforcement():
    rule = RepeatedRouteRule(
        threshold=2,
        window_seconds=60,
        paths=(r'^/accounts/',),
        block_ttl=120,
    )
    engine = RuleEngine([rule], counters=MemoryCounterStore(), clock=lambda: 10)
    event = {
        'event_type': 'audit.http.request.pre',
        'srcip': '10.0.0.5',
        'path': '/accounts/missing/',
        'route_name': 'account-detail',
    }

    assert engine.evaluate(event, enforcement_only=True) == []
    match = engine.evaluate(event, enforcement_only=True)[0]

    assert match.rule_name == 'repeated_route'
    assert match.decision == 'temp_block'
    assert match.metadata['request_count'] == 2
    assert match.metadata['block_ttl'] == 120


def test_custom_rule_receives_explicit_dependencies():
    class CustomRule(Rule):
        name = 'custom'
        event_types = {'custom.event'}

        def evaluate(self, event, ctx):
            count = ctx.counters.incr('custom-counter', ttl=60)
            return RuleMatch(self.name, 3, ctx.now, 'ok', metadata={'count': count})

    match = RuleEngine(
        [CustomRule()], counters=MemoryCounterStore(), clock=lambda: 1
    ).evaluate({'event_type': 'custom.event'})[0]

    assert match.metadata['count'] == 1


def test_enforcement_fail_open_continues_on_store_error():
    class FailingCounter:
        def incr(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

        def get_int(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

        def delete(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

        def expire(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

    class CounterRule(Rule):
        name = 'counter'
        event_types = {'x'}
        safe_for_enforcement = True

        def evaluate(self, event, ctx):
            ctx.counters.incr('x')
            return RuleMatch(self.name, 9, ctx.now, 'block')

    engine = RuleEngine([CounterRule()], counters=FailingCounter(), fail_open=True)

    assert engine.evaluate({'event_type': 'x'}, enforcement_only=True) == []


def test_rule_returning_non_rulematch_is_skipped_in_fail_open_mode(caplog):
    class BadRule(Rule):
        name = 'bad'
        event_types = {'x'}

        def evaluate(self, event, ctx):
            return {'rule_name': self.name}

    engine = RuleEngine([BadRule()], counters=MemoryCounterStore(), fail_open=True)

    with caplog.at_level('DEBUG', logger='sec_audit.rules'):
        matches = engine.evaluate({'event_type': 'x'})

    assert matches == []


def test_rule_returning_non_rulematch_raises_in_fail_closed_mode():
    class BadRule(Rule):
        name = 'bad'
        event_types = {'x'}

        def evaluate(self, event, ctx):
            return 'not-a-rule-match'

    engine = RuleEngine([BadRule()], counters=MemoryCounterStore(), fail_open=False)

    with pytest.raises(TypeError, match='expected RuleMatch or None'):
        engine.evaluate({'event_type': 'x'})


def test_enforcement_fail_closed_raises_on_store_error():
    class FailingCounter:
        def incr(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

        def get_int(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

        def delete(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

        def expire(self, *args, **kwargs):
            raise RuntimeError('state store unavailable')

    class CounterRule(Rule):
        name = 'counter'
        event_types = {'x'}
        safe_for_enforcement = True

        def evaluate(self, event, ctx):
            ctx.counters.incr('x')
            return RuleMatch(self.name, 9, ctx.now, 'block')

    engine = RuleEngine([CounterRule()], counters=FailingCounter(), fail_open=False)

    with pytest.raises(RuntimeError, match='state store unavailable'):
        engine.evaluate({'event_type': 'x'}, enforcement_only=True)


# ---------------------------------------------------------------------------
# Direct unit tests for the per-stage helpers extracted from RuleEngine.evaluate
# ---------------------------------------------------------------------------


def _engine(rules=(), **kwargs):
    return RuleEngine(list(rules), counters=MemoryCounterStore(), **kwargs)


def test_is_internal_event_skips_recursive_event_prefixes():
    engine = _engine()
    for event_type in (
        'audit.rule.match',
        'audit.enforcement.block',
        'audit.context.store',
    ):
        assert engine._is_internal_event(
            RuleEvent.from_mapping({'event_type': event_type})
        )

    for event_type in ('http.request', 'auth.login.failed', 'audit.rules_listing'):
        assert not engine._is_internal_event(
            RuleEvent.from_mapping({'event_type': event_type})
        )


def test_build_evaluation_context_calls_clock_and_extracts_scope_keys():
    clock_calls = []

    def clock():
        clock_calls.append(True)
        return 42.0

    engine = _engine(clock=clock)
    event = RuleEvent.from_mapping({'event_type': 'http.request', 'user_id': 'u1'})

    ctx = engine._build_evaluation_context(event)

    assert isinstance(ctx, _EvaluationContext)
    assert clock_calls == [True]
    assert ctx.now == 42.0
    assert ctx.rule_event is event
    assert ctx.summary['user_id'] == 'u1'
    assert ctx.summary['event_type'] == 'http.request'
    assert any(key.as_string() == 'user:u1' for key in ctx.scope_keys)


def test_rule_applies_filters_by_safe_for_enforcement():
    rule = Rule()
    rule.safe_for_enforcement = False
    audit_event = RuleEvent.from_mapping({'event_type': 'http.request'})

    engine = _engine()

    assert engine._rule_applies(rule, audit_event, enforcement_only=True) is False
    assert engine._rule_applies(rule, audit_event, enforcement_only=False) is True

    rule.safe_for_enforcement = True
    assert engine._rule_applies(rule, audit_event, enforcement_only=True) is True


def test_rule_applies_filters_by_event_types():
    rule = Rule()
    rule.event_types = {'http.request'}
    audit_event = RuleEvent.from_mapping({'event_type': 'auth.login.failed'})

    engine = _engine()

    assert engine._rule_applies(rule, audit_event, enforcement_only=False) is False
    audit_event_ok = RuleEvent.from_mapping({'event_type': 'http.request'})
    assert engine._rule_applies(rule, audit_event_ok, enforcement_only=False) is True

    rule.event_types = None
    assert engine._rule_applies(rule, audit_event, enforcement_only=False) is True


def test_from_mapping_accepts_core_audit_event():
    # rules→core import is allowed; the rules package must consume the core
    # AuditEvent without raising (previously AttributeError on ``.get``).
    from sec_audit.core.events import AuditEvent

    audit_event = AuditEvent(
        event_type='http.request',
        schema_version='1.0',
        body='b',
        attributes={'user.id': 'u9', 'source.address': '10.0.0.9'},
    )
    rule_event = RuleEvent.from_mapping(audit_event)

    assert rule_event.event_type == 'http.request'
    assert rule_event.field('user.id') == 'u9'
    assert rule_event.source.address == '10.0.0.9'


def test_engine_evaluate_accepts_core_audit_event():
    from sec_audit.core.events import AuditEvent

    engine = RuleEngine([], counters=MemoryCounterStore())
    audit_event = AuditEvent(
        event_type='http.request',
        schema_version='1.0',
        body='b',
        attributes={'user.id': 'u9'},
    )

    # Must not raise; no rules configured → no matches.
    assert engine.evaluate(audit_event) == []


def test_from_mapping_preserves_top_level_fields_when_data_key_present():
    # A top-level ``data`` Mapping must no longer replace the whole event.
    rule_event = RuleEvent.from_mapping(
        {'event_type': 'x', 'user_id': 'u1', 'data': {'nested': 1}}
    )

    assert rule_event.event_type == 'x'
    assert rule_event.field('user_id') == 'u1'
    assert rule_event.field('data') == {'nested': 1}


def test_evaluate_rule_returns_none_on_exception_when_fail_open():
    class Boom(Rule):
        name = 'boom'
        event_types = {'x'}

        def evaluate(self, event, ctx):
            raise RuntimeError('nope')

    engine = _engine(rules=[Boom()], fail_open=True)
    ctx = engine._build_evaluation_context(RuleEvent.from_mapping({'event_type': 'x'}))

    assert engine._evaluate_rule(Boom(), ctx, enforcement_only=False) is None
    assert engine._evaluate_rule(Boom(), ctx, enforcement_only=True) is None


def test_evaluate_rule_reraises_in_enforcement_when_fail_closed():
    class Boom(Rule):
        name = 'boom'
        event_types = {'x'}

        def evaluate(self, event, ctx):
            raise RuntimeError('nope')

    engine = _engine(rules=[Boom()], fail_open=False)
    ctx = engine._build_evaluation_context(RuleEvent.from_mapping({'event_type': 'x'}))

    with pytest.raises(RuntimeError, match='nope'):
        engine._evaluate_rule(Boom(), ctx, enforcement_only=True)


def test_evaluate_fail_open_returns_empty_when_context_build_fails():
    def boom(event, **kwargs):
        raise RuntimeError('summary unavailable')

    import sec_audit.rules.engine as engine_module

    original = engine_module.create_history_summary
    engine_module.create_history_summary = boom

    try:
        engine = _engine(fail_open=True)
        assert engine.evaluate({'event_type': 'x'}, enforcement_only=True) == []
    finally:
        engine_module.create_history_summary = original


def test_evaluate_fail_closed_reraises_when_context_build_fails():
    def boom(event, **kwargs):
        raise RuntimeError('summary unavailable')

    import sec_audit.rules.engine as engine_module

    original = engine_module.create_history_summary
    engine_module.create_history_summary = boom
    try:
        engine = _engine(fail_open=False)
        with pytest.raises(RuntimeError, match='summary unavailable'):
            engine.evaluate({'event_type': 'x'}, enforcement_only=True)
    finally:
        engine_module.create_history_summary = original


def test_build_context_wires_counters_history_and_config():
    counters = MemoryCounterStore()
    engine = RuleEngine([], counters=counters, config={'source': 'unit-test'})
    ctx = engine._build_evaluation_context(
        RuleEvent.from_mapping({'event_type': 'x', 'user_id': 'u1'})
    )

    rule = Rule()
    rule_ctx = engine._build_context(rule, ctx)

    assert rule_ctx.now == ctx.now
    assert rule_ctx.counters is counters
    assert rule_ctx.config == {'source': 'unit-test'}
    assert rule_ctx.history.now == ctx.now
    assert 'user:u1' in rule_ctx.history.scope_keys['user']


def test_validate_match_returns_none_for_none():
    engine = _engine()

    assert engine._validate_match(Rule(), None) is None


def test_validate_match_returns_match_for_rulematch():
    engine = _engine()
    match = RuleMatch('r', 1, 1.0, 'm')

    assert engine._validate_match(Rule(), match) is match


def test_validate_match_skips_invalid_type_when_fail_open():
    engine = _engine(fail_open=True)
    captured = []

    class _Capture(logging.Handler):
        def emit(self, record):
            captured.append(record)

    rules_logger = logging.getLogger('sec_audit.rules')
    handler = _Capture(level=logging.DEBUG)
    previous_level = rules_logger.level
    rules_logger.setLevel(logging.DEBUG)
    rules_logger.addHandler(handler)
    try:
        result = engine._validate_match(Rule(), {'rule_name': 'r'})
    finally:
        rules_logger.removeHandler(handler)
        rules_logger.setLevel(previous_level)

    assert result is None
    messages = [record.getMessage() for record in captured]
    matching = [
        msg for msg in messages if 'returned' in msg and 'expected RuleMatch' in msg
    ]
    assert matching, f'no matching log record; saw: {messages}'


def test_validate_match_raises_typeerror_for_invalid_type_when_fail_closed():
    engine = _engine(fail_open=False)

    with pytest.raises(TypeError, match='expected RuleMatch or None'):
        engine._validate_match(Rule(), {'rule_name': 'r'})


def test_persist_matches_calls_all_sinks_and_isolates_failures():
    calls = []

    class SinkA:
        def persist(self, match):
            calls.append(('a', match.rule_name))

    class SinkB:
        def persist(self, match):
            raise RuntimeError('sink b down')

    class SinkC:
        def persist(self, match):
            calls.append(('c', match.rule_name))

    engine = _engine(result_sinks=[SinkA(), SinkB(), SinkC()])
    matches = [
        RuleMatch('first', 1, 1.0, 'm1'),
        RuleMatch('second', 1, 1.0, 'm2'),
    ]

    engine._persist_matches(matches)

    assert calls == [
        ('a', 'first'),
        ('a', 'second'),
        ('c', 'first'),
        ('c', 'second'),
    ]


def test_run_rules_aggregates_matches_from_applicable_rules():
    class MatchingRule(Rule):
        name = 'matching'
        event_types = {'x'}

        def evaluate(self, event, ctx):
            return RuleMatch(self.name, 1, ctx.now, 'matched')

    class SkippedRule(Rule):
        name = 'skipped'
        event_types = {'y'}

        def evaluate(self, event, ctx):
            raise AssertionError('should not run for this event')

    engine = _engine(rules=[MatchingRule(), SkippedRule()])
    ctx = engine._build_evaluation_context(RuleEvent.from_mapping({'event_type': 'x'}))

    matches = engine._run_rules(ctx, enforcement_only=False)

    assert [m.rule_name for m in matches] == ['matching']


# --- Data-loss swallow sites emit at WARNING ---


def test_context_build_fail_open_logs_at_warning(caplog):
    """Whole-evaluation loss: context build fails under fail_open → [] + WARNING."""

    def boom(event):
        raise RuntimeError('summary unavailable')

    import sec_audit.rules.engine as engine_module

    original = engine_module.create_history_summary
    engine_module.create_history_summary = boom
    engine = _engine(fail_open=True)
    rules_logger = logging.getLogger('sec_audit.rules')

    rules_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level('DEBUG', logger='sec_audit.rules'):
            matches = engine.evaluate({'event_type': 'x'}, enforcement_only=True)
    finally:
        rules_logger.removeHandler(caplog.handler)
        engine_module.create_history_summary = original

    assert matches == []  # fail-open return behavior unchanged
    assert any(
        r.levelno == logging.WARNING and 'context build failed' in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]


def test_sink_persist_failure_logs_at_warning(caplog):
    """Match persistence failure (data loss) → DEBUG exc_info + WARNING."""

    class FailingSink:
        def persist(self, match):
            raise RuntimeError('sink down')

    class MatchRule(Rule):
        name = 'm'
        event_types = {'x'}

        def evaluate(self, event, ctx):
            return RuleMatch(self.name, 1, ctx.now, 'matched')

    engine = _engine(rules=[MatchRule()], result_sinks=[FailingSink()], fail_open=True)
    rules_logger = logging.getLogger('sec_audit.rules')

    rules_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level('DEBUG', logger='sec_audit.rules'):
            matches = engine.evaluate({'event_type': 'x'})
    finally:
        rules_logger.removeHandler(caplog.handler)

    assert [m.rule_name for m in matches] == ['m']  # match still returned
    assert any(
        r.levelno == logging.WARNING
        and 'Failed to persist audit rule match' in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]


def test_history_append_failure_logs_at_warning(caplog):
    """History append failure (data loss) → DEBUG exc_info + WARNING."""

    class FailingHistory(MemoryEventHistoryStore):
        def append(self, summary, *, scope_keys, recorded_at):
            raise RuntimeError('history store down')

    # A rule with a user scope ensures non-empty scope_keys reach _append_history.
    class ContextRule(Rule):
        name = 'ctx'
        event_types = {'http.request'}

        def evaluate(self, event, ctx):
            return RuleMatch(self.name, 1, ctx.now, 'matched')

    engine = RuleEngine(
        [ContextRule()],
        counters=MemoryCounterStore(),
        history=FailingHistory(),
        fail_open=True,
    )
    rules_logger = logging.getLogger('sec_audit.rules')

    rules_logger.addHandler(caplog.handler)
    try:
        with caplog.at_level('DEBUG', logger='sec_audit.rules'):
            matches = engine.evaluate({'event_type': 'http.request', 'user_id': 'u1'})
    finally:
        rules_logger.removeHandler(caplog.handler)

    assert [m.rule_name for m in matches] == ['ctx']  # match still returned
    assert any(
        r.levelno == logging.WARNING
        and 'Failed to append audit event history' in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]


def test_ingress_pass_does_not_append_history():
    """The enforcement_only ingress pass evaluates rules but must NOT write
    history; only the egress pass appends, so a request is counted once (the
    synthetic pre-request event shares the real event's scope keys)."""

    class ContextRule(Rule):
        name = 'ctx'
        event_types = {'http.request'}

        def evaluate(self, event, ctx):
            return None

    history = MemoryEventHistoryStore()
    engine = RuleEngine(
        [ContextRule()],
        counters=MemoryCounterStore(),
        history=history,
    )
    event = {'event_type': 'http.request', 'user_id': 'u1'}

    engine.evaluate(event, enforcement_only=True)
    assert (
        history.query(scope_key='user:u1', event_types=None, since=0.0, limit=100) == []
    )

    engine.evaluate(event)
    rows = history.query(scope_key='user:u1', event_types=None, since=0.0, limit=100)
    assert len(rows) == 1
