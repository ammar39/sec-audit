import concurrent.futures

import pytest

from sec_audit.rules import (
    ContextRequirements,
    Rule,
    RuleContext,
    RuleEngine,
    RuleEvent,
    RuleMatch,
    SummaryKey,
)
from sec_audit.rules.events import create_history_summary
from sec_audit.rules.history import (
    ScopeKey,
    build_history_scope_extractors,
    extract_scope_keys,
)
from sec_audit.rules.stores import MemoryCounterStore, MemoryEventHistoryStore


class PasswordResetThenTransferRule(Rule):
    name = 'password_reset_then_transfer'
    severity = 8
    event_types = {'transfer.created'}
    context = ContextRequirements(
        scopes={'user'},
        event_types={'auth.password.reset.success'},
        window_seconds=1800,
        max_events=10,
    )

    def evaluate(self, event: RuleEvent, ctx: RuleContext):
        if ctx.history.count('user') == 0:
            return None
        return RuleMatch(self.name, self.severity, ctx.now, 'Transfer after reset')


def test_default_scope_extractors_cover_user_session_ip_and_route():
    extractors = build_history_scope_extractors()

    keys = extract_scope_keys(
        {
            'event_type': 'x',
            'user_id': 'u1',
            'session_id': 's1',
            'srcip': '10.0.0.1',
            'route': 'account-detail',
        },
        extractors,
    )

    assert {key.as_string() for key in keys} == {
        'user:u1',
        'session:s1',
        'ip:10.0.0.1',
        'route:account-detail',
    }


def test_rules_route_extractor_ignores_framework_route_and_raw_path_fields():
    extractors = build_history_scope_extractors()

    assert extract_scope_keys({'route_pattern': '/accounts/<id>/'}, extractors) == ()
    assert extract_scope_keys({'path': '/accounts/123/'}, extractors) == ()


def test_default_scope_extractors_consume_summary_key_constants():
    extractors = build_history_scope_extractors()
    keys = extract_scope_keys(
        {
            SummaryKey.EVENT_TYPE: 'x',
            SummaryKey.USER_ID: 'u1',
            SummaryKey.SESSION_ID: 's1',
            SummaryKey.SRCIP: '10.0.0.1',
            SummaryKey.ROUTE: 'account-detail',
        },
        extractors,
    )
    assert {key.as_string() for key in keys} == {
        'user:u1',
        'session:s1',
        'ip:10.0.0.1',
        'route:account-detail',
    }


def test_memory_history_query_uses_compound_scope_key_and_bounds_results():
    history = MemoryEventHistoryStore(max_events_per_key=2)
    history.append(
        {'event_type': 'x', 'id': 'old'},
        scope_keys=[ScopeKey('session', 's1')],
        recorded_at=1,
    )
    history.append(
        {'event_type': 'y', 'id': 'wrong'},
        scope_keys=[ScopeKey('session', 's1')],
        recorded_at=10,
    )
    history.append(
        {'event_type': 'x', 'id': 'inside'},
        scope_keys=[ScopeKey('session', 's1')],
        recorded_at=11,
    )
    history.append(
        {'event_type': 'x', 'id': 'newest'},
        scope_keys=[ScopeKey('session', 's1')],
        recorded_at=12,
    )

    rows = history.query(
        scope_key='session:s1',
        event_types={'x'},
        since=0,
        limit=10,
    )

    assert [row['id'] for row in rows] == ['newest', 'inside']


def test_context_rule_sees_previous_events_by_user():
    history = MemoryEventHistoryStore()
    history.append(
        {'event_type': 'auth.password.reset.success', 'user_id': 'u1'},
        scope_keys=[ScopeKey('user', 'u1')],
        recorded_at=10.0,
    )
    engine = RuleEngine(
        [PasswordResetThenTransferRule()],
        counters=MemoryCounterStore(),
        history=history,
        clock=lambda: 20.0,
    )

    match = engine.evaluate({'event_type': 'transfer.created', 'user_id': 'u1'})[0]

    assert match.rule_name == 'password_reset_then_transfer'


def test_context_rule_sees_previous_events_by_object():
    class ObjectRule(Rule):
        name = 'object_rule'
        event_types = {'model.update'}
        context = ContextRequirements(scopes={'object'}, event_types={'model.update'})

        def evaluate(self, event, ctx):
            count = ctx.history.count('object')
            return RuleMatch(self.name, 3, ctx.now, 'ok', metadata={'count': count})

    history = MemoryEventHistoryStore()
    history.append(
        {
            'event_type': 'model.update',
            'model_label': 'fintech.transfer',
            'object_id': 't1',
        },
        scope_keys=[ScopeKey('object', 'fintech.transfer:t1')],
        recorded_at=1,
    )
    engine = RuleEngine(
        [ObjectRule()],
        counters=MemoryCounterStore(),
        history=history,
        clock=lambda: 2,
        history_extractors=[_ObjectExtractor()],
    )

    match = engine.evaluate(
        {
            'event_type': 'model.update',
            'model_label': 'fintech.transfer',
            'object_id': 't1',
        }
    )[0]

    assert match.metadata['count'] == 1


def test_scoped_history_reader_reads_multiple_keys_for_same_scope_newest_first():
    class MultiObjectRule(Rule):
        name = 'multi_object'
        event_types = {'x'}
        context = ContextRequirements(scopes={'object'}, event_types={'y'})

        def evaluate(self, event, ctx):
            rows = ctx.history.events('object')
            return RuleMatch(
                self.name,
                1,
                ctx.now,
                'ok',
                metadata={'ids': tuple(row['id'] for row in rows)},
            )

    history = MemoryEventHistoryStore()
    history.append(
        {'event_type': 'y', 'id': 'old'},
        scope_keys=[ScopeKey('object', 'a')],
        recorded_at=1,
    )
    history.append(
        {'event_type': 'y', 'id': 'new'},
        scope_keys=[ScopeKey('object', 'b')],
        recorded_at=2,
    )
    engine = RuleEngine(
        [MultiObjectRule()],
        counters=MemoryCounterStore(),
        history=history,
        clock=lambda: 3,
        history_extractors=[_MultiObjectExtractor()],
    )

    match = engine.evaluate({'event_type': 'x', 'changed_fields': ('a', 'b')})[0]

    assert match.metadata['ids'] == ('new', 'old')


class _MultiObjectExtractor:
    scope_names = {'object'}

    def extract(self, event_summary):
        return [
            ScopeKey('object', value)
            for value in event_summary.get('changed_fields', ())
        ]


class _ObjectExtractor:
    scope_names = {'object'}

    def extract(self, event_summary):
        if event_summary.get('model_label') and event_summary.get('object_id'):
            return [
                ScopeKey(
                    'object',
                    f'{event_summary["model_label"]}:{event_summary["object_id"]}',
                )
            ]
        return []


def test_current_event_is_not_visible_until_after_evaluation():
    seen = []

    class CountPreviousRule(Rule):
        name = 'count_previous'
        event_types = {'x'}
        context = ContextRequirements(scopes={'user'}, event_types={'x'})

        def evaluate(self, event, ctx):
            seen.append(ctx.history.count('user'))
            return None

    history = MemoryEventHistoryStore()
    engine = RuleEngine(
        [CountPreviousRule()],
        counters=MemoryCounterStore(),
        history=history,
        clock=lambda: 20.0,
    )

    engine.evaluate({'event_type': 'x', 'user_id': 'u1'})
    engine.evaluate({'event_type': 'x', 'user_id': 'u1'})

    assert seen == [0, 1]


def test_missing_current_scope_returns_empty_history():
    class MissingScopeRule(Rule):
        name = 'missing'
        event_types = {'x'}
        context = ContextRequirements(scopes={'object'}, event_types={'y'})

        def evaluate(self, event, ctx):
            return RuleMatch(
                self.name,
                1,
                ctx.now,
                'ok',
                metadata={'count': ctx.history.count('object')},
            )

    match = RuleEngine(
        [MissingScopeRule()],
        counters=MemoryCounterStore(),
        history=MemoryEventHistoryStore(),
        clock=lambda: 1.0,
    ).evaluate({'event_type': 'x', 'user_id': 'u1'})[0]

    assert match.metadata['count'] == 0


def test_internal_audit_events_are_not_stored():
    history = MemoryEventHistoryStore()
    engine = RuleEngine([], counters=MemoryCounterStore(), history=history)

    engine.evaluate({'event_type': 'audit.rule.match', 'user_id': 'u1'})
    engine.evaluate({'event_type': 'audit.enforcement.block', 'user_id': 'u1'})
    engine.evaluate({'event_type': 'audit.context.store', 'user_id': 'u1'})

    assert history.query(scope_key='user:u1', event_types=None, since=0, limit=10) == []


def test_memory_history_bounds_max_keys_and_max_events_per_key():
    history = MemoryEventHistoryStore(max_keys=2, max_events_per_key=2)
    history.append(
        {'event_type': 'x', 'id': 'a1'},
        scope_keys=[ScopeKey('user', 'a')],
        recorded_at=1,
    )
    history.append(
        {'event_type': 'x', 'id': 'a2'},
        scope_keys=[ScopeKey('user', 'a')],
        recorded_at=2,
    )
    history.append(
        {'event_type': 'x', 'id': 'a3'},
        scope_keys=[ScopeKey('user', 'a')],
        recorded_at=3,
    )
    history.append(
        {'event_type': 'x'}, scope_keys=[ScopeKey('user', 'b')], recorded_at=4
    )
    history.append(
        {'event_type': 'x'}, scope_keys=[ScopeKey('user', 'c')], recorded_at=5
    )

    assert [
        row['id']
        for row in history.query(
            scope_key='user:a', event_types=None, since=0, limit=10
        )
    ] == []
    assert history.query(scope_key='user:b', event_types=None, since=0, limit=10)
    assert history.query(scope_key='user:c', event_types=None, since=0, limit=10)


def test_runtime_summary_omits_raw_objects_bodies_and_sensitive_values():
    class RequestObject:
        pass

    summary = create_history_summary(
        RuleEvent.from_mapping(
            {
                'event_type': 'x',
                'session_id': 's1',
                'password': 'secret',
                'request': RequestObject(),
                'payload': b'raw',
                'body': {'password': 'secret'},
            }
        ),
        sensitive_keys=('password',),
    )

    assert 'password' not in summary
    assert 'request' not in summary
    assert 'payload' not in summary
    assert 'body' not in summary


def test_memory_history_concurrent_appends_are_thread_safe():
    store = MemoryEventHistoryStore(max_events_per_key=300)

    def append(index):
        store.append(
            {'event_type': 'x', 'index': index},
            scope_keys=[ScopeKey('session', 's1')],
            recorded_at=float(index),
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append, range(200)))

    assert (
        len(
            store.query(
                scope_key='session:s1',
                event_types={'x'},
                since=0,
                limit=300,
            )
        )
        == 199
    )


def test_context_requirements_sets_are_immutable():
    context = ContextRequirements(
        scopes={'user'},
        event_types={'auth.login.failed'},
    )

    assert isinstance(context.scopes, frozenset)
    assert isinstance(context.event_types, frozenset)

    with pytest.raises(AttributeError):
        context.scopes.add('evil')

    with pytest.raises(AttributeError):
        context.event_types.add('evil')
