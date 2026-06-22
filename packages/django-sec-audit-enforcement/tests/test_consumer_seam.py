import logging

import pytest
from sec_audit.django.events import build_audit_event
from sec_audit.django.runtime import (
    get_runtime,
    register_rule_event_consumer,
    unregister_rule_event_consumer,
)
from sec_audit.enforcement.blocks import BlockScope
from sec_audit.rules.events import RuleEvent
from sec_audit.rules.scopes import ScopeRegistry

from sec_audit.django_enforcement import emit as emit_mod
from sec_audit.django_enforcement.consumer import consume
from sec_audit.django_enforcement.runtime import _set_runtime


def _real_event(event_type, data):
    return build_audit_event(
        'msg', event_type, data, schema_version='1.0', include_usernames=True
    )


def test_otel_scopes_resolve_from_real_audit_event():
    # A real emitted AuditEvent carries OTel-named keys (source.address/session.id/
    # user.id/http.route). Through from_mapping -> summary they must resolve to
    # ip/user/session BlockScopes — the load-bearing srcip normalization.
    event = _real_event(
        'http.response.client_error',
        {
            'srcip': '203.0.113.10',
            'session_id': 'sess_xyz',
            'user_id': '42',
            'username': 'maya',
            'route': '/api/transfer',
            'status': 404,
        },
    )
    # confirm the event really uses OTel keys (not raw)
    assert 'source.address' in event.attributes and 'srcip' not in event.attributes
    # production path: scopes derive from the unscrubbed event fields, so the
    # real ip/user/session values resolve (not the redacted log summary).
    summary = RuleEvent.from_mapping(event).to_dict()
    scopes = {
        s.scope_type: s.scope_value
        for s in ScopeRegistry.from_specs().block_scopes(summary)
    }
    assert scopes == {'ip': '203.0.113.10', 'user': '42', 'session': 'sess_xyz'}


def test_record_dispatch_reaches_consumer():
    seen = []

    def spy(event):
        seen.append(event.event_type)

    register_rule_event_consumer(spy)
    try:
        # auth + model + http events all funnel through record()
        get_runtime().record(
            _real_event('auth.login.failed', {'srcip': '1.1.1.1'}), logging.WARNING
        )
        get_runtime().record(
            _real_event('model.update', {'model': 'transfer'}), logging.INFO
        )
    finally:
        unregister_rule_event_consumer(spy)
    assert 'auth.login.failed' in seen and 'model.update' in seen


def test_no_feedback_loop(make_runtime):
    rt = make_runtime()
    # an emitted audit.enforcement.* event must evaluate to [] (engine skip-list)
    enf_event, _level = emit_mod.build_blocked_event(_entry(), schema_version='1.0')
    assert rt.engine.evaluate(enf_event) == []


def test_reentrant_emit_does_not_loop(make_runtime):
    # Runtime whose emitter routes through the REAL record() (which re-enters the
    # consumer). The skip-list keeps the nested evaluate a no-op; the dispatch is
    # lock-free so this must not recurse/deadlock.
    rt = make_runtime(real_emit=True)
    _set_runtime(rt)
    register_rule_event_consumer(consume)
    try:
        for _ in range(5):
            get_runtime().record(
                _real_event('auth.login.failed', {'source.address': '9.9.9.9'}),
                logging.WARNING,
            )
    finally:
        unregister_rule_event_consumer(consume)
    # a single ip block was applied (the 5th failure), no runaway recursion
    assert rt.block_store.first_active([BlockScope('ip', '9.9.9.9')]) is not None


def _entry():
    from sec_audit.enforcement.blocks import BlockEntry

    return BlockEntry(scope=BlockScope('ip', '1.2.3.4'), rule_name='r')


# DB needed only for the reentrancy test (Tiered/Postgres block store).
test_reentrant_emit_does_not_loop = pytest.mark.django_db(
    test_reentrant_emit_does_not_loop
)
