"""ScopeRegistry parity with the existing extractors + block-scope derivation."""

from sec_audit.rules.events import RuleEvent, create_history_summary
from sec_audit.rules.history import (
    DEFAULT_HISTORY_SCOPE_EXTRACTORS,
    build_history_scope_extractors,
    extract_scope_keys,
)
from sec_audit.rules.scopes import ScopeRegistry


def test_registry_extractors_match_legacy_defaults():
    registry = ScopeRegistry.from_specs()
    legacy = build_history_scope_extractors()
    assert [type(e).__name__ for e in registry.extractors] == [
        type(e).__name__ for e in legacy
    ]
    assert [cls.__name__ for cls in DEFAULT_HISTORY_SCOPE_EXTRACTORS] == [
        type(e).__name__ for e in registry.extractors
    ]


def test_block_scopes_ip_only_and_route_excluded():
    registry = ScopeRegistry.from_specs()
    summary = {
        'srcip': '203.0.113.10',
        'user_id': '42',
        'session_id': 's1',
        'route': '/api/transfer',
    }
    ip_only = registry.block_scopes(summary, only=('ip',))
    assert [(s.scope_type, s.scope_value) for s in ip_only] == [('ip', '203.0.113.10')]
    # route is block_eligible=False by default -> excluded from all block scopes
    all_types = {s.scope_type for s in registry.block_scopes(summary)}
    assert all_types == {'ip', 'user', 'session'}


def test_block_scopes_resolve_ip_from_otel_source_address():
    # A real emitted event carries source.address; from_mapping normalizes it to
    # srcip so the ip ban dimension resolves through the summary path.
    event = RuleEvent.from_mapping(
        {'event_type': 'http.response.client_error', 'source.address': '198.51.100.7'}
    )
    summary = dict(event.to_dict())
    scopes = ScopeRegistry.from_specs().block_scopes(summary, only=('ip',))
    assert [s.scope_value for s in scopes] == ['198.51.100.7']


def test_history_summary_keeps_ip_for_scoping():
    # The non-sensitive scope keys (srcip) survive create_history_summary so the
    # engine's own ip-scoped history works.
    event = RuleEvent.from_mapping(
        {'event_type': 'auth.login.failed', 'source.address': '198.51.100.7'}
    )
    summary = create_history_summary(event)
    assert summary.get('srcip') == '198.51.100.7'


def test_history_summary_keeps_session_id_for_scoping():
    # session_id normalizes to 'sessionid', a DEFAULT_SENSITIVE_KEYS denylist entry.
    # The history summary used to scrub it to '[REDACTED]' (collapsing every session
    # into one 'session:[REDACTED]' bucket); the scrub is now removed, so the
    # whitelist alone preserves it as the real scope key.
    event = RuleEvent.from_mapping(
        {'event_type': 'auth.login.failed', 'session.id': 'sess-abc123'}
    )
    summary = create_history_summary(event)
    assert summary.get('session_id') == 'sess-abc123'

    keys = {
        k.as_string()
        for k in extract_scope_keys(summary, build_history_scope_extractors())
    }
    assert 'session:sess-abc123' in keys
    assert 'session:[REDACTED]' not in keys
