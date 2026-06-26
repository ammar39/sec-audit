import importlib
import sys

import pytest

from sec_audit.enforcement import BlockEntry, BlockScope, SeverityEnforcementPolicy
from sec_audit.enforcement.actions import resolve_rule_action
from sec_audit.rules.base import RuleMatch


def test_block_scope_normalizes_values():
    scope = BlockScope(' ip ', ' 10.0.0.1 ')

    assert scope.scope_type == 'ip'
    assert scope.scope_value == '10.0.0.1'


@pytest.mark.parametrize(
    ('scope_type', 'scope_value'),
    [
        ('', '10.0.0.1'),
        ('   ', '10.0.0.1'),
        ('ip', ''),
        ('ip', '   '),
    ],
)
def test_block_scope_rejects_empty_values(scope_type, scope_value):
    with pytest.raises(ValueError):
        BlockScope(scope_type, scope_value)


def test_block_entry_metadata_is_immutable_and_copied():
    original = {'count': 1}
    entry = BlockEntry(BlockScope('ip', '10.0.0.1'), metadata=original)
    original['count'] = 2

    assert entry.metadata['count'] == 1
    with pytest.raises(TypeError):
        entry.metadata['count'] = 3


def test_enforcement_package_import_does_not_import_django():
    modules = {
        name: module
        for name, module in sys.modules.items()
        if name == 'sec_audit' or name.startswith(('sec_audit.enforcement', 'django'))
    }
    for name in modules:
        sys.modules.pop(name, None)

    try:
        importlib.import_module('sec_audit.enforcement')

        assert 'django' not in sys.modules
    finally:
        for name in list(sys.modules):
            if name == 'sec_audit' or name.startswith('sec_audit.enforcement'):
                sys.modules.pop(name, None)
        sys.modules.update(modules)


def test_resolve_rule_action_uses_default_action():
    action = resolve_rule_action(
        RuleMatch('rule-b', severity=8, matched_at=2.0, message='b'),
        configured_actions={},
        block_rules={},
        default_ttl=None,
        default_action='alert',
    )

    assert action.action == 'alert'


def test_bare_persist_block_defaults_to_user_session_scopes(caplog):
    """A custom rule emitting persist_block with no configured rule_actions entry
    must NOT produce a permanent IP ban (dangerous behind shared NAT)."""
    with caplog.at_level('WARNING', logger='sec_audit.rules'):
        action = resolve_rule_action(
            RuleMatch(
                'custom_perma',
                severity=9,
                matched_at=1.0,
                message='m',
                decision='persist_block',
            ),
            configured_actions={},
            block_rules={},
            default_ttl=None,
        )

    assert action.action == 'persist_block'
    assert action.scopes == ('user', 'session')
    assert 'ip' not in action.scopes
    assert any('persist_block' in r.getMessage() for r in caplog.records)


def test_configured_ip_scope_for_persist_block_is_honored():
    """An explicit rule_actions scopes entry still wins — operator opt-in."""
    action = resolve_rule_action(
        RuleMatch(
            'custom_perma',
            severity=9,
            matched_at=1.0,
            message='m',
            decision='persist_block',
        ),
        configured_actions={
            'custom_perma': {'action': 'persist_block', 'scopes': ['ip']}
        },
        block_rules={},
        default_ttl=None,
    )

    assert action.action == 'persist_block'
    assert action.scopes == ('ip',)


def test_severity_policy_decide_blocks_at_or_above_threshold():
    policy = SeverityEnforcementPolicy(block_severity=8, status_code=418, message='no')
    decision = policy.decide(
        {}, [RuleMatch('r', severity=9, matched_at=1.0, message='m')]
    )

    assert decision.allowed is False
    assert decision.status_code == 418
    assert decision.reason == 'r'


def test_severity_policy_decide_allows_below_threshold():
    policy = SeverityEnforcementPolicy(block_severity=8)
    decision = policy.decide(
        {}, [RuleMatch('r', severity=2, matched_at=1.0, message='m')]
    )

    assert decision.allowed is True
