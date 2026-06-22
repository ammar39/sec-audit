import importlib
import sys

import pytest

from sec_audit.enforcement import BlockEntry, BlockScope
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


def test_resolve_rule_action_uses_policy_decision_without_policy_object():
    decision = type(
        'Decision',
        (),
        {'allowed': False, 'status_code': 418, 'message': 'policy block'},
    )()

    action = resolve_rule_action(
        RuleMatch('rule-a', severity=1, matched_at=1.0, message='a'),
        configured_actions={},
        block_rules={},
        default_ttl=None,
        policy_decision=decision,
        default_action='observe',
    )

    assert action.action == 'block'
    assert action.status_code == 418
    assert action.message == 'policy block'


def test_resolve_rule_action_uses_default_action_when_policy_allows():
    action = resolve_rule_action(
        RuleMatch('rule-b', severity=8, matched_at=2.0, message='b'),
        configured_actions={},
        block_rules={},
        default_ttl=None,
        policy_decision=type('Decision', (), {'allowed': True})(),
        default_action='alert',
    )

    assert action.action == 'alert'
