"""User-registered rules via ``SEC_AUDIT_ENFORCEMENT['rules']``.

No detectors are auto-loaded: the registered set is exactly what ``rules``
declares. Covers runtime resolution (dotted path / instance / bad object / empty
name / duplicate name), the opt-in rule set (no built-ins unless registered), and
end-to-end behavior: a rule blocks only when wired to a ``rule_actions`` entry,
and observes (no block) otherwise.
"""

import pytest
from django.test import override_settings
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.django.events import build_audit_event
from sec_audit.enforcement.blocks import BlockScope
from sec_audit.rules.base import Rule, make_match

from sec_audit.django_enforcement.config import DjangoEnforcementConfig
from sec_audit.django_enforcement.runtime import (
    _all_rules,
    _build_runtime,
    _resolve_custom_rules,
    setup_enforcement,
)


class _S:
    def __init__(self, mapping):
        self.SEC_AUDIT_ENFORCEMENT = mapping


class _AlwaysMatchRule(Rule):
    """Fires on every client-error event; no history/counters needed."""

    name = 'always_match'
    severity = 5
    event_types = {'http.response.client_error'}
    safe_for_enforcement = False

    def evaluate(self, event, ctx):
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='always',
            event=event,
        )


class _NamelessRule(Rule):
    name = ''

    def evaluate(self, event, ctx):  # pragma: no cover - never evaluated
        return None


class _FormerBuiltinNameRule(Rule):
    """Reuses a former built-in name — now allowed, since none are auto-loaded."""

    name = 'brute_force_login'

    def evaluate(self, event, ctx):  # pragma: no cover - never evaluated
        return None


class _NotARule:
    pass


def _config(**cfg):
    return DjangoEnforcementConfig.from_settings(_S({'enabled': True, **cfg}))


# --- resolution ------------------------------------------------------------


def test_dotted_path_to_subclass_is_instantiated():
    rules = _resolve_custom_rules(
        _config(rules=['tests.test_custom_rules._AlwaysMatchRule'])
    )
    assert len(rules) == 1
    assert isinstance(rules[0], _AlwaysMatchRule)


def test_instance_is_used_as_is():
    instance = _AlwaysMatchRule()
    rules = _resolve_custom_rules(_config(rules=[instance]))
    assert rules[0] is instance


def test_only_registered_rules_loaded():
    rules = _all_rules(_config(rules=[_AlwaysMatchRule()]))
    names = [r.name for r in rules]
    # No detectors are auto-loaded: the set is exactly what `rules` declares.
    assert names == ['always_match']


def test_no_rules_configured_is_empty():
    # enabled but no `rules` -> empty set (enforcement inert, nothing forced).
    assert _all_rules(_config()) == []


def test_non_rule_object_raises():
    with pytest.raises(AuditConfigurationError):
        _resolve_custom_rules(_config(rules=[_NotARule()]))


def test_non_rule_class_raises():
    with pytest.raises(AuditConfigurationError):
        _resolve_custom_rules(_config(rules=[_NotARule]))


def test_empty_name_raises():
    with pytest.raises(AuditConfigurationError):
        _resolve_custom_rules(_config(rules=[_NamelessRule()]))


def test_former_builtin_name_is_allowed():
    # No built-ins are auto-loaded, so a user may now register a rule under a
    # former built-in name without colliding.
    rules = _all_rules(_config(rules=[_FormerBuiltinNameRule()]))
    assert [r.name for r in rules] == ['brute_force_login']


def test_duplicate_registered_names_raise():
    with pytest.raises(AuditConfigurationError):
        _all_rules(_config(rules=[_AlwaysMatchRule(), _AlwaysMatchRule()]))


# --- end-to-end enforcement ------------------------------------------------


def _client_error_event(srcip):
    return build_audit_event(
        'msg',
        'http.response.client_error',
        {'srcip': srcip, 'status': 404},
        schema_version='1.0',
        include_usernames=True,
    )


@pytest.mark.django_db
def test_custom_rule_blocks_when_actioned():
    rt = _build_runtime(
        _config(
            rules=[_AlwaysMatchRule()],
            rule_actions={'always_match': {'action': 'temp_block', 'scopes': ['ip']}},
        )
    )
    rt.handle_event(_client_error_event('203.0.113.55'))
    assert rt.block_store.first_active([BlockScope('ip', '203.0.113.55')]) is not None


@pytest.mark.django_db
def test_custom_rule_observes_without_action():
    # Same rule, no rule_actions entry -> Enforcer default_action='observe' -> no block.
    rt = _build_runtime(_config(rules=[_AlwaysMatchRule()]))
    rt.handle_event(_client_error_event('203.0.113.66'))
    assert rt.block_store.first_active([BlockScope('ip', '203.0.113.66')]) is None


# --- startup fail-fast (setup_enforcement at ready()) ----------------------


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True, 'rules': ['a.b.DoesNotExist']}
)
def test_setup_enforcement_fails_fast_on_bad_rule_import():
    # A well-formed but unimportable path is resolved at ready() and crashes the
    # boot, rather than being swallowed by the request-time fail-open. (AuditImport
    # Error subclasses AuditConfigurationError.)
    with pytest.raises(AuditConfigurationError):
        setup_enforcement()


@override_settings(
    SEC_AUDIT_ENFORCEMENT={
        'enabled': True,
        'rules': ['tests.test_custom_rules._AlwaysMatchRule'],
    }
)
def test_setup_enforcement_resolves_good_rules():
    setup_enforcement()  # a valid rule set resolves cleanly — no raise


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': False, 'rules': ['a.b.DoesNotExist']}
)
def test_setup_enforcement_skips_resolution_when_disabled():
    setup_enforcement()  # gated on `enabled`: a bad rule is never resolved
