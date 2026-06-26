"""Custom events via ``fire_event()`` + ``trigger_specs`` registration.

Covers trigger_specs resolution/fail-fast (mirrors custom rules), fire_event
end-to-end (match -> audit.enforcement.* -> block), the reserved-namespace guard,
the unknown-trigger error, and re-entrancy (the engine skip-list breaks any loop).
"""

import pytest
from django.test import override_settings
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.enforcement.blocks import BlockScope
from sec_audit.rules.base import Rule, make_match
from sec_audit.rules.triggers import MappingEventBuilder, Trigger

from sec_audit.django_enforcement import fire_event
from sec_audit.django_enforcement import runtime as runtime_mod
from sec_audit.django_enforcement.config import DjangoEnforcementConfig
from sec_audit.django_enforcement.runtime import (
    _build_runtime,
    _build_trigger_registry,
    setup_enforcement,
)
from sec_audit.django_enforcement.signals import enforcement_event

CUSTOM_EVENT = 'myapp.payment.attempt'


class _PaymentRule(Rule):
    """Fires on every custom payment event; no history/counters needed."""

    name = 'payment_velocity'
    severity = 7
    event_types = {CUSTOM_EVENT}
    safe_for_enforcement = False

    def evaluate(self, event, ctx):
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='payment',
            event=event,
        )


def _payment_trigger() -> Trigger:
    return Trigger(
        name='payment',
        event_types=frozenset({CUSTOM_EVENT}),
        builder=MappingEventBuilder(),
    )


class _S:
    def __init__(self, mapping):
        self.SEC_AUDIT_ENFORCEMENT = mapping


def _config(**cfg):
    return DjangoEnforcementConfig.from_settings(_S({'enabled': True, **cfg}))


@pytest.fixture
def install_runtime():
    """Install a test-built runtime as the global one so ``fire_event`` (which uses
    ``get_enforcement_runtime``) routes through it; tear it down afterwards."""

    def _install(config):
        runtime = _build_runtime(config)
        runtime_mod._set_runtime(runtime)
        return runtime

    yield _install
    runtime_mod.reset_enforcement_runtime()


@pytest.fixture
def captured_events():
    """Capture emitted enforcement event_types via the public signal."""
    seen: list[str] = []

    def _receiver(sender, event_type, **kwargs):
        seen.append(event_type)

    enforcement_event.connect(_receiver)
    try:
        yield seen
    finally:
        enforcement_event.disconnect(_receiver)


# --- trigger_specs resolution / fail-fast ----------------------------------


def test_trigger_specs_resolve_and_append_to_defaults():
    registry = _build_trigger_registry(
        _config(trigger_specs=['tests.test_fire_event._payment_trigger'])
    )
    names = [t.name for t in registry.triggers]
    assert 'http.egress' in names and 'http.ingress' in names  # defaults stay
    assert names[-1] == 'payment'


def test_trigger_specs_instance_used_as_is():
    trigger = _payment_trigger()
    registry = _build_trigger_registry(_config(trigger_specs=[trigger]))
    assert registry.by_name('payment') is trigger


def test_trigger_specs_duplicate_name_raises():
    with pytest.raises(AuditConfigurationError):
        _build_trigger_registry(
            _config(trigger_specs=[_payment_trigger(), _payment_trigger()])
        )


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True, 'trigger_specs': ['a.b.DoesNotExist']}
)
def test_setup_enforcement_fails_fast_on_bad_trigger_import():
    with pytest.raises(AuditConfigurationError):
        setup_enforcement()


# --- fire_event end-to-end -------------------------------------------------


@pytest.mark.django_db
def test_fire_event_matches_and_blocks_when_actioned(install_runtime, captured_events):
    runtime = install_runtime(
        _config(
            rules=[_PaymentRule()],
            trigger_specs=[_payment_trigger()],
            rule_actions={
                'payment_velocity': {'action': 'temp_block', 'scopes': ['ip']}
            },
        )
    )
    matches = fire_event(CUSTOM_EVENT, {'srcip': '203.0.113.77'}, trigger='payment')
    assert [m.rule_name for m in matches] == ['payment_velocity']
    assert (
        runtime.block_store.first_active([BlockScope('ip', '203.0.113.77')]) is not None
    )
    # A real emitted enforcement event — not the non-existent 'audit.rule.match'.
    assert 'audit.enforcement.block_applied' in captured_events


@pytest.mark.django_db
def test_fire_event_alerts_without_blocking(install_runtime, captured_events):
    # An 'alert' action emits audit.enforcement.alert but applies no block (alert is
    # not a BLOCKING_ACTION).
    runtime = install_runtime(
        _config(
            rules=[_PaymentRule()],
            rule_actions={'payment_velocity': {'action': 'alert'}},
        )
    )
    matches = fire_event(CUSTOM_EVENT, {'srcip': '203.0.113.88'})
    assert matches and matches[0].rule_name == 'payment_velocity'
    assert runtime.block_store.first_active([BlockScope('ip', '203.0.113.88')]) is None
    assert 'audit.enforcement.alert' in captured_events


# --- guard rail + errors + re-entrancy -------------------------------------


def test_fire_event_rejects_reserved_namespace():
    # The guard fires before any runtime is touched.
    for reserved in ('audit.rule.match', 'audit.enforcement.alert', 'audit.context.x'):
        with pytest.raises(AuditConfigurationError):
            fire_event(reserved, {'srcip': '203.0.113.99'})


@pytest.mark.django_db
def test_fire_event_unknown_trigger_raises(install_runtime):
    install_runtime(_config(rules=[_PaymentRule()]))
    with pytest.raises(AuditConfigurationError):
        fire_event(CUSTOM_EVENT, {'srcip': '203.0.113.10'}, trigger='nope')


@pytest.mark.django_db
def test_emitted_enforcement_event_is_skip_listed(install_runtime):
    # Re-entrancy guard: an emitted audit.enforcement.* event fed back through the
    # engine produces no matches (skip-listed), so there is no producer loop.
    runtime = install_runtime(_config(rules=[_PaymentRule()]))
    assert (
        runtime.handle_event(
            {'event_type': 'audit.enforcement.alert', 'srcip': '203.0.113.11'}
        )
        == []
    )
