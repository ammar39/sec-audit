"""Stage 4: EventSchema wiring (``schema_specs`` -> engine projection + ScopeRegistry).

End-to-end through ``fire_event``: a registered schema persists MODEL fields into
history (so a stateful rule correlates on a custom scope), redacts SENSITIVE model
fields in the store, derives a custom scope dimension, and fails fast at ready() on
a bad spec.
"""

import pytest
from django.test import override_settings
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.scrubbers import REDACTED
from sec_audit.rules import ContextRequirements
from sec_audit.rules.base import Rule, make_match
from sec_audit.rules.schema import EventSchema, FieldRole, SchemaField
from sec_audit.rules.stores import MemoryEventHistoryStore

from sec_audit.django_enforcement import fire_event
from sec_audit.django_enforcement import runtime as runtime_mod
from sec_audit.django_enforcement.config import DjangoEnforcementConfig
from sec_audit.django_enforcement.runtime import (
    _build_registry,
    _build_schema_registry,
    setup_enforcement,
)

CUSTOM_EVENT = 'myapp.payment.attempt'


def _schema() -> EventSchema:
    return EventSchema(
        CUSTOM_EVENT,
        (
            SchemaField('merchant_id', frozenset({FieldRole.SCOPE})),
            SchemaField('amount', frozenset({FieldRole.MODEL})),
            SchemaField('pan', frozenset({FieldRole.MODEL, FieldRole.SENSITIVE})),
        ),
    )


class _VelocityRule(Rule):
    """Correlates total amount per merchant over the window (reads the model)."""

    name = 'merchant_velocity'
    severity = 8
    event_types = {CUSTOM_EVENT}
    context = ContextRequirements(scopes=frozenset({'merchant_id'}), window_seconds=300)

    def evaluate(self, event, ctx):
        total = float(event.field('amount') or 0)
        for row in ctx.history.events('merchant_id', window_seconds=300):
            total += float(row.get('amount') or 0)
        if total < 1000:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='velocity',
            event=event,
        )


class _S:
    def __init__(self, mapping):
        self.SEC_AUDIT_ENFORCEMENT = mapping


def _config(**cfg):
    return DjangoEnforcementConfig.from_settings(_S({'enabled': True, **cfg}))


@pytest.fixture
def install_runtime():
    def _install(config):
        runtime = runtime_mod._build_runtime(config)
        runtime_mod._set_runtime(runtime)
        return runtime

    yield _install
    runtime_mod.reset_enforcement_runtime()


# --- config parsing -----------------------------------------------------------


def test_schema_specs_parsed_into_config():
    cfg = _config(schema_specs=[_schema()])
    assert len(cfg.schema_specs) == 1


def test_schema_specs_validate_import_path_shape_at_parse():
    # Well-formed dotted path passes parse (import deferred to ready()).
    cfg = _config(schema_specs=['myapp.events.PAYMENT_SCHEMA'])
    assert cfg.schema_specs == ('myapp.events.PAYMENT_SCHEMA',)


# --- ScopeRegistry merge ------------------------------------------------------


def test_schema_scope_merged_into_scope_registry():
    config = _config(schema_specs=[_schema()])
    registry = _build_registry(config, _build_schema_registry(config))
    assert registry.names() == ('user', 'session', 'ip', 'route', 'merchant_id')


# --- end-to-end fire_event ----------------------------------------------------


@pytest.mark.django_db
def test_model_persists_and_sensitive_redacted_and_scope_correlates(install_runtime):
    runtime = install_runtime(
        _config(
            schema_specs=[_schema()],
            rules=[_VelocityRule()],
            rule_actions={'merchant_velocity': {'action': 'alert'}},
        )
    )
    # The no-Redis runtime has no history store (correlation is a Redis feature);
    # inject an in-memory one so we exercise the real fire_event -> wired-engine
    # (schema registry + merged scopes) -> store path.
    runtime.engine.history = MemoryEventHistoryStore()
    fields = {
        'srcip': '203.0.113.5',
        'merchant_id': 'm-1',
        'amount': 600,
        'pan': '4111111111111111',
    }

    first = fire_event(CUSTOM_EVENT, fields)
    assert first == []  # 600 < 1000, no match yet

    # History persisted the MODEL field under the custom scope, redacted the PAN.
    rows = runtime.engine.history.query(
        scope_key='merchant_id:m-1', event_types=None, since=0.0, limit=10
    )
    assert rows and rows[0]['amount'] == 600
    assert rows[0]['pan'] == REDACTED
    assert '4111111111111111' not in str(rows)

    # Second event: current 600 + history 600 = 1200 -> the velocity rule fires,
    # proving the rule correlated across events via the schema-derived scope.
    second = fire_event(CUSTOM_EVENT, {**fields, 'amount': 600})
    assert [m.rule_name for m in second] == ['merchant_velocity']


# --- fail-fast ----------------------------------------------------------------


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True, 'schema_specs': ['a.b.DoesNotExist']}
)
def test_setup_enforcement_fails_fast_on_bad_schema_import():
    with pytest.raises(AuditConfigurationError):
        setup_enforcement()


def test_duplicate_schema_event_type_rejected():
    with pytest.raises(AuditConfigurationError):
        _build_schema_registry(_config(schema_specs=[_schema(), _schema()]))
