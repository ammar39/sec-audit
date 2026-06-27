"""EventSchema / SchemaField / EventSchemaRegistry (the framework-free declarative
event-schema primitive). Inert at this stage: no engine/scope wiring yet."""

import pytest

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.rules.schema import (
    EventSchema,
    EventSchemaRegistry,
    FieldRole,
    SchemaField,
)


def _schema():
    return EventSchema(
        'payment.attempted',
        (
            SchemaField('merchant_id', frozenset({FieldRole.SCOPE})),
            SchemaField('amount', frozenset({FieldRole.MODEL})),
            SchemaField('pan', frozenset({FieldRole.MODEL, FieldRole.SENSITIVE})),
        ),
    )


# --- SchemaField --------------------------------------------------------------


def test_field_role_predicates_and_scope_name_default():
    f = SchemaField('merchant_id', frozenset({FieldRole.SCOPE}))
    assert f.is_scope and not f.is_model and not f.is_sensitive
    assert f.scope_name == 'merchant_id'  # defaults to field name


def test_field_scope_override_name():
    f = SchemaField('merchant_id', frozenset({FieldRole.SCOPE}), scope='merchant')
    assert f.scope_name == 'merchant'


def test_field_rejects_empty_name():
    with pytest.raises(AuditConfigurationError):
        SchemaField('  ', frozenset({FieldRole.MODEL}))


def test_field_rejects_empty_roles():
    with pytest.raises(AuditConfigurationError):
        SchemaField('x', frozenset())


def test_field_rejects_scope_and_sensitive_together():
    with pytest.raises(AuditConfigurationError):
        SchemaField('x', frozenset({FieldRole.SCOPE, FieldRole.SENSITIVE}))


def test_field_rejects_non_role_member():
    with pytest.raises(AuditConfigurationError):
        SchemaField('x', frozenset({'model'}))  # str, not FieldRole


# --- EventSchema --------------------------------------------------------------


def test_schema_role_name_helpers():
    s = _schema()
    assert s.model_field_names == frozenset({'amount', 'pan'})
    assert s.scope_field_names == frozenset({'merchant_id'})
    assert s.sensitive_field_names == frozenset({'pan'})
    assert s.projected_field_names == frozenset({'amount', 'pan', 'merchant_id'})
    assert s.scope_bindings() == (('merchant_id', 'merchant_id'),)


def test_schema_rejects_empty_event_type():
    with pytest.raises(AuditConfigurationError):
        EventSchema('  ', ())


def test_schema_rejects_internal_event_type():
    with pytest.raises(AuditConfigurationError):
        EventSchema('audit.enforcement.blocked', ())


def test_schema_rejects_duplicate_field_name():
    with pytest.raises(AuditConfigurationError):
        EventSchema(
            'e',
            (
                SchemaField('a', frozenset({FieldRole.MODEL})),
                SchemaField('a', frozenset({FieldRole.SCOPE})),
            ),
        )


@pytest.mark.parametrize('reserved', ['srcip', 'event_type', 'session_id', 'route'])
def test_schema_rejects_field_colliding_with_reserved_summary_key(reserved):
    with pytest.raises(AuditConfigurationError):
        EventSchema('e', (SchemaField(reserved, frozenset({FieldRole.MODEL})),))


@pytest.mark.parametrize('builtin', ['ip', 'user', 'session', 'route'])
def test_schema_rejects_scope_shadowing_builtin(builtin):
    with pytest.raises(AuditConfigurationError):
        EventSchema(
            'e', (SchemaField('x', frozenset({FieldRole.SCOPE}), scope=builtin),)
        )


def test_schema_rejects_duplicate_derived_scope_within_schema():
    with pytest.raises(AuditConfigurationError):
        EventSchema(
            'e',
            (
                SchemaField('a', frozenset({FieldRole.SCOPE}), scope='tenant'),
                SchemaField('b', frozenset({FieldRole.SCOPE}), scope='tenant'),
            ),
        )


# --- EventSchemaRegistry ------------------------------------------------------


def test_registry_from_specs_with_injected_defaults_and_get():
    default = EventSchema('order.placed', ())
    reg = EventSchemaRegistry.from_specs((_schema(),), defaults=(default,))
    assert reg.get('payment.attempted').event_type == 'payment.attempted'
    assert reg.get('order.placed') is default
    assert reg.get('missing') is None
    assert {s.event_type for s in reg.schemas} == {'payment.attempted', 'order.placed'}


def test_registry_excludes_defaults_when_disabled():
    default = EventSchema('order.placed', ())
    reg = EventSchemaRegistry.from_specs(
        (_schema(),), include_defaults=False, defaults=(default,)
    )
    assert reg.get('order.placed') is None
    assert reg.get('payment.attempted') is not None


def test_registry_resolves_factory_callable():
    def make_schema():
        return EventSchema('sample.event', ())

    reg = EventSchemaRegistry.from_specs((make_schema,), include_defaults=False)
    assert reg.get('sample.event') is not None


def test_registry_rejects_unresolvable_string_spec():
    with pytest.raises(AuditConfigurationError):
        EventSchemaRegistry.from_specs(('no.such.module.SCHEMA',))


def test_registry_rejects_duplicate_event_type():
    with pytest.raises(AuditConfigurationError):
        EventSchemaRegistry.from_specs((_schema(), _schema()))


def test_registry_rejects_duplicate_scope_across_schemas():
    a = EventSchema(
        'a.event', (SchemaField('x', frozenset({FieldRole.SCOPE}), scope='tenant'),)
    )
    b = EventSchema(
        'b.event', (SchemaField('y', frozenset({FieldRole.SCOPE}), scope='tenant'),)
    )
    with pytest.raises(AuditConfigurationError):
        EventSchemaRegistry.from_specs((a, b))


def test_registry_rejects_non_schema_spec():
    with pytest.raises(AuditConfigurationError):
        EventSchemaRegistry.from_specs((object(),))
