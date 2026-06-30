"""Stage 3: schema-derived scopes (FieldScopeExtractor + scope_definitions()).

A SCOPE-role field becomes a real ``ScopeDefinition`` (detection-only) that the
existing ``ScopeRegistry`` consumes — no fork. The extractor reads the value the
Stage 2 projection placed in the summary.
"""

from sec_audit.rules.events import create_history_summary
from sec_audit.rules.history import FieldScopeExtractor, extract_scope_keys
from sec_audit.rules.schema import (
    EventSchema,
    EventSchemaRegistry,
    FieldRole,
    SchemaField,
)
from sec_audit.rules.scopes import ScopeRegistry

SCHEMA = EventSchema(
    'payment.attempted',
    (
        SchemaField('merchant_id', frozenset({FieldRole.SCOPE})),
        SchemaField('amount', frozenset({FieldRole.MODEL})),
    ),
)
SCHEMA_NAMED = EventSchema(
    'order.placed',
    (SchemaField('tenant_pk', frozenset({FieldRole.SCOPE}), scope='tenant'),),
)


# --- FieldScopeExtractor ------------------------------------------------------


def test_field_extractor_yields_scope_key():
    ex = FieldScopeExtractor('merchant_id', 'merchant')
    assert ex.scope_names == {'merchant'}
    keys = ex.extract({'merchant_id': 'm-42'})
    assert [(k.scope, k.key) for k in keys] == [('merchant', 'm-42')]


def test_field_extractor_missing_or_blank_yields_nothing():
    ex = FieldScopeExtractor('merchant_id', 'merchant')
    assert ex.extract({}) == []
    assert ex.extract({'merchant_id': '   '}) == []


# --- scope_definitions() ------------------------------------------------------


def test_schema_scope_definitions_are_detection_only():
    defs = SCHEMA.scope_definitions()
    assert [d.name for d in defs] == ['merchant_id']
    assert defs[0].block_eligible is False  # detection/correlation, not a ban dim


def test_scope_name_override_used_for_definition():
    defs = SCHEMA_NAMED.scope_definitions()
    assert [d.name for d in defs] == ['tenant']


def test_registry_aggregates_scope_definitions():
    reg = EventSchemaRegistry.from_specs((SCHEMA, SCHEMA_NAMED), include_defaults=False)
    names = sorted(d.name for d in reg.scope_definitions())
    assert names == ['merchant_id', 'tenant']


# --- ScopeRegistry integration ------------------------------------------------


def test_scope_registry_merges_schema_scope_after_builtins():
    registry = ScopeRegistry.from_specs(SCHEMA.scope_definitions())
    assert registry.names() == ('user', 'session', 'ip', 'route', 'merchant_id')


def test_custom_scope_key_extracted_from_projected_summary():
    registry = ScopeRegistry.from_specs(SCHEMA.scope_definitions())
    summary = create_history_summary(
        {
            'event_type': 'payment.attempted',
            'srcip': '203.0.113.5',
            'merchant_id': 'm-42',
        },
        schema=SCHEMA,
    )
    keys = {(k.scope, k.key) for k in extract_scope_keys(summary, registry.extractors)}
    assert ('merchant_id', 'm-42') in keys
    assert ('ip', '203.0.113.5') in keys


def test_custom_scope_absent_when_field_missing():
    registry = ScopeRegistry.from_specs(SCHEMA.scope_definitions())
    summary = create_history_summary(
        {'event_type': 'payment.attempted', 'srcip': '1.2.3.4'}, schema=SCHEMA
    )
    scopes = {k.scope for k in extract_scope_keys(summary, registry.extractors)}
    assert 'ip' in scopes and 'merchant_id' not in scopes
