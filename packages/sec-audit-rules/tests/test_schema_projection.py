"""Stage 2: schema-aware history projection.

``create_history_summary(event, schema=...)`` EXTENDS the fixed whitelist with a
schema's MODEL/SCOPE fields and redacts SENSITIVE fields by EXACT name. The
RuleEngine resolves the per-event-type schema and persists the projected summary.
"""

from sec_audit.core.scrubbers import REDACTED
from sec_audit.rules.engine import RuleEngine
from sec_audit.rules.events import create_history_summary
from sec_audit.rules.schema import (
    EventSchema,
    EventSchemaRegistry,
    FieldRole,
    SchemaField,
)
from sec_audit.rules.stores import MemoryCounterStore, MemoryEventHistoryStore

SCHEMA = EventSchema(
    'payment.attempted',
    (
        SchemaField('merchant_id', frozenset({FieldRole.SCOPE})),
        SchemaField('amount', frozenset({FieldRole.MODEL})),
        SchemaField('token_count', frozenset({FieldRole.MODEL})),  # denylist substring
        SchemaField('pan', frozenset({FieldRole.MODEL, FieldRole.SENSITIVE})),
        SchemaField('cvv', frozenset({FieldRole.SENSITIVE})),  # sensitive-only
    ),
)

EVENT = {
    'event_type': 'payment.attempted',
    'srcip': '203.0.113.5',
    'merchant_id': 'm-42',
    'amount': 250.0,
    'token_count': 7,
    'pan': '4111111111111111',
    'cvv': '123',
}


# --- create_history_summary projection ---------------------------------------


def test_model_and_scope_fields_extend_whitelist():
    s = create_history_summary(EVENT, schema=SCHEMA)
    assert s['amount'] == 250.0
    assert s['merchant_id'] == 'm-42'
    assert s['srcip'] == '203.0.113.5'  # system whitelist field still present


def test_sensitive_model_field_is_redacted_by_exact_name():
    s = create_history_summary(EVENT, schema=SCHEMA)
    assert s['pan'] == REDACTED
    assert '4111111111111111' not in str(s)


def test_model_field_with_denylist_substring_name_is_persisted_raw():
    # Regression: must NOT route through scrub's substring denylist, which would
    # redact 'token_count' (contains 'token') and corrupt the model.
    s = create_history_summary(EVENT, schema=SCHEMA)
    assert s['token_count'] == 7


def test_sensitive_only_field_is_never_projected():
    s = create_history_summary(EVENT, schema=SCHEMA)
    assert 'cvv' not in s


def test_no_schema_is_byte_identical():
    assert create_history_summary(EVENT) == create_history_summary(EVENT, schema=None)


def test_no_schema_drops_custom_fields():
    base = create_history_summary(EVENT)
    assert 'amount' not in base and 'merchant_id' not in base and 'pan' not in base


def test_missing_declared_field_is_simply_absent():
    s = create_history_summary(
        {'event_type': 'payment.attempted', 'merchant_id': 'm-9'}, schema=SCHEMA
    )
    assert s['merchant_id'] == 'm-9'
    assert 'amount' not in s and 'pan' not in s


# --- RuleEngine integration ---------------------------------------------------


def _engine(history, **kw):
    return RuleEngine(
        [], counters=MemoryCounterStore(), history=history, clock=lambda: 1000.0, **kw
    )


def test_engine_persists_projected_summary_with_redaction():
    history = MemoryEventHistoryStore()
    registry = EventSchemaRegistry.from_specs((SCHEMA,), include_defaults=False)
    _engine(history, schemas=registry).evaluate(EVENT)
    rows = history.query(
        scope_key='ip:203.0.113.5', event_types=None, since=0.0, limit=10
    )
    assert len(rows) == 1
    row = rows[0]
    assert row['amount'] == 250.0
    assert row['token_count'] == 7
    assert row['pan'] == REDACTED
    assert '4111111111111111' not in str(row)
    assert 'cvv' not in row


def test_engine_without_schemas_keeps_whitelist_only():
    history = MemoryEventHistoryStore()
    _engine(history).evaluate(EVENT)
    row = history.query(
        scope_key='ip:203.0.113.5', event_types=None, since=0.0, limit=10
    )[0]
    # No registry → custom fields dropped, exactly as before this feature.
    assert 'amount' not in row and 'merchant_id' not in row and 'pan' not in row
    assert row['srcip'] == '203.0.113.5'


def test_engine_unregistered_event_type_is_unaffected():
    history = MemoryEventHistoryStore()
    registry = EventSchemaRegistry.from_specs((SCHEMA,), include_defaults=False)
    other = {'event_type': 'other.event', 'srcip': '198.51.100.9', 'amount': 5}
    _engine(history, schemas=registry).evaluate(other)
    row = history.query(
        scope_key='ip:198.51.100.9', event_types=None, since=0.0, limit=10
    )[0]
    assert 'amount' not in row  # no schema for this event_type → whitelist-only
