"""EventContextBuilder / MappingEventBuilder / Trigger (the framework-free
trigger primitives the engine and enforcement build on)."""

import pytest

from sec_audit.rules.events import RuleEvent
from sec_audit.rules.triggers import (
    EventContextBuilder,
    MappingEventBuilder,
    Trigger,
)


def test_mapping_builder_passes_payload_through_without_override():
    # No override: the payload's own event_type wins and no key is injected.
    event = MappingEventBuilder().build(
        {'event_type': 'http.response.client_error', 'srcip': '198.51.100.7'}
    )
    assert isinstance(event, RuleEvent)
    assert event.event_type == 'http.response.client_error'
    assert event.fields.get('srcip') == '198.51.100.7'


def test_mapping_builder_without_override_does_not_invent_event_type():
    # A payload lacking event_type stays empty — the builder never injects one.
    event = MappingEventBuilder().build({'srcip': '198.51.100.7'})
    assert event.event_type == ''


def test_mapping_builder_override_applied_last_and_wins():
    # The override must beat any event_type already in the payload (this is the
    # behavior the ingress synthetic pre-request event relies on).
    event = MappingEventBuilder('audit.http.request.pre').build(
        {'event_type': 'should.be.replaced', 'path': '/api/transfer'}
    )
    assert event.event_type == 'audit.http.request.pre'
    assert event.fields.get('path') == '/api/transfer'


def test_mapping_builder_duck_types_audit_event():
    # from_mapping reads .attributes, so an AuditEvent-shaped object also works.
    class FakeAuditEvent:
        event_type = 'auth.login.failed'
        attributes = {'event_type': 'auth.login.failed', 'session_id': 's1'}

    event = MappingEventBuilder().build(FakeAuditEvent().attributes)
    assert event.event_type == 'auth.login.failed'
    assert event.fields.get('session_id') == 's1'


def test_mapping_builder_satisfies_protocol():
    assert isinstance(MappingEventBuilder(), EventContextBuilder)


def test_trigger_validates_and_coerces():
    trigger = Trigger(
        name='http.egress',
        event_types={'http.response.client_error', 'http.response.server_error'},
        builder=MappingEventBuilder(),
    )
    assert trigger.name == 'http.egress'
    assert isinstance(trigger.event_types, frozenset)
    assert trigger.enforcement_only is False
    assert isinstance(trigger.builder, EventContextBuilder)


def test_trigger_rejects_empty_name():
    with pytest.raises(ValueError):
        Trigger(name='  ', event_types=frozenset(), builder=MappingEventBuilder())
