"""Built-in DEFAULT_TRIGGERS: structure + behavior-preservation vs the old
``synthesize_pre_request_event`` / egress ``from_mapping`` paths."""

from sec_audit.rules.events import RuleEvent

from sec_audit.django_enforcement.triggers import (
    DEFAULT_TRIGGERS,
    INGRESS_TRIGGER,
    PRE_REQUEST_EVENT,
)


def test_default_triggers_structure():
    names = [t.name for t in DEFAULT_TRIGGERS]
    assert names == ['http.egress', 'auth', 'model', 'http.ingress']
    assert len(set(names)) == len(names)  # unique
    by_name = {t.name: t for t in DEFAULT_TRIGGERS}
    # Only ingress is the synthetic pre-request fast-path.
    assert by_name['http.ingress'].enforcement_only is True
    assert all(
        not by_name[n].enforcement_only for n in ('http.egress', 'auth', 'model')
    )


def test_ingress_builder_matches_legacy_synthesize_behavior():
    # Replaces synthesize_pre_request_event: from_mapping({**summary, event_type=PRE}).
    summary = {'srcip': '198.51.100.7', 'path': '/api/transfer', 'method': 'POST'}
    event = INGRESS_TRIGGER.builder.build(summary)
    expected = RuleEvent.from_mapping({**summary, 'event_type': PRE_REQUEST_EVENT})
    assert event.event_type == PRE_REQUEST_EVENT
    assert event.to_dict() == expected.to_dict()


def test_ingress_override_wins_over_payload_event_type():
    event = INGRESS_TRIGGER.builder.build(
        {'event_type': 'http.response.success', 'srcip': '198.51.100.7'}
    )
    assert event.event_type == PRE_REQUEST_EVENT


def test_egress_builder_passes_emitted_event_through_unchanged():
    # Egress/auth/model: the builder equals RuleEvent.from_mapping of the emitted
    # AuditEvent attributes (the consumer's existing behavior).
    attrs = {
        'event_type': 'http.response.client_error',
        'source.address': '203.0.113.10',
        'http.response.status_code': 404,
    }
    egress = next(t for t in DEFAULT_TRIGGERS if t.name == 'http.egress')
    assert (
        egress.builder.build(attrs).to_dict() == RuleEvent.from_mapping(attrs).to_dict()
    )
