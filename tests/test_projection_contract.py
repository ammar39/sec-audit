"""ordinary keys survive projection; sets are rejected."""

import pytest

from sec_audit.core.events import AuditEvent
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.projection import ProjectionError, project_attributes


def test_ordinary_event_key_survives_top_level():
    out = project_attributes({'event': 'purchase', 'amount': 5})
    assert out == {'event': 'purchase', 'amount': 5}


def test_ordinary_event_key_survives_nested():
    out = project_attributes({'event': 'purchase', 'details': {'event': 'approved'}})
    assert out['event'] == 'purchase'
    assert out['details']['event'] == 'approved'


def test_legacy_envelope_keys_are_ordinary_data():
    # No special-casing of raw_event / event_fields / rule_event.
    out = project_attributes({'raw_event': 1, 'event_fields': 2, 'rule_event': 3})
    assert out == {'raw_event': 1, 'event_fields': 2, 'rule_event': 3}


def test_project_attributes_rejects_set_value():
    with pytest.raises(ProjectionError):
        project_attributes({'s': {1, 2, 3}})


def test_project_attributes_strict_rejects_set():
    with pytest.raises(ProjectionError):
        project_attributes({'s': {1, 2}}, strict=True)


def test_audit_event_rejects_set_attribute():
    with pytest.raises(AuditConfigurationError):
        AuditEvent(
            event_type='x',
            schema_version='1.0',
            body='x',
            attributes={'s': {1, 2}},
        )
