"""public config/event dataclasses validate their own invariants.

These dataclasses are exposed as public APIs of the core and logging packages,
so they must reject invalid values themselves rather than relying on Django
settings conversion. The most dangerous case is ``NaN``: ``random.random() < nan``
is always False, so a ``sample_rate`` of NaN would silently stop emitting
successful records.
"""

import pytest

from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.events import AuditEvent
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.projection import ProjectionLimits
from sec_audit.logging.config import LoggingAuditConfig


# --- ProjectionLimits -------------------------------------------------------


@pytest.mark.parametrize(
    'kwargs',
    [
        {'max_depth': 0},
        {'max_depth': -1},
        {'max_mapping_entries': 0},
        {'max_sequence_length': -5},
        {'max_string_length': 0},
        {'max_attributes': -1},
        {'max_bytes': 0},
        {'max_record_bytes': 0},
    ],
)
def test_projection_limits_reject_non_positive_ints(kwargs):
    with pytest.raises(AuditConfigurationError, match='must be greater than 0'):
        ProjectionLimits(**kwargs)


@pytest.mark.parametrize(
    'kwargs',
    [
        {'max_depth': '8'},
        {'max_attributes': 3.0},
        {'max_bytes': True},
    ],
)
def test_projection_limits_reject_non_int_types(kwargs):
    with pytest.raises(AuditConfigurationError, match='must be an int'):
        ProjectionLimits(**kwargs)


def test_projection_limits_defaults_are_valid():
    # The shipped defaults must pass their own validation.
    limits = ProjectionLimits()
    assert limits.max_depth == 8
    assert limits.max_record_bytes == 256 * 1024


# --- CoreAuditConfig.sample_rate -------------------------------------------


def test_sample_rate_nan_is_rejected():
    with pytest.raises(AuditConfigurationError, match='finite'):
        CoreAuditConfig(sample_rate=float('nan'))


def test_sample_rate_infinity_is_rejected():
    with pytest.raises(AuditConfigurationError, match='finite'):
        CoreAuditConfig(sample_rate=float('inf'))


def test_sample_rate_boundary_values_are_accepted():
    assert CoreAuditConfig(sample_rate=0.0).sample_rate == 0.0
    assert CoreAuditConfig(sample_rate=1.0).sample_rate == 1.0


def test_core_config_rejects_non_bool_body_logging():
    with pytest.raises(AuditConfigurationError, match='log_request_bodies'):
        CoreAuditConfig(log_request_bodies='false')


def test_core_config_rejects_non_bool_ok_logging():
    with pytest.raises(AuditConfigurationError, match='log_ok_responses'):
        CoreAuditConfig(log_ok_responses='false')


def test_core_config_rejects_empty_source():
    with pytest.raises(AuditConfigurationError, match='source'):
        CoreAuditConfig(source='')


def test_core_config_rejects_invalid_status_codes():
    with pytest.raises(AuditConfigurationError, match='HTTP status'):
        CoreAuditConfig(ignore_status_codes=frozenset({99}))


def test_core_config_rejects_non_int_status_codes():
    with pytest.raises(AuditConfigurationError, match='ignore_status_codes'):
        CoreAuditConfig(ignore_status_codes=frozenset({'404'}))


def test_core_config_rejects_non_string_sensitive_keys():
    with pytest.raises(AuditConfigurationError, match='sensitive_keys'):
        CoreAuditConfig(sensitive_keys=('password', 1))


def test_core_config_lowercases_sensitive_key_allowlist():
    cfg = CoreAuditConfig(sensitive_key_allowlist=('Credit_Card_Last4', 'Token_Expiry'))
    assert cfg.sensitive_key_allowlist == ('credit_card_last4', 'token_expiry')


def test_core_config_rejects_non_string_sensitive_key_allowlist():
    with pytest.raises(AuditConfigurationError, match='sensitive_key_allowlist'):
        CoreAuditConfig(sensitive_key_allowlist=('token_expiry', 1))


def test_core_config_rejects_non_positive_body_limit():
    with pytest.raises(AuditConfigurationError, match='max_body_bytes'):
        CoreAuditConfig(max_body_bytes=0)


def test_core_config_rejects_non_tuple_body_allowlist():
    with pytest.raises(AuditConfigurationError, match='body_field_allowlist'):
        CoreAuditConfig(body_field_allowlist=['amount'])  # type: ignore[arg-type]


def test_core_config_rejects_non_string_body_allowlist_item():
    with pytest.raises(AuditConfigurationError, match='body_field_allowlist'):
        CoreAuditConfig(body_field_allowlist=('amount', 1))  # type: ignore[arg-type]


# --- LoggingAuditConfig.schema_version -------------------------------------


def test_logging_schema_version_must_be_non_empty_str():
    with pytest.raises(AuditConfigurationError, match='non-empty'):
        LoggingAuditConfig(schema_version='')


def test_logging_schema_version_rejects_non_str():
    with pytest.raises(AuditConfigurationError, match='schema_version'):
        LoggingAuditConfig(schema_version=1.0)


def test_logging_config_rejects_invalid_projection_limits():
    with pytest.raises(AuditConfigurationError, match='projection_limits'):
        LoggingAuditConfig(projection_limits={'max_depth': 1})


# --- AuditEvent ------------------------------------------------------------


def _ok_event(**overrides):
    base = {
        'event_type': 'http.response',
        'schema_version': '1.0',
        'body': 'evt',
        'attributes': {},
    }
    base.update(overrides)
    return AuditEvent(**base)


def test_audit_event_rejects_nan_attribute():
    with pytest.raises(AuditConfigurationError, match='NaN'):
        _ok_event(attributes={'n': float('nan')})


def test_audit_event_rejects_infinite_attribute():
    with pytest.raises(AuditConfigurationError, match='infinite'):
        _ok_event(attributes={'n': float('inf')})


def test_audit_event_rejects_nested_nan_attribute():
    with pytest.raises(AuditConfigurationError, match='NaN'):
        _ok_event(attributes={'outer': {'n': float('nan')}})


def test_audit_event_rejects_non_string_mapping_key():
    with pytest.raises(AuditConfigurationError, match='non-string key'):
        _ok_event(attributes={1: 'one'})


def test_audit_event_rejects_custom_object_value():
    class Custom:
        pass

    with pytest.raises(AuditConfigurationError, match='unsupported'):
        _ok_event(attributes={'custom': Custom()})


def test_audit_event_rejects_bytes():
    with pytest.raises(AuditConfigurationError, match='bytes'):
        _ok_event(attributes={'raw': b'secret'})


def test_audit_event_rejects_cycles():
    value = {}
    value['self'] = value

    with pytest.raises(AuditConfigurationError, match='cycle'):
        _ok_event(attributes={'value': value})


def test_audit_event_rejects_conflicting_event_type_attribute():
    with pytest.raises(AuditConfigurationError, match='conflicts'):
        _ok_event(attributes={'event_type': 'other'})


def test_audit_event_rejects_conflicting_schema_version_attribute():
    with pytest.raises(AuditConfigurationError, match='conflicts'):
        _ok_event(attributes={'schema_version': '2.0'})


def test_audit_event_adds_authoritative_attributes():
    event = _ok_event(attributes={'request_id': 'req-1'})

    assert event.attributes['event_type'] == 'http.response'
    assert event.attributes['schema_version'] == '1.0'
    assert event.attributes['request_id'] == 'req-1'


def test_audit_event_deeply_freezes_attributes():
    event = _ok_event(attributes={'items': [{'amount': 5}]})

    with pytest.raises(TypeError):
        event.attributes['new'] = 'value'  # type: ignore[index]
    with pytest.raises(TypeError):
        event.attributes['items'][0]['amount'] = 9


def test_audit_event_rejects_empty_event_type():
    with pytest.raises(AuditConfigurationError, match='event_type'):
        AuditEvent(event_type='', schema_version='1.0', body='x', attributes={})


def test_audit_event_rejects_non_str_event_type():
    with pytest.raises(AuditConfigurationError, match='event_type'):
        AuditEvent(event_type=42, schema_version='1.0', body='x', attributes={})


def test_audit_event_rejects_empty_schema_version():
    with pytest.raises(AuditConfigurationError, match='schema_version'):
        AuditEvent(event_type='x', schema_version='', body='x', attributes={})


def test_audit_event_rejects_negative_timestamp():
    with pytest.raises(AuditConfigurationError, match='non-negative'):
        _ok_event(timestamp_ns=-1)


def test_audit_event_rejects_bool_timestamp():
    # bool is an int subclass; it must not pass through as a timestamp.
    with pytest.raises(AuditConfigurationError, match='timestamp_ns'):
        _ok_event(timestamp_ns=True)


def test_audit_event_accepts_explicit_zero_timestamp():
    # Zero is a valid (if unusual) timestamp; it must not be treated as falsy.
    event = _ok_event(timestamp_ns=0)
    assert event.timestamp_ns == 0


def test_audit_event_rejects_negative_observed_timestamp():
    with pytest.raises(AuditConfigurationError, match='non-negative'):
        _ok_event(observed_timestamp_ns=-5)


def test_audit_event_observed_accepts_explicit_zero():
    # an explicit 0 must round-trip, not be replaced by now().
    event = _ok_event(timestamp_ns=1000)
    observed = event.observed(0)
    assert observed.observed_timestamp_ns == 0


def test_audit_event_observed_defaults_when_none():
    event = _ok_event(timestamp_ns=1000)
    observed = event.observed(None)
    assert observed.observed_timestamp_ns is not None
    assert observed.observed_timestamp_ns > 0


# --- SecAuditSettings -------------------------------------------------------


def test_sec_audit_settings_rejects_invalid_core_section_type():
    from sec_audit.django.config import SecAuditSettings

    with pytest.raises(AuditConfigurationError, match='core'):
        SecAuditSettings(core='bad')  # type: ignore[arg-type]


def test_sec_audit_settings_rejects_invalid_logging_section_type():
    from sec_audit.django.config import SecAuditSettings

    with pytest.raises(AuditConfigurationError, match='logging'):
        SecAuditSettings(logging='bad')  # type: ignore[arg-type]


def test_sec_audit_settings_rejects_invalid_django_section_type():
    from sec_audit.django.config import SecAuditSettings

    with pytest.raises(AuditConfigurationError, match='django'):
        SecAuditSettings(django='bad')  # type: ignore[arg-type]
