"""JSONLLogFormatter instrumentation-scope package-name behavior (CORR 4)."""

import json
import logging

from sec_audit.core.events import AuditEvent
from sec_audit.core.projection import ProjectionLimits
from sec_audit.logging import JSONLLogFormatter, build_log_record
from sec_audit.logging.formatters import (
    DEFAULT_PACKAGE_NAME,
    MALFORMED_EVENT_TYPE,
    _timestamp_nanos,
)


def _event(attributes=None, *, body='evt', event_type='x', schema_version='1.0'):
    attrs = {'event_type': event_type, 'schema_version': schema_version}
    attrs.update(attributes or {})
    return AuditEvent(
        event_type=event_type,
        schema_version=schema_version,
        body=body,
        attributes=attrs,
    )


def _record():
    record = logging.LogRecord(
        name='sec_audit',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='evt',
        args=(),
        exc_info=None,
    )
    record.audit_event = _event()
    record.audit_attributes = {}
    return record


def _scope(record, **kwargs):
    return build_log_record(record, **kwargs)['instrumentation_scope']


def test_default_package_name_is_logging_scope():
    assert DEFAULT_PACKAGE_NAME == 'sec_audit.logging'


def test_scope_name_is_package_identifier_not_logger_name():
    # the OTel scope name is the emitting package, not the logger name
    # (the record below is named 'sec_audit', which must NOT leak into scope).
    scope = _scope(_record())
    assert scope['name'] == 'sec_audit.logging'

    explicit = _scope(_record(), package_name='sec_audit.django')
    assert explicit['name'] == 'sec_audit.django'


def test_scope_version_resolves_via_dist_map():
    from importlib import metadata

    scope = _scope(_record(), package_name='sec_audit.logging')
    assert scope.get('version') == metadata.version('sec-audit-logging')


def test_unknown_package_name_yields_empty_version_without_raising():
    scope = _scope(_record(), package_name='definitely-not-installed-xyz')
    assert 'version' not in scope


def test_explicit_package_name_used_for_version_lookup(monkeypatch):
    seen = {}

    def fake_version(name):
        seen['name'] = name
        return '9.9.9'

    import sec_audit.logging.formatters as fmt_mod

    monkeypatch.setattr(fmt_mod, '_package_version', fake_version)
    scope = _scope(_record(), package_name='django-sec-audit')
    assert seen['name'] == 'django-sec-audit'
    assert scope['version'] == '9.9.9'


def test_formatter_threads_package_name_through(monkeypatch):
    import sec_audit.logging.formatters as fmt_mod

    monkeypatch.setattr(fmt_mod, '_package_version', lambda name: '4.2.0')
    formatter = JSONLLogFormatter(package_name='django-sec-audit')
    out = formatter.format_to_dict(_record())
    assert out['instrumentation_scope'].get('version') == '4.2.0'


def test_formatter_defaults_to_sec_audit_scope():
    formatter = JSONLLogFormatter()
    assert formatter.package_name == 'sec_audit.logging'


def _record_with_attributes(attributes):
    record = logging.LogRecord(
        name='sec_audit',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='evt',
        args=(),
        exc_info=None,
    )
    record.audit_event = _event()
    record.audit_attributes = attributes
    return record


def test_raw_attributes_without_event_emit_malformed_fallback():
    record = logging.LogRecord(
        name='sec_audit',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='evt',
        args=(),
        exc_info=None,
    )
    record.audit_attributes = {'event_type': 'x', 'schema_version': '1.0'}

    output = JSONLLogFormatter().format(record)

    parsed = json.loads(output)
    assert parsed['event_name'] == MALFORMED_EVENT_TYPE
    assert parsed['attributes']['event_type'] == MALFORMED_EVENT_TYPE


def test_nan_attribute_routes_to_malformed_fallback():
    record = _record_with_attributes({'n': float('nan')})

    output = JSONLLogFormatter().format(record)

    parsed = json.loads(output)
    assert parsed['event_name'] == MALFORMED_EVENT_TYPE
    assert 'NaN' not in output


def test_infinity_attribute_routes_to_malformed_fallback():
    record = _record_with_attributes({'inf': float('inf')})

    output = JSONLLogFormatter().format(record)

    parsed = json.loads(output)
    assert parsed['event_name'] == MALFORMED_EVENT_TYPE
    assert 'Infinity' not in output


def test_raw_attributes_are_scrubbed_and_projected_by_formatter():
    from sec_audit.core.config import CoreAuditConfig

    record = _record_with_attributes(
        {
            'nested': {'password': 'secret'},
            'items': ['ok', {'token': 'leak'}],
        }
    )

    output = JSONLLogFormatter(config=CoreAuditConfig()).format(record)

    parsed = json.loads(output)
    assert parsed['attributes']['nested'] == {'password': '[REDACTED]'}
    assert parsed['attributes']['items'] == ['ok', {'token': '[REDACTED]'}]
    assert 'secret' not in output
    assert 'leak' not in output


def test_unsafe_attributes_are_scrubbed_even_when_audit_event_present():
    from sec_audit.core.config import CoreAuditConfig

    record = logging.LogRecord(
        name='sec_audit',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='evt',
        args=(),
        exc_info=None,
    )
    record.audit_event = _event()
    record.audit_attributes = {
        'nested': {'password': 'secret'},
    }

    output = JSONLLogFormatter(config=CoreAuditConfig()).format(record)

    parsed = json.loads(output)
    assert parsed['attributes']['nested'] == {'password': '[REDACTED]'}
    assert 'secret' not in output


def test_forged_sanitized_marker_does_not_bypass_scrub():
    # B2: a forged ``_audit_attrs_sanitized = True`` injected via ``extra={...}``
    # must NOT bypass the formatter's scrub. The formatter re-scrubs additions
    # unconditionally, so the value of the marker is irrelevant.
    from sec_audit.core.config import CoreAuditConfig

    record = _record_with_attributes({'password': 'hunter2'})
    record._audit_attrs_sanitized = True

    output = JSONLLogFormatter(config=CoreAuditConfig()).format(record)

    parsed = json.loads(output)
    assert parsed['attributes']['password'] == '[REDACTED]'
    assert 'hunter2' not in output


def test_no_sanitized_marker_can_bypass_second_scrub():
    # B2 (v15): the prior ``_SANITIZED_SENTINEL`` skip-marker was removed because
    # it was importable and thus forgeable in-process. The formatter is now the
    # unconditional final gate — additions carrying ANY marker object are still
    # scrubbed. (A double scrub is idempotent on already-safe data.)
    from sec_audit.core.config import CoreAuditConfig

    record = _record_with_attributes({'password': 'pre-sanitized'})
    record._audit_attrs_sanitized = object()  # any marker must not bypass

    output = JSONLLogFormatter(config=CoreAuditConfig()).format(record)

    parsed = json.loads(output)
    assert parsed['attributes']['password'] == '[REDACTED]'
    assert 'pre-sanitized' not in output


def test_timestamp_nanos_falls_back_for_invalid_created():
    record = logging.LogRecord('sec_audit', logging.INFO, '', 0, 'msg', (), None)

    record.created = None
    assert isinstance(_timestamp_nanos(record), int)

    record.created = float('nan')
    fallback = _timestamp_nanos(record)
    assert isinstance(fallback, int) and fallback > 0


def test_internal_debug_does_not_attach_exception_info():
    from sec_audit.logging.emission import INTERNAL_LOGGER_NAME, _internal_debug

    captured = []

    class _Grab(logging.Handler):
        def emit(self, record):
            captured.append(record)

    internal = logging.getLogger(INTERNAL_LOGGER_NAME)
    handler = _Grab()
    internal.addHandler(handler)
    previous_level = internal.level
    internal.setLevel(logging.DEBUG)
    try:
        try:
            raise ValueError('boom')
        except ValueError:
            _internal_debug('failed')
    finally:
        internal.removeHandler(handler)
        internal.setLevel(previous_level)

    assert captured, 'expected an internal diagnostic record'
    assert captured[-1].name == INTERNAL_LOGGER_NAME
    assert captured[-1].exc_info is None


def test_body_matching_value_pattern_is_redacted():
    """Bug 4a: the formatter scrubs the ``msg`` (body) string before emission."""
    import re

    from sec_audit.core.config import CoreAuditConfig

    pattern = re.compile(r'leaked-token')
    config = CoreAuditConfig(sensitive_value_patterns=(pattern,))

    record = _record()
    record.audit_event = _event(body='leaked-token in body')

    output = JSONLLogFormatter(config=config).format(record)
    parsed = json.loads(output)

    assert parsed['body'] == '[REDACTED]'
    assert 'leaked-token' not in output


# --- the emitted line is always bounded by max_record_bytes ------

# 1024 is MIN_RECORD_BYTES, the smallest limit ProjectionLimits accepts.
_TINY = ProjectionLimits(max_record_bytes=1024)


def test_oversized_source_falls_back_within_byte_limit():
    # A pathologically long source blows the main record and the first fallback
    # (both carry resource.service.name) past the limit; the bounded minimal /
    # last-resort path must still emit a line that fits.
    formatter = JSONLLogFormatter(source='S' * 5000, limits=_TINY)
    output = formatter.format(_record())

    assert len(output.encode('utf-8')) <= 1024
    parsed = json.loads(output)
    assert parsed['event_name'] == MALFORMED_EVENT_TYPE
    assert 'S' * 300 not in output  # the 5000-char source was bounded out


def test_oversized_attributes_fall_back_within_byte_limit():
    record = _record_with_attributes({'blob': 'x' * 20000})
    output = JSONLLogFormatter(limits=_TINY).format(record)

    assert len(output.encode('utf-8')) <= 1024
    parsed = json.loads(output)
    assert parsed['event_name'] == MALFORMED_EVENT_TYPE
    assert 'x' * 200 not in output  # original blob never reaches the fallback


def test_fallback_contains_no_original_secret():
    from sec_audit.core.config import CoreAuditConfig

    record = _record_with_attributes({'note': 'super-secret-blob ' + 'y' * 20000})
    output = JSONLLogFormatter(config=CoreAuditConfig(), limits=_TINY).format(record)

    assert len(output.encode('utf-8')) <= 1024
    assert 'super-secret-blob' not in output


def test_multibyte_source_is_measured_by_bytes_not_chars():
    # 400 three-byte chars = 1200 bytes > 1024 though only 400 characters. The
    # byte measurement (not char count) must trigger the bounded fallback.
    formatter = JSONLLogFormatter(source='€' * 400, limits=_TINY)
    output = formatter.format(_record())

    assert len(output.encode('utf-8')) <= 1024
    parsed = json.loads(output)
    assert parsed['event_name'] == MALFORMED_EVENT_TYPE


def test_compact_and_noncompact_fallback_both_fit():
    for compact in (True, False):
        formatter = JSONLLogFormatter(source='S' * 5000, compact=compact, limits=_TINY)
        output = formatter.format(_record())

        assert len(output.encode('utf-8')) <= 1024
        json.loads(output)  # valid JSON in both separator modes
