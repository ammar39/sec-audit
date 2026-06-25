"""Bug 1: the audit-session id is an independent generated value, never the raw
Django ``session.session_key`` credential.

These tests target ``get_audit_session_id`` directly (the request-phase helper
that produces the value emitted as the ``session.id`` attribute) plus the full
builder path for HTTP/auth/model events to assert the raw credential never
reaches the emitted attributes or body.
"""

import logging
from types import SimpleNamespace

from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.events import AuditEvent
from sec_audit.django.events import (
    EventType,
    Message,
    build_audit_event,
    build_log_attributes,
)
from sec_audit.django.logging.sessions import (
    get_audit_session_id,
    read_audit_session_id,
)
from sec_audit.logging.formatters import JSONLLogFormatter

RAW_SESSION_KEY = 'RAWKEYXYZ'


class _FakeSession(dict):
    """Mimics a Django session: a dict with a stealable ``session_key``."""

    modified = False
    session_key = RAW_SESSION_KEY


class _Request:
    method = 'GET'
    path = '/ok/'
    path_info = '/ok/'
    headers = {}
    META = {'REMOTE_ADDR': '203.0.113.5'}

    def __init__(self, session):
        self.session = session

    def build_absolute_uri(self, path=None):
        return f'https://example.test{path or self.path}'


# --- get_audit_session_id unit behavior -------------------------------------


def test_raw_session_key_is_never_returned():
    session = _FakeSession()
    value = get_audit_session_id(_Request(session))

    assert value
    assert value != RAW_SESSION_KEY
    assert RAW_SESSION_KEY not in value


def test_id_is_stored_under_namespaced_key_and_marks_modified():
    session = _FakeSession()
    value = get_audit_session_id(_Request(session))

    assert session['_sec_audit_session_id'] == value
    assert session.modified is True


def test_id_is_stable_within_one_session():
    session = _FakeSession()
    request = _Request(session)

    first = get_audit_session_id(request)
    session.modified = False  # simulate a fresh request on the same session
    second = get_audit_session_id(request)

    assert first == second
    assert session['_sec_audit_session_id'] == first
    assert session.modified is False  # reuse path does not re-mark


def test_id_differs_across_fresh_sessions():
    a = get_audit_session_id(_Request(_FakeSession()))
    b = get_audit_session_id(_Request(_FakeSession()))
    assert a != b


def test_disabled_returns_empty_and_writes_nothing():
    session = _FakeSession()
    value = get_audit_session_id(_Request(session), enabled=False)

    assert value == ''
    assert '_sec_audit_session_id' not in session


def test_no_session_returns_empty():
    request = SimpleNamespace(session=None)
    assert get_audit_session_id(request) == ''


# --- read_audit_session_id: read-only ingress counterpart -------------------


def test_read_returns_stored_value_without_writing():
    session = _FakeSession()
    session['_sec_audit_session_id'] = 'audit-1'
    session.modified = False

    assert read_audit_session_id(_Request(session)) == 'audit-1'
    assert session.modified is False  # ingress must never mutate the session


def test_read_absent_returns_empty_and_mints_nothing():
    session = _FakeSession()
    assert read_audit_session_id(_Request(session)) == ''
    assert '_sec_audit_session_id' not in session


def test_read_no_session_returns_empty():
    assert read_audit_session_id(SimpleNamespace(session=None)) == ''


# --- builder path emits session.id, never the raw credential ----------------


def _formatted_attributes(attributes):
    record = logging.LogRecord('sec_audit.audit', logging.INFO, '', 0, 'msg', (), None)
    record.audit_event = AuditEvent(
        event_type=attributes['event_type'],
        schema_version=attributes['schema_version'],
        body=attributes['event_type'],
        attributes=attributes,
    )
    record.audit_attributes = {}
    out = JSONLLogFormatter(config=CoreAuditConfig()).format_to_dict(record)
    return out['attributes'], out['body']


def test_http_event_emits_session_id_attr_not_raw_key():
    attributes = build_log_attributes(
        EventType.HTTP_RESPONSE_SUCCESS,
        {'session_id': 'audit-sess-1', 'request_id': 'req-1'},
        schema_version='1.0',
    )
    attrs, body = _formatted_attributes(attributes)

    assert attrs['session.id'] == 'audit-sess-1'
    assert 'session_id' not in attrs
    assert RAW_SESSION_KEY not in body


def test_auth_event_emits_session_id_attr_not_raw_key():
    event = build_audit_event(
        Message.AUTH_LOGIN_SUCCESS,
        EventType.AUTH_LOGIN_SUCCESS,
        {'session_id': 'audit-sess-2', 'user_id': '42'},
        schema_version='1.0',
    )
    attrs, body = _formatted_attributes(dict(event.attributes))

    assert attrs['session.id'] == 'audit-sess-2'
    assert 'session_id' not in attrs
    assert RAW_SESSION_KEY not in body


def test_model_event_emits_session_id_attr_not_raw_key():
    event = build_audit_event(
        Message.MODEL_EVENT,
        EventType.MODEL_UPDATE,
        {'session_id': 'audit-sess-3', 'model': 'account'},
        schema_version='1.0',
    )
    attrs, body = _formatted_attributes(dict(event.attributes))

    assert attrs['session.id'] == 'audit-sess-3'
    assert 'session_id' not in attrs
    assert RAW_SESSION_KEY not in body


def test_disabled_config_omits_session_id_attr():
    # With the flag off, the request-phase helper returns '' so no session.id
    # is emitted on the produced event.
    attributes = build_log_attributes(
        EventType.HTTP_RESPONSE_SUCCESS,
        {'session_id': '', 'request_id': 'req-1'},
        schema_version='1.0',
    )
    attrs, _ = _formatted_attributes(attributes)
    assert 'session.id' not in attrs
    assert 'session_id' not in attrs
