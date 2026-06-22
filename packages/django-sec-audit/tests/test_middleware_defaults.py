"""session.id is opt-in, and ignored paths are checked early.

generating an audit-session id writes into ``request.session`` (which
forces Django to persist it and Set-Cookie). An audit package must not change
application state by default, so ``emit_session_id`` defaults to False.

the ignore-path check must happen before session/IP/route/body work,
so an ignored endpoint is actually ignored — not merely logged-then-extracted.
"""

import re

from sec_audit.django import runtime as audit_runtime
from sec_audit.django.config import SecAuditSettings
from sec_audit.django.logging.body import capture_request_body
from sec_audit.django.middleware import AuditMiddleware


class _FakeSession(dict):
    modified = False
    session_key = 'RAWKEYXYZ'


class _Request:
    method = 'GET'
    path = '/ok/'
    path_info = '/ok/'
    headers = {}
    META = {'REMOTE_ADDR': '203.0.113.5'}
    FILES = {}
    content_type = ''
    resolver_match = None

    def __init__(self, path='/ok/', session=None):
        self.path = path
        self.path_info = path
        self.session = session

    def build_absolute_uri(self, path=None):
        return f'https://example.test{path or self.path}'


class _Response:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def items(self):
        return []


class _CaptureRuntime:
    def __init__(self, settings):
        self.config = SecAuditSettings.from_settings(settings)
        self.events = []

    def record(self, event, level):
        self.events.append((event, level))


def _set_runtime(runtime):
    previous = audit_runtime._runtime
    audit_runtime._set_runtime(runtime)
    return previous


def _restore_runtime(previous):
    audit_runtime._runtime = previous


# --- session.id is opt-in by default -----------------------------


def test_default_config_does_not_write_audit_session_id():
    # The default DjangoAuditConfig has emit_session_id=False, so the middleware
    # path must not touch request.session at all.
    from sec_audit.django.logging.sessions import get_audit_session_id

    session = _FakeSession()
    # The middleware reads the resolved runtime config's flag, so simulate the
    # default runtime (no SEC_AUDIT django section) and confirm the helper no-ops.
    value = get_audit_session_id(
        _Request(session=session), enabled=SecAuditSettings().django.emit_session_id
    )
    assert value == ''
    assert '_sec_audit_session_id' not in session
    assert session.modified is False


def test_middleware_with_default_config_leaves_session_unmodified():
    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    try:
        session = _FakeSession()
        AuditMiddleware(lambda request: _Response())(_Request(session=session))
    finally:
        _restore_runtime(previous)

    assert '_sec_audit_session_id' not in session
    assert session.modified is False


# --- ignore-path check is early ----------------------------------


def test_ignored_path_skips_body_capture(monkeypatch):
    # If the ignore check happens early, capture_request_body is never called
    # for an ignored path. Patch it to record invocations and assert it stays
    # at zero.
    calls = []
    original = capture_request_body

    def _spy(request, config, *, path=''):
        calls.append(path)
        return original(request, config, path=path)

    monkeypatch.setattr('sec_audit.django.middleware.capture_request_body', _spy)
    runtime = _CaptureRuntime(
        {'SEC_AUDIT': {'core': {'ignore_paths': [re.compile(r'^/health')]}}}
    )
    previous = _set_runtime(runtime)
    try:
        response = AuditMiddleware(lambda request: _Response())(
            _Request(path='/health')
        )
    finally:
        _restore_runtime(previous)

    assert response.status_code == 200
    assert calls == [], 'capture_request_body must not run for ignored paths'


def test_ignored_path_skips_session_write():
    runtime = _CaptureRuntime(
        {'SEC_AUDIT': {'core': {'ignore_paths': [re.compile(r'^/health')]}}}
    )
    previous = _set_runtime(runtime)
    try:
        session = _FakeSession()
        AuditMiddleware(lambda request: _Response())(
            _Request(path='/health', session=session)
        )
    finally:
        _restore_runtime(previous)

    # emit_session_id is off by default anyway, but the point is that the whole
    # extraction (including session access) is skipped for ignored paths.
    assert '_sec_audit_session_id' not in session
    assert session.modified is False


def test_non_ignored_path_still_audits():
    runtime = _CaptureRuntime(
        {
            'SEC_AUDIT': {
                'core': {
                    'ignore_paths': [re.compile(r'^/health')],
                    'log_ok_responses': True,
                }
            }
        }
    )
    previous = _set_runtime(runtime)
    try:
        AuditMiddleware(lambda request: _Response())(_Request(path='/api/transfer'))
    finally:
        _restore_runtime(previous)

    assert len(runtime.events) == 1
