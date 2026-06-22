"""R3: the audit context is active during get_response and token-restored after.

The middleware activates an ``AuditContext`` before calling the view and resets
it in a ``finally`` block using the token returned by ``set_context``. Because
restoration is token-based (contextvars), an outer context survives an inner
request instead of being destroyed, and a clean context is restored after a
normal request. Auth signals firing inside the request reuse the same context,
so their correlation ids match the HTTP event.
"""

from sec_audit.core.context import (
    AuditContext,
    clear_context,
    get_context,
    reset_context,
    set_context,
)
from sec_audit.django import runtime as audit_runtime
from sec_audit.django.config import SecAuditSettings
from sec_audit.django.logging import auth as auth_mod
from sec_audit.django.middleware import AuditMiddleware


class _Request:
    method = 'GET'
    headers = {}
    META = {'REMOTE_ADDR': '203.0.113.5'}
    FILES = {}
    content_type = ''
    resolver_match = None
    session = None
    user = None

    def __init__(self, path='/api/thing/'):
        self.path = path
        self.path_info = path

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


def _set_runtime(settings):
    previous = audit_runtime._runtime
    audit_runtime._set_runtime(_CaptureRuntime(settings))
    return previous


def _restore_runtime(previous):
    audit_runtime._runtime = previous


_OK = {'SEC_AUDIT': {'core': {'log_ok_responses': True}}}


def test_context_is_active_during_get_response():
    clear_context()
    previous = _set_runtime(_OK)
    seen = {}

    def view(request):
        ctx = get_context()
        seen['request_id'] = ctx.request_id if ctx else None
        seen['path'] = ctx.path if ctx else None
        return _Response()

    try:
        AuditMiddleware(view)(_Request(path='/api/thing/'))
    finally:
        _restore_runtime(previous)
        clear_context()

    # A full UUID4 request id is minted and reachable from inside the view.
    assert seen['request_id'] and len(seen['request_id']) == 32
    assert seen['path'] == '/api/thing/'


def test_context_restored_to_none_after_successful_response():
    clear_context()
    previous = _set_runtime(_OK)
    try:
        assert get_context() is None
        AuditMiddleware(lambda r: _Response())(_Request())
        # The finally block resets the context the middleware set.
        assert get_context() is None
    finally:
        _restore_runtime(previous)
        clear_context()


def test_outer_context_survives_inner_request():
    clear_context()
    outer = AuditContext(
        request_id='outer-req',
        session_id='',
        url='/outer',
        path='/outer',
        srcip='203.0.113.9',
        method='GET',
    )
    token = set_context(outer)
    previous = _set_runtime(_OK)
    seen = {}

    def view(request):
        # A distinct inner context is active during the inner request (its path
        # is the inner request's; the request id is inherited by design).
        seen['inner_path'] = get_context().path
        return _Response()

    try:
        AuditMiddleware(view)(_Request(path='/inner/'))
        assert seen['inner_path'] == '/inner/'
        # The outer context is restored, not destroyed (clear_context would have
        # left None here). Token-based reset returns the exact outer context.
        assert get_context() is not None
        assert get_context().path == '/outer'
        assert get_context().request_id == 'outer-req'
    finally:
        reset_context(token)
        _restore_runtime(previous)
        clear_context()


def test_login_signal_inside_middleware_shares_request_id():
    clear_context()
    previous = _set_runtime(_OK)

    class _User:
        pk = 7
        is_authenticated = True

        def get_username(self):
            return 'alice'

    captured = {}

    def view(request):
        # An auth signal firing during request handling consumes the active
        # context instead of rebuilding (and re-reading the body).
        captured['ctx_request_id'] = get_context().request_id
        auth_mod.login_logger(sender=None, request=request, user=_User())
        return _Response()

    try:
        AuditMiddleware(view)(_Request(path='/login/'))
        # Capture recorded events while the capture-runtime is still installed.
        events = audit_runtime._runtime.events
    finally:
        _restore_runtime(previous)
        clear_context()

    # Login (recorded during the view) and the HTTP response (recorded after)
    # both carry the active context's request id.
    request_ids = {event.attributes.get('request_id') for event, _level in events}
    assert len(events) == 2  # login + http response
    assert request_ids == {captured['ctx_request_id']}
    assert captured['ctx_request_id'] and len(captured['ctx_request_id']) == 32
