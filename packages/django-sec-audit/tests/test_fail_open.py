"""audit work fails open; application exceptions never swallowed."""

import pytest

from sec_audit.django.config import SecAuditSettings
from sec_audit.django.logging import auth as auth_mod
from sec_audit.django import runtime as rt


class _Resp:
    def __init__(self, status=200):
        self.status_code = status

    def items(self):
        return []


class _Req:
    method = 'GET'
    path = '/x/'
    path_info = '/x/'
    headers = {}
    META = {}
    session = None
    user = None

    def build_absolute_uri(self, p=None):
        return f'https://x.test{p or self.path}'


class _CaptureRuntime:
    def __init__(self, settings):
        self.config = SecAuditSettings.from_settings(settings)
        self.events = []

    def record(self, event, level, *, emit=True):
        self.events.append((event, level))


def _install(settings):
    rt0 = rt._runtime
    rt._runtime = _CaptureRuntime(settings)
    return rt0


# --- middleware: extraction failure does not break the request -------------


def test_middleware_preparation_failure_still_returns_response(monkeypatch):
    from sec_audit.django.middleware import AuditMiddleware

    rt0 = _install({'SEC_AUDIT': {'core': {'log_ok_responses': True}}})
    runtime = rt._runtime

    def boom(request):
        raise RuntimeError('extraction exploded')

    monkeypatch.setattr(
        'sec_audit.django.middleware.AuditMiddleware._prepare_audit_context', boom
    )
    try:
        resp = AuditMiddleware(lambda r: _Resp())(_Req())
    finally:
        rt._runtime = rt0
    assert resp.status_code == 200
    assert runtime.events == []  # preparation failed, nothing recorded


def test_middleware_application_exception_propagates(monkeypatch):
    from sec_audit.django.middleware import AuditMiddleware

    rt0 = _install({'SEC_AUDIT': {}})
    try:

        def view(_):
            raise ValueError('application bug')

        with pytest.raises(ValueError, match='application bug'):
            AuditMiddleware(view)(_Req())
    finally:
        rt._runtime = rt0


# --- auth receivers: logging failure does not block login/logout -----------


def test_login_logger_swallows_logging_failure(monkeypatch):
    rt0 = _install({'SEC_AUDIT': {}})

    def _boom(_r):
        raise RuntimeError('request base exploded')

    monkeypatch.setattr(auth_mod, '_request_base', _boom)
    try:
        # Must not raise even though _request_base blows up.
        auth_mod.login_logger(sender=None, request=_Req(), user=object())
    finally:
        rt._runtime = rt0


def test_model_forwarder_swallows_logging_failure():
    from sec_audit.django.logging import model as model_mod

    class _BadEntry:
        @property
        def action(self):
            raise RuntimeError('auditlog entry exploded')

    # Must not raise; the model op (signal) proceeds.
    model_mod.forward_auditlog(sender=None, log_entry=_BadEntry())
