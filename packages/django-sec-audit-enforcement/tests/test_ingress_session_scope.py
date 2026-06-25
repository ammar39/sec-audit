"""Bug 1: ingress session enforcement keys on the audit-session id that egress
emits (gated on ``emit_session_id``), never the raw ``session.session_key``."""

from types import SimpleNamespace

import pytest
from sec_audit.core.ip import TrustedProxyConfig
from sec_audit.django.config import DjangoAuditConfig, SecAuditSettings
from sec_audit.enforcement.blocks import BlockScope
from sec_audit.rules.scopes import ScopeRegistry

from sec_audit.django_enforcement import middleware as mw
from sec_audit.django_enforcement.middleware import EnforcementMiddleware
from sec_audit.django_enforcement.runtime import _set_runtime
from sec_audit.django_enforcement.scopes import ingress_summary

from tests._helpers import FakeRequest, ok_view

TPC = TrustedProxyConfig()


def _session_scopes(summary):
    scopes = ScopeRegistry.from_specs().block_scopes(summary, only=('session',))
    return [(s.scope_type, s.scope_value) for s in scopes]


def test_session_candidate_uses_audit_id_when_enabled():
    req = FakeRequest(session_key='RAWKEY', audit_session_id='S1')
    summary = ingress_summary(req, trusted_proxy_config=TPC, emit_session_id=True)
    assert summary['session_id'] == 'S1'
    assert _session_scopes(summary) == [('session', 'S1')]


def test_raw_session_key_is_never_the_ban_dimension():
    # session_key present but the audit id has not been minted yet -> no candidate
    req = FakeRequest(session_key='RAWKEY', audit_session_id=None)
    summary = ingress_summary(req, trusted_proxy_config=TPC, emit_session_id=True)
    assert 'session_id' not in summary
    assert _session_scopes(summary) == []


def test_session_dimension_off_when_emit_session_id_false():
    req = FakeRequest(session_key='RAWKEY', audit_session_id='S1')
    summary = ingress_summary(req, trusted_proxy_config=TPC, emit_session_id=False)
    assert 'session_id' not in summary


def _patch_django_emit_session_id(monkeypatch, *, enabled):
    runtime_stub = SimpleNamespace(
        config=SecAuditSettings(django=DjangoAuditConfig(emit_session_id=enabled))
    )
    monkeypatch.setattr(mw, 'get_runtime', lambda: runtime_stub)


@pytest.mark.django_db
def test_e2e_session_block_denies_matching_request(make_runtime, monkeypatch):
    rt = make_runtime()
    _set_runtime(rt)
    _patch_django_emit_session_id(monkeypatch, enabled=True)
    rt.block_store.block(
        BlockScope('session', 'S1'), ttl=None, status_code=403, message='banned'
    )
    resp = EnforcementMiddleware(ok_view)(
        FakeRequest(path='/dashboard/', audit_session_id='S1')
    )
    assert resp.status_code == 403
    assert resp.content == b'banned'


@pytest.mark.django_db
def test_e2e_session_block_not_checked_when_emit_session_id_off(
    make_runtime, monkeypatch
):
    rt = make_runtime()
    _set_runtime(rt)
    _patch_django_emit_session_id(monkeypatch, enabled=False)
    rt.block_store.block(BlockScope('session', 'S1'), ttl=None)
    resp = EnforcementMiddleware(ok_view)(
        FakeRequest(path='/dashboard/', audit_session_id='S1')
    )
    # emit_session_id off -> ingress builds no session candidate -> not denied
    assert resp.status_code == 200
