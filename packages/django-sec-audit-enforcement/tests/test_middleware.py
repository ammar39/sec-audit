import pytest
from sec_audit.enforcement.blocks import BlockScope

from sec_audit.django_enforcement import emit as emit_mod
from sec_audit.django_enforcement.middleware import EnforcementMiddleware
from sec_audit.django_enforcement.runtime import _set_runtime
from sec_audit.django_enforcement.stores import BlockStoreError

from tests._helpers import FakeRequest, ok_view

pytestmark = pytest.mark.django_db

IP = '203.0.113.7'


def _failed_login(ip=IP):
    # OTel-named source.address (as a real emitted event carries) -> normalized.
    return {'event_type': 'auth.login.failed', 'source.address': ip}


def test_ingress_denies_active_block(make_runtime):
    rt = make_runtime()
    _set_runtime(rt)
    rt.block_store.block(BlockScope('ip', IP), ttl=300, status_code=429, message='nope')
    resp = EnforcementMiddleware(ok_view)(FakeRequest(remote_addr=IP, path='/x/'))
    assert resp.status_code == 429
    assert resp.content == b'nope'


def test_disabled_is_passthrough(make_runtime):
    rt = make_runtime(enabled=False)
    _set_runtime(rt)
    rt.block_store.block(BlockScope('ip', IP), ttl=300)
    resp = EnforcementMiddleware(ok_view)(FakeRequest(remote_addr=IP))
    assert resp.status_code == 200  # enforcement off -> not checked


def test_e2e_repeated_failures_block_next_request(make_runtime):
    rt = make_runtime()
    _set_runtime(rt)
    for _ in range(5):  # BruteForceLoginRule threshold
        rt.handle_event(_failed_login())
    # brute_force_login matched -> temp ip block written via DEFAULT_RULE_ACTIONS
    assert rt.block_store.first_active([BlockScope('ip', IP)]) is not None
    resp = EnforcementMiddleware(ok_view)(
        FakeRequest(remote_addr=IP, path='/dashboard/')
    )
    assert resp.status_code == 429


def test_ingress_safe_rule_denies_current_request(make_runtime):
    # brute_force as 'observe' so only the counter climbs (no block); then the
    # ingress login_throttle must deny the current /login request itself.
    rt = make_runtime(rule_actions={'brute_force_login': {'action': 'observe'}})
    _set_runtime(rt)
    for _ in range(5):
        rt.handle_event(_failed_login())
    assert rt.block_store.first_active([BlockScope('ip', IP)]) is None  # no block yet
    resp = EnforcementMiddleware(ok_view)(FakeRequest(remote_addr=IP, path='/login/'))
    assert resp.status_code == 429  # login_throttle applied + denied at ingress
    assert (
        rt.block_store.first_active([BlockScope('ip', IP)]) is not None
    )  # now blocked


def test_fail_open_proceeds_on_store_error(make_runtime, monkeypatch):
    rt = make_runtime()
    _set_runtime(rt)
    monkeypatch.setattr(
        rt.block_store,
        'first_active',
        lambda scopes: (_ for _ in ()).throw(BlockStoreError('down')),
    )
    resp = EnforcementMiddleware(ok_view)(FakeRequest(remote_addr=IP, path='/x/'))
    assert resp.status_code == 200  # fail-open path proceeds


def test_fail_closed_denies_on_store_error(make_runtime, monkeypatch):
    captured = []
    rt = make_runtime(fail_closed_paths=[r'^/api/transfer'], captured=captured)
    _set_runtime(rt)
    monkeypatch.setattr(
        rt.block_store,
        'first_active',
        lambda scopes: (_ for _ in ()).throw(BlockStoreError('down')),
    )
    resp = EnforcementMiddleware(ok_view)(
        FakeRequest(remote_addr=IP, path='/api/transfer/')
    )
    assert resp.status_code == 429  # fail-closed path denies
    types = [e.event_type for e, _ in captured]
    assert emit_mod.EVALUATION_FAILED in types
