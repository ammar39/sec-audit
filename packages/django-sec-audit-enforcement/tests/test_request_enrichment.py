"""Stage 5: automatic request-context enrichment for fire_event.

``fire_event`` backfills the standard scope fields (srcip/session_id/request_id/
route) from the ambient ``AuditContext`` when absent; ``fields_from_request``
assembles the full set including the user dimension (not ambient).
"""

import pytest
from django.test import RequestFactory
from sec_audit.core.context import (
    AuditContext,
    clear_context,
    reset_context,
    set_context,
)
from sec_audit.enforcement.blocks import BlockScope
from sec_audit.rules.base import Rule, make_match

from sec_audit.django_enforcement import fields_from_request, fire_event
from sec_audit.django_enforcement import runtime as runtime_mod
from sec_audit.django_enforcement.api import _backfill_ambient_fields
from sec_audit.django_enforcement.config import DjangoEnforcementConfig

CUSTOM_EVENT = 'myapp.payment.attempt'


class _PaymentRule(Rule):
    name = 'payment_velocity'
    severity = 7
    event_types = {CUSTOM_EVENT}

    def evaluate(self, event, ctx):
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message='payment',
            event=event,
        )


class _S:
    def __init__(self, mapping):
        self.SEC_AUDIT_ENFORCEMENT = mapping


def _config(**cfg):
    return DjangoEnforcementConfig.from_settings(_S({'enabled': True, **cfg}))


@pytest.fixture
def install_runtime():
    def _install(config):
        runtime = runtime_mod._build_runtime(config)
        runtime_mod._set_runtime(runtime)
        return runtime

    yield _install
    runtime_mod.reset_enforcement_runtime()


@pytest.fixture
def ambient_context():
    """Activate an AuditContext for the test and tear it down."""
    tokens = []

    def _set(**kw):
        base = {'request_id': 'req-1', 'session_id': 'sess-1'}
        tokens.append(set_context(AuditContext(**{**base, **kw})))

    clear_context()
    yield _set
    for token in reversed(tokens):
        reset_context(token)
    clear_context()


# --- ambient backfill (unit) --------------------------------------------------


def test_backfill_fills_absent_from_context(ambient_context):
    ambient_context(srcip='203.0.113.5', route='/api/x', route_name='api:x')
    out = _backfill_ambient_fields({})
    assert out['srcip'] == '203.0.113.5'
    assert out['session_id'] == 'sess-1'
    assert out['request_id'] == 'req-1'
    assert out['route'] == '/api/x'
    assert out['route_name'] == 'api:x'


def test_backfill_explicit_value_wins(ambient_context):
    ambient_context(srcip='203.0.113.5')
    out = _backfill_ambient_fields({'srcip': '9.9.9.9'})
    assert out['srcip'] == '9.9.9.9'  # explicit beats ambient
    assert out['session_id'] == 'sess-1'  # absent key still filled


def test_backfill_noop_without_context():
    clear_context()
    out = _backfill_ambient_fields({'srcip': '1.1.1.1'})
    assert out == {'srcip': '1.1.1.1'}  # nothing added


# --- fire_event integration ---------------------------------------------------


@pytest.mark.django_db
def test_fire_event_backfills_srcip_and_blocks_on_ambient_ip(
    install_runtime, ambient_context
):
    runtime = install_runtime(
        _config(
            rules=[_PaymentRule()],
            rule_actions={
                'payment_velocity': {'action': 'temp_block', 'scopes': ['ip']}
            },
        )
    )
    ambient_context(srcip='203.0.113.42')
    # No srcip in fields: the ambient context supplies it, so the block lands on it.
    fire_event(CUSTOM_EVENT, {})
    assert (
        runtime.block_store.first_active([BlockScope('ip', '203.0.113.42')]) is not None
    )


# --- fields_from_request ------------------------------------------------------


class _FakeMatch:
    view_name = 'fintech:transfer'
    route = 'api/transfer/'


class _FakeUser:
    is_authenticated = True
    pk = 42

    def get_username(self):
        return 'maya'


@pytest.mark.django_db
def test_fields_from_request_assembles_full_scope_set(install_runtime):
    install_runtime(_config(rules=[_PaymentRule()]))
    req = RequestFactory().get('/api/transfer/')
    req.META['REMOTE_ADDR'] = '203.0.113.5'
    req.resolver_match = _FakeMatch()
    req.user = _FakeUser()

    fields = fields_from_request(req)
    assert fields['srcip'] == '203.0.113.5'
    assert fields['user_id'] == '42'  # user dimension (not ambient)
    assert fields['route'] == '/api/transfer/'
    assert fields['route_name'] == 'fintech:transfer'
