"""Block-management util API: round-trips, event emission, subject coercion."""

import pytest

from sec_audit.django_enforcement import (
    block_subject,
    block_user,
    is_blocked,
    is_user_blocked,
    list_active_blocks,
    list_blocked_users,
    unblock_subject,
    unblock_user,
)
from sec_audit.django_enforcement import runtime as runtime_mod
from sec_audit.django_enforcement.emit import BLOCK_APPLIED, BLOCK_REVOKED

from ._helpers import FakeUser

pytestmark = pytest.mark.django_db


@pytest.fixture
def captured(make_runtime):
    """Install a fakeredis+DB-backed runtime as the singleton the utils resolve.

    Returns the list the emitter appends ``(event, level)`` pairs to.
    """
    events = []
    runtime_mod._set_runtime(make_runtime(captured=events))
    return events


def _events_of(events, event_type):
    return [event for event, _ in events if event.event_type == event_type]


def test_block_user_roundtrip(captured):
    entry = block_user(42, reason='fraud', actor='admin')
    assert (entry.scope.scope_type, entry.scope.scope_value) == ('user', '42')
    assert is_user_blocked(42) is not None
    assert [e.scope.scope_value for e in list_blocked_users()] == ['42']

    applied = _events_of(captured, BLOCK_APPLIED)
    assert applied[-1].attributes['enforcement.action'] == 'permanent'
    assert applied[-1].attributes['security_rule.name'] == 'manual'

    # Tiered store clears Redis + Postgres, so the revoked count is per-tier (>= 1).
    assert unblock_user(42, revoked_by='admin') >= 1
    assert is_user_blocked(42) is None
    assert list_blocked_users() == []
    revoked = _events_of(captured, BLOCK_REVOKED)
    assert revoked[-1].attributes['enforcement.revoked_by'] == 'admin'


def test_temp_block_via_subject_is_redis_only(captured):
    entry = block_subject('ip', '1.2.3.4', ttl=600)
    assert entry.expires_at is not None
    applied = _events_of(captured, BLOCK_APPLIED)
    assert applied[-1].attributes['enforcement.action'] == 'temp'
    assert applied[-1].attributes['enforcement.ttl'] == 600

    assert is_blocked('ip', '1.2.3.4') is not None
    # Temp (Redis-only) blocks are intentionally not enumerated.
    assert list_active_blocks(scope_type='ip') == []


def test_unblock_missing_returns_zero_and_emits_nothing(captured):
    assert unblock_subject('user', '999') == 0
    assert _events_of(captured, BLOCK_REVOKED) == []


def test_subject_accepts_model_instance(captured):
    block_user(FakeUser(pk=7), reason='x')
    assert is_user_blocked(7) is not None
    assert is_user_blocked(FakeUser(pk=7)) is not None


def test_list_active_blocks_filters_by_scope_type(captured):
    block_user(1, reason='a')
    block_subject('session', 'sess-xyz', reason='b')
    users = {e.scope.scope_value for e in list_active_blocks(scope_type='user')}
    assert users == {'1'}
    both = {e.scope.scope_type for e in list_active_blocks()}
    assert both == {'user', 'session'}
