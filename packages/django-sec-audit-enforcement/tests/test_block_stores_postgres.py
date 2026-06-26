import pytest
from django.db import IntegrityError
from sec_audit.enforcement.blocks import BlockScope

from sec_audit.django_enforcement.models import PermanentBlock
from sec_audit.django_enforcement.stores import BlockStoreError, PostgresBlockStore

pytestmark = pytest.mark.django_db


def test_block_is_idempotent_one_active_row():
    store = PostgresBlockStore()
    user = BlockScope('user', '42')
    store.block(user, reason='first', rule_name='r')
    store.block(user, reason='second', rule_name='r')  # refresh, not duplicate
    active = PermanentBlock.objects.filter(
        scope_type='user', scope_value='42', revoked_at__isnull=True
    )
    assert active.count() == 1
    assert active.first().reason == 'second'


def test_block_wraps_concurrent_integrity_error(monkeypatch):
    """A racing insert that violates the partial unique constraint surfaces as
    BlockStoreError (the package's error contract), not a raw IntegrityError."""
    store = PostgresBlockStore()

    def boom(*args, **kwargs):
        raise IntegrityError('duplicate active block')

    monkeypatch.setattr(PermanentBlock.objects, 'update_or_create', boom)
    with pytest.raises(BlockStoreError):
        store.block(BlockScope('ip', '5.5.5.5'))


def test_get_and_first_active_precedence():
    store = PostgresBlockStore()
    user = BlockScope('user', '42')
    ip = BlockScope('ip', '1.2.3.4')
    store.block(user)
    store.block(ip)
    assert store.get_active(user) is not None
    # caller passes precedence order; user wins
    assert store.first_active([user, ip]).scope == user
    assert store.first_active([BlockScope('session', 'x'), ip]).scope == ip


def test_unblock_is_soft_delete():
    store = PostgresBlockStore()
    ip = BlockScope('ip', '9.9.9.9')
    store.block(ip)
    assert store.unblock(ip, reason='manual', revoked_by='admin') == 1
    assert store.get_active(ip) is None
    # row retained (audit trail), now revoked
    row = PermanentBlock.objects.get(scope_type='ip', scope_value='9.9.9.9')
    assert row.revoked_at is not None
    assert row.revoked_reason == 'manual' and row.revoked_by == 'admin'
    # re-ban allowed after revoke (partial unique constraint exempts revoked)
    store.block(ip)
    assert store.get_active(ip) is not None


def test_active_blocks_lists_only_active():
    store = PostgresBlockStore()
    store.block(BlockScope('ip', '1.1.1.1'))
    store.block(BlockScope('user', '7'))
    store.unblock(BlockScope('ip', '1.1.1.1'))
    scopes = {(e.scope.scope_type, e.scope.scope_value) for e in store.active_blocks()}
    assert scopes == {('user', '7')}
