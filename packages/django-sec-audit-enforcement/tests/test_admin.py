"""PermanentBlockAdmin create + revoke routed through the block-management utils."""

import pytest
from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory

from sec_audit.django_enforcement import block_user, is_blocked, is_user_blocked
from sec_audit.django_enforcement import runtime as runtime_mod
from sec_audit.django_enforcement.admin import BlockActionsMixin, PermanentBlockAdmin
from sec_audit.django_enforcement.config import DjangoEnforcementConfig
from sec_audit.django_enforcement.emit import (
    BLOCK_APPLIED,
    BLOCK_REVOKED,
    EnforcementEmitter,
)
from sec_audit.django_enforcement.models import PermanentBlock
from sec_audit.django_enforcement.runtime import DjangoEnforcementRuntime
from sec_audit.django_enforcement.stores import MemoryBlockStore

pytestmark = pytest.mark.django_db


class _AdminUser:
    def get_username(self):
        return 'root'

    def has_perm(self, perm, obj=None):
        return True


class _ViewerUser:
    """Staff with view access but NOT the change permission that gates revoke."""

    def get_username(self):
        return 'viewer'

    def has_perm(self, perm, obj=None):
        return perm != 'sec_audit_enforcement.change_permanentblock'


def _request(user=None):
    request = RequestFactory().post('/admin/')
    request.user = user or _AdminUser()
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


@pytest.fixture
def admin_and_events(make_runtime):
    events = []
    runtime_mod._set_runtime(make_runtime(captured=events))
    return PermanentBlockAdmin(PermanentBlock, AdminSite()), events


def test_save_model_creates_via_util(admin_and_events):
    model_admin, events = admin_and_events
    obj = PermanentBlock(
        scope_type='user',
        scope_value='42',
        reason='manual ban',
        rule_name='manual',
        status_code=429,
        message='blocked',
    )
    model_admin.save_model(_request(), obj, form=None, change=False)

    active = PermanentBlock.objects.filter(
        scope_type='user', scope_value='42', revoked_at__isnull=True
    )
    assert active.count() == 1
    assert obj.pk is not None  # reloaded so the post-add redirect links to the row
    # actor folded into the persisted metadata
    assert active.get().metadata.get('actor') == 'root'
    assert [e for e, _ in events if e.attributes.get('scope.value') == '42']


def test_change_view_save_is_noop(admin_and_events):
    model_admin, events = admin_and_events
    block_user(5, reason='seed')
    row = PermanentBlock.objects.get(scope_value='5')
    before = PermanentBlock.objects.count()
    model_admin.save_model(_request(), row, form=None, change=True)
    assert PermanentBlock.objects.count() == before  # nothing written on change


def test_revoke_action_soft_revokes_and_emits(admin_and_events):
    model_admin, events = admin_and_events
    block_user(7, reason='x')
    queryset = PermanentBlock.objects.filter(scope_value='7', revoked_at__isnull=True)
    model_admin.revoke_blocks(_request(), queryset)

    row = PermanentBlock.objects.get(scope_value='7')
    assert row.revoked_at is not None
    assert row.revoked_by == 'root'
    assert [e for e, _ in events if e.event_type == BLOCK_REVOKED]


def test_revoke_requires_change_permission(admin_and_events):
    """A view-only staff user can't revoke (defeat) blocks: the revoke action is
    gated on the real change permission, not merely on reaching the changelist."""
    model_admin, _ = admin_and_events

    viewer_request = _request(user=_ViewerUser())
    assert model_admin.has_change_permission(viewer_request) is False
    # permissions=['change'] removes the action for a user without change perm.
    assert 'revoke_blocks' not in model_admin.get_actions(viewer_request)

    # A user WITH change permission still gets the action.
    assert 'revoke_blocks' in model_admin.get_actions(_request())


def test_add_form_restricted_to_operator_fields(admin_and_events):
    model_admin, _ = admin_and_events
    assert model_admin.get_fields(_request(), obj=None) == (
        'scope_type',
        'scope_value',
        'reason',
        'rule_name',
        'status_code',
        'message',
    )


def test_existing_rows_are_read_only(admin_and_events):
    model_admin, _ = admin_and_events
    block_user(9, reason='x')
    row = PermanentBlock.objects.get(scope_value='9')
    readonly = model_admin.get_readonly_fields(_request(), obj=row)
    assert 'scope_value' in readonly and 'revoked_at' in readonly


class _Settings:
    SEC_AUDIT_ENFORCEMENT = {'enabled': True}


def test_save_model_persists_row_with_memory_store():
    """No Postgres tier (e.g. the demo): save_model still creates a durable row
    with a real pk so the admin add doesn't crash on the redirect."""
    config = DjangoEnforcementConfig.from_settings(_Settings)
    runtime_mod._set_runtime(
        DjangoEnforcementRuntime(
            config=config,
            scope_registry=None,
            engine=None,
            block_store=MemoryBlockStore(),
            enforcer=None,
            emitter=EnforcementEmitter(lambda event, level: None),
            schema_version='1.0',
        )
    )
    model_admin = PermanentBlockAdmin(PermanentBlock, AdminSite())
    obj = PermanentBlock(
        scope_type='user', scope_value='99', reason='memory ban', rule_name='manual'
    )
    model_admin.save_model(_request(), obj, form=None, change=False)

    assert obj.pk is not None
    saved = PermanentBlock.objects.get(scope_type='user', scope_value='99')
    assert saved.metadata.get('actor') == 'root'


# --- BlockActionsMixin: block/unblock users from a model changelist ----------


class _UserAdmin(BlockActionsMixin, admin.ModelAdmin):
    pass


@pytest.fixture
def user_admin(make_runtime):
    events = []
    runtime_mod._set_runtime(make_runtime(captured=events))
    User = get_user_model()
    return _UserAdmin(User, AdminSite()), User, events


def test_block_and_unblock_selected_users(user_admin):
    model_admin, User, events = user_admin
    u1 = User.objects.create(username='u1')
    u2 = User.objects.create(username='u2')
    queryset = User.objects.filter(pk__in=[u1.pk, u2.pk])

    model_admin.block_selected(_request(), queryset)
    assert is_user_blocked(u1.pk) is not None
    assert is_user_blocked(u2.pk) is not None
    assert model_admin.block_status(u1) == '🚫 Blocked'
    assert [e for e, _ in events if e.event_type == BLOCK_APPLIED]

    model_admin.unblock_selected(_request(), queryset)
    assert is_user_blocked(u1.pk) is None
    assert is_user_blocked(u2.pk) is None
    assert model_admin.block_status(u1) == ''
    assert [e for e, _ in events if e.event_type == BLOCK_REVOKED]


def test_mixin_merges_actions_without_clobbering_delete(user_admin):
    model_admin, _user, _events = user_admin
    actions = model_admin.get_actions(_request())
    assert 'block_selected' in actions
    assert 'unblock_selected' in actions
    assert 'delete_selected' in actions  # default action preserved


def test_registered_action_is_callable_as_admin_invokes_it(user_admin):
    """admin.response_action calls ``func(modeladmin, request, queryset)`` — the
    stored func must be unbound, else it gets a duplicate first arg."""
    model_admin, User, _events = user_admin
    user = User.objects.create(username='via-action')
    func = model_admin.get_actions(_request())['block_selected'][0]
    func(model_admin, _request(), User.objects.filter(pk=user.pk))
    assert is_user_blocked(user.pk) is not None


# --- Block manager custom view: full block/unblock surface (scope + TTL) ------


def _manager_request(method='get', data=None, superuser=True):
    User = get_user_model()
    if superuser:
        user, _ = User.objects.get_or_create(
            username='mgr',
            defaults={'is_staff': True, 'is_superuser': True, 'email': 'm@x.test'},
        )
    else:
        user, _ = User.objects.get_or_create(username='plain')
    req = getattr(RequestFactory(), method)(
        '/admin/sec_audit_enforcement/permanentblock/manage/', data or {}
    )
    req.user = user
    req.session = {}
    req._messages = FallbackStorage(req)
    return req


@pytest.fixture
def block_admin():
    # Uses the real runtime built from test settings (memory store); the autouse
    # reset_enforcement_runtime fixture clears it after each test.
    return PermanentBlockAdmin(PermanentBlock, AdminSite())


def test_manager_view_get_renders_form(block_admin):
    resp = block_admin.block_manager_view(_manager_request('get'))
    assert resp.status_code == 200
    assert 'block_manager.html' in resp.template_name
    assert 'form' in resp.context_data
    assert 'active_blocks' in resp.context_data


def test_manager_view_blocks_temp_with_ttl_and_scope(block_admin):
    resp = block_admin.block_manager_view(
        _manager_request(
            'post',
            {
                'scope_type': 'ip',
                'scope_value': '1.2.3.4',
                'ttl': '600',
                'reason': 'scanner',
                'block': 'Block',
            },
        )
    )
    assert resp.status_code == 302
    entry = is_blocked('ip', '1.2.3.4')
    assert entry is not None
    assert entry.expires_at is not None  # temp block (ttl set)


def test_manager_view_blocks_permanent_user(block_admin):
    block_admin.block_manager_view(
        _manager_request(
            'post', {'scope_type': 'user', 'scope_value': '42', 'block': 'Block'}
        )
    )
    entry = is_blocked('user', '42')
    assert entry is not None
    assert entry.expires_at is None  # permanent (no ttl)


def test_manager_view_unblocks(block_admin):
    block_admin.block_manager_view(
        _manager_request(
            'post', {'scope_type': 'user', 'scope_value': '42', 'block': 'Block'}
        )
    )
    block_admin.block_manager_view(
        _manager_request(
            'post', {'scope_type': 'user', 'scope_value': '42', 'unblock': 'Unblock'}
        )
    )
    assert is_blocked('user', '42') is None


def test_manager_view_requires_permission(block_admin):
    with pytest.raises(PermissionDenied):
        block_admin.block_manager_view(_manager_request('get', superuser=False))
