from __future__ import annotations

from django import forms
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path
from django.utils import timezone

from sec_audit.django_enforcement.api import (
    block_subject,
    is_blocked,
    list_active_blocks,
    list_temp_blocks,
    unblock_subject,
)
from sec_audit.django_enforcement.models import PermanentBlock
from sec_audit.django_enforcement.runtime import get_enforcement_runtime
from sec_audit.django_enforcement.stores import BlockStoreError

# Fields an operator sets when manually creating a block (permanent only).
_ADD_FIELDS = (
    'scope_type',
    'scope_value',
    'reason',
    'rule_name',
    'status_code',
    'message',
)

# Fallback scope choices when the runtime/registry can't be reached.
_DEFAULT_SCOPE_CHOICES = ('user', 'session', 'ip')


def _block_scope_choices() -> list[tuple[str, str]]:
    """Block-eligible scope names from the runtime registry (user/session/ip + any
    custom scopes), falling back to the built-in defaults."""
    names: list[str] = []
    try:
        registry = get_enforcement_runtime().scope_registry
        names = [
            d.name for d in registry.definitions if getattr(d, 'block_eligible', True)
        ]
    except Exception:
        names = []
    if not names:
        names = list(_DEFAULT_SCOPE_CHOICES)
    return [(name, name) for name in names]


# Fields an Edit button may carry over to prefill the block form.
_PREFILL_FIELDS = (
    'scope_type',
    'scope_value',
    'ttl',
    'reason',
    'status_code',
    'message',
)


def _prefill_from_get(get) -> dict | None:
    """Build form ``initial`` from an Edit button's query params, or ``None``.

    Gated on ``scope_value`` so a plain GET of the page renders an empty form.
    """
    if not get.get('scope_value'):
        return None
    return {f: get[f] for f in _PREFILL_FIELDS if get.get(f)}


def _temp_block_rows(entries) -> list[dict]:
    """Pair each temp ``BlockEntry`` with its remaining TTL (seconds) for display
    and for the Edit button's prefilled TTL."""
    now = timezone.now()
    rows = []
    for entry in entries:
        remaining = None
        if entry.expires_at is not None:
            remaining = max(1, int((entry.expires_at - now).total_seconds()))
        rows.append({'entry': entry, 'remaining_ttl': remaining})
    return rows


class BlockManagerForm(forms.Form):
    """Full block surface: any scope, optional TTL (temp vs permanent), and the
    optional status/message overrides."""

    scope_type = forms.ChoiceField()
    scope_value = forms.CharField(max_length=255)
    ttl = forms.IntegerField(
        label='TTL (seconds)',
        required=False,
        min_value=1,
        help_text='Seconds. Leave blank for a permanent block.',
    )
    reason = forms.CharField(max_length=255, required=False)
    status_code = forms.IntegerField(
        required=False,
        min_value=100,
        max_value=599,
        help_text='Blank uses the configured default (e.g. 429).',
    )
    message = forms.CharField(max_length=255, required=False)

    def __init__(self, *args, scope_choices=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['scope_type'].choices = scope_choices or [
            (name, name) for name in _DEFAULT_SCOPE_CHOICES
        ]


class BlockActionsMixin:
    """Admin mixin: "Block selected" / "Unblock selected" changelist actions.

    Mix into any ``ModelAdmin`` whose rows map to a block scope to let operators
    block/unblock subjects straight from the list (e.g. a ``UserAdmin``). Actions
    route through the block-management utils, so the Redis write-through cache and
    the ``audit.enforcement.*`` events fire. Blocks are permanent (stay until
    unblocked).

    Configure via ``block_scope_type`` (default ``'user'``) and
    ``block_scope_value`` (default ``str(obj.pk)``). For the ``user`` scope the pk
    matches the ban dimension enforcement derives at ingress, so a blocked subject
    is actually denied on its next request.
    """

    block_scope_type = 'user'
    block_reason = 'Blocked via admin'

    def block_scope_value(self, obj) -> str:
        return str(obj.pk)

    def get_actions(self, request):
        # Merge onto the existing actions (keeps delete_selected / any consumer
        # actions); never replace the class `actions` attribute. Store the UNBOUND
        # function (``.__func__``) — admin's response_action calls it as
        # ``func(modeladmin, request, queryset)``, so a bound method would get a
        # duplicate first arg.
        actions = super().get_actions(request)
        for name in ('block_selected', 'unblock_selected'):
            func = getattr(self, name).__func__
            actions[name] = (func, name, func.short_description)
        return actions

    @admin.action(description='Block selected')
    def block_selected(self, request, queryset):
        count = 0
        for obj in queryset:
            block_subject(
                self.block_scope_type,
                self.block_scope_value(obj),
                reason=self.block_reason,
                actor=request.user.get_username(),
            )
            count += 1
        self.message_user(request, f'Blocked {count} subject(s).', messages.SUCCESS)

    @admin.action(description='Unblock selected')
    def unblock_selected(self, request, queryset):
        revoked = 0
        for obj in queryset:
            revoked += unblock_subject(
                self.block_scope_type,
                self.block_scope_value(obj),
                reason='Unblocked via admin',
                revoked_by=request.user.get_username(),
            )
        self.message_user(request, f'Unblocked {revoked} subject(s).', messages.SUCCESS)

    @admin.display(description='Block status')
    def block_status(self, obj) -> str:
        # Per-row lookup — fine at admin page size. Add to `list_display` to show.
        return (
            '🚫 Blocked'
            if is_blocked(self.block_scope_type, self.block_scope_value(obj))
            else ''
        )


@admin.register(PermanentBlock)
class PermanentBlockAdmin(admin.ModelAdmin):
    # Create + revoke are routed through the block-management utils (block_subject /
    # unblock_subject) so the Redis write-through cache and the audit.enforcement.*
    # events fire — a raw obj.save()/delete() would bypass both. Existing rows are
    # never field-editable and never hard-deleted (revoke is a soft delete).
    list_display = (
        'scope_type',
        'scope_value',
        'rule_name',
        'reason',
        'created_at',
        'revoked_at',
    )
    list_filter = ('scope_type', 'rule_name', 'revoked_at')
    search_fields = ('scope_value', 'rule_name', 'reason')
    list_per_page = 50
    ordering = ('-created_at',)
    actions = ('revoke_blocks',)

    # --- "Block manager" custom view: the full block/unblock surface ----------

    def get_urls(self):
        manage = self.admin_site.admin_view(self.block_manager_view)
        custom = [
            path(
                'manage/',
                manage,
                name='sec_audit_enforcement_permanentblock_manage',
            )
        ]
        return custom + super().get_urls()

    def _can_manage(self, request) -> bool:
        return request.user.has_perm('sec_audit_enforcement.add_permanentblock')

    def block_manager_view(self, request):
        """Admin-only page to block/unblock any subject with full options (scope,
        TTL, status, message). Routes through the block-management utils."""
        if not self._can_manage(request):
            raise PermissionDenied
        actor = request.user.get_username()

        if request.method == 'POST' and 'unblock' in request.POST:
            # Main-form Unblock and the per-row inline buttons both post the scope.
            scope_type = request.POST.get('scope_type', '').strip()
            scope_value = request.POST.get('scope_value', '').strip()
            if scope_type and scope_value:
                count = unblock_subject(
                    scope_type,
                    scope_value,
                    reason='Unblocked via admin',
                    revoked_by=actor,
                )
                messages.success(
                    request,
                    f'Unblocked {count} block(s) for {scope_type}:{scope_value}.',
                )
            else:
                messages.error(request, 'Unblock needs a scope type and value.')
            return HttpResponseRedirect(request.path)

        choices = _block_scope_choices()
        editing_subject = ''
        if request.method == 'POST':
            form = BlockManagerForm(request.POST, scope_choices=choices)
            if form.is_valid():
                data = form.cleaned_data
                # Re-blocking an existing scope overwrites it, so the same path
                # serves both "add" and "edit" (the Edit buttons just prefill it).
                block_subject(
                    data['scope_type'],
                    data['scope_value'],
                    reason=data['reason'],
                    ttl=data['ttl'] or None,
                    status_code=data['status_code'],
                    message=data['message'] or None,
                    actor=actor,
                )
                kind = 'temp' if data['ttl'] else 'permanent'
                messages.success(
                    request,
                    f'Blocked {data["scope_type"]}:{data["scope_value"]} ({kind}).',
                )
                return HttpResponseRedirect(request.path)
        else:
            # An Edit button links here with the row's fields as query params to
            # prefill the form; the operator adjusts and re-blocks to overwrite.
            initial = _prefill_from_get(request.GET)
            form = BlockManagerForm(initial=initial, scope_choices=choices)
            if initial:
                editing_subject = f'{initial["scope_type"]}:{initial["scope_value"]}'

        # Temp blocks need a Redis SCAN; isolate a backend error so the page
        # (and the permanent-block surface) still renders.
        try:
            temp_blocks = _temp_block_rows(list_temp_blocks())
            temp_blocks_error = False
        except BlockStoreError:
            temp_blocks = []
            temp_blocks_error = True

        context = {
            **self.admin_site.each_context(request),
            'title': 'Block manager',
            'opts': self.model._meta,
            'form': form,
            'editing_subject': editing_subject,
            'active_blocks': list_active_blocks(),
            'temp_blocks': temp_blocks,
            'temp_blocks_error': temp_blocks_error,
        }
        return TemplateResponse(
            request,
            'admin/sec_audit_enforcement/permanentblock/block_manager.html',
            context,
        )

    def get_fields(self, request, obj=None):
        # Restrict the add form to the operator-settable fields; the change view
        # shows everything (read-only via get_readonly_fields).
        if obj is None:
            return _ADD_FIELDS
        return super().get_fields(request, obj)

    def get_readonly_fields(self, request, obj=None):
        # Existing blocks are viewable but never editable (to change a block:
        # revoke it and create a new one).
        if obj is not None:
            return [field.name for field in self.model._meta.fields]
        return super().get_readonly_fields(request, obj)

    def has_add_permission(self, request):
        return request.user.has_perm('sec_audit_enforcement.add_permanentblock')

    def has_change_permission(self, request, obj=None):
        # Gate the change view + the revoke_blocks action on the real change
        # permission. Edits are still blocked via get_readonly_fields + a no-op
        # save_model on change; this only controls who may reach the change view
        # and run revoke. The changelist stays readable for view-only staff via
        # the default has_view_permission.
        return request.user.has_perm('sec_audit_enforcement.change_permanentblock')

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        if change:
            return  # all fields are read-only on the change view; nothing to save
        # Route creation through the shared util (Redis write-through + block_applied
        # event), then load the persisted active row's pk so the post-add redirect
        # links to it.
        entry = block_subject(
            obj.scope_type,
            obj.scope_value,
            reason=obj.reason,
            rule_name=obj.rule_name or 'manual',
            ttl=None,
            status_code=obj.status_code or 429,
            message=obj.message or '',
            actor=request.user.get_username(),
        )
        saved = (
            PermanentBlock.objects.filter(
                scope_type=entry.scope.scope_type,
                scope_value=entry.scope.scope_value,
                revoked_at__isnull=True,
            )
            .order_by('-created_at')
            .first()
        )
        if saved is not None:
            obj.pk = saved.pk
            return
        # Memory-only deployments (no Postgres tier) don't create a durable row,
        # so persist one here from the entry — the model is the admin's record of
        # the block, and a real pk lets the admin redirect/link work.
        obj.rule_name = entry.rule_name
        obj.status_code = entry.status_code
        obj.message = entry.message
        obj.metadata = dict(entry.metadata or {})
        obj.expires_at = entry.expires_at
        super().save_model(request, obj, form, change)

    @admin.action(description='Revoke selected blocks', permissions=['change'])
    def revoke_blocks(self, request, queryset):
        revoked = 0
        for row in queryset.filter(revoked_at__isnull=True):
            revoked += unblock_subject(
                row.scope_type,
                row.scope_value,
                reason='Revoked via admin',
                revoked_by=request.user.get_username(),
            )
        self.message_user(request, f'Revoked {revoked} block(s).', messages.SUCCESS)
