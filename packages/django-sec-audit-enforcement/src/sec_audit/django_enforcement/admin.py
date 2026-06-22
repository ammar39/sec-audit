from __future__ import annotations

from django.contrib import admin

from sec_audit.django_enforcement.models import PermanentBlock


@admin.register(PermanentBlock)
class PermanentBlockAdmin(admin.ModelAdmin):
    # Read-only in this release. Manual block/unblock write-actions (which emit
    # audit.enforcement.block_revoked) are a later phase.
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

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
