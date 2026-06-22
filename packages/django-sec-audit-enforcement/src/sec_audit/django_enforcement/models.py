from __future__ import annotations

from django.db import models
from django.db.models import Q
from django.utils import timezone

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE


class PermanentBlock(models.Model):
    """Durable, auditable record for a permanent block (the source of truth).

    Temp blocks live only in Redis; this table holds permanent bans so they
    survive a Redis flush and provide the compliance trail (who/why/when/expiry/
    revocation). A revoked row is kept (soft delete) for that trail.
    """

    scope_type = models.CharField(max_length=32)
    scope_value = models.CharField(max_length=255)
    reason = models.CharField(max_length=255, blank=True, default='')
    rule_name = models.CharField(max_length=128, blank=True, default='')
    status_code = models.PositiveSmallIntegerField(default=429)
    message = models.CharField(max_length=255, default=DEFAULT_BLOCK_MESSAGE)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    # Normally null for permanent bans; present only if a durable expiry is set.
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoked_by = models.CharField(max_length=128, blank=True, default='')
    revoked_reason = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        verbose_name = 'permanent block'
        verbose_name_plural = 'permanent blocks'
        constraints = [
            # At most one ACTIVE block per scope. Revoked rows are exempt so the
            # audit history accumulates without blocking a re-ban.
            models.UniqueConstraint(
                fields=['scope_type', 'scope_value'],
                condition=Q(revoked_at__isnull=True),
                name='uniq_active_block_per_scope',
            ),
        ]
        indexes = [
            models.Index(
                fields=['scope_type', 'scope_value', 'revoked_at'],
                name='secenf_active_lookup',
            ),
            models.Index(
                fields=['revoked_at', 'created_at'],
                name='secenf_admin_listing',
            ),
        ]

    def __str__(self) -> str:
        state = 'revoked' if self.revoked_at else 'active'
        return f'{self.scope_type}:{self.scope_value} ({state})'
