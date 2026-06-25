"""Django ORM block store — the durable source of truth for permanent blocks.

Only permanent bans live here (temp bans are Redis-only). Revocation is a soft
delete (``revoked_at``) so the table is the auditable trail of who/why/when.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE, BlockEntry, BlockScope

from sec_audit.django_enforcement.stores.base import BlockStoreError


class PostgresBlockStore:
    demo_only = False

    def __init__(self) -> None:
        # Imported here (not at module level) so importing the stores package
        # never touches the app registry before Django is ready.
        from sec_audit.django_enforcement.models import PermanentBlock

        self._model = PermanentBlock

    def _active_qs(self):
        return self._model.objects.filter(revoked_at__isnull=True).exclude(
            expires_at__lte=timezone.now()
        )

    def block(
        self,
        scope: BlockScope,
        *,
        reason: str = '',
        rule_name: str = '',
        status_code: int = 429,
        message: str = DEFAULT_BLOCK_MESSAGE,
        ttl: int | None = None,
        metadata=None,
    ) -> BlockEntry:
        expires_at = (
            timezone.now() + timezone.timedelta(seconds=int(ttl))
            if ttl is not None
            else None
        )
        defaults = {
            'reason': reason,
            'rule_name': rule_name,
            'status_code': int(status_code),
            'message': message,
            'metadata': dict(metadata or {}),
            'expires_at': expires_at,
        }
        try:
            # The partial unique constraint guarantees at most one active row.
            # update_or_create inside a transaction takes the row lock and keeps
            # the check+write atomic, so two concurrent re-bans of the same scope
            # can't both miss-then-create. The IntegrityError catch is the
            # belt-and-suspenders fallback for a genuinely-racing insert.
            with transaction.atomic():
                row, _ = self._model.objects.update_or_create(
                    scope_type=scope.scope_type,
                    scope_value=scope.scope_value,
                    revoked_at__isnull=True,
                    defaults=defaults,
                )
        except IntegrityError as exc:
            raise BlockStoreError(
                'Postgres block write failed (concurrent block).'
            ) from exc
        except DatabaseError as exc:
            raise BlockStoreError('Postgres block write failed.') from exc
        return _row_to_entry(row)

    def unblock(
        self, scope: BlockScope, *, reason: str = '', revoked_by: str = ''
    ) -> int:
        try:
            return self._model.objects.filter(
                scope_type=scope.scope_type,
                scope_value=scope.scope_value,
                revoked_at__isnull=True,
            ).update(
                revoked_at=timezone.now(),
                revoked_reason=reason,
                revoked_by=revoked_by,
            )
        except DatabaseError as exc:
            raise BlockStoreError('Postgres block revoke failed.') from exc

    def get_active(self, scope: BlockScope) -> BlockEntry | None:
        try:
            row = (
                self._active_qs()
                .filter(scope_type=scope.scope_type, scope_value=scope.scope_value)
                .first()
            )
        except DatabaseError as exc:
            raise BlockStoreError('Postgres block read failed.') from exc
        return _row_to_entry(row) if row is not None else None

    def first_active(self, scopes: Sequence[BlockScope]) -> BlockEntry | None:
        scopes = tuple(scopes)
        if not scopes:
            return None
        query = Q()
        for scope in scopes:
            query |= Q(scope_type=scope.scope_type, scope_value=scope.scope_value)
        try:
            rows = list(self._active_qs().filter(query))
        except DatabaseError as exc:
            raise BlockStoreError('Postgres block lookup failed.') from exc
        # Preserve caller (precedence) order: first scope with an active row wins.
        by_key = {(r.scope_type, r.scope_value): r for r in rows}
        for scope in scopes:
            row = by_key.get((scope.scope_type, scope.scope_value))
            if row is not None:
                return _row_to_entry(row)
        return None

    def active_blocks(self) -> Iterable[BlockEntry]:
        try:
            rows = list(self._active_qs())
        except DatabaseError as exc:
            raise BlockStoreError('Postgres active-block scan failed.') from exc
        return [_row_to_entry(row) for row in rows]


def _row_to_entry(row) -> BlockEntry:
    return BlockEntry(
        scope=BlockScope(scope_type=row.scope_type, scope_value=row.scope_value),
        reason=row.reason,
        rule_name=row.rule_name,
        status_code=int(row.status_code),
        message=row.message,
        created_at=row.created_at,
        expires_at=row.expires_at,
        metadata=dict(row.metadata or {}),
    )
