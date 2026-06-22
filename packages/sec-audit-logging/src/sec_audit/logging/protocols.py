from __future__ import annotations

from typing import Protocol, runtime_checkable
from collections.abc import Mapping

from sec_audit.core.events import AuditEvent


@runtime_checkable
class AuditFilter(Protocol):
    """Decide whether an audit event should be emitted.

    ``filter`` is invoked with an immutable ``AuditEvent``. Returning ``False``
    drops the event. A raised exception is treated as pass-through
    (the event is logged) — a broken filter must never silently drop audit
    records. Exceptions are logged at DEBUG.
    """

    def filter(self, event: AuditEvent) -> bool: ...


@runtime_checkable
class AuditEnricher(Protocol):
    """Augment an audit event with additional attributes.

    ``enrich`` receives an immutable ``AuditEvent`` and must return a NEW
    mapping of additional attributes. A raised exception skips this enricher.
    """

    def enrich(self, event: AuditEvent) -> Mapping[str, object]: ...
