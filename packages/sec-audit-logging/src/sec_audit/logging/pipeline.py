from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sec_audit.logging.protocols import AuditEnricher, AuditFilter


@dataclass(frozen=True)
class AuditPipeline:
    """Immutable, ordered set of audit extensions.

    Owned by ``LoggingRuntime`` and threaded through ``emit_event``. Stages run
    in declaration order:

        filters  ->  enrichers  ->  restore protected attrs  ->  scrub/project

    Failure isolation (enforced by ``emit_event``):

    * A ``filter`` returning ``False`` drops the event.
    * A ``filter`` raising passes through (event is logged).
    * An ``enricher`` raising is skipped; prior attributes are kept.
    """

    filters: tuple[AuditFilter, ...] = ()
    enrichers: tuple[AuditEnricher, ...] = ()

    @classmethod
    def from_sequences(
        cls,
        filters: Sequence[AuditFilter] = (),
        enrichers: Sequence[AuditEnricher] = (),
    ) -> AuditPipeline:
        """Build a pipeline from arbitrary sequences (copied into tuples)."""
        return cls(
            filters=tuple(filters),
            enrichers=tuple(enrichers),
        )
