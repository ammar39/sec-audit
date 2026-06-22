from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence

from sec_audit.core.config import DEFAULT_SENSITIVE_KEYS
from sec_audit.core.events import AuditEvent
from sec_audit.core.projection import ProjectionLimits, project_attributes
from sec_audit.core.scrubbers import scrub
from sec_audit.logging.pipeline import AuditPipeline

INTERNAL_LOGGER_NAME = 'sec_audit.internal'
PROTECTED_ATTRIBUTES = frozenset(
    {'event_type', 'schema_version', 'request_id', 'session.id', 'source.address'}
)


def emit_event(
    logger: logging.Logger,
    event: AuditEvent,
    level: int,
    *,
    pipeline: AuditPipeline | None = None,
    sensitive_keys: Sequence[str] = DEFAULT_SENSITIVE_KEYS,
    value_patterns: Sequence[object] = (),
    allowlist: Sequence[str] = (),
    limits: ProjectionLimits | None = None,
) -> None:
    if isinstance(level, bool) or not isinstance(level, int):
        raise TypeError('level must be an integer logging level.')
    if not isinstance(event, AuditEvent):
        raise TypeError('event must be an AuditEvent.')
    pipeline = pipeline or AuditPipeline()
    event = event.observed()

    for f in pipeline.filters:
        try:
            keep = f.filter(event)
        except Exception:
            _internal_debug('Audit filter raised; treating as pass-through')
            keep = True
        if not keep:
            return

    enriched_attributes: dict[str, object] = {}
    for e in pipeline.enrichers:
        try:
            enriched = e.enrich(event)
        except Exception:
            _internal_debug('Audit enricher failed; skipping')
            continue
        if isinstance(enriched, Mapping):
            for key, value in enriched.items():
                if isinstance(key, str) and key not in PROTECTED_ATTRIBUTES:
                    enriched_attributes[key] = value

    scrubbed = scrub(
        enriched_attributes,
        sensitive_keys=sensitive_keys,
        value_patterns=value_patterns,
        allowlist=allowlist,
    )
    safe = project_attributes(scrubbed, limits=limits)
    # The formatter re-scrubs these additions unconditionally (it is the final
    # emission gate), so no "already sanitized" marker is passed: any record
    # attribute is forgeable in-process, and a second scrub is idempotent.
    logger.log(
        level,
        event.body,
        extra={
            'audit_event': event,
            'audit_attributes': safe,
        },
    )


def _internal_debug(message: str) -> None:
    logging.getLogger(INTERNAL_LOGGER_NAME).debug(message)
