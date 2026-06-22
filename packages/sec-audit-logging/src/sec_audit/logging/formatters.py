from __future__ import annotations

import json
import logging
import math
import time
from functools import lru_cache
from importlib import metadata

from sec_audit.core.config import MAX_SOURCE_LENGTH, CoreAuditConfig
from sec_audit.core.events import AuditEvent
from sec_audit.core.projection import (
    ProjectionLimits,
    project_attributes,
)
from sec_audit.core.scrubbers import scrub
from sec_audit.logging.emission import PROTECTED_ATTRIBUTES

_NANOS_PER_SECOND = 1_000_000_000
DEFAULT_PACKAGE_NAME = 'sec_audit.logging'
MALFORMED_EVENT_TYPE = 'audit.logging.malformed_record'
# The minimal fallback keeps the service name and schema for triage, but they
# are the only variable-length fields, so bound them. With these caps the
# minimal record serializes well under MIN_RECORD_BYTES (1024) — the floor
# ``ProjectionLimits`` enforces for ``max_record_bytes`` — so it fits any valid
# limit. The fixed last-resort record carries no variable content at all.
_FALLBACK_SOURCE_MAX = MAX_SOURCE_LENGTH
_FALLBACK_SCHEMA_MAX = 64
# OTel instrumentation-scope name -> installed distribution, for version lookup.
# The scope name identifies the emitting package (sec_audit.logging for the
# standalone formatter, sec_audit.django for the Django factory), not the logger.
_DIST_FOR_SCOPE = {
    'sec_audit.logging': 'sec-audit-logging',
    'sec_audit.django': 'django-sec-audit',
    'sec_audit.core': 'sec-audit',
}


@lru_cache(maxsize=None)
def _package_version(package_name: str) -> str:
    dist = _DIST_FOR_SCOPE.get(package_name, package_name)
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return ''


def severity_number(levelno: int) -> int:
    if levelno >= logging.CRITICAL:
        return 21
    if levelno >= logging.ERROR:
        return 17
    if levelno >= logging.WARNING:
        return 13
    if levelno >= logging.INFO:
        return 9
    if levelno >= logging.DEBUG:
        return 5
    if levelno > logging.NOTSET:
        return 1
    return 0


def _timestamp_nanos(record: logging.LogRecord) -> int:
    created = getattr(record, 'created', None)
    if isinstance(created, (int, float)) and math.isfinite(created) and created >= 0:
        return int(created * _NANOS_PER_SECOND)
    return time.time_ns()


def _resource(config: CoreAuditConfig, source: str | None) -> dict:
    return {
        'service.name': source or config.source,
    }


def _instrumentation_scope(package_name: str) -> dict:
    # OTel scope name is the emitting package identifier, NOT the Python logger
    # name (which is the application's audit logger, e.g. 'sec_audit.audit').
    scope = {'name': package_name or 'sec_audit'}
    version = _package_version(package_name)
    if version:
        scope['version'] = version
    return scope


def _trace_context(record: logging.LogRecord) -> dict:
    fields = {}
    trace_id = getattr(record, 'otelTraceID', None)
    span_id = getattr(record, 'otelSpanID', None)
    trace_sampled = getattr(record, 'otelTraceSampled', None)
    if trace_id:
        fields['trace_id'] = str(trace_id)
    if span_id:
        fields['span_id'] = str(span_id)
    if trace_sampled is not None:
        fields['trace_flags'] = 1 if bool(trace_sampled) else 0
    return fields


def _record_audit_fields(
    record: logging.LogRecord,
) -> tuple[AuditEvent, str, dict]:
    event = getattr(record, 'audit_event', None)
    if not isinstance(event, AuditEvent):
        raise TypeError('record.audit_event must be an AuditEvent.')
    attributes = getattr(record, 'audit_attributes', None)
    if attributes is None:
        attributes = {}
    if not isinstance(attributes, dict):
        raise TypeError('record.audit_attributes must be a dict.')
    return event, event.body, dict(attributes)


def build_log_record(
    record: logging.LogRecord,
    *,
    config: CoreAuditConfig | None = None,
    source: str | None = None,
    formatter: logging.Formatter | None = None,
    package_name: str = DEFAULT_PACKAGE_NAME,
    limits: ProjectionLimits | None = None,
) -> dict:
    config = config or CoreAuditConfig()
    if source is None:
        source = getattr(record, 'resource_source', None)
    limits = limits or ProjectionLimits()
    event_obj, msg, additions = _record_audit_fields(record)
    attributes = dict(event_obj.attributes)
    additions = {
        key: value
        for key, value in additions.items()
        if isinstance(key, str) and key not in PROTECTED_ATTRIBUTES
    }
    # The formatter is the final emission gate. Always scrub + project the
    # attributes so no path (the emit pipeline, raw audit_attributes, or an
    # audit_event paired with unsanitized attributes) can leak secrets or
    # non-JSON values. Scrub and projection are idempotent on already-safe data.
    attributes = project_attributes(
        scrub(
            attributes,
            sensitive_keys=config.sensitive_keys,
            value_patterns=config.sensitive_value_patterns,
            allowlist=config.sensitive_key_allowlist,
        ),
        limits=limits,
    )
    # Additions (enrichment from emit_event, or raw audit_attributes on a
    # hand-built record) are scrubbed + projected here unconditionally. The
    # formatter is the final emission gate: there is no skip-marker, because any
    # record attribute is forgeable in-process, and a second scrub is idempotent
    # on already-safe data — the CPU cost buys an unconditional guarantee.
    projected_additions = project_attributes(
        scrub(
            additions,
            sensitive_keys=config.sensitive_keys,
            value_patterns=config.sensitive_value_patterns,
            allowlist=config.sensitive_key_allowlist,
        ),
        limits=limits,
    )
    attributes.update(projected_additions)
    attributes['event_type'] = event_obj.event_type
    attributes['schema_version'] = event_obj.schema_version
    for key in ('request_id', 'session.id', 'source.address'):
        if key in event_obj.attributes:
            attributes[key] = project_attributes(
                {key: event_obj.attributes[key]},
                limits=limits,
            )[key]
    # ``msg`` is a bare string, so only value patterns apply (keys are
    # irrelevant for a top-level string) — but a secret embedded in the body
    # would otherwise reach the emitted record unredacted.
    msg = scrub(
        msg,
        sensitive_keys=config.sensitive_keys,
        value_patterns=config.sensitive_value_patterns,
        allowlist=config.sensitive_key_allowlist,
    )
    timestamp = event_obj.timestamp_ns
    observed = (
        event_obj.observed_timestamp_ns
        if event_obj.observed_timestamp_ns is not None
        else _timestamp_nanos(record)
    )

    event = {
        'timestamp': timestamp,
        'observed_timestamp': observed,
        'severity_text': record.levelname,
        'severity_number': severity_number(record.levelno),
        'body': msg,
        'resource': _resource(config, source),
        'instrumentation_scope': _instrumentation_scope(package_name),
        'attributes': attributes,
    }
    event['event_name'] = event_obj.event_type
    event.update(_trace_context(record))
    return event


def _fallback_record(
    record: logging.LogRecord,
    *,
    config: CoreAuditConfig,
    source: str | None,
    package_name: str,
) -> dict:
    event_obj = getattr(record, 'audit_event', None)
    schema_version = (
        event_obj.schema_version if isinstance(event_obj, AuditEvent) else 'unknown'
    )
    attributes = {
        'event_type': MALFORMED_EVENT_TYPE,
        'schema_version': schema_version,
    }
    ts = _timestamp_nanos(record)
    return {
        'timestamp': ts,
        'observed_timestamp': ts,
        'severity_text': 'ERROR',
        'severity_number': severity_number(logging.ERROR),
        'body': MALFORMED_EVENT_TYPE,
        'resource': _resource(config, source),
        'instrumentation_scope': _instrumentation_scope(package_name),
        'attributes': attributes,
        'event_name': MALFORMED_EVENT_TYPE,
    }


class JSONLLogFormatter(logging.Formatter):
    def __init__(
        self,
        *args,
        config: CoreAuditConfig | None = None,
        source: str | None = None,
        compact: bool = False,
        package_name: str = DEFAULT_PACKAGE_NAME,
        limits: ProjectionLimits | None = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.config = config or CoreAuditConfig()
        self.source = source
        self.compact = compact
        self.package_name = package_name
        self.limits = limits or ProjectionLimits()

    def format_to_dict(self, record: logging.LogRecord) -> dict:
        try:
            return build_log_record(
                record,
                config=self.config,
                source=self.source,
                formatter=self,
                package_name=self.package_name,
                limits=self.limits,
            )
        except Exception:
            logging.getLogger('sec_audit.internal').debug(
                'Failed to format audit record'
            )
            return _fallback_record(
                record,
                config=self.config,
                source=self.source,
                package_name=self.package_name,
            )

    def format(self, record: logging.LogRecord) -> str:
        separators = (',', ':') if self.compact else None
        limit = self.limits.max_record_bytes
        try:
            payload = self.format_to_dict(record)
            line = json.dumps(
                payload,
                allow_nan=False,
                separators=separators,
            )
            if _encoded_len(line) <= limit:
                return line
        except Exception:
            pass
        fallback = _fallback_record(
            record,
            config=self.config,
            source=self.source,
            package_name=self.package_name,
        )
        line = json.dumps(fallback, allow_nan=False, separators=separators)
        if _encoded_len(line) <= limit:
            return line
        minimal = _minimal_fallback_record(
            record, config=self.config, source=self.source
        )
        line = json.dumps(minimal, allow_nan=False, separators=separators)
        if _encoded_len(line) <= limit:
            return line
        # Guaranteed-fit floor: ``max_record_bytes`` is validated to be at least
        # MIN_RECORD_BYTES and this fixed record serializes well below it, so the
        # returned line always fits the configured limit.
        return json.dumps(
            _last_resort_record(record), allow_nan=False, separators=separators
        )


def _encoded_len(value: str) -> int:
    return len(value.encode('utf-8'))


def _minimal_fallback_record(
    record: logging.LogRecord,
    *,
    config: CoreAuditConfig,
    source: str | None,
) -> dict:
    event_obj = getattr(record, 'audit_event', None)
    schema_version = (
        event_obj.schema_version if isinstance(event_obj, AuditEvent) else 'unknown'
    )
    # service name and schema are the only variable-length fields; bound both so
    # the record is guaranteed to serialize below the max_record_bytes floor.
    service_name = str(source or config.source)[:_FALLBACK_SOURCE_MAX]
    ts = _timestamp_nanos(record)
    return {
        'timestamp': ts,
        'observed_timestamp': ts,
        'severity_text': 'ERROR',
        'severity_number': severity_number(logging.ERROR),
        'body': MALFORMED_EVENT_TYPE,
        'resource': {'service.name': service_name},
        'attributes': {
            'event_type': MALFORMED_EVENT_TYPE,
            'schema_version': str(schema_version)[:_FALLBACK_SCHEMA_MAX],
        },
        'event_name': MALFORMED_EVENT_TYPE,
    }


def _last_resort_record(record: logging.LogRecord) -> dict:
    # No variable-length content: only bounded ints and fixed constants. This
    # serializes to a few hundred bytes regardless of input, so it always fits a
    # valid (>= MIN_RECORD_BYTES) limit and is the guaranteed-fit last resort.
    ts = _timestamp_nanos(record)
    return {
        'timestamp': ts,
        'observed_timestamp': ts,
        'severity_text': 'ERROR',
        'severity_number': severity_number(logging.ERROR),
        'body': MALFORMED_EVENT_TYPE,
        'attributes': {'event_type': MALFORMED_EVENT_TYPE},
        'event_name': MALFORMED_EVENT_TYPE,
    }
