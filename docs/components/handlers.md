# Handlers

`sec_audit.logging` owns OpenTelemetry LogRecord-shaped JSONL projection and
formatting.

Recommended production delivery is standard Python stdout logging from
`sec_audit.audit`, with Grafana Alloy or platform collectors handling buffering
and Loki delivery.

For local file output, use a stdlib `logging.handlers.RotatingFileHandler` with
the canonical JSONL formatter (the Django `audit_jsonl_formatter` factory, or
`JSONLLogFormatter` directly). A queue-backed `QueuedJSONLHandler` /
file-permission checks and POSIX locking where supported, and claims no durable
delivery, fork safety, cross-process ordering, or rotating-file durability.

HTTP and TCP SIEM handlers are not shipped. For remote delivery, use stdout
JSONL consumed by Grafana Alloy or a platform collector.

Diagnostics use `sec_audit.internal` and must not be routed through audit
output handlers.
