# sec-audit-logging

Framework-free structured audit logging for the [`sec-audit`](https://github.com/ammar39/sec-audit/tree/main/packages/sec-audit)
core. Emits [OpenTelemetry LogRecord](https://opentelemetry.io/docs/specs/otel/logs/data-model/)-shaped
JSONL — one JSON object per line — ready for Loki/Grafana, Wazuh, or any SIEM.

This package is **Django-free**. For Django integration use
[`django-sec-audit`](https://github.com/ammar39/sec-audit/tree/main/packages/django-sec-audit),
which depends on this package.

## Features

- **OTel JSONL formatter** — `JSONLLogFormatter` renders the OTel LogRecord envelope
  (`timestamp`, `severity_*`, `resource`, `attributes`, …) as a single JSON line.
- **Scrubbing** — sensitive keys/value patterns are redacted before emission; cycle- and
  shared-reference-safe.
- **Projection limits** — bounds nesting depth, string sizes, and record bytes with a
  graceful multi-tier fallback so a single oversized record never breaks the stream.
- **Filter / enricher pipeline** — pluggable callables run before emission.
- **Handlers** — works with stdlib `StreamHandler` (stdout) and `RotatingFileHandler` (file).
- **Loki examples** — ships Grafana Alloy / Loki / Grafana templates and the
  `sec-audit-loki-init` generator.

## Install

```bash
pip install sec-audit-logging
```

## Emitting a record

External packages provide the final primitive logging attributes:

```python
import logging
from sec_audit.logging import emit_log

emit_log(
    logging.getLogger('sec_audit'),
    'payment.checked',
    {'event_type': 'payment.checked', 'schema_version': '1.0', 'payment_id': 'pay-1'},
    logging.INFO,
)
```

Builders return new dicts (immutable); scrubbers return new dicts with sensitive values redacted.

## Loki / Grafana stack generator

The bundled console script copies a ready-to-run monitoring stack (Grafana Alloy → Loki →
Grafana) from the package's canonical templates:

```bash
sec-audit-loki-init monitoring \
  --app-label myapp \
  --environment prod \
  --audit-log-path ../logs/sec-audit.jsonl
```

See the [Loki setup guide](https://github.com/ammar39/sec-audit/blob/main/packages/django-sec-audit/docs/loki-setup.md)
for an end-to-end walkthrough.

## License

MIT
