# django-sec-audit

Structured security and audit logging for Django, producing OpenTelemetry
LogRecord-shaped JSONL with ready-to-use Grafana Alloy and Loki examples.

## Packages

- `sec-audit`: framework-neutral `AuditEvent`, context, scrubbing, projection,
  and IP helpers.
- `sec-audit-logging`: event projection, JSONL formatting, stdout/file logging
  support, and Grafana Alloy/Loki examples.
- `django-sec-audit`: Django request, auth, DRF, and optional django-auditlog
  extraction.

`django-sec-audit` depends only on Django, `sec-audit`, and
`sec-audit-logging`. It does not depend on `sec-audit-rules`, does not ship
rules/enforcement/block models, and does not create database tables.

## Install

```bash
pip install django-sec-audit
```

Optional integrations:

```bash
pip install 'django-sec-audit[drf]'
pip install 'django-sec-audit[model]'
```

## Django Configuration

```python
INSTALLED_APPS = [
    'sec_audit.django.apps.SecAuditConfig',
    'django.contrib.auth',
    'django.contrib.sessions',
]

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'sec_audit.django.middleware.AuditMiddleware',
]

SEC_AUDIT = {
    'core': {
        'source': 'my-django-service',
        'log_ok_responses': True,
        'sample_rate': 1.0,
    },
    'logging': {
        'schema_version': '1.0',
    },
    'django': {
        'filters': [],
        'enrichers': [],
        'include_usernames': False,
        'trusted_proxy_cidrs': [],
        'trusted_proxy_count': None,
    },
}
```

## Stdout Logging

Stdout is the recommended production path. Let the platform collector or
Grafana Alloy handle buffering and Loki delivery.

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'audit_stdout': {
            'class': 'logging.StreamHandler',
            'formatter': 'audit_jsonl',
        },
        'console': {'class': 'logging.StreamHandler'},
    },
    'formatters': {
        # The Django factory injects the resolved SEC_AUDIT core config +
        # projection limits at construction (so resource.service.name matches
        # SEC_AUDIT['core']['source']).
        'audit_jsonl': {
            '()': 'sec_audit.django.logging.formatters.audit_jsonl_formatter'
        },
    },
    'loggers': {
        'sec_audit.audit': {
            'handlers': ['audit_stdout'],
            'level': 'INFO',
            'propagate': False,
        },
        'sec_audit.internal': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
```

`sec_audit.audit` emits structured audit records. `sec_audit.internal` is for
bounded package diagnostics and should not share audit output handlers.

## JSONL File Logging

Stdout is the supported path. For local file output, use a stdlib
`RotatingFileHandler` with the same `audit_jsonl` formatter:

```python
LOGGING['handlers']['audit_file'] = {
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': 'logs/sec-audit.jsonl',
    'maxBytes': 10 * 1024 * 1024,
    'backupCount': 3,
    'formatter': 'audit_jsonl',
}
LOGGING['loggers']['sec_audit.audit']['handlers'] = ['audit_file']
```

A queue-backed `sec_audit.logging._sinks.QueuedJSONLHandler` /
supported surface): it makes no durability, fork-safety, or cross-process
ordering guarantees and may change or be removed.

## Event Shape

Every audit line is an OpenTelemetry LogRecord-shaped JSON object:

```json
{
  "timestamp": 1712345678000000000,
  "observed_timestamp": 1712345678001000000,
  "severity_text": "WARNING",
  "severity_number": 13,
  "body": "http.response",
  "resource": {"service.name": "my-django-service"},
  "instrumentation_scope": {"name": "sec_audit.django"},
  "attributes": {
    "event_type": "http.response.client_error",
    "schema_version": "1.0",
    "request_id": "req-1",
    "source.address": "203.0.113.10",
    "http.request.method": "POST",
    "http.response.status_code": 404,
    "url.path": "/api/transfers",
    "duration_ns": 1200000
  },
  "event_name": "http.response.client_error"
}
```

`SEC_AUDIT['logging']['schema_version']` is used when Django creates the
`AuditEvent`. After construction, `AuditEvent.schema_version` is authoritative;
formatters do not replace it from configuration.

## Safety Defaults

- `url.path` excludes query strings, and query parameters are not logged.
- Forwarded IP headers are ignored unless `trusted_proxy_cidrs` and
  `trusted_proxy_count` are explicitly configured and the immediate
  `REMOTE_ADDR` is trusted.
- Body capture is disabled by default. When enabled, only bounded JSON requests
  with valid `CONTENT_LENGTH` are read; multipart, form, file upload, streaming,
  missing-length, invalid-length, negative-length, and oversized bodies are
  skipped.
- Stable `user.id` is emitted by default. Usernames, email addresses, login
  identifiers, display names, and model actors require
  `include_usernames=True`.
- django-auditlog model events emit changed field names only, not raw
  before/after values.
- Malformed records produce a bounded
  `audit.logging.malformed_record` fallback without original arbitrary
  attributes, exception arguments, locals, or secrets.

## Events

- `http.response.success`
- `http.response.client_error`
- `http.response.server_error`
- `auth.login.success`
- `auth.login.failed`
- `auth.logout.success`
- `auth.logout.unknown`
- `model.create`
- `model.update`
- `model.delete`

Each Django request emits at most one HTTP response audit event. Authentication
and model signals may emit their own separate domain records.

## Loki

Use Grafana Alloy rather than a Python Loki client.

Primary path:

```text
Django -> stdout JSONL -> Grafana Alloy -> Loki -> Grafana
```

Secondary path:

```text
Django -> JSONL file -> Grafana Alloy -> Loki -> Grafana
```

Examples live under `examples/`:

- `examples/alloy/stdout-to-loki.alloy`
- `examples/alloy/file-to-loki.alloy`
- `examples/docker-compose/compose.yml`
- `examples/grafana/dashboard.json`
- `examples/logql/examples.md`

Alloy labels only `service_name`, `environment`, `severity`, and `event_type`.
Request IDs, user IDs, session IDs, source addresses, paths, routes, and object
IDs remain in the JSON body.

## Development

```bash
source .venv/bin/activate
pip install -e packages/sec-audit -e packages/sec-audit-logging -e 'packages/django-sec-audit[full,dev]'
pytest -q
ruff check .
ruff format --check .
```

Build order:

1. `sec-audit`
2. `sec-audit-logging`
3. `django-sec-audit`
