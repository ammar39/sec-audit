# django-sec-audit

[![PyPI version](https://img.shields.io/pypi/v/django-sec-audit.svg)](https://pypi.org/project/django-sec-audit/)
[![Python versions](https://img.shields.io/pypi/pyversions/django-sec-audit.svg)](https://pypi.org/project/django-sec-audit/)
[![License](https://img.shields.io/pypi/l/django-sec-audit.svg)](https://github.com/ammar39/sec-audit/blob/main/LICENSE)
[![GitHub](https://img.shields.io/badge/github-ammar39%2Fsec--audit-blue)](https://github.com/ammar39/sec-audit)

Structured security and audit logging for Django, emitting [OpenTelemetry LogRecord](https://opentelemetry.io/docs/specs/otel/logs/data-model/)-shaped JSONL events.

Captures HTTP request/response metadata, auth events (login, logout, failures), model changes (via django-auditlog), and DRF view metadata out of the box.

## Features

- **HTTP middleware** — automatic capture of requests, responses, status codes, timing, client IP, routes, DRF metadata
- **Auth signals** — automatic logging of `user_logged_in`, `user_logged_out`, `user_login_failed`
- **Model forwarding** — forward django-auditlog entries as structured audit events (optional `[model]` extra)
- **DRF integration** — auto-detects `drf_action`, `drf_view_class`, serializer, auth/permission classes (optional `[drf]` extra)
- **Request body capture** — opt-in JSON body capture with scrubbing and size limits
- **OTel JSONL output** — every event is a single JSON line following the OTel LogRecord envelope, ready for Loki/Grafana
- **Pluggable pipeline** — custom filters and enrichers run before emission

## Dependencies

| Package | Role |
|---------|------|
| `django-sec-audit` (this) | Django integration |
| `sec-audit` | Core (events, context, IP resolution, scrubbing) |
| `sec-audit-logging` | Logging runtime, formatters, SIEM handlers |

## Quick Start

```python
# settings.py

INSTALLED_APPS = [
    'sec_audit.django.apps.SecAuditConfig',   # early, before your apps
    # ...
]

MIDDLEWARE = [
    # ... Django security middleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'sec_audit.django.middleware.AuditMiddleware',  # last or near-last
]

SEC_AUDIT = {
    'core': {
        'source': 'myapp',               # appears as resource.service.name
        'log_request_bodies': False,      # opt-in
        'log_ok_responses': False,        # only 4xx/5xx by default
    },
    'logging': {
        'schema_version': '1.0',
    },
    'django': {
        'include_usernames': False,       # opt-in for GDPR considerations
    },
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        # Injects the resolved SEC_AUDIT config at construction.
        'audit_jsonl': {
            '()': 'sec_audit.django.logging.formatters.audit_jsonl_formatter',
        },
    },
    'handlers': {
        'audit_stdout': {
            'class': 'logging.StreamHandler',
            'formatter': 'audit_jsonl',
        },
    },
    'loggers': {
        'sec_audit.audit': {
            'handlers': ['audit_stdout'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
```

Stdout is the supported delivery path (stdout JSONL -> Grafana Alloy -> Loki).
For local file output, swap the handler for a stdlib
`logging.handlers.RotatingFileHandler` using the same `audit_jsonl` formatter.

## Usage Guide

For a step-by-step setup and configuration walkthrough, see
[docs/how-to-use.md](https://github.com/ammar39/sec-audit/blob/main/packages/django-sec-audit/docs/how-to-use.md).

## Monitoring with Loki/Grafana

Audit events are OTel JSONL, ready to ship to Loki (`sec_audit.audit` JSONL → Grafana
Alloy → Loki → Grafana). The bundled `sec-audit-loki-init` command generates the whole
local stack — see
[docs/loki-setup.md](https://github.com/ammar39/sec-audit/blob/main/packages/django-sec-audit/docs/loki-setup.md).

## Configuration

All settings live under the `SEC_AUDIT` dict in `settings.py`. Three sections are recognised:

### `core` (CoreAuditConfig)

| Setting | Default | Description |
|---------|---------|-------------|
| `source` | `'sec-audit'` | Service name in `resource.service.name` |
| `ignore_paths` | `()` | Regex patterns; matching paths are skipped |
| `ignore_status_codes` | `frozenset()` | Status code values to skip (e.g. `{301, 302}`) |
| `sample_rate` | `1.0` | Sampling rate for successful (2xx) responses |
| `log_ok_responses` | `False` | Enable logging for 2xx responses |
| `log_request_bodies` | `False` | Enable request body capture |
| `log_body_paths` | `()` | Regex patterns; only matching paths capture bodies |
| `body_methods` | `{'POST', 'PUT', 'PATCH'}` | HTTP methods eligible for body capture |
| `max_body_bytes` | `4096` | Maximum JSON body size in bytes |
| `sensitive_keys` | `DEFAULT_SENSITIVE_KEYS` | Built-in key patterns to scrub (incl. `password`, `secret`, `token`, `apikey`, etc.) |
| `sensitive_key_allowlist` | `()` | Exact (compacted) field names never redacted, even when a `sensitive_keys` substring matches — e.g. `credit_card_last4`, `token_expiry` |
| `sensitive_value_patterns` | `()` | Regex patterns matching sensitive values to scrub |

### `logging` (LoggingAuditConfig)

| Setting | Default | Description |
|---------|---------|-------------|
| `schema_version` | `'1.0'` | Schema version string in every event |
| `projection_limits` | `ProjectionLimits()` | Bounds for dict/list nesting and string sizes (accepts a dict or `ProjectionLimits`) |

File-rotation parameters (`maxBytes`/`backupCount`/`filename`) are configured on
the handler in Django's `LOGGING` dict, not here.

### `django` (DjangoAuditConfig)

| Setting | Default | Description |
|---------|---------|-------------|
| `include_usernames` | `False` | Include `user.name` in events (opt-in for GDPR) |
| `trusted_proxy_cidrs` | `()` | CIDR ranges considered trusted proxies |
| `trusted_proxy_count` | `None` | Number of trusted proxies (leftmost N IPs are strip) |
| `emit_session_id` | `False` | Emit correlated `session.id` in events (opt-in; writes to `request.session`) |
| `filters` | `()` | Dotted paths to filter callable/classes |
| `enrichers` | `()` | Dotted paths to enricher callable/classes |

### Event Types

```
auth.login.success        auth.login.failed
auth.logout.success       auth.logout.unknown
http.response.success     http.response.client_error   http.response.server_error
model.create              model.update                 model.delete         model.access
```

## Output Format

Each event is a single JSON line:

```jsonc
{
  "timestamp": 1712345678000000000,
  "observed_timestamp": 1712345678000000000,
  "severity_text": "WARNING",
  "severity_number": 13,
  "body": "http.response",
  "resource": { "service.name": "sec-audit" },
  "instrumentation_scope": { "name": "sec_audit.django.middleware", "version": "1.0.0" },
  "attributes": {
    "event_type": "http.response.client_error",
    "source.address": "203.0.113.10",
    "http.request.method": "POST",
    "http.response.status_code": 404,
    "url.full": "https://example.test/api/transfer",
    "url.path": "/api/transfer",
    "user.id": "42"
  },
  "event_name": "http.response.client_error"
}
```

## Optional Extras

| Extra | Dependencies |
|-------|-------------|
| `pip install django-sec-audit[model]` | django-auditlog |
| `pip install django-sec-audit[drf]` | djangorestframework |
| `pip install django-sec-audit[full]` | Both |

## Development

```bash
pip install -e "packages/django-sec-audit[dev]"
pytest
ruff check .
```

## License

MIT
