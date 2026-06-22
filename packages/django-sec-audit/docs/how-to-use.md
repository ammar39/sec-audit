# django-sec-audit — How To Use

## Installation

```bash
pip install django-sec-audit
```

For optional extras:

```bash
pip install "django-sec-audit[drf]"       # DRF metadata
pip install "django-sec-audit[model]"      # django-auditlog model forwarding
pip install "django-sec-audit[full]"       # both
```

---

## 1. Minimal Setup (HTTP audit only)

Add the app and middleware to your Django settings:

```python
INSTALLED_APPS = [
    'sec_audit.django.apps.SecAuditConfig',   # must be early
    # ... your apps
]

MIDDLEWARE = [
    # ... Django stock middleware (Security, Session, Auth, CSRF, etc.)
    'sec_audit.django.middleware.AuditMiddleware',
]

SEC_AUDIT = {
    'core': {
        'source': 'myapp',               # identifies the service in logs
        'log_ok_responses': False,       # only 4xx/5xx (default)
    },
    'logging': {
        'schema_version': '1.0',
    },
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'audit_jsonl': {
            '()': 'sec_audit.django.logging.formatters.audit_jsonl_formatter',
        },
    },
    'handlers': {
        'audit_stdout': {
            'class': 'logging.StreamHandler',
            'formatter': 'audit_jsonl',
            'level': 'INFO',
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

Every HTTP 4xx/5xx response is now written as a JSON line to stdout (collect it
with Grafana Alloy or a platform collector). For local file output, swap
`audit_stdout` for a stdlib `logging.handlers.RotatingFileHandler` using the same
`audit_jsonl` formatter.

---

## 2. Including 2xx Responses

```python
SEC_AUDIT = {
    'core': {
        'log_ok_responses': True,
        'sample_rate': 0.1,   # log 10% of successful responses
    },
}
```

Set `sample_rate: 1.0` to log every 2xx response.

---

## 3. Request Body Capture

```python
SEC_AUDIT = {
    'core': {
        'log_request_bodies': True,
        'max_body_bytes': 4096,           # max JSON payload to capture
        'body_methods': ('POST', 'PUT', 'PATCH'),
        'sensitive_keys': ('password', 'secret', 'token', 'api_key'),
        'sensitive_key_allowlist': ('credit_card_last4', 'token_expiry'),
        'sensitive_value_patterns': (r'\b[A-Za-z0-9-_=]{40,}\b',),
    },
}
```

- Only JSON `application/json` / `application/*+json` bodies are captured
- Multipart and form-urlencoded bodies are skipped
- Scrubbed keys have their values replaced with `'[REDACTED]'`
- `sensitive_keys` matching is a case-insensitive substring test against a
  compacted key, so `api_key` also covers `apiKey`/`API-Key` — keep the list brief
- `sensitive_key_allowlist` is a precise opt-out: a field whose compacted name
  *exactly* matches an entry is never redacted, even when a `sensitive_keys`
  substring would match it. Use it for benign compounds the substring denylist
  over-redacts (`credit_card_last4`, `token_expiry`). It is an exact (whole-key)
  match, so it can only un-redact the exact fields you name — never a class of
  keys — and the full `credit_card` field still gets redacted.
- Sensitive value patterns are matched and redacted regardless of key name

---

## 4. Auth Events (login, logout, failed login)

Auth signals fire automatically once `SecAuditConfig` is installed. No extra
configuration needed.

---

## 4.5 Session Correlation

Every audit event can carry a `session.id` attribute to correlate events
belonging to the same browsing session. However, generating this value writes
into Django's `request.session`, which forces Django to persist the session and
set a session cookie on the response. This can turn a stateless endpoint into a
stateful one and create session records for anonymous visitors — an audit
package must observe application behavior, not change it.

Session correlation is therefore **opt-in**:

```python
SEC_AUDIT = {
    'django': {
        'emit_session_id': True,
    },
}
```

To include usernames in auth events:

```python
SEC_AUDIT = {
    'django': {
        'include_usernames': True,   # opt-in for GDPR/privacy
    },
}
```

---

## 5. Model Audit (with django-auditlog)

Install both extras and add `auditlog` to `INSTALLED_APPS`:

```bash
pip install "django-sec-audit[model]"
```

```python
INSTALLED_APPS = [
    'sec_audit.django.apps.SecAuditConfig',
    'auditlog',         # django-auditlog
    # ...
]
```

Model changes (create/update/delete) are forwarded to the audit log as
`model.create`, `model.update`, `model.delete` events.

Only field **names** are included (via `changed_fields`), not old/new values.

---

## 6. DRF Metadata

```bash
pip install "django-sec-audit[drf]"
```

If `rest_framework` is in `INSTALLED_APPS`, every audit event from a DRF view
automatically includes:

| Attribute | Example |
|-----------|---------|
| `drf_action` | `"create"` |
| `drf_basename` | `"transfer"` |
| `drf_view_class` | `"TransferViewSet"` |
| `drf_serializer_class` | `"TransferSerializer"` |
| `drf_authentication_classes` | `["TokenAuthentication"]` |
| `drf_permission_classes` | `["IsAuthenticated"]` |
| `drf_throttle_scope` | `"transfers"` |

---

## 7. Custom Filters and Enrichers

Filters can drop events; enrichers can add attributes. Both are callables
in a pipeline:

```python
# myapp/audit.py
def skip_health_checks(event, level):
    if event.attributes.get('url.path', '').startswith('/health/'):
        return None   # drop the event
    return event, level

def add_environment(event, level):
    event.attributes['environment'] = 'production'
    return event, level
```

Register them in settings:

```python
SEC_AUDIT = {
    'django': {
        'filters': ['myapp.audit.skip_health_checks'],
        'enrichers': ['myapp.audit.add_environment'],
    },
}
```

Filter signature: `(event: AuditEvent, level: int) -> tuple[AuditEvent, int] | None`

Enricher signature: `(event: AuditEvent, level: int) -> tuple[AuditEvent, int]`

---

## 8. Client IP and Trusted Proxies

By default the client IP is taken from `REMOTE_ADDR`. If you run behind a load
balancer or reverse proxy:

```python
SEC_AUDIT = {
    'django': {
        'trusted_proxy_cidrs': ('10.0.0.0/8', '172.16.0.0/12'),
        'trusted_proxy_count': 1,   # one proxy between client and Django
    },
}
```

When the request comes from a recognised proxy CIDR, the IP is resolved from
`X-Forwarded-For` using the rightmost (trusted_proxy_count) IPs as trusted
proxies and the next one as the client.

If `trusted_proxy_count` is not set, the first IP in `X-Forwarded-For` is used
(uncommon; only do this if you fully control the proxy network).

---

## 9. Ignoring Paths and Status Codes

```python
SEC_AUDIT = {
    'core': {
        'ignore_paths': (r'^/health/', r'^/metrics/', r'^/static/'),
        'ignore_status_codes': {301, 302, 304},
    },
}
```

---

## 10. Writing to a File

Stdout is the supported delivery path. For local file output, use a stdlib
`RotatingFileHandler` with the same `audit_jsonl` formatter:

```python
LOGGING = {
    'handlers': {
        'audit_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/sec-audit.jsonl',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'audit_jsonl',
        },
    },
}
```

A queue-backed `QueuedJSONLHandler` is available in
`sec_audit.logging._sinks`, but it is **experimental** — not part of the
supported surface and not exported from `sec_audit.logging`. For production
delivery, the recommended path is stdout JSONL consumed by Grafana Alloy or a
platform collector. HTTP and TCP SIEM handlers are not shipped with the current
package.

---

## 11. Verifying It Works

Run the Django shell:

```python
from sec_audit.django.runtime import get_runtime
rt = get_runtime()
print(rt.config.core.source)
print(rt.config.logging.schema_version)
```

Make a request to any endpoint:

```bash
curl -v http://localhost:8000/nonexistent
```

Check the log file:

```bash
tail -5 logs/sec-audit.jsonl | python -m json.tool
```

You should see an event with `event_type: "http.response.client_error"`.

---

## 12. Testing

Run the package's test suite:

```bash
pytest packages/django-sec-audit/tests -v
```

---

## 13. Logging to Console (Development)

```python
LOGGING = {
    'handlers': {
        'audit_console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'audit_json',
        },
    },
    'formatters': {
        'audit_json': {
            '()': 'sec_audit.logging.formatters.JSONLLogFormatter',
        },
    },
    'loggers': {
        'sec_audit': {
            'handlers': ['audit_console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
```
