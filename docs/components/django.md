# Django

`sec_audit.django` is the Django-facing package. It extracts request/response,
auth signal, optional DRF, and optional django-auditlog model metadata into
framework-neutral `AuditEvent` objects.

It composes only:

- Django
- `sec-audit`
- `sec-audit-logging`

It does not import or initialize rules, enforcement, state stores, block
models, rule-match models, or migrations. Those modules live in
`sec-audit-rules` and are wired separately.

Supported settings:

```python
SEC_AUDIT = {
    'core': {'source': 'my-service', 'log_ok_responses': True, 'sample_rate': 1.0},
    'logging': {'schema_version': '1.0'},
    'django': {
        'filters': [],
        'enrichers': [],
        'include_usernames': False,
        'emit_session_id': False,
        'trusted_proxy_cidrs': [],
        'trusted_proxy_count': None,
    },
}
```

Each request emits at most one HTTP response audit event. Auth and model signal
events are separate domain events and are not suppressed to enforce a single
total record per request.
