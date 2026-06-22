# Demo

The demo consumes the Django audit package alongside rules and enforcement:

- `sec_audit.django.apps.SecAuditConfig`
- `sec_audit.django.middleware.AuditMiddleware`
- `sec_audit.logging.JSONLLogFormatter`
- optional DRF and django-auditlog metadata
- built-in rules (`brute_force`, `repeated_errors`, `request_body`, `proxy`)
- enforcement middleware for blocking high-severity events

The demo must **consume package features**, not reimplement them. New detectors
belong in `sec_audit.rules.builtins`, not `demo/fintech/`.
