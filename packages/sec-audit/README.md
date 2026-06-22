# sec-audit

Framework-neutral audit core for the logging-only alpha.

It provides:

- `AuditEvent`
- request/session context helpers
- request ID generation
- client IP resolution with explicit trusted-proxy configuration
- scrubbing
- deterministic bounded projection
- configuration validation helpers

`sec-audit` has no Django imports and no logging, rules, enforcement, Loki, or
database dependencies.
