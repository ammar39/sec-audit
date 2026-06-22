# Testing

Coverage for the logging alpha focuses on:

- core and logging import without Django
- `django-sec-audit` imports without `sec-audit-rules`
- Django settings reject removed rules/enforcement/exporter sections
- one request emits at most one HTTP response record
- auth/model signal occurrences emit exactly one record
- success-response sampling applies only to successful HTTP events
- query strings never appear in `url.path`
- forwarded headers are ignored without trusted proxy configuration
- body capture skips unsafe requests and never logs malformed raw bodies
- usernames/emails are omitted by default
- model events emit changed field names only
- projection is cycle-safe and bounded
- formatter fallback records are bounded and non-recursive
- packaged wheels contain no removed Django rule/enforcement modules
