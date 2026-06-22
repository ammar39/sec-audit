# django-sec-audit-enforcement

The enforcement layer for [`django-sec-audit`](../django-sec-audit). It turns the
detection brain in [`sec-audit-rules`](../sec-audit-rules) into action: it holds
block state (temp blocks in Redis, permanent blocks in Postgres with a Redis
read-through cache), applies a matched rule's `RuleAction` as a block, checks
incoming requests against active blocks before the view runs, and emits every
enforcement decision as OTel JSONL on the existing `sec_audit.audit` logger.

**Status:** alpha. Master switch is off by default — installing the package is
inert until `SEC_AUDIT_ENFORCEMENT['enabled']` is set.

## Design

- **Temp blocks → Redis only** (self-expiring TTL keys). **Permanent blocks →
  Postgres** (durable, auditable) **+ a Redis read-through cache** carrying a long
  refresh TTL (never a no-TTL key, which managed Redis can silently evict).
- **One scope vocabulary** (`ip`/`user`/`session`/`route`) shared with detection,
  via the `sec-audit-rules` `ScopeRegistry`. The `ip` scope is resolved through
  `django-sec-audit`'s trusted-proxy config — never a raw `X-Forwarded-For`.
- **Fail-open by default**, per-path fail-closed opt-in.
- **No feedback loop:** emitted `audit.enforcement.*` events are skipped by the
  rule engine.

See `SEC_AUDIT_ENFORCEMENT` settings and the architecture/implementation docs
under `plans/django-enforcement-package/` for the full design.
