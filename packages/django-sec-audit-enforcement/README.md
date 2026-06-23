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

## Documentation

Full docs live in [`docs/`](docs/):

- [Getting started](docs/getting-started.md) — install, `INSTALLED_APPS`/`MIDDLEWARE`, migrate, enable, verify
- [Configuration](docs/configuration.md) — every `SEC_AUDIT_ENFORCEMENT` key + `rule_actions`/`block_rules`
- [Architecture](docs/architecture.md) — the ingress/egress paths, the tiered store, fail modes
- [Custom rules](docs/custom-rules.md) — write and register your own `Rule`
- [Enforcement events](docs/events.md) — the four `audit.enforcement.*` events
- [Operations](docs/operations.md) — deploy tiers, system checks, the `PermanentBlock` model, revocation

## Custom rules

The three built-in rules (`brute_force_login`, `login_throttle`,
`repeated_client_error`) can be extended with your own. Subclass
`sec_audit.rules.Rule`, then register it via `SEC_AUDIT_ENFORCEMENT['rules']`
(appended to the built-ins):

```python
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'rules': ['myapp.security.rules.GeoVelocityRule'],
    # observe-only until you map the rule's name to an action:
    'rule_actions': {'geo_velocity': {'action': 'temp_block', 'scopes': ['ip']}},
}
```

A custom rule observes (detect + log, no block) until it has a `rule_actions`
entry, and runs on the egress path unless it sets `safe_for_enforcement = True`.
See the full [Custom rules guide](docs/custom-rules.md).
