# Operations

Running the enforcement layer in production: deployment tiers, the `manage.py
check` warnings, the `PermanentBlock` model and admin, revoking blocks, and what
to do when Redis is flushed.

## Deployment tiers

| Component | Required? | Why |
|-----------|-----------|-----|
| **Redis** | Yes (for any multi-worker deploy) | Holds all block state read on every request; temp blocks live here exclusively. |
| **Postgres** | Yes, if `permanent_tier_enabled` (default) | Durable source of truth + compliance trail for permanent bans; survives a Redis flush. |

Without `redis_url` the package falls back to per-process in-memory stores. Each
worker then has its own block state — correct only for a single-process dev server
or the demo. `manage.py check` warns (`W004`).

## System checks

`manage.py check` (run in CI and on deploy) surfaces misconfiguration before it
reaches production. Checks only fire when `enabled` is `True`.

| ID | Level | Condition | Fix |
|----|-------|-----------|-----|
| `sec_audit_enforcement.E001` | Error | `EnforcementMiddleware` not in `MIDDLEWARE` | Add it, **above** `AuditMiddleware`. |
| `sec_audit_enforcement.E002` | Error | `EnforcementMiddleware` ordered **below** `AuditMiddleware` | Move it above, so the block check short-circuits before audit work. |
| `sec_audit_enforcement.W003` | Warning | `permanent_tier_enabled` but `sec_audit.django_enforcement` not in `INSTALLED_APPS` | Add the app (the `PermanentBlock` model/migrations won't load otherwise). |
| `sec_audit_enforcement.W004` | Warning | enabled but `redis_url` empty | Set `redis_url` (in-memory stores are wrong on multi-worker). |
| `sec_audit_enforcement.W005` | Warning | `fail_closed_paths` configured | Confirm the blast radius — a store outage **denies** all matching traffic. |

A bad `SEC_AUDIT_ENFORCEMENT` value (unknown key, wrong type, malformed
regex/import path) raises `AuditConfigurationError` at app `ready()` — startup
fails loudly rather than at request time.

## The `PermanentBlock` model

Permanent bans are rows in `PermanentBlock` (table
`sec_audit_enforcement_permanentblock`). Temp blocks are **not** here — they live
only in Redis.

| Field | Type | Notes |
|-------|------|-------|
| `scope_type` | `CharField(32)` | `ip` / `user` / `session` / … |
| `scope_value` | `CharField(255)` | the banned value |
| `reason` | `CharField(255)` | free-text reason |
| `rule_name` | `CharField(128)` | rule that created it |
| `status_code` | `PositiveSmallIntegerField` | default `429` |
| `message` | `CharField(255)` | block response body |
| `metadata` | `JSONField` | arbitrary structured context |
| `created_at` | `DateTimeField` | indexed |
| `expires_at` | `DateTimeField` (null) | normally null for permanent; set only for a durable expiry |
| `revoked_at` | `DateTimeField` (null, indexed) | null = active; set = revoked (soft delete) |
| `revoked_by` | `CharField(128)` | who revoked |
| `revoked_reason` | `CharField(255)` | why |

**Constraint** `uniq_active_block_per_scope`: at most one **active** row per
`(scope_type, scope_value)` — revoked rows are exempt, so the audit history
accumulates and a scope can be re-banned after revocation.

## Admin

The bundled `PermanentBlockAdmin` is **read-only** in this release — a review
surface, not a write surface:

- List columns: `scope_type`, `scope_value`, `rule_name`, `reason`, `created_at`,
  `revoked_at`; filter by `scope_type` / `rule_name` / `revoked_at`; search
  `scope_value` / `rule_name` / `reason`.
- Add / change / delete are all disabled.

Manual revoke actions (which will emit `audit.enforcement.block_revoked`) are a
later phase. Until then, revoke via the ORM/store (below).

## Revoking a block

Revoke removes the block from **both** tiers (deletes the Redis key and
soft-deletes the Postgres row, preserving the trail):

```python
# Django shell
from sec_audit.django_enforcement.runtime import get_enforcement_runtime
from sec_audit.enforcement.blocks import BlockScope

rt = get_enforcement_runtime()
rt.block_store.unblock(
    BlockScope('user', '42'),
    reason='false positive',
    revoked_by='you@example.com',
)
```

> The store `unblock` clears the block but does **not** itself emit an
> `audit.enforcement.block_revoked` event (no bundled code path emits it yet — the
> builder is wired for the forthcoming admin action). If you want the audit trail
> entry now, emit it explicitly with
> `sec_audit.django_enforcement.emit.build_block_revoked_event(...)` via
> `runtime.emitter.emit(...)`.

To inspect the durable trail directly:

```python
from sec_audit.django_enforcement.models import PermanentBlock
PermanentBlock.objects.filter(revoked_at__isnull=True)   # active permanent bans
```

## Recovering from a Redis flush

Temp blocks are lost on a Redis flush (by design — they're short-lived).
Permanent bans are **not** lost: they live in Postgres. On the next request after
a flush the `TieredBlockStore` finds its warm sentinel gone, re-warms all active
permanent blocks from Postgres into Redis, marks the cache warm, and answers —
no manual step needed. Permanent bans are cached with `permanent_cache_ttl`
(default 3600s) and re-warmed on miss, so they survive cache eviction too.

## Monitoring checklist

- **Alert** on any `audit.enforcement.evaluation_failed` — the block store was
  unreachable during a check (see [fail modes](architecture.md#fail-modes)).
- **Dashboard** `audit.enforcement.block_applied` by `security_rule.name` — catch
  a new or custom rule that's over-firing before it impacts real users.
- **Track** `audit.enforcement.blocked` rate to understand enforcement impact.

See [Enforcement events](events.md) for the full attribute reference.
