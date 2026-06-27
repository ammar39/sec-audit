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

## Managing blocks programmatically

`sec_audit.django_enforcement` exposes block-management utilities you can call
from anywhere — views, signals, Celery tasks, the shell. They route through the
runtime's block store, so the Redis write-through cache and the
`audit.enforcement.*` events stay consistent with rule-driven blocks. Manual
blocks reuse the existing taxonomy with `security_rule.name = "manual"` (no new
schema fields).

```python
from sec_audit.django_enforcement import (
    block_user, unblock_user, is_user_blocked, list_blocked_users,
    block_subject, unblock_subject, is_blocked, list_active_blocks,
    list_temp_blocks,
)

block_user(42, reason='fraud review', actor='you@example.com')   # permanent user ban
is_user_blocked(42)            # -> BlockEntry | None
list_blocked_users()           # -> [BlockEntry, ...] (active, user-scoped)
unblock_user(42, revoked_by='you@example.com')   # emits block_revoked

# Generic by subject — any scope, optional ttl for a temp (Redis-only) block:
block_subject('ip', '203.0.113.10', ttl=600, reason='scanner')
is_blocked('ip', '203.0.113.10')
list_active_blocks(scope_type='session')
```

`block_user` / `block_subject` accept a user id **or** a model instance (its
`pk` is used). `ttl=None` (default) writes a permanent block (Postgres
source-of-truth + Redis write-through); a positive `ttl` writes a temp block
(Redis-only). A block only **takes effect** when `enabled` is `True` and
`EnforcementMiddleware` is installed — the utils are available regardless.

`list_active_blocks` / `list_blocked_users` enumerate **durable (permanent)**
blocks. `list_temp_blocks(scope_type=...)` enumerates the **temporary**
(Redis-only, TTL-backed) blocks for operator tooling — it costs a Redis `SCAN`,
so call it on demand (e.g. an admin page), never on the request path.

## Admin

The bundled `PermanentBlockAdmin` lets operators **view, create, and revoke**
blocks. Create and revoke are routed through the utilities above, so they keep
the Redis cache and audit events consistent — never a raw ORM write.

- List columns: `scope_type`, `scope_value`, `rule_name`, `reason`, `created_at`,
  `revoked_at`; filter by `scope_type` / `rule_name` / `revoked_at`; search
  `scope_value` / `rule_name` / `reason`.
- **Add** (requires the `add_permanentblock` permission) creates a permanent
  block from `scope_type` / `scope_value` / `reason` / `rule_name` / `status_code`
  / `message`; the operator's username is recorded in the block metadata.
- **Revoke selected blocks** (bulk action) soft-revokes the chosen active rows,
  recording `revoked_by` and emitting `audit.enforcement.block_revoked`.
- Existing rows are **read-only** (to change a block, revoke it and create a new
  one) and are never hard-deleted.

### Block manager page

A **Block manager** button on the `PermanentBlock` changelist opens a dedicated
admin page (`/admin/sec_audit_enforcement/permanentblock/manage/`) that exposes the
**full** block surface in one form:

- **Scope** — a dropdown of the block-eligible scopes from your scope registry
  (`user` / `session` / `ip`, plus any custom scopes), and the scope value.
- **TTL** — seconds for a temporary (Redis-only) block; leave blank for a permanent
  one (Postgres source-of-truth + Redis write-through).
- Optional **reason**, **status code**, and **message** overrides.
- **Block** / **Unblock** buttons, plus two tables — **Active blocks** (durable)
  and **Active temp blocks** (Redis-only, with their expiry) — each row with an
  inline **Edit** and **Unblock**.

The page is gated by the `add_permanentblock` permission (on top of admin
staff/login). Block/unblock route through `block_subject` / `unblock_subject`, so the
cache and `audit.enforcement.*` events stay consistent. The **Active blocks** table
lists durable (permanent) blocks (via `list_active_blocks`); the **Active temp blocks**
table lists the Redis-only TTL blocks (via `list_temp_blocks`, a `SCAN` run only when
the page loads) and shows when each expires.

- **Add** a temp block from the form: fill in a positive **TTL** (blank = permanent).
- **Edit** a temp block: the row's **Edit** button prefills the form (scope, remaining
  TTL, reason, status/message); adjust and re-block to **overwrite** it (re-blocking the
  same scope replaces the entry — there is no separate edit endpoint).
- **Unblock** a temp block lifts it immediately rather than waiting for its TTL.

If Redis is unavailable the temp table shows a notice and the permanent surface still
renders.

### Block users from the admin

`BlockActionsMixin` adds **Block selected** / **Unblock selected** changelist
actions (and an optional `block_status` column) to any `ModelAdmin` whose rows map
to a block scope. Mix it into your `UserAdmin` to block/unblock users straight from
the Users list — the actions route through `block_subject` / `unblock_subject`, so
the cache and `audit.enforcement.*` events stay consistent:

```python
# yourapp/admin.py
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from sec_audit.django_enforcement.admin import BlockActionsMixin

User = get_user_model()
admin.site.unregister(User)


@admin.register(User)
class UserAdmin(BlockActionsMixin, DjangoUserAdmin):
    list_display = DjangoUserAdmin.list_display + ('block_status',)
```

The default scope is `('user', str(obj.pk))` — the same dimension enforcement reads
at ingress — so a blocked user is denied (the configured status, default 429) on
their next request. Override `block_scope_type` / `block_scope_value(obj)` to block
on a different scope (e.g. an account or tenant). Blocks are permanent.

> With no Postgres tier (the Redis-less in-memory fallback, e.g. the demo) these
> blocks are enforced but live only in the in-memory store — they won't appear in
> `PermanentBlockAdmin`, which reads the durable model.

## Revoking a block

Prefer the utilities — they clear **both** tiers (delete the Redis key,
soft-delete the Postgres row, preserving the trail) **and** emit
`audit.enforcement.block_revoked`:

```python
from sec_audit.django_enforcement import unblock_user, unblock_subject

unblock_user(42, reason='false positive', revoked_by='you@example.com')
unblock_subject('ip', '203.0.113.10', reason='expired threat')
```

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

## Redis eviction policy (`allkeys-*` / `volatile-*`)

The warm sentinel carries the ban **membership set**, so an evicting policy never
unbans an actor: non-banned traffic is still answered from the sentinel with no
Postgres read, and a banned actor whose cached key was evicted is re-verified
against Postgres on the spot. The cost of an evicting policy is the extra Postgres
read per eviction, plus — if the active-ban list exceeds the sentinel embed cap
(1000) — a per-request Postgres re-verify on requests whose scope type matches an
active ban (size the database for it). The `sec_audit_enforcement.W006` system
check warns at `manage.py check` time when it can read `maxmemory-policy` and finds
an evicting policy. **Recommended:** run the block store under `noeviction`, or
give it a dedicated Redis database/instance not subject to an `allkeys-*` /
`volatile-*` policy.

## Session-scoped blocks require `emit_session_id`

The ingress check keys the session dimension on the audit-session id that egress
emits (`_sec_audit_session_id`), never the raw `request.session.session_key`. That
id only exists when `SEC_AUDIT['django']['emit_session_id']` is `True` (off by
default), so session-scoped permanent bans (e.g. the `sensitive_field_change`
default, scoped `['user', 'session']`) only enforce when it is enabled; the `user`
half always enforces. With it enabled, place `EnforcementMiddleware` **after**
`SessionMiddleware` so `request.session` is loaded at ingress — the
`sec_audit_enforcement.W007` check flags a wrong order. A session block created on
one request becomes enforceable from the next request on that session (the id is
minted on the first request's response), matching the egress-then-enforce model.

## Monitoring checklist

- **Alert** on any `audit.enforcement.evaluation_failed` — the block store was
  unreachable during a check (see [fail modes](architecture.md#fail-modes)).
- **Dashboard** `audit.enforcement.block_applied` by `security_rule.name` — catch
  a new or custom rule that's over-firing before it impacts real users.
- **Track** `audit.enforcement.blocked` rate to understand enforcement impact.
- **Dashboard** `audit.enforcement.alert` by `security_rule.name` — alert-only
  rules (`alert` action, no block) surface here; this is how detect-and-surface
  detectors stay observable without blocking.

To page a responder directly (no Loki ruler / Alertmanager required), connect a
receiver to the `enforcement_event` signal — see [Enforcement events → Subscribing
to enforcement events](events.md#subscribing-to-enforcement-events-custom-notifications).
A dashboard nobody is watching detects nothing; the signal is the route to on-call.

These are prebuilt. The `sec-audit-logging` Grafana dashboard has an
**Enforcement** row (requests blocked, blocks applied, evaluation failures,
alerts, blocks by rule/scope) and matching LogQL recipes in `loki/queries.md`; the
`sec-audit-rules` Wazuh ruleset alerts on `audit.enforcement.blocked` /
`block_applied` / `evaluation_failed` / `alert` (ids `100081`–`100085` plus
`sigma/enforcement-*.yml`). See
[Shipping audit logs to Loki + Grafana](https://github.com/ammar39/sec-audit/blob/main/packages/django-sec-audit/docs/loki-setup.md).

See [Enforcement events](events.md) for the full attribute reference.
