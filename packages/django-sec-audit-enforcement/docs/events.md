# Enforcement events

Every enforcement decision is emitted as an OTel-shaped audit event on the
existing `sec_audit.audit` logger — the same JSONL pipeline as `django-sec-audit`
(scrubbing and the size bound are applied by that pipeline). There are four event
types, all prefixed `audit.enforcement.`.

`body` is the event-type string only; all structured context is in `attributes`.
Empty/null attributes are omitted. The stdlib logging level sets the OTel
severity number the formatter writes.

| Event type | When | Level (OTel severity) |
|------------|------|-----------------------|
| `audit.enforcement.blocked` | An incoming request matched an active block (ingress) | WARNING (13) |
| `audit.enforcement.block_applied` | A new block was applied (temp or permanent) | WARNING (13) |
| `audit.enforcement.block_revoked` | A block was revoked | INFO (9) |
| `audit.enforcement.evaluation_failed` | A store/engine error occurred (fail-open/closed) | ERROR (17) |

## `audit.enforcement.blocked`

A request hit an active block and was short-circuited.

| Attribute | Example | Notes |
|-----------|---------|-------|
| `scope.type` | `"ip"` | The block dimension that matched |
| `scope.value` | `"203.0.113.10"` | |
| `security_rule.name` | `"brute_force_login"` | The rule that created the block (if known) |
| `enforcement.action` | `"blocked"` | literal |
| `http.response.status_code` | `429` | The status returned to the client |

## `audit.enforcement.block_applied`

A new block was written to the store.

| Attribute | Example | Notes |
|-----------|---------|-------|
| `scope.type` | `"ip"` | |
| `scope.value` | `"203.0.113.10"` | |
| `security_rule.name` | `"brute_force_login"` | |
| `enforcement.action` | `"temp"` / `"permanent"` | the kind actually applied |
| `enforcement.ttl` | `300` | seconds — present for temp blocks only |
| `enforcement.expires_at` | `"2026-06-23T14:05:00+00:00"` | ISO 8601 — present only if a durable expiry is set |

## `audit.enforcement.block_revoked`

A block was revoked (soft delete). The builder exists for the revocation path,
but **no bundled code path emits it yet** — it is wired for a forthcoming admin
revoke action (the bundled admin is read-only in this release). Revoking via the
store today removes the block but does not emit this event; emit it yourself with
`build_block_revoked_event(...)` if you want the trail entry (see
[Operations → Revoking a block](operations.md#revoking-a-block)).

| Attribute | Example | Notes |
|-----------|---------|-------|
| `scope.type` | `"user"` | |
| `scope.value` | `"42"` | |
| `enforcement.revoked_by` | `"admin@example.com"` | who revoked it |
| `enforcement.reason` | `"false positive"` | |

## `audit.enforcement.evaluation_failed`

The block store or engine errored. The request was allowed (`open`) or denied
(`closed`) per the configured [fail mode](architecture.md#fail-modes). This is a
diagnostic — alert on it.

| Attribute | Example | Notes |
|-----------|---------|-------|
| `enforcement.fail_mode` | `"open"` / `"closed"` | whether the request proceeded or was denied |
| `error.type` | `"BlockStoreError"` | exception **class name only** — never the message (which can carry PII) |

## Consuming these events

They ride the same `sec_audit.audit` logger as all audit output, so any sink you
already have (stdout JSONL → Grafana Alloy/Loki, a file handler, etc.) receives
them. Useful queries:

- Alert on **any** `audit.enforcement.evaluation_failed` — it means Redis/Postgres
  was unreachable during a check.
- Dashboard `audit.enforcement.block_applied` by `security_rule.name` to see which
  rules are firing and whether a new/custom rule is too aggressive.
- Track `audit.enforcement.blocked` rate to size the impact of a block on real
  traffic.

The `sec-audit-logging` Grafana dashboard ships an **Enforcement** row and
`loki/queries.md` has ready-made enforcement LogQL recipes; the `sec-audit-rules`
Wazuh ruleset alerts on these events. See [Operations → Monitoring
checklist](operations.md#monitoring-checklist).

There is **no feedback loop**: emitted `audit.enforcement.*` events are on the
rule engine's skip-list, so they are never re-evaluated.
