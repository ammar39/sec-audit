# Enforcement events

Every enforcement decision is emitted as an OTel-shaped audit event on the
existing `sec_audit.audit` logger — the same JSONL pipeline as `django-sec-audit`
(scrubbing and the size bound are applied by that pipeline). There are five event
types, all prefixed `audit.enforcement.`.

`body` is the event-type string only; all structured context is in `attributes`.
Empty/null attributes are omitted. The stdlib logging level sets the OTel
severity number the formatter writes.

| Event type | When | Level (OTel severity) |
|------------|------|-----------------------|
| `audit.enforcement.alert` | A rule matched but resolved to `alert` — surfaced, **not** blocked | WARNING (13) |
| `audit.enforcement.blocked` | An incoming request matched an active block (ingress) | WARNING (13) |
| `audit.enforcement.block_applied` | A new block was applied (temp or permanent) | WARNING (13) |
| `audit.enforcement.block_revoked` | A block was revoked | INFO (9) |
| `audit.enforcement.evaluation_failed` | A store/engine error occurred (fail-open/closed) | ERROR (17) |

## `audit.enforcement.alert`

A rule matched and its resolved action is `alert` — a detect-and-surface
decision that takes **no** blocking action and writes nothing to the block store.
Emitted once per match so alert-only rules (e.g. `resource_enumeration`) are
observable always-on, without having to stream every success response. The
`observe` action stays silent (no event).

| Attribute | Example | Notes |
|-----------|---------|-------|
| `security_rule.name` | `"resource_enumeration"` | The rule that matched |
| `security_rule.severity` | `5` | Rule severity (1–10) |
| `security_rule.description` | `"one IP touched 20+ resources"` | The match message |
| `enforcement.action` | `"alert"` | literal |
| `source.address` | `"203.0.113.10"` | Client IP from the match (omitted if unknown) |
| `session.id` | `"sess_xyz"` | Session from the match (omitted if absent) |

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

## Subscribing to enforcement events (custom notifications)

A SIEM dashboard detects nothing if no one is paged. To route enforcement events
to your own notifier (Slack, PagerDuty, email, a task queue) **without** standing up
Loki ruler rules + Alertmanager, connect a receiver to the `enforcement_event`
Django signal. The package only dispatches — it never makes the outbound call, so
delivery (and the choice to do it inline vs. hand off to a queue) is entirely yours.

The signal fires **once per emitted event**, for all five event types, **after** the
event has been logged. Connect a receiver in your `AppConfig.ready()`:

```python
# yourapp/apps.py
from django.apps import AppConfig
from sec_audit.django_enforcement import on_enforcement_event


def _notify(sender, *, event_type, event, level, **kwargs):
    # Hand off — DON'T block the request thread on a network call.
    notify_task.delay(event_type, dict(event.attributes))


class YourAppConfig(AppConfig):
    name = 'yourapp'

    def ready(self):
        on_enforcement_event(
            _notify,
            events={'audit.enforcement.alert', 'audit.enforcement.evaluation_failed'},
        )
```

The raw Django `@receiver` pattern works too (branch on `event_type` yourself):

```python
from django.dispatch import receiver
from sec_audit.django_enforcement import enforcement_event


@receiver(enforcement_event)
def page_oncall(sender, *, event_type, event, level, **kwargs):
    if event_type == 'audit.enforcement.evaluation_failed':
        notify_task.delay(event_type, dict(event.attributes))
```

Receiver signature: `(sender, *, event, event_type, level, **kwargs)` — `event` is the
immutable `AuditEvent`, `event_type` is the convenience string (e.g.
`'audit.enforcement.alert'`), `level` is the stdlib logging level.

**Four guarantees / one caveat:**

- **Isolated (fail-open).** Receivers run via `send_robust`: a receiver that raises is
  caught and logged at WARNING — it never breaks enforcement, the response, or other
  receivers.
- **Logged first.** The signal fires *after* the durable JSONL write, so a slow or
  broken receiver can never suppress the audit trail.
- **Already-safe payload.** `event.attributes` is read-only and already scrubbed +
  size-bounded by the emit pipeline (`evaluation_failed` is class-name-only). Treat
  `event` as immutable.
- **Sink-independent.** The signal fires even with no Loki/SIEM sink attached, so this
  is a self-contained route-to-human path.
- **Caveat — you own latency, and don't re-enter.** Receivers run **synchronously** on
  the emit path (post-response egress / ingress block check), so keep them fast and
  push network I/O to a queue (Celery/thread). And do **not** perform enforcement
  actions from a receiver (e.g. `block_user`, which emits `block_applied`) — that
  causes re-entrant dispatch.
