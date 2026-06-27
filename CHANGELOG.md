# Changelog

All notable changes to the `sec-audit` distributions are documented here. Packages are
versioned and released **independently** (the original four-in-lockstep model has been
retired now that the five distributions have diverged); each release section below lists the
per-package versions it covers.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
breaking changes may land in minor releases).

## [Unreleased]

_Nothing yet._

## [2026-06-27]

Released: **`sec-audit-rules` 0.1.0a4**, **`django-sec-audit` 0.1.0a6**,
**`django-sec-audit-enforcement` 0.1.0a4** (`sec-audit` unchanged at `0.1.0a1`,
`sec-audit-logging` unchanged at `0.1.0a2`). Built-in enforcement detectors are
now **opt-in** (breaking — see Changed), plus admin temp-block management and the
prior code-review follow-ups across `sec-audit-rules` and
`django-sec-audit-enforcement`.

### Added
- **`django-sec-audit-enforcement` — manage temp blocks from the admin block
  manager.** The block-manager page now lists, creates, edits, and revokes
  temporary (Redis-only, TTL-backed) blocks alongside permanent ones.
  `RedisBlockStore.scan_blocks()` enumerates live block keys via a non-blocking
  `SCAN`; `TieredBlockStore.active_temp_blocks()` returns Redis blocks minus the
  permanent membership; `MemoryBlockStore.active_blocks()` is now permanent-only
  so the two surfaces stay disjoint on every backend. New
  `list_temp_blocks(scope_type=…)` API (re-exported), called on demand only —
  never on the request path.
- **`django-sec-audit` — `read_audit_session_id(request)` helper** (`sessions.py`):
  a read-only counterpart to `get_audit_session_id` that never mints or persists an
  id. The enforcement ingress session-scope check uses it so a session block is
  looked up under the same audit-session id that egress emits, never
  `request.session.session_key`.

### Security
- **`django-sec-audit-enforcement`** — admin block **revocation now requires the
  `change_permanentblock` permission**. `PermanentBlockAdmin.has_change_permission`
  previously returned `True` unconditionally and the `revoke_blocks` action carried
  no permission gate, so any staff user who could reach the changelist could revoke
  (defeat) active blocks. The action is now gated with `permissions=['change']` and
  the change view is gated on the real permission. View-only staff keep read access
  but can no longer revoke. **Back-compat:** staff with view/add but not change lose
  the revoke action and the change view.

### Changed
- **`django-sec-audit-enforcement` — built-in detectors are now opt-in
  (BREAKING).** The built-in detectors (`brute_force_login`, `login_throttle`,
  `repeated_client_error`, `resource_enumeration`) were auto-loaded and prepended
  to every deployment's rule set with no way to disable them; nothing runs now
  unless registered in `SEC_AUDIT_ENFORCEMENT['rules']`. `DEFAULT_RULE_ACTIONS` is
  retained but inert until the named rule is registered, and the former built-in
  names are reusable. **Back-compat:** deployments relying on the auto-loaded
  built-ins must now list them in `rules` (e.g.
  `'sec_audit.rules.builtins.BruteForceLoginRule'`).
- **`sec-audit-rules`** — a bare `persist_block` decision (a custom rule returning
  `decision='persist_block'` with no matching `rule_actions` entry) now defaults its
  scopes to `('user', 'session')` instead of `('ip',)`, and logs a warning. This
  prevents an accidental **permanent IP ban behind shared egress** (NAT, mobile
  carrier). An explicit `rule_actions[...].scopes` entry still wins. **Back-compat:**
  un-configured custom `persist_block` rules now ban user/session, not ip.
- **`django-sec-audit-enforcement`** — `block_subject('ip', …, ttl=None)` (a permanent
  IP ban via the manual API) now logs a warning about shared-egress lockout risk; the
  block is still applied.
- **`django-sec-audit-enforcement`** — `apply_via_sink=True` now logs a warning when a
  resolved action requests the `user` scope, since the sink path has no user identity
  and silently could not apply it. Documented next to the setting.
- **`django-sec-audit-enforcement`** — the block-deny response is now served as
  `text/plain` instead of the default `text/html`.

### Fixed
- **`sec-audit-rules`** — session-scope history keys no longer collapse to
  `sec_audit:hist:session:[REDACTED]`. `create_history_summary` scrubbed the summary
  before scope keys were extracted from it, and `session_id` normalizes to `sessionid`
  — a `DEFAULT_SENSITIVE_KEYS` denylist entry — so every session merged into one
  `[REDACTED]` history bucket (breaking per-session correlation). The scope-key fields
  (`session_id`, `srcip`, `user_id`, `username`, `route`) are now allowlisted from the
  history-summary scrub, so they survive intact in both the scope key and the stored
  summary body; genuinely sensitive body values still scrub. Only `session` was
  affected in practice (the other scope fields don't collide with the denylist).
- **`django-sec-audit-enforcement`** — `PostgresBlockStore.block()` is now atomic
  (`update_or_create` inside `transaction.atomic()`), closing a check-then-create race
  where two concurrent re-bans of the same scope could raise a raw `IntegrityError`;
  a genuinely-racing insert now surfaces as `BlockStoreError`.
- **`sec-audit-rules`** — the synthetic ingress pre-request evaluation
  (`enforcement_only=True`) no longer appends to the event history store, so a request
  is counted **once** (egress) instead of twice; egress history-reading rules
  (e.g. `resource_enumeration`) are no longer inflated.

### Removed
- **`sec-audit-rules` / `django-sec-audit-enforcement`** — removed the dead
  `SeverityEnforcementPolicy` wiring: the `policy_decision` parameter of
  `resolve_rule_action`, the `policy` field on `DjangoEnforcementRuntime`, and the
  unreachable policy branch. The `SeverityEnforcementPolicy`/`EnforcementDecision`
  classes remain exported from `sec_audit.enforcement` (now with direct unit coverage).

### CI / docs
- **`django-sec-audit-enforcement`** — added Python 3.14 to the Enforcement CI matrix
  (the classifier already advertised it; `Logging`/`Rules` already tested it).
- **`sec-audit-rules`** — documented that `Rule.history_attributes` output is **not
  scrubbed** and must not carry secrets/PII (docstring + `CLAUDE.md`).

## [2026-06-25]

Released: **`sec-audit-logging` 0.1.0a2**, **`sec-audit-rules` 0.1.0a3**,
**`django-sec-audit` 0.1.0a5**, **`django-sec-audit-enforcement` 0.1.0a3**
(`sec-audit` unchanged at `0.1.0a1`).

### Added
- **`enforcement_event` Django signal** for `django-sec-audit-enforcement` (`0.1.0a3`): a
  public extension point fired once per emitted `audit.enforcement.*` event, *after* it has
  been logged, so deployments can route alerts to their own notifier
  (Slack/PagerDuty/email/queue) without the package making the outbound call itself. Receivers
  run via `send_robust` (fail-open: a raising receiver is isolated and never affects
  enforcement or the response). Connect with the `on_enforcement_event(handler, events=...)`
  helper — optionally filtered to specific event-type strings, and wired with `weak=False` so a
  handler defined in `AppConfig.ready()` is not garbage-collected.
- **Always-on alert detection event** for `django-sec-audit-enforcement`
  (`0.1.0a2`): a rule that resolves to the `alert` action (detect-and-surface, no
  block) now emits a lightweight per-match `audit.enforcement.alert` event
  (WARNING / OTel severity 13) instead of being silently dropped, so alert-only
  rules (e.g. `resource_enumeration`) are observable in Loki/Grafana/Wazuh without
  blocking and without streaming every success response. `observe` stays silent.
  The new event type is purely additive (`schema_version` unchanged) and rides the
  existing enforcement skip-list, so it is never re-evaluated. Ships matching
  consumer assets: Wazuh rule `100085` + `sigma/enforcement-alert.yml`, a Grafana
  "Alerts (no block)" panel, and a `loki/queries.md` recipe.
- **Rule-contributed history attributes** for `sec-audit-rules`: a `Rule` can override the
  new `history_attributes(event, ctx)` hook to persist its own derived data (e.g. an extracted
  resource id) under its namespace (`rule_attrs[<name>]`) in the per-event history summary, so
  later events in the same scope window can read it back for correlation. Values are coerced
  with `json_safe` but not scrubbed (rule-authored, trusted). Ships the
  `resource_enumeration` built-in (alert-only) which uses it to flag one source IP touching
  many distinct resources under a single route template. History summaries are internal
  correlation state and not part of the emitted OTel schema.
- **Custom enforcement rules** for `django-sec-audit-enforcement`: register your own
  `sec_audit.rules.Rule` subclasses via the new `SEC_AUDIT_ENFORCEMENT['rules']` setting
  (dotted-path strings or `Rule` instances), appended to the built-in defaults. Validated
  fail-fast at app `ready()`; observe-only until mapped to a `rule_actions` entry. See the
  "Custom rules" section in `packages/django-sec-audit-enforcement/README.md`.
- Loki/Grafana setup guide for `django-sec-audit` (`packages/django-sec-audit/docs/loki-setup.md`).
- Publishing runbook (`PUBLISHING.md`) covering the four-package build/upload order.
- Package metadata for PyPI: `authors`, `keywords`, and `[project.urls]` across all four
  distributions; per-package `README.md` (long description) and bundled `LICENSE`.

### Changed
- **Decoupled rule/enforcement dispatch from log emission for non-error responses**
  (`sec-audit-rules` `0.1.0a3`, `django-sec-audit` `0.1.0a5`). Successful and redirect
  responses now reach registered rule consumers even when their logging is suppressed
  (`log_ok_responses=False` or sampled out): `Runtime.record(..., emit=False)` skips the log
  write but still feeds the event to consumers, and the middleware routes non-error responses
  through a new `_record_non_error` path gated on `has_rule_event_consumers()` so the
  (expensive) event is still built only when something will consume it. Previously, turning off
  success logging also blinded enforcement/detection rules to good traffic.

## [0.1.0a1] - 2026-06-22

Initial alpha release of the four coordinated distributions.

### Added
- **sec-audit** — framework-free audit core: events, config, context, scrubbing, projection,
  and client-IP resolution.
- **sec-audit-logging** — OpenTelemetry LogRecord-shaped JSONL emission, scrubbing, formatters,
  file/stdout handlers, filter/enricher pipeline, and the `sec-audit-loki-init` Grafana
  Alloy/Loki/Grafana asset generator.
- **sec-audit-rules** — pure rule-detector engine, enforcement policies, and Wazuh
  detection-rule package data (optional `[wazuh]` extra).
- **django-sec-audit** — Django integration: HTTP request/response middleware, auth-signal
  logging, django-auditlog model forwarding (`[model]`), and DRF metadata capture (`[drf]`).

[Unreleased]: https://github.com/ammar39/sec-audit/compare/sec-audit-rules-v0.1.0a4...HEAD
[2026-06-27]: https://github.com/ammar39/sec-audit/compare/sec-audit-rules-v0.1.0a3...sec-audit-rules-v0.1.0a4
[2026-06-25]: https://github.com/ammar39/sec-audit/compare/v0.1.0a1...sec-audit-rules-v0.1.0a3
[0.1.0a1]: https://github.com/ammar39/sec-audit/releases/tag/v0.1.0a1
