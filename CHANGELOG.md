# Changelog

All notable changes to the `sec-audit` distributions are documented here. Packages are
versioned and released **independently** (the original four-in-lockstep model has been
retired now that the five distributions have diverged); each release section below lists the
per-package versions it covers.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
breaking changes may land in minor releases).

## [Unreleased]

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

[Unreleased]: https://github.com/ammar39/sec-audit/compare/sec-audit-rules-v0.1.0a3...HEAD
[2026-06-25]: https://github.com/ammar39/sec-audit/compare/v0.1.0a1...sec-audit-rules-v0.1.0a3
[0.1.0a1]: https://github.com/ammar39/sec-audit/releases/tag/v0.1.0a1
