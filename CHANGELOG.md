# Changelog

All notable changes to the `sec-audit` distributions are documented here. The four packages
(`sec-audit`, `sec-audit-logging`, `sec-audit-rules`, `django-sec-audit`) are versioned and
released together.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
breaking changes may land in minor releases).

## [Unreleased]

### Added
- **Custom enforcement rules** for `django-sec-audit-enforcement`: register your own
  `sec_audit.rules.Rule` subclasses via the new `SEC_AUDIT_ENFORCEMENT['rules']` setting
  (dotted-path strings or `Rule` instances), appended to the built-in defaults. Validated
  fail-fast at app `ready()`; observe-only until mapped to a `rule_actions` entry. See the
  "Custom rules" section in `packages/django-sec-audit-enforcement/README.md`.
- Loki/Grafana setup guide for `django-sec-audit` (`packages/django-sec-audit/docs/loki-setup.md`).
- Publishing runbook (`PUBLISHING.md`) covering the four-package build/upload order.
- Package metadata for PyPI: `authors`, `keywords`, and `[project.urls]` across all four
  distributions; per-package `README.md` (long description) and bundled `LICENSE`.

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

[Unreleased]: https://github.com/ammar39/sec-audit/compare/v0.1.0a1...HEAD
[0.1.0a1]: https://github.com/ammar39/sec-audit/releases/tag/v0.1.0a1
