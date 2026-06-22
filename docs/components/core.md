# Core

`sec_audit.core` is framework-neutral. It owns:

- **`AuditEvent`** — the handoff object between Django extraction and logging
  projection. Django supplies the configured schema version when the event is
  created; after construction, `AuditEvent.schema_version` is authoritative.
- **`CoreAuditConfig`** — configuration dataclass for source, sampling, body
  capture, sensitive-key scrubbing, path/status-code suppression.
- **`ProjectionLimits`** — bounds for dict/list nesting depth, number of keys,
  and string/byte sizes to prevent unbounded memory from malformed events.
- **`project_attributes`** — recursively projects an attribute dict through
  `ProjectionLimits`, returning a new dict with oversized values truncated and
  deeply nested structures pruned.
- **Scrubbers** — `scrub_event` and `scrub_log_attributes` redact values whose
  keys match `sensitive_keys` or whose values match `sensitive_value_patterns`.
  Key matching is a case-insensitive substring test against a compacted key
  (all non-alphanumerics stripped), so a brief denylist covers every variant —
  `apikey` matches `api_key`/`apiKey`/`API-Key`, `token` matches `access_token`.
  `sensitive_key_allowlist` is a precedence-taking, **exact** (whole compacted
  key) opt-out for benign compounds the substring denylist over-redacts
  (`credit_card_last4`, `token_expiry`); it can only un-redact the exact fields
  named, never a class of keys. Handles cycles, shared references,
  `MappingProxyType`, and bytes/bytearray.
- **`TrustedProxyConfig`** — validated configuration for resolving client IP
  through `X-Forwarded-For` behind trusted reverse proxies.
- **`resolve_client_ip`** — resolves the client IP from `REMOTE_ADDR` and
  optional trusted proxy headers.
- **JSON-safe conversion** — `json_safe()` converts a value tree to
  JSON-compatible types, coercing NaN/Inf to `None`, converting sets to lists,
  and handling `datetime`/`UUID`/`Decimal`/`Path`.

Forwarded client-IP headers are ignored by default. They may be used only with
explicit trusted proxy CIDRs/count and only when the immediate `REMOTE_ADDR`
belongs to a trusted proxy.
