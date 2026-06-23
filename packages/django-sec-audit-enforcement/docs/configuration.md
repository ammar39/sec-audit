# Configuration reference

Everything is configured through a single Django setting, `SEC_AUDIT_ENFORCEMENT`,
a dict (or a pre-built `DjangoEnforcementConfig` instance). It is parsed and
validated **fail-fast at app `ready()`** — an unknown key, a wrong type, a
malformed regex, or a malformed import path raises `AuditConfigurationError` at
startup. Unknown keys are rejected (no silent typos).

```python
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'redis_url': 'redis://localhost:6379/0',
    'fail_closed_paths': [r'^/api/transfer'],
    'rule_actions': {
        'brute_force_login': {'action': 'temp_block', 'scopes': ['ip']},
    },
    'block_rules': {'brute_force_login': 900},
}
```

## Settings

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `enabled` | bool | `False` | Master switch. Off = the package is inert (no checks, no consumer). |
| `redis_url` | str | `''` | Redis connection URL. Empty → per-process in-memory stores (dev/demo only; wrong on multi-worker). |
| `permanent_tier_enabled` | bool | `True` | Store permanent bans in Postgres (the `PermanentBlock` table). If `False`, permanent bans degrade to long-lived Redis keys. |
| `permanent_cache_ttl` | int (>0) | `3600` | TTL (seconds) for the Redis read-through cache of permanent blocks. Redis never holds a no-TTL key. |
| `default_temp_ttl` | int (>0) | `300` | Default TTL (seconds) for a temp block when a rule/action doesn't specify one. |
| `fail_open` | bool | `True` | Global posture: on an unexpected enforcement error, proceed (allow) and emit a diagnostic event rather than crash the request. |
| `fail_closed_paths` | list[regex] | `()` | Path patterns that **deny** (return the block response) if the block store is unreachable. Everything else fails open. See the blast-radius warning below. |
| `eval_safe_on_ingress` | bool | `True` | Evaluate `safe_for_enforcement` rules **inline** (pre-response) on a synthetic pre-request event, so e.g. `login_throttle` can block before the view runs. |
| `apply_via_sink` | bool | `False` | Apply blocks through the rule engine's result-sink (egress) instead of the consumer path. When `True`, ingress safe-rule application is skipped. |
| `status_code` | int | `429` | Default HTTP status for a block response. |
| `message` | str | `'Request blocked by audit enforcement policy'` | Default block response body. |
| `block_severity` | int \| None | `None` | Severity gate for the `block` action: only matches at/above this severity escalate to a permanent ban; below it they degrade to a temp block. |
| `scope_specs` | sequence | `()` | Custom scope definitions for the `ScopeRegistry` (the `ip`/`user`/`session`/`route` vocabulary is built in). |
| `block_precedence` | list[str] | `()` | Order in which scopes are checked for an active block (named scopes first, in this order, then the rest). |
| `rule_actions` | dict | see below | Map a rule **name** → the action to take when it fires. Merged over the scope-safe defaults. |
| `block_rules` | dict | `{}` | Map a rule **name** → temp-block TTL (seconds). |
| `rules` | list | `()` | Register custom `Rule` detectors (dotted paths or instances), appended to the built-ins. See [Custom rules](custom-rules.md). |

## `rule_actions`

`rule_actions` decides what happens when a rule matches. Each entry maps a rule
name to `{'action': ..., 'scopes': [...]}`:

| `action` | Effect |
|----------|--------|
| `observe` | Detect + log only (no block). The default for any rule with no `rule_actions` entry. |
| `temp_block` | Self-expiring block in Redis (TTL from `block_rules[name]`, the action, or `default_temp_ttl`). |
| `persist_block` | Durable permanent block in Postgres (+ Redis cache). |
| `block` | Severity-gated: permanent if `match.severity >= block_severity`, else temp. |

`scopes` is the list of block dimensions to apply (`ip`, `user`, `session`, …).

Your map is **merged over** the scope-safe defaults, so you only specify what you
want to change:

```python
DEFAULT_RULE_ACTIONS = {
    'brute_force_login':      {'action': 'temp_block',    'scopes': ['ip']},
    'login_throttle':         {'action': 'temp_block',    'scopes': ['ip']},
    'repeated_client_error':  {'action': 'temp_block',    'scopes': ['ip']},
    'repeated_route':         {'action': 'temp_block',    'scopes': ['ip']},
    'request_body_threshold': {'action': 'temp_block',    'scopes': ['ip']},
    'suspicious_proxy_header':{'action': 'temp_block',    'scopes': ['ip']},
    'sensitive_field_change': {'action': 'persist_block', 'scopes': ['user', 'session']},
}
```

### Scope-safety: why permanent bans never key on `ip`

Temp blocks key on `ip`. **Permanent** (`persist_block`) bans key on
`user`/`session`, **never `ip`** — an ip-scoped permanent ban on shared egress
(corporate NAT, a mobile carrier) locks out many unrelated users. This property
is encoded in the defaults; preserve it when you override `rule_actions`.

## `block_rules`

Sets the temp-block TTL (seconds) per rule name. Without an entry, a temp block
uses the action's TTL or `default_temp_ttl` (300s):

```python
'block_rules': {'brute_force_login': 900, 'login_throttle': 120}
```

## Passing a pre-built config

For programmatic setups you can hand a `DjangoEnforcementConfig` directly instead
of a dict:

```python
from sec_audit.django_enforcement.config import DjangoEnforcementConfig
SEC_AUDIT_ENFORCEMENT = DjangoEnforcementConfig(enabled=True, redis_url='redis://...')
```

## Related

- [Architecture](architecture.md) — how `fail_open`/`fail_closed_paths`,
  `apply_via_sink`, and the tiers interact at request time.
- [Operations](operations.md#system-checks) — the `manage.py check` warnings that
  catch the risky combinations (`W004` no Redis, `W005` fail-closed blast radius).
