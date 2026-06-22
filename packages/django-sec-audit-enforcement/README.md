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

See `SEC_AUDIT_ENFORCEMENT` settings and the architecture/implementation docs
under `plans/django-enforcement-package/` for the full design.

## Custom rules

The package ships three built-in rules (`brute_force_login`, `login_throttle`,
`repeated_client_error`). You can register your own detectors via the
`SEC_AUDIT_ENFORCEMENT['rules']` setting — they are **appended to** the built-in
defaults (the defaults always stay on).

A rule is a subclass of `sec_audit.rules.Rule` that implements
`evaluate(self, event, ctx)` and returns a `RuleMatch` (use the `make_match`
helper) when it fires, or `None` otherwise. Declare a unique, non-empty `name`;
if your rule needs counters/history, declare a `context = ContextRequirements(...)`.

```python
# myapp/security/rules.py
from sec_audit.rules import Rule
from sec_audit.rules.base import make_match

class GeoVelocityRule(Rule):
    name = 'geo_velocity'
    severity = 5
    event_types = {'auth.login.succeeded'}

    def evaluate(self, event, ctx):
        if self._impossible_travel(event, ctx):
            return make_match(
                rule_name=self.name, severity=self.severity,
                now=ctx.now, message='impossible travel', event=event,
            )
        return None
```

Register it (a dotted path to the class/instance, or an instantiated `Rule`):

```python
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'rules': ['myapp.security.rules.GeoVelocityRule'],
    # A custom rule OBSERVES (detect + log, no block) until you map its name to
    # an action. Add a rule_actions entry to make it block:
    'rule_actions': {'geo_velocity': {'action': 'temp_block', 'scopes': ['ip']}},
    'block_rules': {'geo_velocity': 600},  # optional TTL (seconds) for temp blocks
}
```

Two things to know:

- **Observe-only by default.** A rule with no `rule_actions` entry detects and
  logs but does not block — add `rule_actions['<name>']` to enable enforcement.
- **Inline (pre-response) enforcement requires `safe_for_enforcement = True`.**
  By default rules run on the **egress** path (after the response, off the
  recorded event). Only set `safe_for_enforcement = True` for a cheap,
  side-effect-free rule you want evaluated on the ingress fast path.

Config is validated fail-fast at app `ready()`: a malformed import path, a
non-`Rule` object, an empty name, or a name colliding with a built-in raises
`AuditConfigurationError`. The rule module itself is imported lazily on first
request (so its import side effects don't run during settings parsing).
