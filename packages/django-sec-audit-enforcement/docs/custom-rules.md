# Custom rules

No detectors run unless you register them. `SEC_AUDIT_ENFORCEMENT['rules']` is
the single registration surface: list the rules you want there — the shipped
built-ins (`brute_force_login`, `login_throttle`, `repeated_client_error`,
`resource_enumeration`, under `sec_audit.rules.builtins`) **and/or** your own
detectors. The registered set is exactly what `rules` declares; nothing is forced
on you.

## The `Rule` API

A rule is a subclass of `sec_audit.rules.Rule` (from the `sec-audit-rules`
package). It is a pure, stateless detector: all state — counters, history, the
clock, config — is injected via the `RuleContext`, so rules are deterministic and
unit-testable.

```python
class Rule:
    name: str = ''                         # unique, non-empty — actions key on this
    severity: int = 1                      # 1..n; used by the `block` action's severity gate
    event_types: set[str] | None = None    # restrict to these event types (None = all)
    safe_for_enforcement: bool = False     # True = eligible for the ingress fast path
    context: ContextRequirements | None = None  # declare history/counter needs

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None: ...
```

Return a `RuleMatch` (build it with `make_match`) when the rule fires, or `None`.

### Counters and history

If your rule needs to count events over a window (e.g. "5 failures in 15
minutes"), declare a `context`. The engine then provides a scoped, bounded
history reader on `ctx`:

```python
from sec_audit.rules.base import ContextRequirements

context = ContextRequirements(
    scopes=frozenset({'ip'}),     # which scope keys the rule may read
    window_seconds=900,           # max lookback
    max_events=100,               # cap
)
```

## A worked example

```python
# myapp/security/rules.py
from sec_audit.rules import Rule
from sec_audit.rules.base import ContextRequirements, make_match


class RepeatedNotFoundRule(Rule):
    """Block an IP that probes for many missing routes (scanner behavior)."""

    name = 'repeated_not_found'
    severity = 3
    event_types = {'http.response.client_error'}
    context = ContextRequirements(scopes=frozenset({'ip'}), window_seconds=300)

    def evaluate(self, event, ctx):
        if event.field('http.response.status_code') != 404:
            return None
        recent = ctx.history.count('ip', event_type='http.response.client_error',
                                   window_seconds=300)
        if recent < 20:
            return None
        return make_match(
            rule_name=self.name, severity=self.severity, now=ctx.now,
            message='repeated 404 probing', event=event,
        )
```

## Register it

Point `rules` at a dotted path to the class (or an instance), and map its `name`
to an action so it actually blocks:

```python
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'redis_url': 'redis://localhost:6379/0',
    'rules': ['myapp.security.rules.RepeatedNotFoundRule'],
    'rule_actions': {'repeated_not_found': {'action': 'temp_block', 'scopes': ['ip']}},
    'block_rules': {'repeated_not_found': 600},   # optional TTL (seconds)
}
```

`rules` entries may be:

- **a dotted-path string** to a `Rule` subclass (instantiated for you) or to a
  `Rule` instance, or
- **an already-instantiated `Rule`** passed directly.

The shipped built-ins register the same way — add their dotted paths alongside
your own (a built-in carries a scope-safe default action, so it blocks once
registered without a `rule_actions` entry):

```python
'rules': [
    'sec_audit.rules.builtins.BruteForceLoginRule',
    'myapp.security.rules.RepeatedNotFoundRule',
],
```

## Two behaviors to remember

1. **Observe-only by default.** A rule with **no `rule_actions` entry** detects
   and logs but does **not** block (the Enforcer's default action is `observe`).
   Add `rule_actions['<name>']` to enable enforcement. This is a deliberately safe
   default — register, watch the `audit.enforcement.*` logs, then arm it.

2. **Inline (pre-response) enforcement requires `safe_for_enforcement = True`.**
   By default a custom rule runs on the **egress** path (after the response, off
   the recorded event). Only set `safe_for_enforcement = True` for a cheap,
   side-effect-free rule you want evaluated on the ingress fast path — and only
   then does `eval_safe_on_ingress` apply to it. See
   [Architecture](architecture.md#ingress-vs-egress-which-path-runs-a-rule).

## Validation (fail-fast at `ready()`)

Configuration errors surface at app startup, not at request time:

| Problem | Result |
|---------|--------|
| Malformed import path (not `"module.attr"`) | `AuditConfigurationError` at `ready()` |
| Path/object isn't a `Rule` subclass or instance | `AuditConfigurationError` |
| Empty `name` | `AuditConfigurationError` |
| Name duplicates another registered rule | `AuditConfigurationError` |

The import-path **shape** is validated at settings-parse time; the rule module is
then imported and resolved **eagerly at `ready()`** (in `setup_enforcement`), so
a well-formed but non-existent path — or any other resolution failure — crashes
the boot, naming the offending rule, rather than being swallowed by the
request-time fail-open. Only store construction / the Redis connection stay lazy
(deferred to the first request), so `migrate` / `check` / `collectstatic` still
work when Redis is down.

## Testing your rule

Rules are pure, so you can test `evaluate()` directly. For an end-to-end test
(rule → action → block), build the runtime from a config and drive an event — see
[`tests/test_custom_rules.py`](../tests/test_custom_rules.py) for the pattern
(memory stores, `_build_runtime`, assert against `block_store.first_active(...)`).
