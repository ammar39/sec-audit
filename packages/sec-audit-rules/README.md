# sec-audit-rules

Framework-free audit **rules engine**, **enforcement policies**, and **SIEM integrations**
for the [`sec-audit`](https://github.com/ammar39/sec-audit/tree/main/packages/sec-audit) core.

This package is **Django-free** and shares the `sec_audit` namespace with its sibling
distributions.

## Features

- **Rules** — pure, read-only detectors that evaluate an event and optionally return a
  `RuleMatch`. All state (counters, history, clock, config) is injected via `RuleContext`,
  so rules have no side effects.
- **Engine** — filters events by type, isolates rule exceptions, and enforces safety flags
  (`safe_for_enforcement`) for pre-request blocking.
- **Enforcement** — policies that turn matches into alert/block decisions with persistent
  block scopes.
- **Integrations** — Wazuh XML/YAML detection rules ship as package data (no runtime Wazuh
  import required).

## Install

```bash
pip install sec-audit-rules
# with the Wazuh HTTP client extra:
pip install "sec-audit-rules[wazuh]"
```

## Writing a rule

```python
from sec_audit.rules import Rule, RuleMatch

class TooManyFailedLogins(Rule):
    name = 'too_many_failed_logins'
    event_types = {'auth.login.failed'}
    severity = 8
    safe_for_enforcement = True

    def evaluate(self, event, ctx):
        srcip = str(event.fields.get('srcip') or '')
        count = ctx.counters.incr(f'login_fail:{srcip}', ttl=300)
        if count < 5:
            return None
        return RuleMatch(
            self.name, self.severity, ctx.now,
            f'Too many failed logins from {srcip}',
            metadata={'count': count, 'srcip': srcip},
        )
```

Rules are pure detectors — no logging, DB writes, or external calls; `RuleMatch.metadata`
is immutable after creation.

## License

MIT
