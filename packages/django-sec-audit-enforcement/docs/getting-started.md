# Getting started

This guide installs the enforcement layer on top of a working `django-sec-audit`
setup (see that package's [how-to-use](../../django-sec-audit/docs/how-to-use.md)
for the audit base — enforcement reuses its logging runtime, trusted-proxy IP
resolution, and `sec_audit.audit` logger).

## 1. Install

```bash
pip install django-sec-audit-enforcement
```

This pulls in `sec-audit-rules[redis]` and `django-sec-audit`.

## 2. Add the app

The app ships the `PermanentBlock` model and registers Django system checks.
Add it to `INSTALLED_APPS` (the audit base app must already be present):

```python
INSTALLED_APPS = [
    'sec_audit.django.apps.SecAuditConfig',          # the audit base (early)
    'sec_audit.django_enforcement',                  # this package
    # ... your apps
]
```

## 3. Add the middleware

`EnforcementMiddleware` must sit **above** `AuditMiddleware` so an active block
short-circuits before any audit/view work:

```python
MIDDLEWARE = [
    # ... Django stock middleware (Security, Session, Auth, CSRF, etc.)
    'sec_audit.django_enforcement.middleware.EnforcementMiddleware',  # above AuditMiddleware
    'sec_audit.django.middleware.AuditMiddleware',
]
```

A misplaced or missing middleware is reported by `manage.py check`
(`sec_audit_enforcement.E001`/`E002`) — see [Operations](operations.md#system-checks).

## 4. Run migrations

The permanent-block tier needs the `PermanentBlock` table:

```bash
python manage.py migrate sec_audit_enforcement
```

## 5. Enable enforcement

The master switch is **off by default**. Turn it on, point it at Redis, and
**register the rules you want** — no detectors run unless you list them:

```python
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'redis_url': 'redis://localhost:6379/0',
    # permanent_tier_enabled defaults to True -> permanent bans go to Postgres
    'rules': [
        # Register the built-ins you want (or your own — see Custom rules).
        'sec_audit.rules.builtins.BruteForceLoginRule',
        'sec_audit.rules.builtins.LoginThrottleRule',
        'sec_audit.rules.builtins.RepeatedClientErrorRule',
    ],
}
```

Nothing is forced on you: with `rules` empty, enforcement still honours blocks
you create manually or via the admin, but no rule writes new ones. Each rule you
register is wired to a scope-safe default action (see the table below) and can be
retuned via [`rule_actions`](configuration.md#rule_actions).

Without `redis_url` the engine and block store fall back to **per-process
in-memory** stores. That is fine for a single-process dev server or the demo,
but it is incorrect on a multi-worker deployment (each worker has its own state)
— `manage.py check` warns with `sec_audit_enforcement.W004`.

Config is validated **fail-fast at app `ready()`**: an unknown key, a bad type,
or a malformed regex/import path raises `AuditConfigurationError` at startup, not
at request time. See the full [Configuration reference](configuration.md).

## 6. Verify

```bash
python manage.py check          # should report no E001/E002 errors
```

Drive the registered `brute_force_login` rule by failing auth repeatedly from one
IP, then confirm the IP is blocked:

```python
# Django shell
from sec_audit.django_enforcement.runtime import get_enforcement_runtime
from sec_audit.enforcement.blocks import BlockScope

rt = get_enforcement_runtime()
print(rt.config.enabled)                                   # True
print(rt.block_store.first_active([BlockScope('ip', '203.0.113.10')]))  # a BlockEntry once blocked
```

A blocked request returns the configured status (default **429**) with the
configured message, and emits an `audit.enforcement.blocked` event on the
`sec_audit.audit` logger (see [Enforcement events](events.md)).

## Built-in rules you can register

The package ships these detectors. None run until you list them in `rules`; once
registered, each is wired to a scope-safe default action:

| Rule | Fires on | Default action |
|------|----------|----------------|
| `brute_force_login` | repeated auth failures | temp block on `ip` |
| `login_throttle` | login request rate (ingress fast path) | temp block on `ip` |
| `repeated_client_error` | repeated 4xx from one source | temp block on `ip` |

Register them by dotted path under `sec_audit.rules.builtins` (see the example in
step 5). To add your own detectors, see [Custom rules](custom-rules.md). To change
what a rule does when it fires, see [`rule_actions`](configuration.md#rule_actions).
