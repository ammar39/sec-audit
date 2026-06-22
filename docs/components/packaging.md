# Packaging

The project is published as four coordinated distributions:

| Distribution | Owns |
|---|---|
| `sec-audit` | `sec_audit.core` |
| `sec-audit-logging` | `sec_audit.logging` |
| `sec-audit-rules` | `sec_audit.rules`, `sec_audit.enforcement`, `sec_audit.integrations` |
| `django-sec-audit` | `sec_audit.django` |

Dependency graph:

```text
django-sec-audit
├── Django
├── sec-audit
└── sec-audit-logging
    └── sec-audit

sec-audit-rules
└── sec-audit
```

`django-sec-audit` must not depend on or import `sec-audit-rules`, and its
wheel must not include rule/enforcement/block modules, state/history stores,
models, or migrations.

Build order:

1. `sec-audit`
2. `sec-audit-logging`
3. `sec-audit-rules`
4. `django-sec-audit`
