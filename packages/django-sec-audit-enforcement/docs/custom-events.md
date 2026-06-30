# Custom events

Fire your own events into the same rules + enforcement pipeline the built-in
HTTP/auth/model triggers use, accumulate a correlated model across a stream of
them, and react with a rule — without leaking PII into any retention surface.

```python
from sec_audit.django_enforcement import fire_event

fire_event('payment.attempted', {'merchant_id': 'm-42', 'amount': 250.0})
```

`fire_event(event_type, fields=None, *, trigger=None) -> list[RuleMatch]` builds a
normalized event from `fields` and runs it through `engine.evaluate → enforcement
→ emit`. Custom rules subscribe by `Rule.event_types`; a match yields the usual
`audit.enforcement.*` event and may apply a block. The `event_type` must not use a
reserved internal namespace (`audit.rule.*` / `audit.enforcement.*` /
`audit.context.*`).

## The problem a schema solves

`fields` is a free-form mapping. Without a schema:

- You must know the magic scope keys (`srcip`/`session_id`/`user_id`/`route`); a
  typo is silently unmapped.
- Every field except a fixed system whitelist is **dropped** before history is
  persisted — so you cannot accumulate your own fields for correlation.

An `EventSchema` names each field's **role**, which drives scope derivation,
history persistence, and redaction.

## Field roles

| Role | Effect |
|---|---|
| `SCOPE` | Derives a custom correlation dimension keyed on this field, so a rule can read accumulated history grouped by it. (`ip`/`user`/`session`/`route` are built in.) |
| `MODEL` | Persisted into the per-event history summary (extends the fixed whitelist) so rules correlate it across events — no per-rule `history_attributes`. |
| `SENSITIVE` | Redacted everywhere it could land, **including the history store**. Combine with `MODEL` to persist a field safely. |

A field may hold multiple roles. `{SCOPE, SENSITIVE}` is rejected at registration
(a redacted value is a useless correlation key), as is a field name that collides
with a reserved system summary key or a built-in scope name.

## End to end

```python
# 1) Declare the schema (framework-free; lives wherever you like)
from sec_audit.rules.schema import EventSchema, SchemaField, FieldRole

PAYMENT_SCHEMA = EventSchema(
    'payment.attempted',
    (
        SchemaField('merchant_id', frozenset({FieldRole.SCOPE})),          # correlate on it
        SchemaField('amount',      frozenset({FieldRole.MODEL})),          # accumulate it
        SchemaField('pan',         frozenset({FieldRole.MODEL,             # persist redacted
                                              FieldRole.SENSITIVE})),
    ),
)

# 2) Write a stateful rule that reads the model from history
from sec_audit.rules.base import ContextRequirements, Rule, make_match

class HighValueMerchantBurst(Rule):
    name = 'high_value_merchant_burst'
    severity = 8
    event_types = {'payment.attempted'}
    context = ContextRequirements(scopes=frozenset({'merchant_id'}), window_seconds=300)

    def evaluate(self, event, ctx):
        total = float(event.field('amount') or 0)
        for row in ctx.history.events('merchant_id', window_seconds=300):
            total += float(row.get('amount') or 0)
        if total < 10_000:
            return None
        return make_match(rule_name=self.name, severity=self.severity, now=ctx.now,
                          message=f'merchant burst ({total:.2f})', event=event)

# 3) Register the schema + rule (settings.py). The 'merchant_id' scope is derived
#    automatically — no scope_specs needed.
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'schema_specs': ('myapp.events.PAYMENT_SCHEMA',),
    'rules': ('myapp.rules.HighValueMerchantBurst',),
}

# 4) Fire it from a view, task, or signal
fire_event('payment.attempted', {'merchant_id': 'm-42', 'amount': 250.0, 'pan': '4111...'})
```

> Correlation history (and therefore a stateful rule) requires a configured
> history store — set `redis_url`. With no store the schema still validates and
> redacts, but cross-event accumulation is a no-op.

## Request context (standard scopes)

The schema's `SCOPE` fields are your *custom* dimensions. The *standard*
dimensions (`ip`/`session`/`route`/`user`) come from the request:

- Inside a request, `fire_event` **auto-attaches** `srcip`/`session_id`/
  `request_id`/`route` from the ambient `AuditContext` (set by `AuditMiddleware`)
  for any key you did not supply — explicit values always win.
- The `user` dimension is not ambient (resolved post-response). Use
  `fields_from_request(request)` to add it (and re-confirm ip/session/route):

  ```python
  from sec_audit.django_enforcement import fields_from_request, fire_event

  fire_event('payment.attempted',
             {**fields_from_request(request), 'merchant_id': 'm-42', 'amount': 250.0})
  ```

Outside a request (Celery, shell) nothing is auto-attached — pass what you need.

## Safety guarantee — and your responsibility

A `SENSITIVE` field is redacted **before** it reaches the history store (the
redaction runs inside the per-event projection, ahead of scope extraction and the
store append), so a `MODEL ∪ SENSITIVE` field is persisted as `[REDACTED]`. The
emitted `audit.enforcement.*` log stream is built from the match with a fixed
shape, so custom fields never auto-leak there either.

Redaction is **by exact declared field name** — the schema is the source of
truth. The projection does *not* guess: a `MODEL` field that nests sensitive
sub-values you did not mark `SENSITIVE` is your responsibility — declare the field
`SENSITIVE` or don't persist it. (This is deliberate: a name-substring denylist
would silently redact innocuous fields like `token_count` and corrupt your model.)

## Fail-loud behavior

- **Unmapped key.** Under a registered schema, `fire_event` logs a warning when a
  field key matches no declared field and no known scope key — catching a typo
  that would otherwise be silently dropped. (Unschematized event types keep their
  free-form behavior.)
- **Enabled but no rules.** If enforcement is enabled with an empty `rules` list,
  the `W008` system check (and a boot warning) flags the silent no-op.

## See also

- [Custom rules](custom-rules.md) — writing detectors and `rule_actions`.
- [Configuration](configuration.md) — `schema_specs` / `trigger_specs` / `scope_specs`.
- [Events](events.md) — the emitted `audit.enforcement.*` reference.
