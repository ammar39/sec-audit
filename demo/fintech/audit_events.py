"""Demo: a user-authored custom event + schema + stateful rule.

Shows the public authoring story end to end (consuming package features, not
reimplementing them): an ``EventSchema`` declares field roles, the rule reads the
accumulated model from history keyed on the schema-derived ``account_id`` scope,
and the recipient handle is persisted to history *redacted* (declared SENSITIVE).
The demo's ``transfer`` view fires the event via ``fire_event``.
"""

from __future__ import annotations

from sec_audit.rules.base import ContextRequirements, Rule, make_match
from sec_audit.rules.schema import EventSchema, FieldRole, SchemaField

TRANSFER_EVENT = 'fintech.transfer.attempted'

# account_id -> a custom correlation dimension; amount -> the accumulated model;
# destination_alias -> persisted for correlation but redacted in the history store.
TRANSFER_SCHEMA = EventSchema(
    TRANSFER_EVENT,
    (
        SchemaField('account_id', frozenset({FieldRole.SCOPE})),
        SchemaField('amount', frozenset({FieldRole.MODEL})),
        SchemaField(
            'destination_alias', frozenset({FieldRole.MODEL, FieldRole.SENSITIVE})
        ),
    ),
)


class TransferVelocityRule(Rule):
    """Alert when an account's total transferred amount exceeds a window threshold.

    Reads the per-account model the schema persisted into history — no per-rule
    ``history_attributes`` needed.
    """

    name = 'transfer_velocity'
    severity = 7
    event_types = {TRANSFER_EVENT}
    context = ContextRequirements(scopes=frozenset({'account_id'}), window_seconds=300)

    threshold = 10_000.0

    def evaluate(self, event, ctx):
        total = float(event.field('amount') or 0)
        for row in ctx.history.events('account_id', window_seconds=300):
            total += float(row.get('amount') or 0)
        if total < self.threshold:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message=f'Transfer velocity exceeded ({total:.2f} in 5m window)',
            event=event,
            metadata={'window_total': total},
        )
