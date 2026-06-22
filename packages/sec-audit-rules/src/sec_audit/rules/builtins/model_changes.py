from __future__ import annotations

from collections.abc import Sequence

from sec_audit.rules.base import Rule, RuleContext, RuleMatch, make_match
from sec_audit.rules.events import RuleEvent


class SensitiveFieldChangeRule(Rule):
    name = 'sensitive_field_change'
    severity = 7
    event_types = {'model.update'}
    safe_for_enforcement = False

    def __init__(
        self,
        *,
        fields: Sequence[str],
        model_labels: Sequence[str] = (),
        severity: int | None = None,
        message: str = 'Sensitive model fields were changed',
        tags: Sequence[str] = ('model', 'sensitive-change'),
    ) -> None:
        self.fields = frozenset(str(field).lower() for field in fields)
        self.model_labels = frozenset(str(label).lower() for label in model_labels)
        if severity is not None:
            self.severity = int(severity)
        self.message = str(message)
        self.tags = tuple(str(tag) for tag in tags)

    def evaluate(self, event: RuleEvent, ctx: RuleContext) -> RuleMatch | None:
        model_label = event.model.label.lower()
        if self.model_labels and model_label not in self.model_labels:
            return None
        changed = _changed_fields(event.field('changed_fields'))
        matched = tuple(sorted(changed.intersection(self.fields)))
        if not matched:
            return None
        return make_match(
            rule_name=self.name,
            severity=self.severity,
            now=ctx.now,
            message=self.message,
            event=event,
            tags=self.tags,
            metadata={
                'changed_fields': matched,
                'model_label': model_label,
            },
            subject=event.model.object_id or None,
        )


def _changed_fields(value: object) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value.lower()})
    try:
        return frozenset(str(field).lower() for field in value)
    except TypeError:
        return frozenset()
