from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string
from sec_audit.rules.events import RuleEvent

__all__ = [
    'EventContextBuilder',
    'MappingEventBuilder',
    'Trigger',
    'TriggerRegistry',
]


@runtime_checkable
class EventContextBuilder(Protocol):
    """Build a normalized :class:`RuleEvent` from framework-specific trigger input.

    Framework-free contract: a concrete builder (e.g. in ``django-sec-audit``) reads a
    request/signal payload and returns the normalized event the rule engine consumes.
    Rules and enforcement depend on this contract, never on the framework.
    """

    def build(self, payload: Mapping[str, object]) -> RuleEvent: ...


class MappingEventBuilder:
    """Builder for payloads that are already normalized mappings.

    ``RuleEvent.from_mapping`` already duck-types the core ``AuditEvent`` (via its
    ``.attributes``), so this single builder covers the egress/auth/model triggers
    (pass the event through) and the ingress trigger (override the ``event_type`` to
    the synthetic pre-request type).
    """

    def __init__(self, event_type: str | None = None) -> None:
        self._event_type = event_type

    def build(self, payload: Mapping[str, object]) -> RuleEvent:
        # Apply the event_type override LAST so it wins over any payload 'event_type'
        # (matches the historical synthesize_pre_request_event). With no override pass
        # the payload through unchanged — never inject an 'event_type' key.
        if self._event_type is not None:
            return RuleEvent.from_mapping(
                {**dict(payload), 'event_type': self._event_type}
            )
        return RuleEvent.from_mapping(payload)


@dataclass(frozen=True)
class Trigger:
    """A named source of normalized events feeding the rule engine.

    ``name``             stable identifier (e.g. ``'http.egress'``, ``'http.ingress'``,
                         ``'auth'``, ``'model'``, or a user's custom name).
    ``event_types``      the event_type string(s) this trigger emits; documents which
                         rules (via ``Rule.event_types``) subscribe and enforces registry
                         uniqueness. Informational — it does not gate dispatch.
    ``builder``          the :class:`EventContextBuilder` producing the ``RuleEvent``.
    ``enforcement_only`` True only for the ingress synthetic fast-path; the engine
                         evaluates these with ``enforcement_only=True`` and does not write
                         history (mirrors the pre-request middleware behavior).
    """

    name: str
    event_types: frozenset[str]
    builder: EventContextBuilder
    enforcement_only: bool = False

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError('Trigger.name must be non-empty.')
        object.__setattr__(self, 'name', str(self.name))
        object.__setattr__(self, 'event_types', frozenset(map(str, self.event_types)))


class TriggerRegistry:
    """Resolved set of triggers, keyed by name. Mirrors ``ScopeRegistry``.

    Built-in defaults are *injected* by the caller (``defaults=``) rather than
    hardcoded here: the concrete built-ins live in the Django/enforcement layer,
    which this framework-free module must not import.
    """

    def __init__(self, triggers: Sequence[Trigger]) -> None:
        by_name: dict[str, Trigger] = {}
        for trigger in triggers:
            if not isinstance(trigger, Trigger):
                raise AuditConfigurationError(
                    f'TriggerRegistry requires Trigger instances, got {trigger!r}.'
                )
            if trigger.name in by_name:
                raise AuditConfigurationError(
                    f'Duplicate trigger name {trigger.name!r}.'
                )
            by_name[trigger.name] = trigger
        self._by_name = by_name
        self._triggers = tuple(by_name.values())

    @property
    def triggers(self) -> tuple[Trigger, ...]:
        return self._triggers

    def by_name(self, name: str) -> Trigger | None:
        return self._by_name.get(name)

    @classmethod
    def from_specs(
        cls,
        specs: Sequence[object] = (),
        *,
        include_defaults: bool = True,
        defaults: Sequence[Trigger] = (),
    ) -> 'TriggerRegistry':
        triggers = list(defaults) if include_defaults else []
        for spec in specs:
            triggers.append(_coerce_trigger(spec))
        return cls(triggers)


def _coerce_trigger(spec: object) -> Trigger:
    """Resolve a spec to a ``Trigger``: an instance, an import path, or a factory."""
    resolved = import_string(spec) if isinstance(spec, str) else spec
    if isinstance(resolved, Trigger):
        return resolved
    if callable(resolved):
        try:
            built = resolved()
        except Exception as exc:
            raise AuditConfigurationError(
                f'Failed to build trigger from spec {spec!r}: {exc}'
            ) from exc
        if isinstance(built, Trigger):
            return built
    raise AuditConfigurationError(
        f'Trigger spec {spec!r} did not resolve to a Trigger '
        f'(got {type(resolved).__name__}).'
    )
