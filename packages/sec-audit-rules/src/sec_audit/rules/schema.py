"""Declarative event schemas: name the fields of a custom event and their roles.

A library user registers an :class:`EventSchema` for a custom ``event_type`` so
that, without memorizing the magic summary keys, they can:

- **SCOPE**     — derive a correlation dimension keyed on a field they choose
                  (wired into the existing ``ScopeRegistry`` in Stage 3/4).
- **MODEL**     — persist a field into the per-event history summary, *extending*
                  (never bypassing) the fixed whitelist, so rules correlate it
                  across events without per-rule ``history_attributes``.
- **SENSITIVE** — redact a field everywhere it could land, *including* the history
                  store, so a MODEL field can be persisted safely.

This module is framework-free (no Django) and inert on its own: it is consumed by
the engine's history projection (Stage 2) and the enforcement wiring (Stage 4).
The registry mirrors :class:`~sec_audit.rules.triggers.TriggerRegistry` — built-in
defaults are *injected* by the caller (``defaults=``), never hardcoded here.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string
from sec_audit.rules.engine import is_internal_event_type
from sec_audit.rules.events import SummaryKey, _HISTORY_WHITELIST
from sec_audit.rules.history import FieldScopeExtractor
from sec_audit.rules.scopes import DEFAULT_SCOPE_DEFINITIONS, ScopeDefinition

__all__ = [
    'FieldRole',
    'SchemaField',
    'EventSchema',
    'EventSchemaRegistry',
]


class FieldRole(enum.Enum):
    """The role a declared field plays in scope/history/redaction."""

    SCOPE = 'scope'
    MODEL = 'model'
    SENSITIVE = 'sensitive'


# Summary keys the schema must never let a custom field clobber: the fixed history
# whitelist plus the structured containers and the store-owned ``recorded_at``.
# A custom field named e.g. ``srcip``/``event_type`` would otherwise silently
# overwrite the system value, so registration rejects the collision (fail loud).
_RESERVED_SUMMARY_KEYS = frozenset(_HISTORY_WHITELIST) | {
    'actor',
    'target',
    'rule_attrs',
    'recorded_at',
    SummaryKey.SRCIP,
    SummaryKey.SESSION_ID,
    SummaryKey.USER_ID,
    SummaryKey.ROUTE,
}

# Built-in correlation dimensions a schema-derived scope must not shadow: a custom
# scope must introduce a NEW name, not silently collide with ip/user/session/route
# (which already populate automatically from the standard magic keys).
_BUILTIN_SCOPE_NAMES = frozenset(d.name for d in DEFAULT_SCOPE_DEFINITIONS)


@dataclass(frozen=True)
class SchemaField:
    """One declared field of an :class:`EventSchema`.

    ``roles``  one or more :class:`FieldRole`. ``{SCOPE, SENSITIVE}`` is rejected —
               a redacted value is a useless correlation key.
    ``scope``  the derived scope dimension name when ``SCOPE`` is in ``roles``;
               defaults to ``name``. Ignored otherwise.
    """

    name: str
    roles: frozenset[FieldRole]
    scope: str | None = None

    def __post_init__(self) -> None:
        name = str(self.name).strip()
        if not name:
            raise AuditConfigurationError('SchemaField.name must be non-empty.')
        roles = frozenset(self.roles)
        if not roles:
            raise AuditConfigurationError(
                f'SchemaField {name!r} must declare at least one role.'
            )
        bad = [r for r in roles if not isinstance(r, FieldRole)]
        if bad:
            raise AuditConfigurationError(
                f'SchemaField {name!r} has invalid role(s) {bad!r}; '
                'use FieldRole members.'
            )
        if FieldRole.SCOPE in roles and FieldRole.SENSITIVE in roles:
            raise AuditConfigurationError(
                f'SchemaField {name!r} cannot be both SCOPE and SENSITIVE: a redacted '
                'value is a useless correlation key.'
            )
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'roles', roles)
        scope = (str(self.scope).strip() or None) if self.scope is not None else None
        object.__setattr__(self, 'scope', scope)

    @property
    def is_scope(self) -> bool:
        return FieldRole.SCOPE in self.roles

    @property
    def is_model(self) -> bool:
        return FieldRole.MODEL in self.roles

    @property
    def is_sensitive(self) -> bool:
        return FieldRole.SENSITIVE in self.roles

    @property
    def scope_name(self) -> str:
        """Derived scope dimension name (``scope`` override or the field name)."""
        return self.scope or self.name


@dataclass(frozen=True)
class EventSchema:
    """A declared schema for one custom ``event_type``."""

    event_type: str
    fields: tuple[SchemaField, ...] = ()

    def __post_init__(self) -> None:
        event_type = str(self.event_type).strip()
        if not event_type:
            raise AuditConfigurationError('EventSchema.event_type must be non-empty.')
        if is_internal_event_type(event_type):
            raise AuditConfigurationError(
                f'EventSchema event_type {event_type!r} uses a reserved internal '
                'namespace (audit.rule.*/audit.enforcement.*/audit.context.*).'
            )
        fields = tuple(self.fields)
        seen_names: set[str] = set()
        seen_scopes: set[str] = set()
        for f in fields:
            if not isinstance(f, SchemaField):
                raise AuditConfigurationError(
                    f'EventSchema {event_type!r} fields must be SchemaField '
                    f'instances, got {f!r}.'
                )
            if f.name in seen_names:
                raise AuditConfigurationError(
                    f'EventSchema {event_type!r} has duplicate field {f.name!r}.'
                )
            seen_names.add(f.name)
            if f.name in _RESERVED_SUMMARY_KEYS:
                raise AuditConfigurationError(
                    f'EventSchema {event_type!r} field {f.name!r} collides with a '
                    'reserved system summary key; choose a different name.'
                )
            if f.is_scope:
                scope = f.scope_name
                if scope in _BUILTIN_SCOPE_NAMES:
                    raise AuditConfigurationError(
                        f'EventSchema {event_type!r} field {f.name!r} derives '
                        f'built-in scope {scope!r}; custom scopes need a new name '
                        '(ip/user/session/route populate automatically).'
                    )
                if scope in seen_scopes:
                    raise AuditConfigurationError(
                        f'EventSchema {event_type!r} derives duplicate scope '
                        f'{scope!r} from more than one field.'
                    )
                seen_scopes.add(scope)
        object.__setattr__(self, 'event_type', event_type)
        object.__setattr__(self, 'fields', fields)

    @property
    def field_names(self) -> frozenset[str]:
        return frozenset(f.name for f in self.fields)

    @property
    def model_field_names(self) -> frozenset[str]:
        return frozenset(f.name for f in self.fields if f.is_model)

    @property
    def scope_field_names(self) -> frozenset[str]:
        return frozenset(f.name for f in self.fields if f.is_scope)

    @property
    def sensitive_field_names(self) -> frozenset[str]:
        return frozenset(f.name for f in self.fields if f.is_sensitive)

    @property
    def projected_field_names(self) -> frozenset[str]:
        """Field names added to the history summary (MODEL plus SCOPE values)."""
        return self.model_field_names | self.scope_field_names

    def scope_bindings(self) -> tuple[tuple[str, str], ...]:
        """``(scope_name, field_name)`` pairs for each SCOPE field, sorted by name."""
        return tuple(sorted((f.scope_name, f.name) for f in self.fields if f.is_scope))

    def scope_definitions(self) -> list[ScopeDefinition]:
        """``ScopeDefinition``s for this schema's SCOPE fields, for the ScopeRegistry.

        Schema-derived scopes are detection/correlation dimensions only
        (``block_eligible=False``, like ``route``): a rule correlates on the custom
        dimension but bans on the standard ip/user/session dimensions via its action.
        """
        return [
            ScopeDefinition(
                name=scope_name,
                extractor=FieldScopeExtractor(field_name, scope_name),
                block_eligible=False,
            )
            for scope_name, field_name in self.scope_bindings()
        ]


class EventSchemaRegistry:
    """Resolved schemas keyed by ``event_type``. Mirrors ``TriggerRegistry``.

    Built-in defaults are *injected* by the caller (``defaults=``); this
    framework-free module never hardcodes them.
    """

    def __init__(self, schemas: Sequence[EventSchema]) -> None:
        by_type: dict[str, EventSchema] = {}
        scope_owner: dict[str, str] = {}
        for schema in schemas:
            if not isinstance(schema, EventSchema):
                raise AuditConfigurationError(
                    f'EventSchemaRegistry requires EventSchema instances, got '
                    f'{schema!r}.'
                )
            if schema.event_type in by_type:
                raise AuditConfigurationError(
                    f'Duplicate EventSchema for event_type {schema.event_type!r}.'
                )
            for scope_name, _field in schema.scope_bindings():
                if scope_name in scope_owner:
                    raise AuditConfigurationError(
                        f'Duplicate schema-derived scope {scope_name!r}: defined by '
                        f'{scope_owner[scope_name]!r} and {schema.event_type!r}.'
                    )
                scope_owner[scope_name] = schema.event_type
            by_type[schema.event_type] = schema
        self._by_type = by_type
        self._schemas = tuple(by_type.values())

    @property
    def schemas(self) -> tuple[EventSchema, ...]:
        return self._schemas

    def get(self, event_type: str) -> EventSchema | None:
        return self._by_type.get(str(event_type))

    def scope_definitions(self) -> list[ScopeDefinition]:
        """Aggregate schema-derived ``ScopeDefinition``s across every schema.

        Scope-name uniqueness across schemas is already enforced at construction,
        so these can be appended to the built-in scope specs without collision.
        """
        definitions: list[ScopeDefinition] = []
        for schema in self._schemas:
            definitions.extend(schema.scope_definitions())
        return definitions

    @classmethod
    def from_specs(
        cls,
        specs: Sequence[object] = (),
        *,
        include_defaults: bool = True,
        defaults: Sequence[EventSchema] = (),
    ) -> 'EventSchemaRegistry':
        schemas = list(defaults) if include_defaults else []
        for spec in specs:
            schemas.append(_coerce_schema(spec))
        return cls(schemas)


def _coerce_schema(spec: object) -> EventSchema:
    """Resolve a spec to an ``EventSchema``: an instance, import path, or factory."""
    resolved = import_string(spec) if isinstance(spec, str) else spec
    if isinstance(resolved, EventSchema):
        return resolved
    if callable(resolved):
        try:
            built = resolved()
        except Exception as exc:
            raise AuditConfigurationError(
                f'Failed to build EventSchema from spec {spec!r}: {exc}'
            ) from exc
        if isinstance(built, EventSchema):
            return built
    raise AuditConfigurationError(
        f'EventSchema spec {spec!r} did not resolve to an EventSchema '
        f'(got {type(resolved).__name__}).'
    )
