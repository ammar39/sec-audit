from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string
from sec_audit.rules.events import SummaryKey


@dataclass(frozen=True)
class ScopeKey:
    scope: str
    key: str

    def __post_init__(self) -> None:
        scope = str(self.scope).strip()
        key = str(self.key).strip()
        if not scope:
            raise ValueError('scope cannot be empty.')
        if not key:
            raise ValueError('scope key cannot be empty.')
        object.__setattr__(self, 'scope', scope)
        object.__setattr__(self, 'key', key)

    def as_string(self) -> str:
        return f'{self.scope}:{self.key}'


class HistoryScopeExtractor(Protocol):
    scope_names: set[str]

    def extract(self, event_summary: Mapping[str, object]) -> Sequence[ScopeKey]: ...


class UserScopeExtractor:
    scope_names = {'user'}

    def extract(self, event_summary: Mapping[str, object]) -> Sequence[ScopeKey]:
        actor = event_summary.get('actor')
        actor_id = actor_name = None
        if isinstance(actor, Mapping):
            actor_id = _clean_key(actor.get(SummaryKey.ACTOR_ID))
            actor_name = _clean_key(actor.get(SummaryKey.ACTOR_NAME))
        user_id = (
            _clean_key(event_summary.get(SummaryKey.USER_ID))
            or actor_id
            or _clean_key(event_summary.get(SummaryKey.USERNAME))
            or actor_name
        )
        return [ScopeKey('user', user_id)] if user_id else []


class SessionScopeExtractor:
    scope_names = {'session'}

    def extract(self, event_summary: Mapping[str, object]) -> Sequence[ScopeKey]:
        session_id = _clean_key(event_summary.get(SummaryKey.SESSION_ID))
        return [ScopeKey('session', session_id)] if session_id else []


class IPScopeExtractor:
    scope_names = {'ip'}

    def extract(self, event_summary: Mapping[str, object]) -> Sequence[ScopeKey]:
        srcip = _clean_key(event_summary.get(SummaryKey.SRCIP))
        return [ScopeKey('ip', srcip)] if srcip else []


class RouteScopeExtractor:
    scope_names = {'route'}

    def extract(self, event_summary: Mapping[str, object]) -> Sequence[ScopeKey]:
        route = _clean_key(event_summary.get(SummaryKey.ROUTE))
        return [ScopeKey('route', route)] if route else []


class FieldScopeExtractor:
    """Extract a custom correlation key from a single declared summary field.

    Backs a schema-derived scope (a ``SCOPE``-role field): reads the field the
    schema projected into the summary and yields a ``ScopeKey(scope_name, value)``
    so a rule can correlate a user-defined dimension. A missing/empty field yields
    no scope (silently), matching the built-in extractors.
    """

    def __init__(self, field_name: str, scope_name: str) -> None:
        self.field_name = str(field_name)
        self._scope_name = str(scope_name)
        self.scope_names = {self._scope_name}

    def extract(self, event_summary: Mapping[str, object]) -> Sequence[ScopeKey]:
        value = _clean_key(event_summary.get(self.field_name))
        return [ScopeKey(self._scope_name, value)] if value else []


DEFAULT_HISTORY_SCOPE_EXTRACTORS = (
    UserScopeExtractor,
    SessionScopeExtractor,
    IPScopeExtractor,
    RouteScopeExtractor,
)


def build_history_scope_extractors(
    specs: Sequence[object] = (),
    *,
    include_defaults: bool = True,
) -> tuple[HistoryScopeExtractor, ...]:
    configured = (
        (*DEFAULT_HISTORY_SCOPE_EXTRACTORS, *tuple(specs))
        if include_defaults
        else tuple(specs)
    )
    extractors = [_build_extractor(spec) for spec in configured]
    _validate_unique_scope_names(extractors)
    return tuple(extractors)


def extract_scope_keys(
    event_summary: Mapping[str, object],
    extractors: Sequence[HistoryScopeExtractor],
) -> tuple[ScopeKey, ...]:
    seen = set()
    keys = []
    for extractor in extractors:
        for scope_key in extractor.extract(event_summary):
            compound = scope_key.as_string()
            if compound not in seen:
                keys.append(scope_key)
                seen.add(compound)
    return tuple(keys)


def _build_extractor(spec: object) -> HistoryScopeExtractor:
    if isinstance(spec, str):
        spec = import_string(spec)
    if isinstance(spec, type):
        try:
            return spec()
        except Exception as exc:
            raise AuditConfigurationError(
                f'Failed to initialize history scope extractor {spec!r}: {exc}'
            ) from exc
    return spec


def _validate_unique_scope_names(extractors: Sequence[HistoryScopeExtractor]) -> None:
    owners = {}
    for extractor in extractors:
        names = getattr(extractor, 'scope_names', None)
        if not names:
            raise AuditConfigurationError(
                f'History scope extractor {extractor!r} must define scope_names.'
            )
        for scope in names:
            scope = str(scope)
            if scope in owners:
                raise AuditConfigurationError(
                    f'Duplicate history scope extractor for scope {scope!r}: '
                    f'{owners[scope]!r} and {extractor!r}.'
                )
            owners[scope] = extractor
        if not callable(getattr(extractor, 'extract', None)):
            raise AuditConfigurationError(
                f'History scope extractor {extractor!r} must define extract().'
            )


def _clean_key(value: object) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None
