"""Unified scope registry shared by detection history, counters, and blocks.

The registry wraps the existing :mod:`sec_audit.rules.history` extractors into an
ordered set of named scope definitions. Order is *block precedence*: on an
ingress block check the candidate scopes are evaluated in order and the first
active block wins, so ``user`` before ``ip`` attributes an authenticated ban
correctly even behind shared NAT.

``block_scopes()`` is the single place where the detection vocabulary
(``ScopeKey``) becomes the ban vocabulary (``BlockScope``), so a rule that fires
on ``ip`` bans the same ``ip`` the ingress check reads — closing the
spoof/mismatch gap by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.rules.history import (
    HistoryScopeExtractor,
    IPScopeExtractor,
    RouteScopeExtractor,
    ScopeKey,
    SessionScopeExtractor,
    UserScopeExtractor,
    _build_extractor,
    extract_scope_keys,
)


@dataclass(frozen=True)
class ScopeDefinition:
    name: str
    extractor: HistoryScopeExtractor
    # Whether a block may be keyed on this scope. ``route`` is a detection
    # dimension by default but not a ban dimension (banning a whole route bans
    # every client of it — a self-DoS), matching DEFAULT_BLOCK_SCOPES=('ip',).
    block_eligible: bool = True


DEFAULT_SCOPE_DEFINITIONS: tuple[ScopeDefinition, ...] = (
    ScopeDefinition('user', UserScopeExtractor()),
    ScopeDefinition('session', SessionScopeExtractor()),
    ScopeDefinition('ip', IPScopeExtractor()),
    ScopeDefinition('route', RouteScopeExtractor(), block_eligible=False),
)


class ScopeRegistry:
    def __init__(self, definitions: Sequence[ScopeDefinition]) -> None:
        definitions = tuple(definitions)
        seen: set[str] = set()
        for definition in definitions:
            if not isinstance(definition, ScopeDefinition):
                raise AuditConfigurationError(
                    'ScopeRegistry definitions must be ScopeDefinition instances.'
                )
            if definition.name in seen:
                raise AuditConfigurationError(
                    f'Duplicate scope definition for {definition.name!r}.'
                )
            seen.add(definition.name)
        self._definitions = definitions

    @property
    def definitions(self) -> tuple[ScopeDefinition, ...]:
        return self._definitions

    @property
    def extractors(self) -> tuple[HistoryScopeExtractor, ...]:
        """Ordered extractor set, suitable for ``RuleEngine(history_extractors=)``."""
        return tuple(definition.extractor for definition in self._definitions)

    def names(self) -> tuple[str, ...]:
        return tuple(definition.name for definition in self._definitions)

    def scope_keys(self, summary: Mapping[str, object]) -> tuple[ScopeKey, ...]:
        return extract_scope_keys(summary, self.extractors)

    def block_scopes(
        self,
        summary: Mapping[str, object],
        *,
        only: Sequence[str] | None = None,
    ):
        """Derive ``BlockScope`` candidates from a summary, in precedence order.

        ``only`` (a ``RuleAction.scopes`` list) restricts the result to those
        scope names; ``None`` returns every block-eligible scope present.
        ``BlockScope`` is imported lazily so importing this module never pulls
        the enforcement package at rules-import time (avoids an import cycle).
        """
        from sec_audit.enforcement.blocks import BlockScope

        allowed = set(only) if only is not None else None
        result = []
        seen: set[tuple[str, str]] = set()
        for definition in self._definitions:
            if not definition.block_eligible:
                continue
            if allowed is not None and definition.name not in allowed:
                continue
            for scope_key in definition.extractor.extract(summary):
                pair = (scope_key.scope, scope_key.key)
                if pair in seen:
                    continue
                seen.add(pair)
                result.append(
                    BlockScope(scope_type=scope_key.scope, scope_value=scope_key.key)
                )
        return tuple(result)

    @classmethod
    def from_specs(
        cls,
        specs: Sequence[object] = (),
        *,
        include_defaults: bool = True,
    ) -> 'ScopeRegistry':
        definitions = list(DEFAULT_SCOPE_DEFINITIONS) if include_defaults else []
        for spec in specs:
            definitions.append(_coerce_definition(spec))
        return cls(definitions)


def _coerce_definition(spec: object) -> ScopeDefinition:
    if isinstance(spec, ScopeDefinition):
        return spec
    extractor = _build_extractor(spec)
    names = getattr(extractor, 'scope_names', None)
    if not names:
        raise AuditConfigurationError(
            f'Scope extractor {extractor!r} must define scope_names.'
        )
    # A custom extractor may declare several names; use a stable representative
    # (sorted for determinism) as the definition name.
    name = sorted(str(scope) for scope in names)[0]
    return ScopeDefinition(name=name, extractor=extractor)


__all__ = [
    'DEFAULT_SCOPE_DEFINITIONS',
    'ScopeDefinition',
    'ScopeRegistry',
]
