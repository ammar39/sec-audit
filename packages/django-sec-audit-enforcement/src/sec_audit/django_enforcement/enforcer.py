"""Turns a resolved ``RuleAction`` into a block-store write + enforcement events.

The Enforcer is framework-agnostic and unit-testable: it takes the block store,
the scope registry, and the policy primitives, and produces ``(AuditEvent,
level)`` pairs (it does not emit — the consumer emits). ``persist`` is the
optional ``ResultSink`` entry point (engine-driven application); it emits via an
injected emitter and is limited to scopes derivable from the match itself.
"""

from __future__ import annotations

import logging

from sec_audit.core.json import json_safe
from sec_audit.core.scrubbers import scrub
from sec_audit.enforcement.actions import effective_action_ttl, resolve_rule_action
from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE

from sec_audit.django_enforcement import emit as emit_mod

logger = logging.getLogger('sec_audit.enforcement')


class Enforcer:
    def __init__(
        self,
        *,
        block_store,
        scope_registry,
        schema_version: str,
        rule_actions=None,
        block_rules=None,
        default_ttl: int | None = 300,
        default_action: str = 'observe',
        block_severity: int | None = None,
        status_code: int = 429,
        message: str = DEFAULT_BLOCK_MESSAGE,
        emitter=None,
    ) -> None:
        self.block_store = block_store
        self.scope_registry = scope_registry
        self.schema_version = schema_version
        self.rule_actions = dict(rule_actions or {})
        self.block_rules = dict(block_rules or {})
        self.default_ttl = default_ttl
        self.default_action = default_action
        self.block_severity = block_severity
        self.status_code = int(status_code)
        self.message = message
        self._emitter = emitter

    def resolve_action(self, match):
        return resolve_rule_action(
            match,
            configured_actions=self.rule_actions,
            block_rules=self.block_rules,
            default_ttl=self.default_ttl,
            default_action=self.default_action,
        )

    def apply(self, match, action, summary):
        """Apply ``action`` for ``match``; return ``(AuditEvent, level)`` pairs."""
        kind = self._action_kind(action, match)
        if kind is None:
            if action.action == 'alert':
                # Detect-and-surface: emit a per-match detection event so
                # alert-only rules are observable always-on, without blocking.
                return [
                    emit_mod.build_alert_event(
                        match, schema_version=self.schema_version
                    )
                ]
            return []  # observe / unknown write nothing
        scopes = self.scope_registry.block_scopes(summary, only=action.scopes)
        metadata = self._safe_metadata(match)
        results = []
        for scope in scopes:
            if kind == 'temp':
                ttl = (
                    effective_action_ttl(action, match, self.default_ttl)
                    or self.default_ttl
                    or 300
                )
            else:
                ttl = None  # permanent
            entry = self.block_store.block(
                scope,
                reason=match.message or match.rule_name,
                rule_name=match.rule_name,
                status_code=int(action.status_code or self.status_code),
                message=action.message or self.message,
                ttl=ttl,
                metadata=metadata,
            )
            results.append(
                emit_mod.build_block_applied_event(
                    entry,
                    action_kind=kind,
                    ttl=ttl,
                    schema_version=self.schema_version,
                )
            )
        return results

    def persist(self, match) -> None:
        """ResultSink entry. Scopes are limited to what the match carries
        (``srcip``/``session_id``); the consumer path has the full event."""
        try:
            action = self.resolve_action(match)
            summary = {
                'srcip': match.srcip or '',
                'session_id': match.session_id or '',
            }
            for built in self.apply(match, action, summary):
                if self._emitter is not None:
                    self._emitter.emit(built)
        except Exception:
            logger.warning(
                'Enforcement persist failed for %r',
                getattr(match, 'rule_name', match),
                exc_info=True,
            )

    def _action_kind(self, action, match) -> str | None:
        name = action.action
        if name == 'temp_block':
            return 'temp'
        if name == 'persist_block':
            # An explicit operator decision; the default rule_actions scope
            # permanent bans to user/session (never ip) for shared-egress safety.
            return 'permanent'
        if name == 'block':
            # Severity-gated escalation: only high-severity matches reach the
            # permanent tier; everything else degrades to a temp block.
            return 'permanent' if self._severity_ok(match) else 'temp'
        return None  # observe / alert / unknown

    def _severity_ok(self, match) -> bool:
        return self.block_severity is not None and match.severity >= self.block_severity

    @staticmethod
    def _safe_metadata(match) -> dict:
        safe = json_safe(scrub(dict(match.metadata or {})))
        return safe if isinstance(safe, dict) else {}
