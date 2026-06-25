from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping

from sec_audit.rules.base import RuleMatch

logger = logging.getLogger('sec_audit.rules')

TEMPORARY_ACTIONS = {'temp_block'}
PERSISTENT_ACTIONS = {'persist_block'}
BLOCKING_ACTIONS = {'block', 'temp_block', 'persist_block'}
ALERT_SEVERITY = 4
DEFAULT_BLOCK_SCOPES = ('ip',)
# A bare persist_block (permanent) never defaults to ip — a permanent ip ban
# behind shared egress (NAT, mobile carrier) would lock out many users.
PERSIST_DEFAULT_SCOPES = ('user', 'session')


@dataclass(frozen=True)
class RuleAction:
    action: str
    ttl: int | None = None
    scopes: tuple[str, ...] = DEFAULT_BLOCK_SCOPES
    status_code: int | None = None
    message: str | None = None


def _configured_rule_action(spec: object) -> RuleAction:
    if isinstance(spec, str):
        return RuleAction(action=spec)
    data = dict(spec) if isinstance(spec, Mapping) else {}
    scopes = data.get('scopes') or DEFAULT_BLOCK_SCOPES
    if isinstance(scopes, str):
        scopes = (scopes,)
    return RuleAction(
        action=str(data.get('action') or 'observe'),
        ttl=data.get('ttl'),
        scopes=tuple(str(scope) for scope in scopes),
        status_code=data.get('status_code'),
        message=data.get('message'),
    )


def _match_block_ttl(match: RuleMatch, default_ttl: int | None) -> int | None:
    ttl = match.metadata.get('block_ttl', match.metadata.get('ttl'))
    if ttl is None and match.decision == 'temp_block':
        ttl = default_ttl or 300
    return int(ttl) if ttl is not None else None


def effective_action_ttl(
    rule_action: RuleAction,
    match: RuleMatch,
    default_ttl: int | None,
) -> int | None:
    return rule_action.ttl or _match_block_ttl(match, default_ttl) or default_ttl


def resolve_rule_action(
    match: RuleMatch,
    *,
    configured_actions: Mapping[str, object],
    block_rules: Mapping[str, int],
    default_ttl: int | None,
    default_action: str = 'observe',
) -> RuleAction:
    configured = configured_actions.get(match.rule_name)
    if configured is not None:
        return _configured_rule_action(configured)
    if match.rule_name in block_rules:
        return RuleAction(action='temp_block', ttl=block_rules[match.rule_name])
    if match.decision == 'persist_block':
        # A bare persist_block (no configured rule_actions entry) would inherit
        # DEFAULT_BLOCK_SCOPES=('ip',) and produce a permanent IP ban. Default it
        # to user/session (never ip); an explicit rule_actions scopes entry still
        # wins (it resolves via configured_actions above).
        logger.warning(
            'Rule %r resolved persist_block with no configured scopes; '
            'defaulting to %s (never ip) for shared-egress safety. Set '
            'rule_actions[%r].scopes to override.',
            match.rule_name,
            PERSIST_DEFAULT_SCOPES,
            match.rule_name,
        )
        return RuleAction(
            action='persist_block',
            ttl=_match_block_ttl(match, default_ttl),
            scopes=PERSIST_DEFAULT_SCOPES,
        )
    if match.decision in BLOCKING_ACTIONS or match.decision in {'alert', 'observe'}:
        return RuleAction(
            action=str(match.decision),
            ttl=_match_block_ttl(match, default_ttl),
        )
    if default_action == 'alert':
        return RuleAction(action='alert')
    if default_action in BLOCKING_ACTIONS:
        return RuleAction(
            action=str(default_action),
            ttl=_match_block_ttl(match, default_ttl),
        )
    return RuleAction(action='observe')
