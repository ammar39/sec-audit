from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from sec_audit.core.config_validation import int_value, str_value
from sec_audit.core.exceptions import AuditConfigurationError

RULE_ACTIONS = {'observe', 'alert', 'block', 'temp_block', 'persist_block'}


@dataclass(frozen=True)
class EnforcementAuditConfig:
    enforcement_block_severity: int | None = None
    enforcement_status_code: int = 429
    enforcement_message: str = 'Request blocked by audit enforcement policy'
    block_cache_ttl: int = 300
    block_rules: dict[str, int] = field(default_factory=dict)
    rule_actions: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.enforcement_block_severity is not None:
            severity = int_value(
                'enforcement_block_severity', self.enforcement_block_severity
            )
            if severity < 0 or severity > 10:
                raise AuditConfigurationError(
                    'enforcement_block_severity must be None or between 0 and 10.'
                )
            object.__setattr__(self, 'enforcement_block_severity', severity)
        status_code = int_value('enforcement_status_code', self.enforcement_status_code)
        if status_code < 100 or status_code > 599:
            raise AuditConfigurationError(
                'enforcement_status_code must be an HTTP status code.'
            )
        object.__setattr__(self, 'enforcement_status_code', status_code)
        object.__setattr__(
            self,
            'enforcement_message',
            str_value('enforcement_message', self.enforcement_message),
        )
        block_cache_ttl = int_value('block_cache_ttl', self.block_cache_ttl)
        if block_cache_ttl < 0:
            raise AuditConfigurationError(
                'block_cache_ttl must be greater than or equal to 0.'
            )
        object.__setattr__(self, 'block_cache_ttl', block_cache_ttl)
        object.__setattr__(self, 'block_rules', _validate_block_rules(self.block_rules))
        object.__setattr__(
            self, 'rule_actions', _validate_rule_actions(self.rule_actions)
        )


def _validate_block_rules(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise AuditConfigurationError('block_rules must be a mapping.')
    parsed = {}
    for rule_name, ttl in value.items():
        parsed[str(rule_name)] = int_value('block_rules TTL', ttl)
        if parsed[str(rule_name)] <= 0:
            raise AuditConfigurationError('block_rules TTLs must be positive.')
    return parsed


def _validate_rule_actions(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise AuditConfigurationError('rule_actions must be a mapping.')
    parsed = {}
    for rule_name, spec in value.items():
        if isinstance(spec, str):
            normalized = {'action': spec}
        elif isinstance(spec, Mapping):
            normalized = dict(spec)
        else:
            raise AuditConfigurationError(
                'rule_actions values must be action strings or mappings.'
            )
        action = normalized.get('action')
        if not isinstance(action, str) or action not in RULE_ACTIONS:
            raise AuditConfigurationError(
                f'rule_actions action for {rule_name!r} must be one of: '
                f'{", ".join(sorted(RULE_ACTIONS))}.'
            )
        if 'ttl' in normalized and normalized['ttl'] is not None:
            normalized['ttl'] = int_value('rule_actions ttl', normalized['ttl'])
            if normalized['ttl'] <= 0:
                raise AuditConfigurationError('rule_actions ttl must be positive.')
        if 'status_code' in normalized and normalized['status_code'] is not None:
            normalized['status_code'] = int_value(
                'rule_actions status_code', normalized['status_code']
            )
            if normalized['status_code'] < 100 or normalized['status_code'] > 599:
                raise AuditConfigurationError(
                    'rule_actions status_code must be an HTTP status code.'
                )
        if 'scopes' in normalized and isinstance(normalized['scopes'], str):
            raise AuditConfigurationError('rule_actions scopes must be a sequence.')
        parsed[str(rule_name)] = normalized
    return parsed
