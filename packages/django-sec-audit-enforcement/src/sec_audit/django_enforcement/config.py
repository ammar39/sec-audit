"""``SEC_AUDIT_ENFORCEMENT`` settings -> validated ``DjangoEnforcementConfig``.

Parsed and validated fail-fast at app ``ready()`` so a misconfiguration is a
deploy-time error, not a runtime surprise. The master switch ``enabled`` is off
by default, so installing the package is inert until opted in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from re import Pattern
from typing import Any, Mapping

from sec_audit.core import config_validation as cv
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.enforcement.blocks import DEFAULT_BLOCK_MESSAGE
from sec_audit.enforcement.config import EnforcementAuditConfig

# Scope-safe defaults: temp blocks key on ``ip``; permanent (persist) blocks key
# on ``user``/``session`` — NEVER ``ip`` — because an ip-scoped permanent ban on
# shared egress (corporate NAT, mobile carrier) locks out many users. The block
# scope comes from ``action.scopes`` independent of temp/permanent, so this
# property must be encoded in the mapping, not left to operator discipline.
DEFAULT_RULE_ACTIONS: dict[str, object] = {
    'brute_force_login': {'action': 'temp_block', 'scopes': ['ip']},
    'login_throttle': {'action': 'temp_block', 'scopes': ['ip']},
    'repeated_client_error': {'action': 'temp_block', 'scopes': ['ip']},
    'repeated_route': {'action': 'temp_block', 'scopes': ['ip']},
    'request_body_threshold': {'action': 'temp_block', 'scopes': ['ip']},
    'sensitive_field_change': {
        'action': 'persist_block',
        'scopes': ['user', 'session'],
    },
    'suspicious_proxy_header': {'action': 'temp_block', 'scopes': ['ip']},
}

_KNOWN_KEYS = {
    'enabled',
    'fail_open',
    'fail_closed_paths',
    'redis_url',
    'permanent_tier_enabled',
    'permanent_cache_ttl',
    'default_temp_ttl',
    'eval_safe_on_ingress',
    'apply_via_sink',
    'scope_specs',
    'block_precedence',
    'status_code',
    'message',
    'block_severity',
    'rule_actions',
    'block_rules',
    'rules',
}


@dataclass(frozen=True)
class DjangoEnforcementConfig:
    enabled: bool = False
    fail_open: bool = True
    fail_closed_paths: tuple[Pattern[str], ...] = ()
    redis_url: str = ''
    permanent_tier_enabled: bool = True
    permanent_cache_ttl: int = 3600
    default_temp_ttl: int = 300
    eval_safe_on_ingress: bool = True
    apply_via_sink: bool = False
    scope_specs: tuple[object, ...] = ()
    # User-registered custom rules: import-path strings (``"module.attr"``) to a
    # ``Rule`` subclass/instance, or already-instantiated ``Rule`` objects. Here
    # only the ``"module.attr"`` shape of string entries is validated, fail-fast;
    # the actual import/instantiation runs eagerly at ``ready()`` in
    # ``setup_enforcement`` (via ``_all_rules``).
    rules: tuple[object, ...] = ()
    block_precedence: tuple[str, ...] = ()
    status_code: int = 429
    message: str = DEFAULT_BLOCK_MESSAGE
    enforcement: EnforcementAuditConfig = field(default_factory=EnforcementAuditConfig)

    def __post_init__(self) -> None:
        if not isinstance(self.enforcement, EnforcementAuditConfig):
            raise AuditConfigurationError(
                'enforcement must be an EnforcementAuditConfig instance.'
            )
        if self.permanent_cache_ttl <= 0:
            raise AuditConfigurationError('permanent_cache_ttl must be positive.')
        if self.default_temp_ttl <= 0:
            raise AuditConfigurationError('default_temp_ttl must be positive.')

    @classmethod
    def from_settings(cls, settings_obj: Any) -> 'DjangoEnforcementConfig':
        raw = getattr(settings_obj, 'SEC_AUDIT_ENFORCEMENT', None)
        if isinstance(raw, DjangoEnforcementConfig):
            return raw
        if raw is None:
            raw = {}
        if not isinstance(raw, Mapping):
            raise AuditConfigurationError(
                'SEC_AUDIT_ENFORCEMENT must be a mapping or DjangoEnforcementConfig.'
            )
        unknown = sorted(set(raw) - _KNOWN_KEYS)
        if unknown:
            names = ', '.join(str(name) for name in unknown)
            raise AuditConfigurationError(
                f'Unknown SEC_AUDIT_ENFORCEMENT key(s): {names}.'
            )

        # User rule_actions override the scope-safe defaults per rule name.
        rule_actions = {**DEFAULT_RULE_ACTIONS, **dict(raw.get('rule_actions', {}))}
        enforcement = EnforcementAuditConfig(
            enforcement_block_severity=raw.get('block_severity'),
            enforcement_status_code=cv.int_value(
                'status_code', raw.get('status_code', 429)
            ),
            enforcement_message=cv.str_value(
                'message', raw.get('message', DEFAULT_BLOCK_MESSAGE)
            ),
            block_rules=dict(raw.get('block_rules', {})),
            rule_actions=rule_actions,
        )

        return cls(
            enabled=cv.bool_value('enabled', raw.get('enabled', False)),
            fail_open=cv.bool_value('fail_open', raw.get('fail_open', True)),
            fail_closed_paths=cv.regex_tuple(
                'fail_closed_paths', raw.get('fail_closed_paths', ())
            ),
            redis_url=cv.str_value('redis_url', raw.get('redis_url', '')),
            permanent_tier_enabled=cv.bool_value(
                'permanent_tier_enabled', raw.get('permanent_tier_enabled', True)
            ),
            permanent_cache_ttl=cv.int_value(
                'permanent_cache_ttl', raw.get('permanent_cache_ttl', 3600)
            ),
            default_temp_ttl=cv.int_value(
                'default_temp_ttl', raw.get('default_temp_ttl', 300)
            ),
            eval_safe_on_ingress=cv.bool_value(
                'eval_safe_on_ingress', raw.get('eval_safe_on_ingress', True)
            ),
            apply_via_sink=cv.bool_value(
                'apply_via_sink', raw.get('apply_via_sink', False)
            ),
            scope_specs=cv.sequence('scope_specs', raw.get('scope_specs', ())),
            rules=cv.importable_tuple('rules', raw.get('rules', ())),
            block_precedence=cv.str_tuple(
                'block_precedence', raw.get('block_precedence', ())
            ),
            status_code=cv.int_value('status_code', raw.get('status_code', 429)),
            message=cv.str_value('message', raw.get('message', DEFAULT_BLOCK_MESSAGE)),
            enforcement=enforcement,
        )
