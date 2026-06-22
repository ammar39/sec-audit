from __future__ import annotations

import math
from dataclasses import dataclass
from re import Pattern

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.config_validation import (
    bool_value,
    float_value,
    int_value,
    regex_tuple,
    sequence,
    str_value,
    str_tuple,
)

MAX_SOURCE_LENGTH = 256

# Matched as case-insensitive substrings of a compacted key (see
# ``sec_audit.core.scrubbers.normalize_key``), so each entry covers every
# separator/case variant: 'token' catches access_token & refreshToken, 'apikey'
# catches api_key & API-Key, 'password' catches password1 & passwordConfirmation.
DEFAULT_SENSITIVE_KEYS = (
    'password',
    'passwd',
    'pwd',
    'passcode',
    'secret',
    'token',
    'apikey',
    'authorization',
    'bearer',
    'jwt',
    'cookie',
    'sessionid',
    'csrf',
    'creditcard',
    'ssn',
)


@dataclass(frozen=True)
class CoreAuditConfig:
    ignore_paths: tuple[Pattern[str], ...] = ()
    ignore_status_codes: frozenset[int] = frozenset()
    sample_rate: float = 1.0
    log_request_bodies: bool = False
    log_body_paths: tuple[Pattern[str], ...] = ()
    body_methods: frozenset[str] = frozenset({'PATCH', 'POST', 'PUT'})
    max_body_bytes: int = 4096
    body_field_allowlist: tuple[str, ...] = ()

    sensitive_keys: tuple[str, ...] = DEFAULT_SENSITIVE_KEYS
    # Exact field names (compacted, case/separator-insensitive) that must NEVER be
    # redacted, even when a sensitive_keys substring matches. A precise opt-out for
    # benign compounds the substring denylist over-redacts (credit_card_last4,
    # token_expiry). Takes precedence over sensitive_keys.
    sensitive_key_allowlist: tuple[str, ...] = ()
    sensitive_value_patterns: tuple[Pattern[str], ...] = ()

    log_ok_responses: bool = False
    source: str = 'sec-audit'

    def __post_init__(self) -> None:
        object.__setattr__(
            self, 'ignore_paths', _patterns('ignore_paths', self.ignore_paths)
        )
        object.__setattr__(
            self,
            'ignore_status_codes',
            _http_status_frozenset('ignore_status_codes', self.ignore_status_codes),
        )
        sample_rate = float_value('sample_rate', self.sample_rate)
        # NaN defeats every comparison (``nan < 0`` and ``nan > 1`` are both
        # False), so it would slip past the range check and silently break
        # sampling (``random.random() < nan`` is always False -> no records).
        if not math.isfinite(sample_rate):
            raise AuditConfigurationError('sample_rate must be a finite number.')
        if sample_rate < 0 or sample_rate > 1:
            raise AuditConfigurationError('sample_rate must be between 0 and 1.')
        object.__setattr__(self, 'sample_rate', sample_rate)
        object.__setattr__(
            self, 'log_body_paths', _patterns('log_body_paths', self.log_body_paths)
        )
        object.__setattr__(
            self,
            'log_request_bodies',
            bool_value('log_request_bodies', self.log_request_bodies),
        )
        object.__setattr__(
            self,
            'body_methods',
            _body_methods('body_methods', self.body_methods),
        )
        max_body_bytes = int_value('max_body_bytes', self.max_body_bytes)
        if max_body_bytes <= 0:
            raise AuditConfigurationError('max_body_bytes must be greater than 0.')
        object.__setattr__(self, 'max_body_bytes', max_body_bytes)
        object.__setattr__(
            self,
            'body_field_allowlist',
            _exact_str_tuple('body_field_allowlist', self.body_field_allowlist),
        )
        object.__setattr__(
            self,
            'sensitive_keys',
            tuple(
                key.lower() for key in str_tuple('sensitive_keys', self.sensitive_keys)
            ),
        )
        object.__setattr__(
            self,
            'sensitive_key_allowlist',
            tuple(
                key.lower()
                for key in str_tuple(
                    'sensitive_key_allowlist', self.sensitive_key_allowlist
                )
            ),
        )
        object.__setattr__(
            self,
            'sensitive_value_patterns',
            _patterns('sensitive_value_patterns', self.sensitive_value_patterns),
        )
        object.__setattr__(
            self,
            'log_ok_responses',
            bool_value('log_ok_responses', self.log_ok_responses),
        )
        source = str_value('source', self.source)
        if not source:
            raise AuditConfigurationError('source must be a non-empty str.')
        if len(source) > MAX_SOURCE_LENGTH:
            raise AuditConfigurationError(
                f'source must be {MAX_SOURCE_LENGTH} characters or fewer.'
            )
        object.__setattr__(self, 'source', source)


def _patterns(name: str, value: object) -> tuple[Pattern[str], ...]:
    return regex_tuple(name, value)


def _http_status_frozenset(name: str, value: object) -> frozenset[int]:
    statuses = frozenset(
        int_value(f'{name} item', item) for item in sequence(name, value)
    )
    invalid = sorted(status for status in statuses if status < 100 or status > 599)
    if invalid:
        raise AuditConfigurationError(f'{name} must contain HTTP status codes.')
    return statuses


def _body_methods(name: str, value: object) -> frozenset[str]:
    methods = frozenset(method.upper() for method in str_tuple(name, value))
    if any(not method for method in methods):
        raise AuditConfigurationError(f'{name} must not contain empty methods.')
    if any(
        not method.isascii() or not method.replace('-', '').isalnum()
        for method in methods
    ):
        raise AuditConfigurationError(f'{name} must contain HTTP method tokens.')
    return methods


def _exact_str_tuple(name: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise AuditConfigurationError(f'{name} must be a tuple.')
    if not all(isinstance(item, str) for item in value):
        raise AuditConfigurationError(f'{name} must contain only str values.')
    return value
