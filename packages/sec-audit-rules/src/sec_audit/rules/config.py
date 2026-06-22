from __future__ import annotations

from dataclasses import dataclass

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.config_validation import (
    int_value,
)
from sec_audit.rules.stores import DEFAULT_MEMORY_COUNTER_STORE


@dataclass(frozen=True)
class RulesAuditConfig:
    rules: tuple[object, ...] = ()
    rules_counter_store_backend: str = DEFAULT_MEMORY_COUNTER_STORE
    rules_counter_store: object | None = None
    rules_history_store: object | None = None
    history_scope_extractors: tuple[object, ...] = ()
    history_max_keys: int = 10_000
    history_max_events_per_key: int = 100
    rule_engine_max_keys: int = 10_000
    rule_engine_fail_open: bool = True
    state_key_prefix: str = 'sec_audit'
    # Connection URL for the Redis-backed counter/history stores (e.g.
    # ``redis://localhost:6379/0``). ``None`` keeps the in-memory defaults; the
    # Redis stores read it via ``getattr(config, 'rules_redis_url', None)``.
    rules_redis_url: str | None = None

    def __post_init__(self) -> None:
        _validate_positive_int('history_max_keys', self.history_max_keys)
        _validate_positive_int(
            'history_max_events_per_key', self.history_max_events_per_key
        )
        _validate_positive_int('rule_engine_max_keys', self.rule_engine_max_keys)
        if self.rules_redis_url is not None and not isinstance(
            self.rules_redis_url, str
        ):
            raise AuditConfigurationError('rules_redis_url must be a str or None.')


def _validate_positive_int(name: str, value: object) -> None:
    value = int_value(name, value)
    if value < 1:
        raise AuditConfigurationError(f'{name} must be positive.')
