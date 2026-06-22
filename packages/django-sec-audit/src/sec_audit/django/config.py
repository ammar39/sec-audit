from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from sec_audit.core import config_validation as cv
from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.logging.config import LoggingAuditConfig
from sec_audit.core.ip import TrustedProxyConfig

Converter = Callable[[str, object], object]


@dataclass(frozen=True)
class DjangoAuditConfig:
    filters: tuple[object, ...] = ()
    enrichers: tuple[object, ...] = ()
    include_usernames: bool = False
    # session correlation is opt-in. Generating an audit-session id
    # writes into ``request.session`` (forcing Django to persist it and set a
    # session cookie), which can turn a stateless endpoint stateful and create
    # session records for anonymous visitors. An audit package must observe
    # application behavior, not change it by default.
    emit_session_id: bool = False
    # optional integrations must be explicitly enabled. Installing a
    # dependency (DRF, django-auditlog) does not mean the application wants the
    # integration active — implicit activation adds fields unexpectedly,
    # registers signal receivers, and can create privacy surprises.
    drf_enabled: bool = False
    model_events_enabled: bool = False
    trusted_proxy_cidrs: tuple[str, ...] = ()
    trusted_proxy_count: int | None = None
    # Built once in __post_init__; CIDRs are compiled there instead of on every
    # request. Excluded from init/repr/compare so it stays an implementation
    # cache and does not affect equality of two configs with the same inputs.
    _trusted_proxy_config: TrustedProxyConfig | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self, 'filters', cv.importable_tuple('filters', self.filters)
        )
        object.__setattr__(
            self, 'enrichers', cv.importable_tuple('enrichers', self.enrichers)
        )
        object.__setattr__(
            self,
            'include_usernames',
            cv.bool_value('include_usernames', self.include_usernames),
        )
        object.__setattr__(
            self,
            'emit_session_id',
            cv.bool_value('emit_session_id', self.emit_session_id),
        )
        object.__setattr__(
            self, 'drf_enabled', cv.bool_value('drf_enabled', self.drf_enabled)
        )
        object.__setattr__(
            self,
            'model_events_enabled',
            cv.bool_value('model_events_enabled', self.model_events_enabled),
        )
        object.__setattr__(
            self,
            'trusted_proxy_cidrs',
            cv.str_tuple('trusted_proxy_cidrs', self.trusted_proxy_cidrs),
        )
        if self.trusted_proxy_count is not None:
            object.__setattr__(
                self,
                'trusted_proxy_count',
                cv.optional_int('trusted_proxy_count', self.trusted_proxy_count),
            )
        # Construct once: this both validates the CIDRs/count (its __post_init__
        # raises on bad input) and caches the compiled networks for reuse.
        object.__setattr__(
            self,
            '_trusted_proxy_config',
            TrustedProxyConfig(
                trusted_proxy_cidrs=self.trusted_proxy_cidrs,
                trusted_proxy_count=self.trusted_proxy_count,
            ),
        )

    @property
    def trusted_proxy_config(self) -> TrustedProxyConfig:
        return self._trusted_proxy_config


@dataclass(frozen=True)
class SecAuditSettings:
    core: CoreAuditConfig = field(default_factory=CoreAuditConfig)
    logging: LoggingAuditConfig = field(default_factory=LoggingAuditConfig)
    django: DjangoAuditConfig = field(default_factory=DjangoAuditConfig)

    def __post_init__(self) -> None:
        if not isinstance(self.core, CoreAuditConfig):
            raise AuditConfigurationError('core must be a CoreAuditConfig instance.')
        if not isinstance(self.logging, LoggingAuditConfig):
            raise AuditConfigurationError(
                'logging must be a LoggingAuditConfig instance.'
            )
        if not isinstance(self.django, DjangoAuditConfig):
            raise AuditConfigurationError(
                'django must be a DjangoAuditConfig instance.'
            )

    @classmethod
    def from_settings(
        cls, settings_obj: Mapping[str, Any] | object
    ) -> 'SecAuditSettings':
        raw = _sec_audit_value(settings_obj)
        if isinstance(raw, SecAuditSettings):
            return raw
        if not isinstance(raw, Mapping):
            raise AuditConfigurationError(
                'SEC_AUDIT must be a mapping or SecAuditSettings instance.'
            )

        unknown = sorted(set(raw) - _SECTIONS)
        if unknown:
            names = ', '.join(str(name) for name in unknown)
            raise AuditConfigurationError(f'Unknown SEC_AUDIT section(s): {names}.')

        core = _build_section(
            'core', raw.get('core'), CoreAuditConfig, _CORE_CONVERTERS
        )
        logging = _build_section(
            'logging', raw.get('logging'), LoggingAuditConfig, _LOGGING_CONVERTERS
        )
        django = _build_section(
            'django', raw.get('django'), DjangoAuditConfig, _DJANGO_CONVERTERS
        )
        return cls(
            core=core,
            logging=logging,
            django=django,
        )


def _lower_tuple(setting_name: str, value: object) -> tuple[str, ...]:
    return tuple(item.lower() for item in cv.str_tuple(setting_name, value))


_SECTIONS = {'core', 'logging', 'django'}

_CORE_CONVERTERS: dict[str, Converter] = {
    'ignore_paths': cv.regex_tuple,
    'ignore_status_codes': cv.int_frozenset,
    'sample_rate': cv.float_value,
    'log_request_bodies': cv.bool_value,
    'log_body_paths': cv.regex_tuple,
    'body_methods': lambda name, value: frozenset(
        item.upper() for item in cv.str_tuple(name, value)
    ),
    'max_body_bytes': cv.int_value,
    'body_field_allowlist': cv.str_tuple,
    'sensitive_keys': _lower_tuple,
    'sensitive_key_allowlist': _lower_tuple,
    'sensitive_value_patterns': cv.regex_tuple,
    'log_ok_responses': cv.bool_value,
    'source': cv.str_value,
}
_LOGGING_CONVERTERS: dict[str, Converter] = {
    'schema_version': cv.str_value,
    'projection_limits': cv.projection_limits,
}
_DJANGO_CONVERTERS: dict[str, Converter] = {
    'filters': cv.importable_tuple,
    'enrichers': cv.importable_tuple,
    'include_usernames': cv.bool_value,
    'emit_session_id': cv.bool_value,
    'drf_enabled': cv.bool_value,
    'model_events_enabled': cv.bool_value,
    'trusted_proxy_cidrs': cv.str_tuple,
    'trusted_proxy_count': cv.optional_int,
}


def _sec_audit_value(settings_obj: Mapping[str, Any] | object) -> object:
    if isinstance(settings_obj, SecAuditSettings):
        return settings_obj
    if isinstance(settings_obj, Mapping):
        if 'SEC_AUDIT' in settings_obj:
            return settings_obj['SEC_AUDIT']
        return settings_obj
    return getattr(settings_obj, 'SEC_AUDIT', {})


def _build_section(
    section: str,
    raw: object,
    config_type: type,
    converters: Mapping[str, Converter],
):
    if raw is None:
        kwargs: dict[str, object] = {}
    elif isinstance(raw, config_type):
        return raw
    elif isinstance(raw, Mapping):
        unknown = sorted(set(raw) - set(converters))
        if unknown:
            names = ', '.join(str(name) for name in unknown)
            raise AuditConfigurationError(
                f"Unknown SEC_AUDIT['{section}'] setting(s): {names}."
            )
        kwargs = {
            key: converters[key](_setting_name(section, key), value)
            for key, value in raw.items()
        }
    else:
        raise AuditConfigurationError(f"SEC_AUDIT['{section}'] must be a mapping.")

    return config_type(**kwargs)


def _setting_name(section: str, key: str) -> str:
    return f"SEC_AUDIT['{section}']['{key}']"


__all__ = ['DjangoAuditConfig', 'SecAuditSettings']
