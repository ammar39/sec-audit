"""Enforcement runtime: config-fail-fast at ready(), lazy store/engine build.

``setup_enforcement`` (called from ``AppConfig.ready``) validates the config,
resolves the full rule set (importing any custom rule modules) fail-fast, and —
when enabled — registers the ``record()`` consumer. It does NOT construct stores
or connect to Redis, so ``migrate``/``check``/``collectstatic`` work even when
Redis is down. The engine instance, block store, and Redis connection are built
lazily on the first ``get_enforcement_runtime()`` (first request).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from django.conf import settings

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string
from sec_audit.django.runtime import (
    get_runtime,
    register_rule_event_consumer,
    unregister_rule_event_consumer,
)
from sec_audit.rules.base import Rule
from sec_audit.rules.builtins import (
    BruteForceLoginRule,
    LoginThrottleRule,
    RepeatedClientErrorRule,
    ResourceEnumerationRule,
)
from sec_audit.rules.config import RulesAuditConfig
from sec_audit.rules.engine import RuleEngine
from sec_audit.rules.events import RuleEvent
from sec_audit.rules.scopes import (
    ScopeDefinition,
    ScopeRegistry,
)
from sec_audit.rules.stores import (
    DEFAULT_REDIS_COUNTER_STORE,
    DEFAULT_REDIS_HISTORY_STORE,
    build_counter_store,
    build_history_store,
)

from sec_audit.django_enforcement.config import DjangoEnforcementConfig
from sec_audit.django_enforcement.emit import EnforcementEmitter
from sec_audit.django_enforcement.enforcer import Enforcer
from sec_audit.django_enforcement.stores import (
    MemoryBlockStore,
    PostgresBlockStore,
    RedisBlockStore,
    TieredBlockStore,
)

logger = logging.getLogger('sec_audit.enforcement')

_STATE_KEY_PREFIX = 'sec_audit'

_config: DjangoEnforcementConfig | None = None
_runtime: 'DjangoEnforcementRuntime | None' = None
_lock = threading.Lock()


@dataclass
class DjangoEnforcementRuntime:
    config: DjangoEnforcementConfig
    scope_registry: ScopeRegistry
    engine: RuleEngine
    block_store: object
    enforcer: Enforcer
    emitter: EnforcementEmitter
    schema_version: str

    def handle_event(self, event) -> None:
        """Egress detection + application for one recorded event (all types)."""
        rule_event = RuleEvent.from_mapping(event)
        matches = self.engine.evaluate(rule_event)
        if self.config.apply_via_sink:
            return  # the engine result-sink already applied
        if not matches:
            return
        # Derive ban scopes from the UNSCRUBBED event fields: the scope values
        # (ip/session/user) must be the real ban dimensions. The log summary
        # scrubs them (the default sensitive keys redact ``session_id``), which
        # would collapse every session onto one ban key. Block metadata is
        # scrubbed separately by the enforcer; the log output is scrubbed by the
        # emit pipeline — only the scope keys are taken in the clear here.
        summary = rule_event.to_dict()
        for match in matches:
            action = self.enforcer.resolve_action(match)
            for built in self.enforcer.apply(match, action, summary):
                self.emitter.emit(built)


def setup_enforcement() -> None:
    """Called from AppConfig.ready(): validate config + resolve rules fail-fast;
    register the consumer when enabled. No store construction / Redis connection
    here."""
    global _config
    config = DjangoEnforcementConfig.from_settings(settings)
    _config = config
    if config.enabled:
        # Resolve the full rule set now so a deterministic config/import error in
        # a custom rule spec fails the boot here — instead of being swallowed by
        # the request-time fail-open in the middleware/consumer (which must stay
        # fail-open for genuine Redis/store outages). Rule resolution touches no
        # Redis, so migrate/check/collectstatic still work when Redis is down;
        # the result is discarded — _build_runtime re-resolves lazily.
        _all_rules(config)
        from sec_audit.django_enforcement.consumer import consume

        register_rule_event_consumer(consume)


def get_config() -> DjangoEnforcementConfig:
    if _config is not None:
        return _config
    return DjangoEnforcementConfig.from_settings(settings)


def get_enforcement_runtime() -> 'DjangoEnforcementRuntime':
    runtime = _runtime
    if runtime is not None:
        return runtime
    with _lock:
        if _runtime is None:
            _set_runtime(_build_runtime(get_config()))
        return _runtime


def _set_runtime(runtime: 'DjangoEnforcementRuntime') -> None:
    global _runtime
    _runtime = runtime


def reset_enforcement_runtime() -> None:
    """Test helper: drop the cached runtime/config and unregister the consumer."""
    global _runtime, _config
    _runtime = None
    _config = None
    from sec_audit.django_enforcement.consumer import consume

    unregister_rule_event_consumer(consume)


def _build_runtime(config: DjangoEnforcementConfig) -> 'DjangoEnforcementRuntime':
    log_runtime = get_runtime()
    schema_version = log_runtime.config.logging.schema_version
    registry = _build_registry(config)
    counters, history = _build_detection_stores(config)
    block_store = _build_block_store(config)
    emitter = EnforcementEmitter(log_runtime.record)
    enforcer = Enforcer(
        block_store=block_store,
        scope_registry=registry,
        schema_version=schema_version,
        rule_actions=config.enforcement.rule_actions,
        block_rules=config.enforcement.block_rules,
        default_ttl=config.default_temp_ttl,
        default_action='observe',
        block_severity=config.enforcement.enforcement_block_severity,
        status_code=config.status_code,
        message=config.message,
        emitter=emitter,
    )
    engine = RuleEngine(
        _all_rules(config),
        counters=counters,
        history=history,
        history_extractors=registry.extractors,
        result_sinks=(enforcer,) if config.apply_via_sink else (),
        fail_open=config.fail_open,
    )
    return DjangoEnforcementRuntime(
        config=config,
        scope_registry=registry,
        engine=engine,
        block_store=block_store,
        enforcer=enforcer,
        emitter=emitter,
        schema_version=schema_version,
    )


def _build_registry(config: DjangoEnforcementConfig) -> ScopeRegistry:
    registry = ScopeRegistry.from_specs(config.scope_specs)
    if not config.block_precedence:
        return registry
    # Reorder block-precedence: named scopes first (in the given order), the rest
    # after in their original order.
    by_name = {d.name: d for d in registry.definitions}
    ordered: list[ScopeDefinition] = []
    for name in config.block_precedence:
        if name in by_name:
            ordered.append(by_name.pop(name))
    ordered.extend(d for d in registry.definitions if d.name in by_name)
    return ScopeRegistry(ordered)


def _build_detection_stores(config: DjangoEnforcementConfig):
    if config.redis_url:
        rules_config = RulesAuditConfig(
            rules_redis_url=config.redis_url,
            rules_counter_store_backend=DEFAULT_REDIS_COUNTER_STORE,
            rules_history_store=DEFAULT_REDIS_HISTORY_STORE,
            state_key_prefix=_STATE_KEY_PREFIX,
        )
    else:
        # No Redis configured: fall back to the in-memory (demo) stores.
        rules_config = RulesAuditConfig(state_key_prefix=_STATE_KEY_PREFIX)
    return build_counter_store(rules_config), build_history_store(rules_config)


def _build_block_store(config: DjangoEnforcementConfig):
    if not config.redis_url:
        return MemoryBlockStore()
    redis_store = RedisBlockStore(
        url=config.redis_url,
        key_prefix=_STATE_KEY_PREFIX,
        permanent_cache_ttl=config.permanent_cache_ttl,
    )
    pg_store = PostgresBlockStore() if config.permanent_tier_enabled else None
    return TieredBlockStore(
        redis_store=redis_store,
        postgres_store=pg_store,
        permanent_cache_ttl=config.permanent_cache_ttl,
    )


def _default_rules():
    # Conservative, generally-applicable default set. brute_force_login counts
    # auth failures (egress); login_throttle is the ingress fast path; both are
    # wired to scope-safe temp ip-blocks via DEFAULT_RULE_ACTIONS.
    # resource_enumeration is alert-only (not in DEFAULT_RULE_ACTIONS) and is a
    # no-op until a history store is configured (i.e. Redis); it relies on the
    # 'ip' scope, which is a registry default.
    return [
        BruteForceLoginRule(),
        LoginThrottleRule(),
        RepeatedClientErrorRule(),
        ResourceEnumerationRule(),
    ]


def _resolve_custom_rules(config: DjangoEnforcementConfig) -> list[Rule]:
    """Resolve ``config.rules`` specs into ``Rule`` instances.

    Each spec is a dotted ``"module.attr"`` path (the import runs here, eagerly
    at ``ready()`` via ``setup_enforcement`` — settings-parse only validates the
    path shape) or an already-instantiated ``Rule``. A path/object pointing at a
    ``Rule`` subclass is instantiated; a ``Rule`` instance is used as-is.
    """
    resolved: list[Rule] = []
    for spec in config.rules:
        obj = import_string(spec) if isinstance(spec, str) else spec
        if isinstance(obj, type) and issubclass(obj, Rule):
            rule = obj()
        elif isinstance(obj, Rule):
            rule = obj
        else:
            raise AuditConfigurationError(
                f'SEC_AUDIT_ENFORCEMENT rules entry {spec!r} is not a Rule '
                'subclass or instance.'
            )
        name = getattr(rule, 'name', '')
        if not isinstance(name, str) or not name:
            raise AuditConfigurationError(
                f'SEC_AUDIT_ENFORCEMENT rules entry {spec!r} has an empty name; '
                'a Rule must declare a non-empty `name`.'
            )
        resolved.append(rule)
    return resolved


def _all_rules(config: DjangoEnforcementConfig) -> list[Rule]:
    """Built-in defaults plus user-registered custom rules (appended).

    Duplicate rule names — across the combined set — are rejected fail-fast so a
    custom rule cannot silently shadow a built-in (e.g. ``brute_force_login``);
    enforcement actions key on the rule name, so collisions would be ambiguous.
    """
    rules = _default_rules() + _resolve_custom_rules(config)
    seen: set[str] = set()
    for rule in rules:
        if rule.name in seen:
            raise AuditConfigurationError(
                f'Duplicate enforcement rule name {rule.name!r}; custom rule '
                'names must be unique and must not collide with a built-in.'
            )
        seen.add(rule.name)
    return rules


__all__ = [
    'DjangoEnforcementRuntime',
    'get_config',
    'get_enforcement_runtime',
    'reset_enforcement_runtime',
    'setup_enforcement',
]
