import fakeredis
import pytest

from sec_audit.enforcement.policies import SeverityEnforcementPolicy
from sec_audit.rules.builtins import (
    BruteForceLoginRule,
    LoginThrottleRule,
    RepeatedClientErrorRule,
)
from sec_audit.rules.engine import RuleEngine
from sec_audit.rules.scopes import ScopeRegistry
from sec_audit.rules.stores.redis import RedisCounterStore, RedisEventHistoryStore

from sec_audit.django_enforcement.config import DjangoEnforcementConfig
from sec_audit.django_enforcement.emit import EnforcementEmitter
from sec_audit.django_enforcement.enforcer import Enforcer
from sec_audit.django_enforcement.runtime import (
    DjangoEnforcementRuntime,
    reset_enforcement_runtime,
)
from sec_audit.django_enforcement.stores import (
    PostgresBlockStore,
    RedisBlockStore,
    TieredBlockStore,
)


@pytest.fixture
def redis_client():
    """A fresh in-memory Redis double per test (Lua-capable via fakeredis[lua])."""
    return fakeredis.FakeStrictRedis(decode_responses=True)


class _Settings:
    def __init__(self, mapping):
        self.SEC_AUDIT_ENFORCEMENT = mapping


def _build_runtime(
    redis_client,
    *,
    enabled=True,
    permanent_tier=True,
    captured=None,
    real_emit=False,
    **cfg,
):
    config = DjangoEnforcementConfig.from_settings(
        _Settings({'enabled': enabled, **cfg})
    )
    registry = ScopeRegistry.from_specs()
    counters = RedisCounterStore(client=redis_client, key_prefix='sec_audit')
    history = RedisEventHistoryStore(client=redis_client, key_prefix='sec_audit')
    redis_block = RedisBlockStore(
        client=redis_client,
        key_prefix='sec_audit',
        permanent_cache_ttl=config.permanent_cache_ttl,
    )
    pg = PostgresBlockStore() if permanent_tier else None
    block_store = TieredBlockStore(
        redis_store=redis_block,
        postgres_store=pg,
        permanent_cache_ttl=config.permanent_cache_ttl,
    )
    if real_emit:
        from sec_audit.django.runtime import get_runtime

        record = get_runtime().record  # routes through record() -> dispatch
    elif captured is not None:
        record = lambda event, level: captured.append((event, level))  # noqa: E731
    else:
        record = lambda event, level: None  # noqa: E731
    emitter = EnforcementEmitter(record)
    enforcer = Enforcer(
        block_store=block_store,
        scope_registry=registry,
        schema_version='1.0',
        rule_actions=config.enforcement.rule_actions,
        block_rules=config.enforcement.block_rules,
        default_ttl=config.default_temp_ttl,
        block_severity=config.enforcement.enforcement_block_severity,
        status_code=config.status_code,
        message=config.message,
        emitter=emitter,
    )
    engine = RuleEngine(
        [BruteForceLoginRule(), LoginThrottleRule(), RepeatedClientErrorRule()],
        counters=counters,
        history=history,
        history_extractors=registry.extractors,
        result_sinks=(enforcer,) if config.apply_via_sink else (),
        fail_open=config.fail_open,
    )
    policy = SeverityEnforcementPolicy(
        block_severity=config.enforcement.enforcement_block_severity
    )
    return DjangoEnforcementRuntime(
        config=config,
        scope_registry=registry,
        engine=engine,
        block_store=block_store,
        enforcer=enforcer,
        emitter=emitter,
        policy=policy,
        schema_version='1.0',
    )


@pytest.fixture
def make_runtime(redis_client):
    """Factory: build a DjangoEnforcementRuntime backed by fakeredis + test DB."""

    def _factory(**kwargs):
        return _build_runtime(redis_client, **kwargs)

    return _factory


@pytest.fixture(autouse=True)
def _reset_enforcement_runtime():
    yield
    reset_enforcement_runtime()
