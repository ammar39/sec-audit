from sec_audit.enforcement.blocks import BlockScope
from sec_audit.rules.base import RuleMatch
from sec_audit.rules.scopes import ScopeRegistry

from sec_audit.django_enforcement.enforcer import Enforcer
from sec_audit.django_enforcement.stores import MemoryBlockStore


def _match(**kw):
    defaults = dict(
        rule_name='r',
        severity=8,
        matched_at=0.0,
        message='m',
        srcip='1.2.3.4',
        session_id='sess',
        metadata={'password': 'secret', 'count': 5},
    )
    defaults.update(kw)
    return RuleMatch(**defaults)


def _enforcer(store, **kw):
    return Enforcer(
        block_store=store,
        scope_registry=ScopeRegistry.from_specs(),
        schema_version='1.0',
        **kw,
    )


def test_temp_block_action_creates_temp_block():
    store = MemoryBlockStore()
    enf = _enforcer(
        store, rule_actions={'r': {'action': 'temp_block', 'scopes': ['ip']}}
    )
    match = _match()
    action = enf.resolve_action(match)
    events = enf.apply(match, action, {'srcip': '1.2.3.4'})
    assert len(events) == 1
    event, _level = events[0]
    assert event.attributes['enforcement.action'] == 'temp'
    entry = store.get_active(BlockScope('ip', '1.2.3.4'))
    assert entry is not None and entry.expires_at is not None  # temp has expiry


def test_metadata_is_scrubbed_before_store():
    store = MemoryBlockStore()
    enf = _enforcer(
        store, rule_actions={'r': {'action': 'temp_block', 'scopes': ['ip']}}
    )
    match = _match()
    enf.apply(match, enf.resolve_action(match), {'srcip': '1.2.3.4'})
    entry = store.get_active(BlockScope('ip', '1.2.3.4'))
    assert entry.metadata['password'] == '[REDACTED]'
    assert entry.metadata['count'] == 5


def test_persist_block_is_permanent():
    store = MemoryBlockStore()
    enf = _enforcer(
        store, rule_actions={'r': {'action': 'persist_block', 'scopes': ['user']}}
    )
    match = _match()
    events = enf.apply(match, enf.resolve_action(match), {'user_id': '42'})
    assert events and events[0][0].attributes['enforcement.action'] == 'permanent'
    entry = store.get_active(BlockScope('user', '42'))
    assert entry is not None and entry.expires_at is None  # permanent: no expiry


def test_block_action_severity_gating():
    # Low severity 'block' -> temp (never permanent).
    store = MemoryBlockStore()
    enf = _enforcer(store, rule_actions={'r': 'block'}, block_severity=8)
    low = _match(severity=4)
    enf.apply(low, enf.resolve_action(low), {'srcip': '1.2.3.4'})
    assert store.get_active(BlockScope('ip', '1.2.3.4')).expires_at is not None  # temp

    # High severity 'block' -> permanent.
    store2 = MemoryBlockStore()
    enf2 = _enforcer(store2, rule_actions={'r': 'block'}, block_severity=8)
    high = _match(severity=9)
    enf2.apply(high, enf2.resolve_action(high), {'srcip': '1.2.3.4'})
    assert (
        store2.get_active(BlockScope('ip', '1.2.3.4')).expires_at is None
    )  # permanent


def test_observe_action_writes_nothing():
    store = MemoryBlockStore()
    enf = _enforcer(store, rule_actions={'r': 'observe'})
    match = _match()
    assert enf.apply(match, enf.resolve_action(match), {'srcip': '1.2.3.4'}) == []


def test_persist_sink_path_emits_and_blocks_ip():
    store = MemoryBlockStore()
    emitted = []

    class _Emitter:
        def emit(self, built):
            emitted.append(built)

    enf = _enforcer(
        store,
        rule_actions={'r': {'action': 'temp_block', 'scopes': ['ip']}},
        emitter=_Emitter(),
    )
    enf.persist(_match())
    assert store.get_active(BlockScope('ip', '1.2.3.4')) is not None
    assert len(emitted) == 1
