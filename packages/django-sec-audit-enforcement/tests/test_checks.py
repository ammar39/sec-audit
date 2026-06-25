from django.test import override_settings

from sec_audit.django_enforcement import checks

AUDIT = 'sec_audit.django.middleware.AuditMiddleware'
ENF = 'sec_audit.django_enforcement.middleware.EnforcementMiddleware'
SESSION = 'django.contrib.sessions.middleware.SessionMiddleware'


@override_settings(SEC_AUDIT_ENFORCEMENT={'enabled': True}, MIDDLEWARE=[AUDIT])
def test_missing_middleware_is_error():
    errors = checks.check_enforcement_middleware(None)
    assert any(e.id == 'sec_audit_enforcement.E001' for e in errors)


@override_settings(SEC_AUDIT_ENFORCEMENT={'enabled': True}, MIDDLEWARE=[AUDIT, ENF])
def test_misordered_middleware_is_error():
    errors = checks.check_enforcement_middleware(None)
    assert any(e.id == 'sec_audit_enforcement.E002' for e in errors)


@override_settings(SEC_AUDIT_ENFORCEMENT={'enabled': True}, MIDDLEWARE=[ENF, AUDIT])
def test_correct_order_passes():
    assert checks.check_enforcement_middleware(None) == []


@override_settings(SEC_AUDIT_ENFORCEMENT={'enabled': False}, MIDDLEWARE=[])
def test_disabled_skips_checks():
    assert checks.check_enforcement_middleware(None) == []


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True, 'fail_closed_paths': [r'^/api/transfer']}
)
def test_config_warnings_redis_and_fail_closed():
    warnings = checks.check_enforcement_config(None)
    ids = {w.id for w in warnings}
    assert 'sec_audit_enforcement.W004' in ids  # no redis_url
    assert 'sec_audit_enforcement.W005' in ids  # fail-closed blast radius


# --- W007: session enforcement requires SessionMiddleware first -------------


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True},
    SEC_AUDIT={'django': {'emit_session_id': True}},
    MIDDLEWARE=[ENF, SESSION, AUDIT],
)
def test_session_order_warns_when_enforcement_before_session():
    ids = {w.id for w in checks.check_session_enforcement_order(None)}
    assert 'sec_audit_enforcement.W007' in ids


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True},
    SEC_AUDIT={'django': {'emit_session_id': True}},
    MIDDLEWARE=[SESSION, ENF, AUDIT],
)
def test_session_order_ok_when_session_first():
    assert checks.check_session_enforcement_order(None) == []


@override_settings(
    SEC_AUDIT_ENFORCEMENT={'enabled': True},
    SEC_AUDIT={'django': {'emit_session_id': False}},
    MIDDLEWARE=[ENF, SESSION, AUDIT],
)
def test_session_order_skipped_when_emit_session_id_off():
    assert checks.check_session_enforcement_order(None) == []


# --- W006: Redis eviction policy can drop cached block keys ------------------


class _FakeRedis:
    def __init__(self, policy=None, raises=False):
        self._policy = policy
        self._raises = raises

    def config_get(self, _key):
        if self._raises:
            raise RuntimeError('CONFIG disabled')
        return {'maxmemory-policy': self._policy}


_W006 = {'enabled': True, 'redis_url': 'redis://localhost:6379/0'}


@override_settings(SEC_AUDIT_ENFORCEMENT=_W006)
def test_eviction_policy_warns_on_allkeys_lru(monkeypatch):
    monkeypatch.setattr(
        'redis.Redis.from_url', lambda *a, **k: _FakeRedis('allkeys-lru')
    )
    ids = {w.id for w in checks.check_redis_eviction_policy(None)}
    assert 'sec_audit_enforcement.W006' in ids


@override_settings(SEC_AUDIT_ENFORCEMENT=_W006)
def test_eviction_policy_ok_on_noeviction(monkeypatch):
    monkeypatch.setattr(
        'redis.Redis.from_url', lambda *a, **k: _FakeRedis('noeviction')
    )
    assert checks.check_redis_eviction_policy(None) == []


@override_settings(SEC_AUDIT_ENFORCEMENT=_W006)
def test_eviction_policy_silent_when_config_disabled(monkeypatch):
    monkeypatch.setattr('redis.Redis.from_url', lambda *a, **k: _FakeRedis(raises=True))
    assert checks.check_redis_eviction_policy(None) == []  # no crash, no warning


@override_settings(SEC_AUDIT_ENFORCEMENT={'enabled': True})
def test_eviction_policy_skipped_without_redis_url():
    assert checks.check_redis_eviction_policy(None) == []
