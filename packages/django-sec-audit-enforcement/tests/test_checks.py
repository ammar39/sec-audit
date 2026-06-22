from django.test import override_settings

from sec_audit.django_enforcement import checks

AUDIT = 'sec_audit.django.middleware.AuditMiddleware'
ENF = 'sec_audit.django_enforcement.middleware.EnforcementMiddleware'


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
