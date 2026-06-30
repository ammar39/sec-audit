import pytest
from sec_audit.core.exceptions import AuditConfigurationError

from sec_audit.django_enforcement.config import DjangoEnforcementConfig


class _S:
    def __init__(self, mapping):
        self.SEC_AUDIT_ENFORCEMENT = mapping


def test_defaults_when_absent():
    cfg = DjangoEnforcementConfig.from_settings(object())
    assert cfg.enabled is False
    assert cfg.fail_open is True
    assert cfg.permanent_tier_enabled is True


def test_unknown_key_raises_fail_fast():
    with pytest.raises(AuditConfigurationError):
        DjangoEnforcementConfig.from_settings(_S({'enabledd': True}))


def test_bad_type_raises_fail_fast():
    with pytest.raises(AuditConfigurationError):
        DjangoEnforcementConfig.from_settings(_S({'enabled': 'yes'}))


def test_bad_regex_raises_fail_fast():
    with pytest.raises(AuditConfigurationError):
        DjangoEnforcementConfig.from_settings(_S({'fail_closed_paths': ['(']}))


def test_default_rule_actions_encode_scope_safety():
    cfg = DjangoEnforcementConfig.from_settings(_S({'enabled': True}))
    ra = cfg.enforcement.rule_actions
    # temp blocks -> ip
    assert ra['brute_force_login']['scopes'] == ['ip']
    # permanent (persist) -> user/session, never ip (shared-egress safety)
    assert ra['sensitive_field_change']['action'] == 'persist_block'
    assert 'ip' not in ra['sensitive_field_change']['scopes']


def test_user_rule_actions_override_defaults():
    cfg = DjangoEnforcementConfig.from_settings(
        _S({'rule_actions': {'brute_force_login': {'action': 'observe'}}})
    )
    assert cfg.enforcement.rule_actions['brute_force_login']['action'] == 'observe'


def test_fail_closed_paths_compiled():
    cfg = DjangoEnforcementConfig.from_settings(
        _S({'fail_closed_paths': [r'^/api/transfer']})
    )
    assert cfg.fail_closed_paths[0].search('/api/transfer/x')


def test_rules_key_accepted_and_instance_passes_through():
    # A non-string entry (an already-instantiated Rule, here a sentinel) is not
    # touched at parse time; resolution/validation happens at runtime build.
    sentinel = object()
    cfg = DjangoEnforcementConfig.from_settings(_S({'rules': [sentinel]}))
    assert cfg.rules == (sentinel,)


def test_rules_string_shape_validated_fail_fast():
    # Shape-only validation: a non "module.attr" path is rejected at ready().
    with pytest.raises(AuditConfigurationError):
        DjangoEnforcementConfig.from_settings(_S({'rules': ['nodotmodule']}))


def test_rules_valid_dotted_path_passes_parse_without_import():
    # A well-formed but non-existent path passes parse — the import is deferred
    # to the runtime build (no import side effects during settings parsing).
    cfg = DjangoEnforcementConfig.from_settings(_S({'rules': ['a.b.DoesNotExist']}))
    assert cfg.rules == ('a.b.DoesNotExist',)


def test_require_redis_defaults_false_and_is_backward_compatible():
    # Default is False so existing deployments parse exactly as before.
    assert DjangoEnforcementConfig.from_settings(object()).require_redis is False
    assert DjangoEnforcementConfig.from_settings(
        _S({'enabled': True, 'redis_url': ''})
    ).require_redis is False


def test_require_redis_fails_fast_when_enabled_without_redis():
    # With enforcement enabled, refuse the in-memory fallback (it under-counts on a
    # multi-worker deploy). The guard is enabled AND require_redis AND no redis_url.
    with pytest.raises(AuditConfigurationError):
        DjangoEnforcementConfig.from_settings(
            _S({'enabled': True, 'require_redis': True, 'redis_url': ''})
        )


def test_require_redis_satisfied_with_redis_and_inert_when_disabled():
    ok = DjangoEnforcementConfig.from_settings(
        _S({'enabled': True, 'require_redis': True, 'redis_url': 'redis://x:6379/0'})
    )
    assert ok.require_redis is True and ok.redis_url == 'redis://x:6379/0'
    # Disabled enforcement never trips the guard (dev/test posture).
    off = DjangoEnforcementConfig.from_settings(
        _S({'enabled': False, 'require_redis': True, 'redis_url': ''})
    )
    assert off.enabled is False
