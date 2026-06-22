import pytest

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.projection import ProjectionLimits
from sec_audit.django.config import DjangoAuditConfig, SecAuditSettings
from sec_audit.logging.config import LoggingAuditConfig


def test_logging_alpha_settings_parse_expected_shape():
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'source': 'billing',
                    'log_ok_responses': True,
                    'sample_rate': 0.5,
                },
                'logging': {
                    'schema_version': '2.0',
                    'projection_limits': {'max_attributes': 50},
                },
                'django': {
                    'filters': (),
                    'enrichers': (),
                    'include_usernames': True,
                    'trusted_proxy_cidrs': ('10.0.0.0/8',),
                    'trusted_proxy_count': 1,
                },
            }
        }
    )

    assert config.core.source == 'billing'
    assert config.core.log_ok_responses is True
    assert config.core.sample_rate == 0.5
    assert config.logging.schema_version == '2.0'
    assert config.logging.projection_limits.max_attributes == 50
    assert config.django.include_usernames is True
    assert config.django.trusted_proxy_cidrs == ('10.0.0.0/8',)
    assert config.django.trusted_proxy_count == 1


def test_projection_limits_accepts_dict_and_instance():
    from_dict = SecAuditSettings.from_settings(
        {'SEC_AUDIT': {'logging': {'projection_limits': {'max_depth': 4}}}}
    )
    assert from_dict.logging.projection_limits.max_depth == 4

    limits = ProjectionLimits(max_attributes=7)
    from_instance = SecAuditSettings.from_settings(
        {'SEC_AUDIT': {'logging': {'projection_limits': limits}}}
    )
    assert from_instance.logging.projection_limits is limits


def test_projection_limits_rejects_unknown_key():
    with pytest.raises(AuditConfigurationError, match='bogus'):
        SecAuditSettings.from_settings(
            {'SEC_AUDIT': {'logging': {'projection_limits': {'bogus': 1}}}}
        )


def test_projection_limits_rejects_invalid_value():
    with pytest.raises(AuditConfigurationError, match='max_depth'):
        SecAuditSettings.from_settings(
            {'SEC_AUDIT': {'logging': {'projection_limits': {'max_depth': 0}}}}
        )


def test_schema_version_lives_in_logging_section_only():
    config = SecAuditSettings.from_settings({'SEC_AUDIT': {}})
    assert isinstance(config.logging, LoggingAuditConfig)
    assert config.logging.schema_version == '1.0'
    assert not hasattr(config.core, 'schema_version')

    with pytest.raises(AuditConfigurationError, match='schema_version'):
        SecAuditSettings.from_settings(
            {'SEC_AUDIT': {'core': {'schema_version': '2.0'}}}
        )


def test_rules_and_enforcement_sections_are_rejected():
    with pytest.raises(AuditConfigurationError, match='rules'):
        SecAuditSettings.from_settings({'SEC_AUDIT': {'rules': {}}})

    with pytest.raises(AuditConfigurationError, match='enforcement'):
        SecAuditSettings.from_settings({'SEC_AUDIT': {'enforcement': {}}})


def test_exporters_are_not_alpha_configuration():
    with pytest.raises(AuditConfigurationError, match='exporters'):
        SecAuditSettings.from_settings({'SEC_AUDIT': {'django': {'exporters': []}}})


def test_trusted_proxy_settings_validate_at_startup():
    assert isinstance(DjangoAuditConfig(), DjangoAuditConfig)

    with pytest.raises(AuditConfigurationError, match='trusted_proxy'):
        SecAuditSettings.from_settings(
            {'SEC_AUDIT': {'django': {'trusted_proxy_cidrs': ['10.0.0.0/8']}}}
        )

    with pytest.raises(AuditConfigurationError, match='invalid CIDR'):
        SecAuditSettings.from_settings(
            {
                'SEC_AUDIT': {
                    'django': {
                        'trusted_proxy_cidrs': ['not-a-cidr'],
                        'trusted_proxy_count': 1,
                    }
                }
            }
        )
