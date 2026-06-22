"""Core config construction behavior (framework-free)."""

import re

import pytest

from sec_audit.core import CoreAuditConfig
from sec_audit.core.config_validation import import_path_shape
from sec_audit.core.exceptions import AuditConfigurationError


def test_core_config_accepts_regex_strings():
    # #B4: direct construction must accept plain regex strings (compiling them),
    # matching the settings path — not only pre-compiled patterns.
    config = CoreAuditConfig(ignore_paths=[r'^/health$'])
    assert isinstance(config.ignore_paths[0], re.Pattern)
    assert config.ignore_paths[0].search('/health')


def test_core_config_accepts_compiled_patterns():
    pattern = re.compile(r'^/metrics$')
    config = CoreAuditConfig(sensitive_value_patterns=[pattern])
    assert config.sensitive_value_patterns == (pattern,)


def test_core_config_rejects_malformed_regex_string():
    with pytest.raises(AuditConfigurationError, match='malformed regex'):
        CoreAuditConfig(ignore_paths=['('])


def test_import_path_shape_accepts_well_formed_without_importing():
    # #A8: shape validation must NOT import the target (no exception for a
    # non-existent but well-formed path).
    assert import_path_shape('filters', 'nonexistent_module.Thing') is None


def test_import_path_shape_rejects_malformed():
    with pytest.raises(AuditConfigurationError, match='module.attr'):
        import_path_shape('filters', 'notdotted')
