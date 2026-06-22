"""identity helpers are side-effect-free and integrations opt-in."""

import importlib
import importlib.util

import pytest
from django.contrib.auth.signals import (
    user_logged_in,
    user_login_failed,
    user_logged_out,
)
from django.core.exceptions import ImproperlyConfigured

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.django import runtime as audit_runtime
from sec_audit.django.config import DjangoAuditConfig, SecAuditSettings
from sec_audit.django.logging import identity


def _find_spec_missing(missing_name):
    real = importlib.util.find_spec

    def _patched(name, *args, **kwargs):
        if name == missing_name:
            return None
        return real(name, *args, **kwargs)

    return _patched


def test_identity_module_registers_no_signals():
    # Importing identity.py must not connect any auth-signal receivers.
    # Count receivers, force a fresh import of identity, re-count.
    def _count():
        return (
            len(user_logged_in.receivers)
            + len(user_login_failed.receivers)
            + len(user_logged_out.receivers)
        )

    before = _count()
    importlib.reload(identity)
    assert _count() == before


def test_drf_disabled_by_default():
    assert DjangoAuditConfig().drf_enabled is False
    assert DjangoAuditConfig().model_events_enabled is False


def test_audit_drf_info_returns_empty_when_disabled(monkeypatch):
    # Even with DRF "installed" (monkeypatched), drf_enabled=False yields {}.
    from sec_audit.django.logging import drf as drf_mod
    from sec_audit.django.config import SecAuditSettings
    from sec_audit.django import runtime as rt

    class _R:
        config = SecAuditSettings()  # drf_enabled defaults False

    monkeypatch.setattr(rt, 'get_runtime', lambda: _R())
    monkeypatch.setattr(drf_mod, '_drf_registered', lambda: True)
    assert drf_mod.audit_drf_info(request=None, config=None) == {}


def test_model_disabled_by_default():
    # The default config must not opt into the forwarder import; this is the
    # guard that lets ready() skip the auditlog import entirely.
    assert DjangoAuditConfig().model_events_enabled is False


def test_drf_enabled_without_drf_fails_at_startup(monkeypatch):
    # Explicitly enabling a security integration whose dependency is missing
    # must fail loudly at startup, never silently disable itself.
    monkeypatch.setattr(
        importlib.util, 'find_spec', _find_spec_missing('rest_framework')
    )
    with pytest.raises(ImproperlyConfigured, match='drf_enabled'):
        audit_runtime._build_runtime({'SEC_AUDIT': {'django': {'drf_enabled': True}}})


def test_model_events_enabled_without_auditlog_fails_at_startup(monkeypatch):
    monkeypatch.setattr(importlib.util, 'find_spec', _find_spec_missing('auditlog'))
    with pytest.raises(ImproperlyConfigured, match='model_events_enabled'):
        audit_runtime._build_runtime(
            {'SEC_AUDIT': {'django': {'model_events_enabled': True}}}
        )


def test_filter_import_is_deferred_to_runtime_build():
    # #A8: a well-formed but non-existent path passes settings parsing (no import
    # at parse time) and surfaces only when the runtime resolves extensions.
    cfg = SecAuditSettings.from_settings(
        {'SEC_AUDIT': {'django': {'filters': ['nonexistent_module.Filter']}}}
    )
    assert cfg.django.filters == ('nonexistent_module.Filter',)
    with pytest.raises(ImproperlyConfigured):
        audit_runtime._build_runtime(
            {'SEC_AUDIT': {'django': {'filters': ['nonexistent_module.Filter']}}}
        )


def test_filter_with_malformed_shape_rejected_at_parse():
    # #A8: an obviously malformed path is still caught at parse time.
    with pytest.raises(AuditConfigurationError, match='module.attr'):
        SecAuditSettings.from_settings(
            {'SEC_AUDIT': {'django': {'filters': ['notdotted']}}}
        )
