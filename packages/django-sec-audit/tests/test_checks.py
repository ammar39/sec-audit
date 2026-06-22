"""Django system checks. The check functions are called directly with a
monkeypatched ``settings`` to avoid configuring global Django settings."""

import importlib.util
import logging

import sec_audit.django.checks as checks_mod
from sec_audit.logging.formatters import JSONLLogFormatter


def _fake_settings(**attrs):
    return type('FakeSettings', (), attrs)()


def test_e001_flags_missing_middleware(monkeypatch):
    monkeypatch.setattr(checks_mod, 'settings', _fake_settings(MIDDLEWARE=[]))
    ids = [e.id for e in checks_mod.check_audit_middleware_installed(None)]
    assert ids == ['sec_audit.E001']


def test_e001_passes_when_installed(monkeypatch):
    monkeypatch.setattr(
        checks_mod, 'settings', _fake_settings(MIDDLEWARE=[checks_mod.AUDIT_MIDDLEWARE])
    )
    assert checks_mod.check_audit_middleware_installed(None) == []


def test_e002_flags_middleware_before_session_or_auth(monkeypatch):
    middleware = [checks_mod.AUDIT_MIDDLEWARE, checks_mod.SESSION_MIDDLEWARE]
    monkeypatch.setattr(checks_mod, 'settings', _fake_settings(MIDDLEWARE=middleware))
    ids = [e.id for e in checks_mod.check_audit_middleware_order(None)]
    assert ids == ['sec_audit.E002']


def test_e002_passes_when_correctly_ordered(monkeypatch):
    middleware = [
        checks_mod.SESSION_MIDDLEWARE,
        checks_mod.AUTH_MIDDLEWARE,
        checks_mod.AUDIT_MIDDLEWARE,
    ]
    monkeypatch.setattr(checks_mod, 'settings', _fake_settings(MIDDLEWARE=middleware))
    assert checks_mod.check_audit_middleware_order(None) == []


def test_w003_flags_logger_without_jsonl_handler():
    logger = logging.getLogger(checks_mod.AUDIT_LOGGER_NAME)
    saved_handlers, saved_propagate = logger.handlers[:], logger.propagate
    logger.handlers, logger.propagate = [], False
    try:
        ids = [w.id for w in checks_mod.check_audit_logger_has_jsonl_handler(None)]
        assert ids == ['sec_audit.W003']
    finally:
        logger.handlers, logger.propagate = saved_handlers, saved_propagate


def test_w003_passes_with_jsonl_handler():
    logger = logging.getLogger(checks_mod.AUDIT_LOGGER_NAME)
    saved_handlers, saved_propagate = logger.handlers[:], logger.propagate
    handler = logging.StreamHandler()
    handler.setFormatter(JSONLLogFormatter())
    logger.handlers, logger.propagate = [handler], False
    try:
        assert checks_mod.check_audit_logger_has_jsonl_handler(None) == []
    finally:
        logger.handlers, logger.propagate = saved_handlers, saved_propagate


def test_e004_flags_enabled_integration_without_dependency(monkeypatch):
    monkeypatch.setattr(
        checks_mod,
        'settings',
        _fake_settings(SEC_AUDIT={'django': {'drf_enabled': True}}),
    )
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        'find_spec',
        lambda name: None if name == 'rest_framework' else real_find_spec(name),
    )
    ids = [e.id for e in checks_mod.check_integration_dependencies(None)]
    assert ids == ['sec_audit.E004']


def test_e006_flags_model_events_without_auditlog(monkeypatch):
    monkeypatch.setattr(
        checks_mod,
        'settings',
        _fake_settings(SEC_AUDIT={'django': {'model_events_enabled': True}}),
    )
    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        'find_spec',
        lambda name: None if name == 'auditlog' else real_find_spec(name),
    )
    ids = [e.id for e in checks_mod.check_integration_dependencies(None)]
    assert ids == ['sec_audit.E006']


def test_e004_passes_when_integrations_disabled(monkeypatch):
    monkeypatch.setattr(
        checks_mod, 'settings', _fake_settings(SEC_AUDIT={'django': {}})
    )
    assert checks_mod.check_integration_dependencies(None) == []


def test_w005_flags_body_logging_with_empty_allowlist(monkeypatch):
    monkeypatch.setattr(
        checks_mod,
        'settings',
        _fake_settings(
            SEC_AUDIT={'core': {'log_request_bodies': True, 'body_field_allowlist': []}}
        ),
    )
    ids = [w.id for w in checks_mod.check_body_logging_allowlist(None)]
    assert ids == ['sec_audit.W005']


def test_w005_passes_with_allowlist(monkeypatch):
    monkeypatch.setattr(
        checks_mod,
        'settings',
        _fake_settings(
            SEC_AUDIT={
                'core': {'log_request_bodies': True, 'body_field_allowlist': ['amount']}
            }
        ),
    )
    assert checks_mod.check_body_logging_allowlist(None) == []
