"""The Django ``audit_jsonl_formatter`` factory injects the resolved SEC_AUDIT
core config + projection limits at construction. This replaces the old
``_apply_core_config`` post-construction mutation, so a stdlib handler wired via
dictConfig emits the configured ``resource.service.name``."""

from __future__ import annotations

import io
import json
import logging

import sec_audit.django.logging.formatters as factory_mod
from sec_audit.core.events import AuditEvent
from sec_audit.logging import emit_event
from sec_audit.logging.formatters import JSONLLogFormatter


def _fake_settings(sec_audit):
    # The factory only reads ``settings.SEC_AUDIT``; a plain object avoids
    # configuring global Django settings (which would leak across the suite).
    return type('FakeSettings', (), {'SEC_AUDIT': sec_audit})()


def test_factory_wires_core_config_and_projection_limits(monkeypatch):
    monkeypatch.setattr(
        factory_mod,
        'settings',
        _fake_settings(
            {
                'core': {'source': 'billing'},
                'logging': {'projection_limits': {'max_attributes': 11}},
            }
        ),
    )
    fmt = factory_mod.audit_jsonl_formatter()
    assert isinstance(fmt, JSONLLogFormatter)
    assert fmt.config.source == 'billing'
    assert fmt.limits.max_attributes == 11
    assert fmt.package_name == 'sec_audit.django'


def test_factory_forwards_dictconfig_kwargs(monkeypatch):
    monkeypatch.setattr(
        factory_mod, 'settings', _fake_settings({'core': {'source': 'billing'}})
    )
    fmt = factory_mod.audit_jsonl_formatter(compact=True)
    assert fmt.compact is True


def test_factory_formatter_emits_configured_service_name(monkeypatch):
    monkeypatch.setattr(
        factory_mod, 'settings', _fake_settings({'core': {'source': 'my-svc'}})
    )
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(factory_mod.audit_jsonl_formatter())
    logger = logging.Logger('test.factory.audit')
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    emit_event(
        logger,
        AuditEvent(
            event_type='x',
            schema_version='1.0',
            body='evt',
            attributes={'event_type': 'x', 'schema_version': '1.0'},
        ),
        logging.INFO,
    )
    handler.flush()

    payload = json.loads(stream.getvalue().strip())
    assert payload['resource']['service.name'] == 'my-svc'
