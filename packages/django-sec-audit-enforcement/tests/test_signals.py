import logging

from sec_audit.core.events import AuditEvent

from sec_audit.django_enforcement import (
    emit,
    enforcement_event,
    on_enforcement_event,
)
from sec_audit.django_enforcement.emit import EnforcementEmitter


class _Match:
    def __init__(self, **kw):
        self.rule_name = kw.get('rule_name', 'resource_enumeration')
        self.severity = kw.get('severity', 5)
        self.message = kw.get('message', 'IP touched many distinct resources')
        self.srcip = kw.get('srcip', '203.0.113.10')
        self.session_id = kw.get('session_id', 'sess_xyz')


def test_signal_fires_after_logging_with_full_payload():
    captured = []
    received = []
    emitter = EnforcementEmitter(lambda e, level: captured.append((e, level)))

    def receiver(sender, *, event, event_type, level, **kwargs):
        received.append((event, event_type, level))

    enforcement_event.connect(receiver, weak=False)
    try:
        emitter.emit(emit.build_alert_event(_Match(), schema_version='1.0'))
    finally:
        enforcement_event.disconnect(receiver)

    # durable log write happened ...
    assert len(captured) == 1
    # ... and the signal fired once with the same AuditEvent
    assert len(received) == 1
    event, event_type, level = received[0]
    assert isinstance(event, AuditEvent)
    assert event is captured[0][0]
    assert event_type == 'audit.enforcement.alert'
    assert level == logging.WARNING


def test_raising_receiver_is_isolated(caplog):
    captured = []
    good_calls = []
    emitter = EnforcementEmitter(lambda e, level: captured.append((e, level)))

    def boom(sender, **kwargs):
        raise RuntimeError('receiver blew up')

    def good(sender, *, event_type, **kwargs):
        good_calls.append(event_type)

    enforcement_event.connect(boom, weak=False)
    enforcement_event.connect(good, weak=False)
    try:
        with caplog.at_level(logging.WARNING, logger='sec_audit.enforcement'):
            # must NOT raise — fail-open via send_robust
            emitter.emit(emit.build_alert_event(_Match(), schema_version='1.0'))
    finally:
        enforcement_event.disconnect(boom)
        enforcement_event.disconnect(good)

    # the durable trail is written despite the raising receiver ...
    assert len(captured) == 1
    # ... the sibling receiver still fired ...
    assert good_calls == ['audit.enforcement.alert']
    # ... and the failure was logged, not propagated.
    assert any(
        'receiver' in r.getMessage() and r.levelno == logging.WARNING
        for r in caplog.records
    )


def test_on_enforcement_event_filters_by_type():
    captured = []
    seen = []
    emitter = EnforcementEmitter(lambda e, level: captured.append((e, level)))

    def handler(sender, *, event_type, **kwargs):
        seen.append(event_type)

    wrapper = on_enforcement_event(
        handler, events={'audit.enforcement.evaluation_failed'}
    )
    try:
        emitter.emit(emit.build_alert_event(_Match(), schema_version='1.0'))
        emitter.emit(
            emit.build_evaluation_failed_event(
                fail_mode='open', error=ValueError('x'), schema_version='1.0'
            )
        )
    finally:
        enforcement_event.disconnect(wrapper)

    # both events logged, but only the subscribed type reached the handler
    assert len(captured) == 2
    assert seen == ['audit.enforcement.evaluation_failed']
