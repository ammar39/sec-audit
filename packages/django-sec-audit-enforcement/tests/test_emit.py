import logging

from sec_audit.core.events import AuditEvent
from sec_audit.enforcement.blocks import BlockEntry, BlockScope

from sec_audit.django_enforcement import emit


def _entry(**kw):
    defaults = dict(scope=BlockScope('ip', '1.2.3.4'), rule_name='r', status_code=429)
    defaults.update(kw)
    return BlockEntry(**defaults)


class _Match:
    def __init__(self, **kw):
        self.rule_name = kw.get('rule_name', 'resource_enumeration')
        self.severity = kw.get('severity', 5)
        self.message = kw.get('message', 'IP touched many distinct resources')
        self.srcip = kw.get('srcip', '203.0.113.10')
        self.session_id = kw.get('session_id', 'sess_xyz')


def test_alert_event_shape():
    event, level = emit.build_alert_event(_Match(), schema_version='1.0')
    assert isinstance(event, AuditEvent)
    assert event.event_type == 'audit.enforcement.alert'
    assert event.body == 'audit.enforcement.alert'  # body is the type string
    assert level == logging.WARNING
    assert event.attributes['security_rule.name'] == 'resource_enumeration'
    assert event.attributes['security_rule.severity'] == 5
    assert event.attributes['security_rule.description'].startswith('IP touched')
    assert event.attributes['enforcement.action'] == 'alert'
    assert event.attributes['source.address'] == '203.0.113.10'
    assert event.attributes['session.id'] == 'sess_xyz'


def test_alert_event_omits_empty_subject():
    event, _level = emit.build_alert_event(
        _Match(srcip='', session_id=''), schema_version='1.0'
    )
    # empty/null attributes are filtered out (no block, no client context yet).
    assert 'source.address' not in event.attributes
    assert 'session.id' not in event.attributes
    assert event.attributes['enforcement.action'] == 'alert'


def test_blocked_event_shape():
    event, level = emit.build_blocked_event(_entry(), schema_version='1.0')
    assert isinstance(event, AuditEvent)
    assert event.event_type == 'audit.enforcement.blocked'
    assert event.body == 'audit.enforcement.blocked'  # body is the type string
    assert level == logging.WARNING
    assert event.attributes['scope.type'] == 'ip'
    assert event.attributes['scope.value'] == '1.2.3.4'
    assert event.attributes['http.response.status_code'] == 429


def test_block_applied_temp_carries_ttl():
    event, level = emit.build_block_applied_event(
        _entry(rule_name='login_throttle'),
        action_kind='temp',
        ttl=300,
        schema_version='1.0',
    )
    assert event.event_type == 'audit.enforcement.block_applied'
    assert event.attributes['enforcement.action'] == 'temp'
    assert event.attributes['enforcement.ttl'] == 300
    assert level == logging.WARNING


def test_block_revoked_is_info():
    event, level = emit.build_block_revoked_event(
        BlockScope('user', '42'),
        revoked_by='admin',
        reason='manual',
        schema_version='1.0',
    )
    assert event.event_type == 'audit.enforcement.block_revoked'
    assert level == logging.INFO
    assert event.attributes['enforcement.revoked_by'] == 'admin'


def test_evaluation_failed_is_error_and_carries_no_message():
    err = ValueError('secret-token-leak')
    event, level = emit.build_evaluation_failed_event(
        fail_mode='closed', error=err, schema_version='1.0'
    )
    assert event.event_type == 'audit.enforcement.evaluation_failed'
    assert level == logging.ERROR
    assert event.attributes['error.type'] == 'ValueError'
    # the exception message must never reach the event
    assert 'secret-token-leak' not in str(dict(event.attributes))
    assert event.attributes['enforcement.fail_mode'] == 'closed'
