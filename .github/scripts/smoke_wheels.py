"""Clean-wheel smoke test.

Run with an interpreter that has ONLY the built wheels (+ Django) installed.
Proves the four-distribution sec_audit namespace composes, django.setup() runs,
and one real AuditEvent formats to a single valid JSON line.
"""

import json
import logging

import django
from django.conf import settings

settings.configure(
    INSTALLED_APPS=['sec_audit.django'],
    SEC_AUDIT={'core': {'source': 'smoke-svc'}},
    DATABASES={},
)

# All four distributions compose under the shared sec_audit namespace.
import sec_audit.core  # noqa: E402,F401
import sec_audit.django  # noqa: E402,F401
import sec_audit.logging  # noqa: E402,F401
import sec_audit.rules  # noqa: E402,F401

django.setup()

from sec_audit.core.events import AuditEvent  # noqa: E402
from sec_audit.logging.formatters import JSONLLogFormatter  # noqa: E402

record = logging.LogRecord('sec_audit.audit', logging.INFO, '', 0, 'evt', (), None)
record.audit_event = AuditEvent(
    event_type='x',
    schema_version='1.0',
    body='evt',
    attributes={'event_type': 'x', 'schema_version': '1.0'},
)
record.audit_attributes = {}

line = JSONLLogFormatter(source='smoke-svc').format(record)
payload = json.loads(line)
assert payload['resource']['service.name'] == 'smoke-svc', payload
assert payload['event_name'] == 'x', payload
print('OK clean-wheel smoke:', line)
