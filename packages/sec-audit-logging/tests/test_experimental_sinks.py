"""EXPERIMENTAL queue/file sinks: basic file emission + the queue-identity fix.

These handlers are not part of the supported surface (stdout is), but the
queue-identity bug (an externally supplied listener must consume the queue the
handler publishes to) is fixed here so the experimental code is not shipped
broken.
"""

import json
import logging
import logging.handlers
import queue
import time

import pytest
from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.events import AuditEvent
from sec_audit.core.exceptions import AuditConfigurationError

from sec_audit.logging import emit_event
from sec_audit.logging._sinks import QueuedJSONLHandler


def _event():
    return AuditEvent(
        event_type='x',
        schema_version='1.0',
        body='evt',
        attributes={'event_type': 'x', 'schema_version': '1.0'},
    )


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def test_file_handler_writes_jsonl(tmp_path):
    path = tmp_path / 'audit.jsonl'
    handler = QueuedJSONLHandler(
        filename=str(path), core_config=CoreAuditConfig(source='exp-svc')
    )
    try:
        logger = logging.Logger('test.experimental.audit')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        emit_event(logger, _event(), logging.INFO)
        handler._listener.stop()
        handler._listener_started = False
        time.sleep(0.05)

        payload = json.loads(path.read_text().strip())
        assert payload['resource']['service.name'] == 'exp-svc'
    finally:
        handler.close()


def test_file_handler_unopenable_path_raises_config_error(tmp_path):
    # #A7: open() is the authority on writability (no racy os.access pre-check).
    # A path that cannot be opened (here, a directory) surfaces as an
    # AuditConfigurationError from the actual open.
    with pytest.raises(AuditConfigurationError, match='Unable to open audit log file'):
        QueuedJSONLHandler(filename=str(tmp_path))


def test_external_listener_uses_its_own_queue():
    # a listener supplied without queue_obj must consume the queue the
    # handler publishes to, or every record is silently dropped.
    q = queue.Queue(-1)
    capture = _Capture()
    listener = logging.handlers.QueueListener(q, capture)
    listener.start()
    handler = QueuedJSONLHandler(listener=listener)
    try:
        assert handler.queue is q
        logger = logging.Logger('test.experimental.external')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        emit_event(logger, _event(), logging.INFO)
        time.sleep(0.05)
        assert len(capture.records) == 1
    finally:
        listener.stop()


def test_mismatched_queue_obj_is_rejected():
    q = queue.Queue(-1)
    listener = logging.handlers.QueueListener(q, _Capture())
    with pytest.raises(AuditConfigurationError, match='listener.queue'):
        QueuedJSONLHandler(listener=listener, queue_obj=queue.Queue(-1))
