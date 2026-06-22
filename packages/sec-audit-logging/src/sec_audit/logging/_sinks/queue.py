"""EXPERIMENTAL — see ``sec_audit.logging._sinks`` package docstring."""

import logging.handlers
import queue
import threading

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.logging._sinks._file_base import _RotatingJSONLFileHandler


class QueuedJSONLHandler(logging.handlers.QueueHandler):
    def __init__(self, *, listener=None, queue_obj=None, **handler_kwargs):
        self._owns_listener = listener is None
        if listener is not None:
            # Enqueue to the listener's own queue so the records this handler
            # publishes are the ones the externally owned listener consumes. A
            # mismatched explicit queue_obj would silently drop every record.
            if queue_obj is not None and queue_obj is not listener.queue:
                raise AuditConfigurationError(
                    'queue_obj must be the provided listener.queue.'
                )
            queue_obj = listener.queue
        else:
            queue_obj = queue_obj or queue.Queue(-1)
            listener = logging.handlers.QueueListener(
                queue_obj, _RotatingJSONLFileHandler(**handler_kwargs)
            )
        self._listener = listener
        self._listener_started = False
        self._listener_lock = threading.Lock()
        super().__init__(queue_obj)

    def emit(self, record):
        if self._owns_listener and not self._listener_started:
            with self._listener_lock:
                if not self._listener_started:
                    self._listener.start()
                    self._listener_started = True
        super().emit(record)

    def close(self):
        super().close()
        if self._owns_listener and self._listener_started:
            self._listener.stop()
            self._listener_started = False
