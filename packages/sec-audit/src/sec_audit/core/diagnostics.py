"""Rate-limited internal diagnostics (Django-free).

Audit-loss failures (an unaudited request, a dropped record) must be visible
under a production logging configuration that runs ``sec_audit.internal`` at
WARNING — but a hot failure path must not flood the log. ``diagnostic_warning``
emits at most one WARNING per ``reason_code`` per time window. Diagnostics are
always routed to ``sec_audit.internal``, never the audit logger, so they never
pollute the JSONL audit stream.
"""

from __future__ import annotations

import logging
import threading
import time

INTERNAL_LOGGER_NAME = 'sec_audit.internal'
_DEFAULT_WINDOW_SECONDS = 60.0


class _RateLimiter:
    def __init__(self, window_seconds: float = _DEFAULT_WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, reason_code: str) -> bool:
        # monotonic clock: immune to wall-clock jumps; the question is only
        # "has the window elapsed". Guarded so concurrent failures on the same
        # path can't double-emit.
        now = time.monotonic()
        with self._lock:
            previous = self._last.get(reason_code)
            if previous is not None and (now - previous) < self._window:
                return False
            self._last[reason_code] = now
            return True


_limiter = _RateLimiter()


def diagnostic_warning(reason_code: str, message: str) -> None:
    """Emit a rate-limited WARNING on the internal diagnostics logger."""
    if _limiter.allow(reason_code):
        logging.getLogger(INTERNAL_LOGGER_NAME).warning('%s: %s', reason_code, message)


def diagnostic_debug(message: str) -> None:
    """Emit a DEBUG diagnostic for expected, high-frequency, non-loss paths."""
    logging.getLogger(INTERNAL_LOGGER_NAME).debug(message)
