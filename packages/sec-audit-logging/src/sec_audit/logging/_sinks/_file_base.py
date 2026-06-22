"""EXPERIMENTAL — see ``sec_audit.logging._sinks`` package docstring.

Decoupled from ``LoggingAuditConfig``: rotation parameters come from standard
``RotatingFileHandler`` kwargs (``filename``/``maxBytes``/``backupCount``), not
from the supported config object.
"""

from __future__ import annotations

import logging.handlers
import os
from contextlib import contextmanager
from pathlib import Path

from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.logging.formatters import JSONLLogFormatter

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None


class _RotatingJSONLFileHandler(logging.handlers.RotatingFileHandler):
    def __init__(
        self,
        *,
        core_config: CoreAuditConfig | None = None,
        limits=None,
        log_mode: int | None = None,
        **kwargs,
    ):
        self.core_config = core_config or CoreAuditConfig()
        self._log_mode = log_mode
        filename = kwargs.get('filename')
        if filename is None:
            raise AuditConfigurationError(
                '_RotatingJSONLFileHandler requires a filename.'
            )
        self._log_path = Path(filename)
        # Let the actual open() be the authority on writability: a pre-check via
        # os.access() tests the real (not effective) UID — wrong under setuid —
        # and races with the open() that follows (TOCTOU).
        try:
            super().__init__(**kwargs)
        except OSError as exc:
            raise AuditConfigurationError(
                f'Unable to open audit log file {self._log_path}: {exc}'
            ) from exc
        if self._log_mode is not None:
            self._ensure_log_mode()
        self._lock_path = Path(f'{self.baseFilename}.lock')
        self._lock_handle = self._open_lock_handle()
        self.setFormatter(JSONLLogFormatter(config=self.core_config, limits=limits))

    def _open_lock_handle(self):
        try:
            return self._lock_path.open('a+')
        except OSError as exc:
            raise AuditConfigurationError(
                f'Unable to create audit log lock file {self._lock_path}: {exc}'
            ) from exc

    @contextmanager
    def _acquire_lock(self):
        if fcntl is None:
            yield
            return
        fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)

    def emit(self, record):
        with self._acquire_lock():
            super().emit(record)

    def close(self):
        try:
            super().close()
        finally:
            if not self._lock_handle.closed:
                self._lock_handle.close()

    def _open(self):
        stream = super()._open()
        if self._log_mode is not None:
            self._ensure_log_mode()
        return stream

    def _ensure_log_mode(self):
        try:
            os.chmod(self.baseFilename, self._log_mode)
        except OSError as exc:
            raise AuditConfigurationError(
                f'Unable to set audit log mode on {self.baseFilename}: {exc}'
            ) from exc
