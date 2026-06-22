from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.events import AuditEvent
from sec_audit.logging.config import LoggingAuditConfig
from sec_audit.logging.emission import emit_event
from sec_audit.logging.pipeline import AuditPipeline


@dataclass(frozen=True)
class LoggingRuntime:
    logger: logging.Logger
    core_config: CoreAuditConfig = field(default_factory=CoreAuditConfig)
    logging_config: LoggingAuditConfig = field(default_factory=LoggingAuditConfig)
    pipeline: AuditPipeline = field(default_factory=AuditPipeline)

    def emit_event(self, event: AuditEvent, level: int) -> None:
        emit_event(
            self.logger,
            event,
            level,
            pipeline=self.pipeline,
            sensitive_keys=self.core_config.sensitive_keys,
            value_patterns=self.core_config.sensitive_value_patterns,
            allowlist=self.core_config.sensitive_key_allowlist,
            limits=self.logging_config.projection_limits,
        )
