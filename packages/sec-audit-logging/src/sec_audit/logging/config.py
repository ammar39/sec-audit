from __future__ import annotations

from dataclasses import dataclass

from sec_audit.core.config_validation import str_value
from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.projection import ProjectionLimits


@dataclass(frozen=True)
class LoggingAuditConfig:
    schema_version: str = '1.0'
    projection_limits: ProjectionLimits = ProjectionLimits()

    def __post_init__(self) -> None:
        schema_version = str_value('schema_version', self.schema_version)
        if not schema_version:
            raise AuditConfigurationError('schema_version must be a non-empty str.')
        object.__setattr__(self, 'schema_version', schema_version)
        if not isinstance(self.projection_limits, ProjectionLimits):
            raise AuditConfigurationError(
                'projection_limits must be a ProjectionLimits instance.'
            )
