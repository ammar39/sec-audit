from __future__ import annotations

from sec_audit.core.projection import project_value


def json_safe(value: object) -> object:
    return project_value(value)
