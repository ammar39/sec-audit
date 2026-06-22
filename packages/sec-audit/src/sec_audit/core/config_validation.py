from __future__ import annotations

import re
from pathlib import Path
from re import Pattern
from typing import Iterable, Mapping

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.imports import import_string


def bool_value(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise AuditConfigurationError(f'{name} must be a bool.')
    return value


def int_value(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditConfigurationError(f'{name} must be an int.')
    return value


def optional_int(name: str, value: object) -> int | None:
    return None if value is None else int_value(name, value)


def float_value(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuditConfigurationError(f'{name} must be a float.')
    return float(value)


def str_value(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise AuditConfigurationError(f'{name} must be a str.')
    return value


def path_value(name: str, value: object) -> Path:
    if isinstance(value, Path):
        return value
    if isinstance(value, str):
        return Path(value)
    raise AuditConfigurationError(f'{name} must be a path string or Path.')


def sequence(name: str, value: object) -> tuple[object, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise AuditConfigurationError(f'{name} must be a sequence.')
    return tuple(value)


def str_tuple(name: str, value: object) -> tuple[str, ...]:
    items = sequence(name, value)
    if not all(isinstance(item, str) for item in items):
        raise AuditConfigurationError(f'{name} must contain only str values.')
    return tuple(items)


def str_frozenset(name: str, value: object) -> frozenset[str]:
    return frozenset(str_tuple(name, value))


def int_frozenset(name: str, value: object) -> frozenset[int]:
    items = sequence(name, value)
    if any(isinstance(item, bool) or not isinstance(item, int) for item in items):
        raise AuditConfigurationError(f'{name} must contain only int values.')
    return frozenset(items)


def regex_tuple(name: str, value: object) -> tuple[Pattern[str], ...]:
    patterns = []
    for item in sequence(name, value):
        if isinstance(item, re.Pattern):
            patterns.append(item)
            continue
        if not isinstance(item, str):
            raise AuditConfigurationError(
                f'{name} must contain regex strings or compiled patterns.'
            )
        try:
            patterns.append(re.compile(item))
        except re.error as exc:
            raise AuditConfigurationError(
                f'{name} contains malformed regex {item!r}: {exc}.'
            ) from exc
    return tuple(patterns)


def mapping(name: str, value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise AuditConfigurationError(f'{name} must be a mapping.')
    return dict(value)


def projection_limits(name: str, value: object):
    """Build a ``ProjectionLimits`` from an instance or a dict of known keys."""
    # Imported lazily to keep this module importable before projection's
    # heavier dependency graph is needed, and to avoid any import-order surprise.
    from sec_audit.core.projection import ProjectionLimits

    if isinstance(value, ProjectionLimits):
        return value
    data = mapping(name, value)
    known = frozenset(ProjectionLimits.__dataclass_fields__)
    unknown = sorted(set(data) - known)
    if unknown:
        raise AuditConfigurationError(
            f'{name} has unknown key(s): {", ".join(unknown)}.'
        )
    # Per-value type/range validation comes from ProjectionLimits.__post_init__.
    return ProjectionLimits(**data)


def import_path(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise AuditConfigurationError(f'{name} must be an import path string.')
    validate_import_path(name, value)
    return value


def optional_import_path_or_object(name: str, value: object) -> object:
    if value is None:
        return None
    if isinstance(value, str):
        validate_import_path(name, value)
    return value


def importable_tuple(name: str, value: object) -> tuple[object, ...]:
    specs = sequence(name, value)
    for spec in specs:
        if isinstance(spec, str):
            # Validate the "module.attr" shape only; defer the actual import to
            # the runtime build so a filter/enricher module's import-time side
            # effects don't run during settings parsing. A well-formed but
            # non-existent path surfaces when the runtime resolves it.
            import_path_shape(name, spec)
    return specs


def import_path_shape(name: str, path: str) -> None:
    module_name, _, attr_name = path.rpartition('.')
    if not module_name or not attr_name:
        raise AuditConfigurationError(
            f'{name} import path must be "module.attr", got {path!r}.'
        )


def validate_import_path(name: str, path: str) -> None:
    try:
        import_string(path)
    except Exception as exc:
        raise AuditConfigurationError(
            f'{name} has invalid import path {path!r}: {exc}'
        ) from exc
