from __future__ import annotations

import inspect
from importlib import import_module
from typing import Any, Mapping

from sec_audit.core.exceptions import AuditImportError


def import_string(path: str) -> object:
    try:
        module_name, attr_name = str(path).rsplit('.', 1)
    except ValueError as exc:
        raise AuditImportError(
            f'Import path must be "module.attr", got {path!r}.'
        ) from exc
    try:
        module = import_module(module_name)
    except ModuleNotFoundError as exc:
        # Distinguish "the requested module path is wrong" from "the module
        # exists but failed to import a missing transitive dependency": if the
        # missing module IS the requested one (or an ancestor package), the
        # operator's path is wrong; otherwise a dependency of it is absent.
        missing = exc.name or ''
        if missing and (
            module_name == missing or module_name.startswith(missing + '.')
        ):
            raise AuditImportError(f'Module {module_name!r} not found.') from exc
        raise AuditImportError(
            f'Module {module_name!r} failed to import (missing dependency {missing!r}).'
        ) from exc
    except ImportError as exc:
        raise AuditImportError(
            f'Module {module_name!r} failed to import: {exc}'
        ) from exc
    try:
        return getattr(module, attr_name)
    except AttributeError as exc:
        raise AuditImportError(f'Import target {path!r} does not exist.') from exc


def build_from_import_string(
    path: str, config: Mapping[str, Any] | None = None
) -> object:
    target = import_string(path)
    config = dict(config or {})
    from_config = getattr(target, 'from_config', None)
    if callable(from_config):
        return from_config(config)
    # Decide whether to pass config by inspecting the signature rather than
    # catching TypeError — a bare ``except TypeError`` would silently swallow a
    # real constructor bug (wrong signature, type error in __init__) and build a
    # broken object.
    if _accepts_config(target):
        return target(config=config)
    return target()


def _accepts_config(target: object) -> bool:
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == 'config' and parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return True
    return False
