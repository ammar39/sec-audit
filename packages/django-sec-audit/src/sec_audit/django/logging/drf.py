from __future__ import annotations

import importlib
import logging
from typing import Any

from django.apps import apps
from django.core.exceptions import AppRegistryNotReady, ImproperlyConfigured

from .routes import resolve_request_match

logger = logging.getLogger('sec_audit.internal')


def audit_drf_info(request, config, match: Any | None = None) -> dict[str, object]:
    # DRF metadata capture is opt-in. Installing DRF no longer
    # implicitly activates it; the operator must set SEC_AUDIT['django']
    # ['drf_enabled'] = True.
    if not getattr(config, 'drf_enabled', False):
        return {}
    if not _drf_registered():
        return {}
    try:
        importlib.import_module('rest_framework')
    except ImportError:
        logger.debug(
            'Django REST framework is not installed; DRF audit metadata skipped'
        )
        return {}

    if match is None:
        match = resolve_request_match(request)
    if match is None:
        return {}
    view_func = getattr(match, 'func', None)
    view_class = getattr(view_func, 'cls', None)
    initkwargs = getattr(view_func, 'initkwargs', None) or {}
    info = {}

    action = _drf_action(request, view_func, view_class, initkwargs)
    if action:
        info['drf_action'] = action
    basename = initkwargs.get('basename') or getattr(view_class, 'basename', None)
    if basename:
        info['drf_basename'] = str(basename)
    if view_class is not None:
        info['drf_view_class'] = _class_name(view_class)
        serializer = getattr(view_class, 'serializer_class', None)
        if serializer is not None:
            info['drf_serializer_class'] = _class_name(serializer)
        info.update(
            _class_list(
                'drf_authentication_classes',
                getattr(view_class, 'authentication_classes', None),
            )
        )
        info.update(
            _class_list(
                'drf_permission_classes',
                getattr(view_class, 'permission_classes', None),
            )
        )
        throttle_scope = getattr(view_class, 'throttle_scope', None)
        if throttle_scope:
            info['drf_throttle_scope'] = str(throttle_scope)
    return info


def _drf_registered() -> bool:
    try:
        return apps.is_installed('rest_framework')
    except (AppRegistryNotReady, ImproperlyConfigured):
        return False


def _drf_action(request, view_func, view_class, initkwargs) -> str:
    actions = getattr(view_func, 'actions', None) or initkwargs.get('actions') or {}
    method = str(getattr(request, 'method', '') or '').lower()
    action = actions.get(method) if isinstance(actions, dict) else None
    if action:
        return str(action)
    return str(getattr(view_class, 'action', '') or '')


def _class_list(key: str, classes) -> dict[str, object]:
    if not classes:
        return {}
    return {key: [_class_name(cls) for cls in classes]}


def _class_name(value) -> str:
    if isinstance(value, type):
        return value.__name__
    return value.__class__.__name__
