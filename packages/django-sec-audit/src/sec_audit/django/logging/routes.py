from __future__ import annotations

from typing import Any


def resolve_request_match(request) -> Any | None:
    match = getattr(request, 'resolver_match', None)
    if match is not None:
        return match
    try:
        from django.urls import resolve
    except ImportError:
        return None
    try:
        path = getattr(request, 'path_info', None) or getattr(request, 'path', None)
        if not path:
            return None
        return resolve(path)
    except Exception:
        return None


def audit_route_info(request, match=None) -> dict:
    if match is None:
        match = resolve_request_match(request)
    if match is None:
        return {}
    info = {}
    view_name = getattr(match, 'view_name', '') or ''
    route = getattr(match, 'route', '') or ''
    if view_name:
        info['route_name'] = view_name
    if route:
        info['route_pattern'] = '/' + str(route).lstrip('/')
    return info
