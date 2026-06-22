from __future__ import annotations


def request_path(request) -> str:
    return getattr(request, 'path_info', None) or getattr(request, 'path', '')


def request_url(request, path: str) -> str:
    try:
        return request.build_absolute_uri(path).split('?', 1)[0]
    except TypeError:
        return str(request.build_absolute_uri()).split('?', 1)[0]
