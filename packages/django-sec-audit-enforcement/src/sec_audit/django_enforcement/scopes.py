"""Derive the ingress scope summary from a request.

The client ``ip`` goes through ``django-sec-audit``'s trusted-proxy resolver —
the single IP-resolution path — so a spoofed ``X-Forwarded-For`` cannot be
turned into the ban dimension. The resulting raw-keyed summary feeds both the
ingress block check (candidate scopes) and the synthetic pre-request event.
"""

from __future__ import annotations

from sec_audit.core.ip import resolve_client_ip


def ingress_summary(request, *, trusted_proxy_config) -> dict:
    meta = getattr(request, 'META', {}) or {}
    client = resolve_client_ip(meta, trusted_proxy_config)
    summary: dict[str, object] = {
        'path': getattr(request, 'path', '') or '',
        'method': getattr(request, 'method', '') or '',
    }
    if client.ip:
        summary['srcip'] = client.ip
    session_id = _session_id(request)
    if session_id:
        summary['session_id'] = session_id
    user_id = _user_id(request)
    if user_id:
        summary['user_id'] = user_id
    return summary


def _session_id(request) -> str:
    session = getattr(request, 'session', None)
    key = getattr(session, 'session_key', None)
    return str(key) if key else ''


def _user_id(request) -> str:
    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return ''
    pk = getattr(user, 'pk', None)
    return str(pk) if pk is not None else ''
