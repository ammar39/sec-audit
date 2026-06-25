"""Derive the ingress scope summary from a request.

The client ``ip`` goes through ``django-sec-audit``'s trusted-proxy resolver —
the single IP-resolution path — so a spoofed ``X-Forwarded-For`` cannot be
turned into the ban dimension. The session dimension uses the audit-session id
(``_sec_audit_session_id``) that egress emits — NOT ``request.session.session_key``
(the raw stealable credential) — so the ingress lookup key matches the egress ban
key. It is included only when ``emit_session_id`` is enabled, so ingress and egress
agree on whether the session dimension is active. The resulting summary feeds both
the ingress block check (candidate scopes) and the synthetic pre-request event.
"""

from __future__ import annotations

from sec_audit.core.ip import resolve_client_ip
from sec_audit.django.logging.sessions import read_audit_session_id


def ingress_summary(
    request, *, trusted_proxy_config, emit_session_id: bool = False
) -> dict:
    meta = getattr(request, 'META', {}) or {}
    client = resolve_client_ip(meta, trusted_proxy_config)
    summary: dict[str, object] = {
        'path': getattr(request, 'path', '') or '',
        'method': getattr(request, 'method', '') or '',
    }
    if client.ip:
        summary['srcip'] = client.ip
    if emit_session_id:
        session_id = _session_id(request)
        if session_id:
            summary['session_id'] = session_id
    user_id = _user_id(request)
    if user_id:
        summary['user_id'] = user_id
    return summary


def _session_id(request) -> str:
    # The audit-session id egress emits — the value session blocks are keyed by.
    return read_audit_session_id(request)


def _user_id(request) -> str:
    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return ''
    pk = getattr(user, 'pk', None)
    return str(pk) if pk is not None else ''
