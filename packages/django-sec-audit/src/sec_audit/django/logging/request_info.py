from __future__ import annotations

from typing import Mapping

from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.context import generate_id, get_request_id
from sec_audit.core.ip import TrustedProxyConfig, resolve_client_ip
from sec_audit.core.scrubbers import scrub


def build_request_info(
    *,
    method: str,
    path: str,
    url: str,
    headers: Mapping[str, str],
    meta: Mapping[str, str],
    config: CoreAuditConfig,
    proxy_config: TrustedProxyConfig | None = None,
    request_id: str | None = None,
    session_id: str = '',
) -> dict:
    client = resolve_client_ip(meta, proxy_config)
    # The canonical request id is always internally generated. Client-supplied
    # ``X-Request-Id`` headers are intentionally never trusted as the canonical
    # id (they are attacker-controllable), even on a trusted route. ``headers``
    # is retained for future, non-canonical inbound correlation only.
    selected_request_id = get_request_id() or request_id or generate_id()
    data = {
        'request_id': selected_request_id,
        'session_id': session_id,
        'url': url,
        'srcip': client.ip,
        'path': path,
        'method': method,
        'trusted_route': client.trusted_route,
    }
    return scrub(
        data,
        sensitive_keys=config.sensitive_keys,
        value_patterns=config.sensitive_value_patterns,
        allowlist=config.sensitive_key_allowlist,
    )
