from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Mapping

from sec_audit.core.exceptions import AuditConfigurationError


@dataclass(frozen=True)
class ClientIP:
    ip: str
    trusted_route: bool
    is_global: bool = False
    is_private: bool = False
    is_loopback: bool = False


@dataclass(frozen=True)
class TrustedProxyConfig:
    trusted_proxy_cidrs: tuple[str, ...] = ()
    trusted_proxy_count: int | None = None

    def __post_init__(self) -> None:
        networks = []
        for cidr in self.trusted_proxy_cidrs:
            try:
                networks.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError as exc:
                raise AuditConfigurationError(
                    f'trusted_proxy_cidrs contains invalid CIDR {cidr!r}.'
                ) from exc
        object.__setattr__(self, '_networks', tuple(networks))
        if self.trusted_proxy_count is not None:
            if (
                isinstance(self.trusted_proxy_count, bool)
                or not isinstance(self.trusted_proxy_count, int)
                or self.trusted_proxy_count < 1
            ):
                raise AuditConfigurationError(
                    'trusted_proxy_count must be a positive integer or None.'
                )
        if bool(self.trusted_proxy_cidrs) != (self.trusted_proxy_count is not None):
            raise AuditConfigurationError(
                'trusted_proxy_cidrs and trusted_proxy_count must be configured together.'
            )


def resolve_client_ip(
    meta: Mapping[str, str],
    config: TrustedProxyConfig | None = None,
) -> ClientIP:
    remote_addr = str(meta.get('REMOTE_ADDR') or '')
    config = config or TrustedProxyConfig()
    if not config.trusted_proxy_cidrs:
        return _client_ip(remote_addr, trusted_route=False)
    try:
        remote_ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return _client_ip(remote_addr, trusted_route=False)
    if not any(remote_ip in network for network in config._networks):
        return _client_ip(remote_addr, trusted_route=False, ip_obj=remote_ip)
    forwarded_for = str(meta.get('HTTP_X_FORWARDED_FOR') or '')
    ip = _client_from_forwarded_for(
        forwarded_for, config.trusted_proxy_count or 0, config._networks
    )
    if ip is None:
        return _client_ip(remote_addr, trusted_route=False, ip_obj=remote_ip)
    return _client_ip(str(ip), trusted_route=True, ip_obj=ip)


def _client_ip(ip: str, *, trusted_route: bool, ip_obj=None) -> ClientIP:
    if not ip:
        return ClientIP(ip='', trusted_route=trusted_route)
    if ip_obj is None:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return ClientIP(ip='', trusted_route=trusted_route)
    return ClientIP(
        ip=str(ip_obj),
        trusted_route=trusted_route,
        is_global=bool(getattr(ip_obj, 'is_global', False)),
        is_private=bool(getattr(ip_obj, 'is_private', False)),
        is_loopback=bool(getattr(ip_obj, 'is_loopback', False)),
    )


def _parse_ip_address(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _client_from_forwarded_for(
    header: str, trusted_proxy_count: int, trusted_networks: tuple
):
    parts = [part.strip() for part in header.split(',') if part.strip()]
    # REMOTE_ADDR (the immediate TCP peer) is NOT an XFF entry, so with N
    # trusted proxies the client is the Nth-from-last entry (the Nth trusted
    # proxy is REMOTE_ADDR itself, checked separately by the caller). We need
    # at least N entries (client + N-1 intermediate hops).
    if not parts or len(parts) < trusted_proxy_count:
        return None
    # Validate the complete trusted chain: every rightmost (N-1) intermediate
    # hop must be a trusted proxy. A spoofed/invalid hop means the XFF chain
    # cannot be trusted, so fall back rather than attributing a wrong client.
    if trusted_proxy_count > 1:
        for hop in parts[-(trusted_proxy_count - 1) :]:
            hop_ip = _parse_ip_address(hop)
            if hop_ip is None or not any(hop_ip in net for net in trusted_networks):
                return None
    return _parse_ip_address(parts[-trusted_proxy_count])
