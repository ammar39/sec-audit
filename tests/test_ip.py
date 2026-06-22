import pytest

from sec_audit.core.exceptions import AuditConfigurationError
from sec_audit.core.ip import TrustedProxyConfig, resolve_client_ip


def test_untrusted_proxy_uses_remote_addr():
    client = resolve_client_ip(
        {'REMOTE_ADDR': '203.0.113.5', 'HTTP_X_FORWARDED_FOR': '8.8.8.8'},
    )
    assert client.ip == '203.0.113.5'
    assert client.trusted_route is False


def test_single_trusted_proxy_uses_forwarded_client():
    # REMOTE_ADDR is the TCP peer and is NOT an XFF entry, so a single trusted
    # proxy surfaces the client as the sole XFF entry.
    client = resolve_client_ip(
        {'REMOTE_ADDR': '127.0.0.1', 'HTTP_X_FORWARDED_FOR': '8.8.8.8'},
        TrustedProxyConfig(
            trusted_proxy_cidrs=('127.0.0.1/32',),
            trusted_proxy_count=1,
        ),
    )
    assert client.ip == '8.8.8.8'
    assert client.trusted_route is True


def test_two_trusted_proxies_use_forwarded_client():
    client = resolve_client_ip(
        {'REMOTE_ADDR': '10.0.0.3', 'HTTP_X_FORWARDED_FOR': '8.8.8.8, 10.0.0.2'},
        TrustedProxyConfig(
            trusted_proxy_cidrs=('10.0.0.0/8',),
            trusted_proxy_count=2,
        ),
    )
    assert client.ip == '8.8.8.8'
    assert client.trusted_route is True


def test_spoofed_intermediate_hop_is_rejected():
    # The intermediate hop (203.0.113.99) is not a trusted proxy, so the XFF
    # chain is untrusted and we fall back to REMOTE_ADDR.
    client = resolve_client_ip(
        {'REMOTE_ADDR': '10.0.0.3', 'HTTP_X_FORWARDED_FOR': '8.8.8.8, 203.0.113.99'},
        TrustedProxyConfig(
            trusted_proxy_cidrs=('10.0.0.0/8',),
            trusted_proxy_count=2,
        ),
    )
    assert client.ip == '10.0.0.3'
    assert client.trusted_route is False


def test_forwarded_with_too_few_entries_falls_back_to_remote_addr():
    client = resolve_client_ip(
        {'REMOTE_ADDR': '10.0.0.3', 'HTTP_X_FORWARDED_FOR': '8.8.8.8'},
        TrustedProxyConfig(
            trusted_proxy_cidrs=('10.0.0.0/8',),
            trusted_proxy_count=2,
        ),
    )
    assert client.ip == '10.0.0.3'
    assert client.trusted_route is False


def test_forwarded_header_from_untrusted_remote_addr_is_ignored():
    client = resolve_client_ip(
        {'REMOTE_ADDR': '203.0.113.9', 'HTTP_X_FORWARDED_FOR': '8.8.8.8'},
        TrustedProxyConfig(
            trusted_proxy_cidrs=('10.0.0.0/8',),
            trusted_proxy_count=1,
        ),
    )
    assert client.ip == '203.0.113.9'
    assert client.trusted_route is False


def test_trusted_proxy_config_requires_cidrs_and_count_together():
    with pytest.raises(AuditConfigurationError):
        TrustedProxyConfig(trusted_proxy_cidrs=('10.0.0.0/8',))

    with pytest.raises(AuditConfigurationError):
        TrustedProxyConfig(trusted_proxy_count=1)


def test_malformed_and_missing_remote_addr_are_safe():
    assert resolve_client_ip({'HTTP_X_FORWARDED_FOR': 'not an ip'}).ip == ''
    assert resolve_client_ip({}).ip == ''
