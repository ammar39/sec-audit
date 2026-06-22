from sec_audit.core.ip import TrustedProxyConfig
from sec_audit.rules.scopes import ScopeRegistry

from sec_audit.django_enforcement.scopes import ingress_summary

from tests._helpers import FakeRequest


def test_forged_xff_does_not_change_ban_dimension():
    # REMOTE_ADDR is the trusted proxy; the client is the rightmost-untrusted
    # XFF entry. A forged leftmost value must not become the ban dimension.
    tpc = TrustedProxyConfig(trusted_proxy_cidrs=('10.0.0.0/8',), trusted_proxy_count=1)
    req = FakeRequest(remote_addr='10.0.0.1', xff='6.6.6.6, 1.2.3.4')
    summary = ingress_summary(req, trusted_proxy_config=tpc)
    assert summary['srcip'] == '1.2.3.4'
    # the ip BlockScope is derived through the summary path
    scopes = ScopeRegistry.from_specs().block_scopes(summary, only=('ip',))
    assert [s.scope_value for s in scopes] == ['1.2.3.4']
    assert all(s.scope_value != '6.6.6.6' for s in scopes)
