from importlib.resources import files


def test_wazuh_and_sigma_assets_use_canonical_event_type_path():
    wazuh = files('sec_audit.integrations.wazuh').joinpath('rules')
    xml = wazuh.joinpath('0375-sec-audit.xml').read_text()
    sigma = wazuh.joinpath('sigma', 'audit-rule-match.yml').read_text()

    assert 'attributes.schema_version' in xml
    assert 'attributes.event_type: audit.rule.match' in sigma
