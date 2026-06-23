from importlib.resources import files


def test_wazuh_and_sigma_assets_use_canonical_event_type_path():
    wazuh = files('sec_audit.integrations.wazuh').joinpath('rules')
    xml = wazuh.joinpath('0375-sec-audit.xml').read_text()
    sigma = wazuh.joinpath('sigma', 'audit-rule-match.yml').read_text()

    assert 'attributes.schema_version' in xml
    assert 'attributes.event_type: audit.rule.match' in sigma


def test_wazuh_xml_alerts_on_enforcement_events():
    wazuh = files('sec_audit.integrations.wazuh').joinpath('rules')
    xml = wazuh.joinpath('0375-sec-audit.xml').read_text()

    assert 'audit.enforcement.blocked' in xml
    assert 'audit.enforcement.block_applied' in xml
    assert 'audit.enforcement.evaluation_failed' in xml


def test_sigma_enforcement_rules_use_canonical_event_type_path():
    sigma_dir = files('sec_audit.integrations.wazuh').joinpath('rules', 'sigma')
    blocked = sigma_dir.joinpath('enforcement-blocked.yml').read_text()
    failed = sigma_dir.joinpath('enforcement-evaluation-failed.yml').read_text()

    assert 'attributes.event_type: audit.enforcement.blocked' in blocked
    assert 'attributes.event_type: audit.enforcement.evaluation_failed' in failed
