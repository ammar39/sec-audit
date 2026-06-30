"""The optional ``impact.value`` attribute slot on ``build_log_attributes``.

Lets a custom event carry one action's magnitude (an EGP amount, an ordinal tier
rank) so a detection rule can gate on impact, not just count. It is additive: a
numeric value rides through, anything else (including absence) is dropped, so
events that do not set it are byte-identical to before.
"""

from sec_audit.django.events import build_log_attributes


def _attrs(data):
    return build_log_attributes('audit.mutation', data, schema_version='1.0')


def test_impact_value_rides_through_when_numeric():
    assert _attrs({'impact.value': 4}).get('impact.value') == 4
    # The flat ``impact_value`` alias is accepted too (mirrors method/status dual keys).
    assert _attrs({'impact_value': 2_000_000}).get('impact.value') == 2_000_000


def test_impact_value_dropped_when_absent_or_non_numeric():
    assert 'impact.value' not in _attrs({})
    assert 'impact.value' not in _attrs({'impact.value': None})
    assert 'impact.value' not in _attrs({'impact.value': 'not-a-number'})
