import re
import types

import pytest

from sec_audit.core.scrubbers import scrub, scrub_dict


def test_shared_non_cyclic_dict_is_scrubbed_independently():
    shared = {'x': 1}

    assert scrub([shared, shared]) == [{'x': 1}, {'x': 1}]


def test_shared_sensitive_dict_is_scrubbed_independently():
    shared = {'password': 'x'}

    assert scrub([shared, shared]) == [
        {'password': '[REDACTED]'},
        {'password': '[REDACTED]'},
    ]


def test_true_cycle_is_redacted():
    obj = {}
    obj['self'] = obj

    assert scrub(obj) == {'self': '[REDACTED]'}


def test_scrub_respects_empty_sensitive_keys():
    assert scrub({'password': 'x'}, sensitive_keys=[]) == {'password': 'x'}


def test_scrub_dict_respects_empty_sensitive_keys():
    assert scrub_dict({'password': 'x'}, sensitive_keys=[]) == {'password': 'x'}


def test_frozen_nested_mapping_sensitive_key_is_redacted():
    frozen = types.MappingProxyType({'password': 'x', 'ok': 'fine'})

    assert scrub({'outer': frozen}) == {
        'outer': {'password': '[REDACTED]', 'ok': 'fine'}
    }


def test_nested_sensitive_value_patterns_are_redacted():
    pattern = re.compile(r'leaked-token')
    data = {
        'items': ['ok', 'leaked-token-here'],
        'meta': {'note': 'also leaked-token here'},
    }

    result = scrub(data, value_patterns=(pattern,))

    assert result == {
        'items': ['ok', '[REDACTED]'],
        'meta': {'note': '[REDACTED]'},
    }


def test_set_is_rejected():
    # Audit attributes must be JSON-compatible: sets have no guaranteed iteration
    # order, so the same logical event would scrub differently across processes.
    # scrub() rejects rather than coercing; callers must pass list or tuple.
    pattern = re.compile(r'leaked-token')
    data = {'ok', 'leaked-token-here', 'also leaked-token', 'aaa'}

    with pytest.raises(TypeError, match='list or tuple'):
        scrub(data, value_patterns=(pattern,))


def test_frozenset_is_rejected():
    pattern = re.compile(r'secret')
    data = frozenset({'keep', 'secret-val', 'safe', 'secret-key'})

    with pytest.raises(TypeError, match='list or tuple'):
        scrub(data, value_patterns=(pattern,))


def test_bytes_value_is_redacted_without_decoding():
    assert scrub({'token': b'super-secret-bytes'}) == {'token': '[REDACTED]'}
    assert scrub(b'raw-secret') == '[REDACTED]'


def test_bytearray_value_is_redacted_without_decoding():
    assert scrub(bytearray(b'raw-secret')) == '[REDACTED]'


def test_password_variants_redacted_by_single_keyword():
    data = {'password1': 'a', 'password2': 'b', 'passwordConfirmation': 'c'}

    assert scrub(data) == {
        'password1': '[REDACTED]',
        'password2': '[REDACTED]',
        'passwordConfirmation': '[REDACTED]',
    }


def test_api_key_separator_and_case_variants_redacted():
    data = {'api_key': 1, 'api-key': 2, 'apiKey': 3, 'apikey': 4}

    assert scrub(data) == {
        'api_key': '[REDACTED]',
        'api-key': '[REDACTED]',
        'apiKey': '[REDACTED]',
        'apikey': '[REDACTED]',
    }


def test_token_keyword_covers_prefixed_token_keys():
    data = {'access_token': 'a', 'refresh_token': 'b'}

    assert scrub(data) == {
        'access_token': '[REDACTED]',
        'refresh_token': '[REDACTED]',
    }


def test_empty_keyword_does_not_redact_everything():
    assert scrub({'x': 1, 'y': 2}, sensitive_keys=['', '-']) == {'x': 1, 'y': 2}


def test_benign_keys_are_not_over_redacted():
    # We deliberately avoid bare short keywords like 'key' or 'auth', so these
    # benign substrings must survive.
    data = {'monkey': 1, 'author': 2, 'keyboard': 3}

    assert scrub(data) == {'monkey': 1, 'author': 2, 'keyboard': 3}


def test_allowlist_preserves_benign_compound_but_keeps_redacting_sibling():
    # R10: substring matching over-redacts compounds (token_expiry, credit_card_
    # last4). An allowlist is a precise opt-out: the named field survives, while
    # the genuinely sensitive sibling (credit_card / access_token) is still
    # redacted because the allowlist is an EXACT (whole-key) match, not substring.
    data = {
        'credit_card_last4': '4242',
        'credit_card': '4111111111111111',
        'token_expiry': '2026-01-01',
        'access_token': 'abc',
    }

    assert scrub(data, allowlist=('credit_card_last4', 'token_expiry')) == {
        'credit_card_last4': '4242',
        'credit_card': '[REDACTED]',
        'token_expiry': '2026-01-01',
        'access_token': '[REDACTED]',
    }


def test_allowlist_matches_compactly_across_separator_and_case_variants():
    # The allowlist normalizes like the denylist, so one entry covers every
    # separator/case spelling of the field name.
    data = {'creditCardLast4': 1, 'credit-card-last4': 2, 'credit_card_last4': 3}

    assert scrub(data, allowlist=('credit_card_last4',)) == data


def test_empty_allowlist_entries_never_disable_redaction():
    # A stray '' / '-' in the allowlist normalizes away and must not become an
    # exact match for every key (mirrors the empty-keyword denylist guard).
    assert scrub({'password': 'x'}, allowlist=['', '-']) == {'password': '[REDACTED]'}


def test_scrub_dict_threads_allowlist():
    assert scrub_dict({'token_expiry': 1}, allowlist=['token_expiry']) == {
        'token_expiry': 1
    }
