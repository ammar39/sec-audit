import re
from collections.abc import Mapping
from functools import lru_cache

from sec_audit.core.config import DEFAULT_SENSITIVE_KEYS

REDACTED = '[REDACTED]'


@lru_cache(maxsize=1024)
def normalize_key(value):
    # Collapse a key to a compact lowercase form by stripping every non
    # alphanumeric separator, so api_key, api-key, apiKey, and apikey all become
    # 'apikey'. Substring matching against this form lets a brief denylist catch
    # every separator/case variant of a sensitive name.
    #
    # lru_cache: this runs for every dict key AND every denylist entry on every
    # event, but the inputs (field names, the fixed denylist) repeat heavily, so
    # caching turns the regex into a one-time cost per distinct key. Keys are
    # always hashable (mapping keys, denylist strings); the cache is bounded.
    return re.sub(r'[^a-z0-9]+', '', str(value).lower())


def _is_sensitive_key(key, sensitive_keys, allowlist=frozenset()):
    norm = normalize_key(key)
    if not norm:
        return False
    # The allowlist is a precise, explicit opt-out checked BEFORE the denylist: a
    # field whose compacted form EXACTLY matches an allowlisted entry is never
    # redacted (e.g. credit_card_last4, token_expiry). Exact match — not substring
    # — keeps it precise, so an allowlist entry can never un-redact a whole class
    # of keys, only the exact fields the operator named.
    if norm in allowlist:
        return False
    for sensitive in sensitive_keys:
        # ``if s_norm`` guards against an empty keyword: '' is a substring of
        # every string, so a stray '' / '-' must not redact every key.
        s_norm = normalize_key(sensitive)
        if s_norm and s_norm in norm:
            return True
    return False


def _is_sensitive_value(value, value_patterns):
    return isinstance(value, str) and any(
        pattern.search(value) for pattern in value_patterns
    )


def scrub(
    value,
    *,
    sensitive_keys=DEFAULT_SENSITIVE_KEYS,
    value_patterns=(),
    allowlist=(),
):
    # Pre-normalize the allowlist once per call to a set of compacted keys, so the
    # per-field check is an O(1) exact-match lookup. allowlist takes precedence
    # over sensitive_keys (see _is_sensitive_key).
    allowlist_norm = frozenset(n for n in map(normalize_key, allowlist) if n)
    return _scrub_recursive(
        value, sensitive_keys, value_patterns, allowlist_norm, set()
    )


def scrub_dict(data, sensitive_keys=None, value_patterns=None, allowlist=None):
    return scrub(
        data,
        sensitive_keys=DEFAULT_SENSITIVE_KEYS
        if sensitive_keys is None
        else sensitive_keys,
        value_patterns=() if value_patterns is None else value_patterns,
        allowlist=() if allowlist is None else allowlist,
    )


def _scrub_recursive(data, sensitive_keys, value_patterns, allowlist, active):
    if isinstance(data, (set, frozenset)):
        # Audit attributes must be JSON-compatible: sets have no guaranteed
        # iteration order, so scrubbing them would serialize differently across
        # processes. Reject rather than coerce; callers must pass list or tuple.
        raise TypeError('set/frozenset are not valid audit values; use list or tuple.')
    if isinstance(data, (Mapping, list, tuple)):
        obj_id = id(data)
        if obj_id in active:
            return REDACTED
        active.add(obj_id)
        try:
            if isinstance(data, Mapping):
                return {
                    key: (
                        REDACTED
                        if _is_sensitive_key(key, sensitive_keys, allowlist)
                        else _scrub_recursive(
                            value,
                            sensitive_keys,
                            value_patterns,
                            allowlist,
                            active,
                        )
                    )
                    for key, value in data.items()
                }
            return [
                _scrub_recursive(
                    item, sensitive_keys, value_patterns, allowlist, active
                )
                for item in data
            ]
        finally:
            active.discard(obj_id)
    if isinstance(data, (bytes, bytearray)):
        # Redact unconditionally: the audit builder never emits bytes, but if a
        # raw value reaches the scrubber it may hold a binary secret. Do not
        # decode (base64 would still be reversible) — redaction is leak-proof.
        return REDACTED
    if _is_sensitive_value(data, value_patterns):
        return REDACTED
    return data
