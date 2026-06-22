"""Redis-backed counter and event-history stores for multi-worker deployments.

These replace the ``demo_only`` in-memory stores in production: a counter
incremented by one Gunicorn worker must be visible to every other worker, which
per-process memory cannot provide. Both satisfy the existing ``CounterStore`` /
``EventHistoryStore`` protocols, so the engine and the ``build_*_store``
factories are unchanged — configuration just points at these classes.

Every read-modify-write is a single registered Lua script executed atomically by
Redis (``EVALSHA`` with an ``EVAL`` fallback). This eliminates the classic
``INCR`` then ``EXPIRE`` race (a crash between the two leaks a TTL-less key that
counts forever) — a branch on the intermediate count that ``MULTI``/``EXEC``
cannot express. Store operations fail open: a ``RedisError`` degrades detection
(a wider window, a missed count) rather than breaking request handling.
"""

from __future__ import annotations

import json
import logging
import uuid

import redis
from redis.exceptions import RedisError

from sec_audit.core.exceptions import AuditConfigurationError

logger = logging.getLogger('sec_audit.rules')

# KEYS[1]=counter key; ARGV[1]=amount; ARGV[2]=ttl seconds (0 = no expiry).
# Set the TTL only on creation (count == amount) so a fixed window is not reset
# on every hit; the count-branch is exactly what MULTI/EXEC cannot do.
_INCR_EXPIRE_LUA = """
local v = redis.call('INCRBY', KEYS[1], ARGV[1])
local ttl = tonumber(ARGV[2])
if ttl > 0 and v == tonumber(ARGV[1]) then
  redis.call('EXPIRE', KEYS[1], ttl)
end
return v
"""

# KEYS[1]=sorted-set key. ARGV: 1=score(recorded_at) 2=member 3=window_floor
# 4=max_events 5=ttl. Prune the window, add, rank-trim to the cap, and bound the
# key lifetime — all atomically, so no four-command interleave can corrupt it.
_HISTORY_APPEND_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[3])
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
local n = redis.call('ZCARD', KEYS[1])
local cap = tonumber(ARGV[4])
if n > cap then
  redis.call('ZREMRANGEBYRANK', KEYS[1], 0, n - cap - 1)
end
redis.call('EXPIRE', KEYS[1], ARGV[5])
return n
"""


def _as_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return str(value)


def _resolve_client(config, client, url):
    if client is not None:
        return client
    if url is None and config is not None:
        url = getattr(config, 'rules_redis_url', None)
    if not url:
        raise AuditConfigurationError(
            'Redis stores require rules_redis_url (or an injected client).'
        )
    return redis.Redis.from_url(url, decode_responses=True)


def _resolve_prefix(config, key_prefix) -> str:
    if key_prefix is None and config is not None:
        key_prefix = getattr(config, 'state_key_prefix', 'sec_audit')
    return (key_prefix or 'sec_audit').strip(':')


class RedisCounterStore:
    demo_only = False

    def __init__(self, *, config=None, client=None, url=None, key_prefix=None) -> None:
        self._client = _resolve_client(config, client, url)
        self.key_prefix = _resolve_prefix(config, key_prefix)
        self._incr = self._client.register_script(_INCR_EXPIRE_LUA)

    def _key(self, key: str) -> str:
        return f'{self.key_prefix}:counter:{key}'

    def incr(self, key: str, *, amount: int = 1, ttl: int | None = None) -> int:
        try:
            return int(
                self._incr(keys=[self._key(key)], args=[int(amount), int(ttl or 0)])
            )
        except RedisError:
            _warn('increment counter')
            return int(amount)

    def get_int(self, key: str, *, default: int = 0) -> int:
        try:
            value = self._client.get(self._key(key))
        except RedisError:
            _warn('read counter')
            return default
        if value is None:
            return default
        try:
            return int(_as_text(value))
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value, *, ttl: int | None = None) -> None:
        try:
            self._client.set(
                self._key(key),
                str(value),
                ex=int(ttl) if ttl is not None else None,
            )
        except RedisError:
            _warn('set counter')

    def delete(self, key: str) -> None:
        try:
            self._client.delete(self._key(key))
        except RedisError:
            _warn('delete counter')

    def expire(self, key: str, ttl: int) -> None:
        try:
            self._client.expire(self._key(key), int(ttl))
        except RedisError:
            _warn('expire counter')


class RedisEventHistoryStore:
    demo_only = False

    def __init__(
        self,
        *,
        config=None,
        client=None,
        url=None,
        key_prefix=None,
        max_events_per_key: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        self._client = _resolve_client(config, client, url)
        self.key_prefix = _resolve_prefix(config, key_prefix)
        if max_events_per_key is None and config is not None:
            max_events_per_key = getattr(config, 'history_max_events_per_key', 100)
        if window_seconds is None and config is not None:
            window_seconds = getattr(config, 'history_max_window_seconds', 3600)
        self.max_events_per_key = int(
            max_events_per_key if max_events_per_key is not None else 100
        )
        self.window_seconds = int(
            window_seconds if window_seconds is not None else 3600
        )
        self._append = self._client.register_script(_HISTORY_APPEND_LUA)

    def _key(self, scope_key: str) -> str:
        return f'{self.key_prefix}:hist:{scope_key}'

    def append(self, event_summary, *, scope_keys, recorded_at: float) -> None:
        entry = dict(event_summary)
        entry['recorded_at'] = float(recorded_at)
        # Member = "{uuid}:{json}". The uuid keeps two equal-timestamp events
        # from colliding on ZADD (which dedups by member); query splits on the
        # first ':' so the JSON stays parseable.
        member = f'{uuid.uuid4().hex}:{json.dumps(entry, sort_keys=True)}'
        floor = float(recorded_at) - self.window_seconds
        ttl = self.window_seconds + 60
        for scope_key in scope_keys:
            try:
                self._append(
                    keys=[self._key(scope_key.as_string())],
                    args=[
                        float(recorded_at),
                        member,
                        floor,
                        self.max_events_per_key,
                        ttl,
                    ],
                )
            except RedisError:
                _warn('append history')

    def query(self, *, scope_key: str, event_types, since: float, limit: int):
        try:
            # Newest first, scores strictly greater than ``since`` (exclusive,
            # matching the in-memory store).
            members = self._client.zrevrangebyscore(
                self._key(scope_key), '+inf', f'({float(since)}'
            )
        except RedisError:
            _warn('query history')
            return []
        rows = []
        for raw in members:
            _, _, payload = _as_text(raw).partition(':')
            try:
                row = json.loads(payload)
            except (ValueError, TypeError):
                continue
            if not isinstance(row, dict):
                continue
            if event_types is not None and str(row.get('event_type') or '') not in (
                event_types
            ):
                continue
            rows.append(row)
            if len(rows) >= int(limit):
                break
        return rows


def _warn(action: str) -> None:
    logger.debug('Redis store failed to %s', action, exc_info=True)
    logger.warning('Redis store failed to %s; failing open.', action)
