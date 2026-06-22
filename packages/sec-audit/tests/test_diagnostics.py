"""Rate-limited internal diagnostics."""

import logging

import pytest

from sec_audit.core import diagnostics


@pytest.fixture
def fresh_limiter(monkeypatch):
    # Isolate from other tests / module state.
    monkeypatch.setattr(diagnostics, '_limiter', diagnostics._RateLimiter())


def _warnings(caplog):
    return [r for r in caplog.records if r.levelno == logging.WARNING]


def test_same_reason_code_is_rate_limited(fresh_limiter, caplog):
    with caplog.at_level(logging.WARNING, logger=diagnostics.INTERNAL_LOGGER_NAME):
        diagnostics.diagnostic_warning('audit.x', 'first')
        diagnostics.diagnostic_warning('audit.x', 'second')
    assert len(_warnings(caplog)) == 1


def test_distinct_reason_codes_each_emit(fresh_limiter, caplog):
    with caplog.at_level(logging.WARNING, logger=diagnostics.INTERNAL_LOGGER_NAME):
        diagnostics.diagnostic_warning('audit.x', 'm')
        diagnostics.diagnostic_warning('audit.y', 'm')
    assert len(_warnings(caplog)) == 2


def test_window_expiry_allows_reemission(fresh_limiter, caplog, monkeypatch):
    clock = {'t': 1000.0}
    monkeypatch.setattr(diagnostics.time, 'monotonic', lambda: clock['t'])
    with caplog.at_level(logging.WARNING, logger=diagnostics.INTERNAL_LOGGER_NAME):
        diagnostics.diagnostic_warning('audit.x', 'm')
        clock['t'] += diagnostics._DEFAULT_WINDOW_SECONDS + 1
        diagnostics.diagnostic_warning('audit.x', 'm')
    assert len(_warnings(caplog)) == 2


def test_rate_limiter_is_thread_safe(fresh_limiter):
    import threading

    limiter = diagnostics._RateLimiter(window_seconds=3600.0)
    allowed = []

    def hammer():
        allowed.append(limiter.allow('audit.x'))

    threads = [threading.Thread(target=hammer) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Within one long window, exactly one caller is allowed through.
    assert sum(1 for a in allowed if a) == 1
