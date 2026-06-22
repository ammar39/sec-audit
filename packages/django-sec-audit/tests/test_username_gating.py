"""username/email accessors run only when include_usernames is on."""

from sec_audit.django import runtime as rt
from sec_audit.django.config import SecAuditSettings
from sec_audit.django.logging.auth import _add_user_identity


class _ExplodingUser:
    pk = 42

    @staticmethod
    def get_username():
        raise RuntimeError('custom user model username lookup failed')


def _install_default_runtime():
    """Build a runtime whose include_usernames flag is the default (False)."""

    class _R:
        config = SecAuditSettings()

    prev = rt._runtime
    rt._runtime = _R()
    return prev


def test_get_username_not_called_when_disabled():
    prev = _install_default_runtime()
    calls = []
    try:

        class _User:
            pk = 1

            def get_username(self_):
                calls.append(1)
                return 'alice'

        data = {}
        _add_user_identity(data, _User())
    finally:
        rt._runtime = prev
    assert calls == []
    assert 'username' not in data
    assert data['user_id'] == '1'  # correlation id stays enabled


def test_exploding_get_username_does_not_break_when_disabled():
    prev = _install_default_runtime()
    try:
        data = {}
        _add_user_identity(data, _ExplodingUser())  # must not raise
    finally:
        rt._runtime = prev
    assert 'username' not in data
    assert data['user_id'] == '42'
