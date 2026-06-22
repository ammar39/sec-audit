import logging

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver

from sec_audit.core.diagnostics import diagnostic_warning
from sec_audit.django.events import EventType, Message
from sec_audit.django.logging.identity import (
    _add_user_identity,
    _record,
    _request_base,
)
from sec_audit.django.runtime import get_runtime


@receiver(user_logged_in)
def login_logger(sender, **kwargs):
    request = kwargs.get('request')
    user = kwargs.get('user')
    if not request or not user:
        return
    # audit logging must fail open. A logging receiver can never
    # prevent login from completing; only the logging work is wrapped.
    try:
        base = _request_base(request)
        _add_user_identity(base, user)
        _record(
            Message.AUTH_LOGIN_SUCCESS,
            EventType.AUTH_LOGIN_SUCCESS,
            base,
            logging.INFO,
        )
    except Exception:
        diagnostic_warning(
            'audit.auth_login', 'Audit login logging failed; login proceeds'
        )


@receiver(user_login_failed)
def login_failed_logger(sender, **kwargs):
    request = kwargs.get('request')
    credentials = kwargs.get('credentials', {})
    try:
        base = _request_base(request) if request else {}
        if get_runtime().config.django.include_usernames:
            # Only access credentials when username logging is enabled.
            username = next(
                (
                    str(credentials[k])
                    for k in ('username', 'email')
                    if k in credentials
                ),
                '',
            )
            if username:
                base['username'] = username
        _record(
            Message.AUTH_LOGIN_FAILED,
            EventType.AUTH_LOGIN_FAILED,
            base,
            logging.WARNING,
        )
    except Exception:
        diagnostic_warning(
            'audit.auth_login_failed',
            'Audit login-failed logging failed; login failure proceeds',
        )


@receiver(user_logged_out)
def logout_logger(sender, **kwargs):
    request = kwargs.get('request')
    if not request:
        return
    user = kwargs.get('user')
    # user_logged_out fires AFTER a successful logout. user=None only means the
    # request was already anonymous/expired (identity unknown) — the logout still
    # succeeded, so it is not a failure. Record it as the unknown-actor variant.
    event_type = (
        EventType.AUTH_LOGOUT_SUCCESS if user else EventType.AUTH_LOGOUT_UNKNOWN
    )
    try:
        base = _request_base(request)
        _add_user_identity(base, user)
        _record(
            Message.AUTH_LOGOUT,
            event_type,
            base,
            logging.INFO,
        )
    except Exception:
        diagnostic_warning(
            'audit.auth_logout', 'Audit logout logging failed; logout proceeds'
        )
