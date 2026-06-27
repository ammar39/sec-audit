"""Side-effect-free audit identity and request-context helpers.

This module exists specifically so that importing the identity helper
(``_add_user_identity``) and request-context builders does NOT register Django
auth signal receivers as an import side effect. The auth-signal receivers live
in ``sec_audit.django.logging.auth`` and are registered exclusively under
``SecAuditConfig.ready()``.

Importing ``auth`` here (to avoid a circular reference) would re-introduce the
exact coupling this module exists to break, so the helpers are duplicated here
rather than imported from ``auth``.
"""

from .drf import audit_drf_info
from sec_audit.core.context import get_context
from sec_audit.django.events import build_audit_event
from sec_audit.django.utils.request import (
    request_path as _request_path,
    request_url as _request_url,
)
from .request_info import build_request_info
from .routes import audit_route_info, resolve_request_match
from .sessions import get_audit_session_id
from sec_audit.django.runtime import get_runtime


def _request_base(request):
    runtime = get_runtime()
    config = runtime.config.core
    active = get_context()
    if active is not None:
        base = {
            'request_id': active.request_id,
            'session_id': active.session_id,
            'url': active.url,
            'path': active.path,
            'srcip': active.srcip,
            'method': active.method,
        }
        match = resolve_request_match(request)
        base.update(audit_route_info(request, match=match))
        base.update(audit_drf_info(request, runtime.config.django, match=match))
        return base
    path = _request_path(request)
    base = build_request_info(
        method=request.method,
        path=path,
        url=_request_url(request, path),
        headers=dict(request.headers.items()),
        meta=request.META,
        config=config,
        proxy_config=runtime.config.django.trusted_proxy_config,
        session_id=get_audit_session_id(
            request, enabled=runtime.config.django.emit_session_id
        ),
    )
    match = resolve_request_match(request)
    base.update(audit_route_info(request, match=match))
    base.update(audit_drf_info(request, runtime.config.django, match=match))
    return base


def _record(message, event_type, data, level):
    runtime = get_runtime()
    event = build_audit_event(
        message,
        event_type,
        data,
        schema_version=runtime.config.logging.schema_version,
        include_usernames=runtime.config.django.include_usernames,
    )
    runtime.record(event, level)


def _add_user_identity(data, user) -> None:
    if not user:
        return
    include_usernames = get_runtime().config.django.include_usernames
    # never call username/email accessors unless username logging is
    # enabled. Custom user models may implement expensive or failing username
    # logic, and lazy fields may trigger DB queries; accessing them while the
    # feature is disabled both wastes work and can break request processing.
    username = ''
    if include_usernames and callable(getattr(user, 'get_username', None)):
        username = user.get_username()
    if username:
        data['username'] = username
    # user.id / actor.id stay enabled as stable correlation identifiers. They
    # are still personal/pseudonymous identifiers and must be covered by the
    # package privacy documentation; they are not gated by include_usernames.
    user_id = getattr(user, 'pk', None)
    if user_id is None:
        user_id = getattr(user, 'id', None)
    if user_id is not None:
        data['user_id'] = str(user_id)
    actor = data.get('actor')
    if not isinstance(actor, dict):
        actor = {}
    if user_id is not None:
        actor['id'] = str(user_id)
    if username:
        actor['name'] = username
    data['actor'] = actor


def request_base(request):
    return _request_base(request)


def record(message, event_type, data, level):
    return _record(message, event_type, data, level)


def add_user_identity(data, user) -> None:
    return _add_user_identity(data, user)
