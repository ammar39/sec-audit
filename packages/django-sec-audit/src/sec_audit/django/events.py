from __future__ import annotations

from collections.abc import Mapping

from sec_audit.core.events import AuditEvent
from sec_audit.core.context import get_request_id, get_session_id


class EventType:
    AUTH_LOGIN_SUCCESS = 'auth.login.success'
    AUTH_LOGIN_FAILED = 'auth.login.failed'
    AUTH_LOGOUT_SUCCESS = 'auth.logout.success'
    AUTH_LOGOUT_FAILED = 'auth.logout.failed'
    # Successful logout whose actor could not be identified (already anonymous /
    # expired session). Distinct from FAILED, which the built-in handler no
    # longer emits; the constant is kept for custom emitters / API stability.
    AUTH_LOGOUT_UNKNOWN = 'auth.logout.unknown'
    HTTP_RESPONSE_SUCCESS = 'http.response.success'
    HTTP_RESPONSE_REDIRECT = 'http.response.redirect'
    HTTP_RESPONSE_CLIENT_ERROR = 'http.response.client_error'
    HTTP_RESPONSE_SERVER_ERROR = 'http.response.server_error'
    MODEL_CREATE = 'model.create'
    MODEL_UPDATE = 'model.update'
    MODEL_DELETE = 'model.delete'
    MODEL_ACCESS = 'model.access'


class Message:
    HTTP_RESPONSE = 'http.response'
    AUTH_LOGIN_SUCCESS = 'auth.login.success'
    AUTH_LOGIN_FAILED = 'auth.login.failed'
    AUTH_LOGOUT = 'auth.logout'
    MODEL_EVENT = 'model.event'


_DRF_FIELDS = (
    'drf_action',
    'drf_basename',
    'drf_view_class',
    'drf_serializer_class',
    'drf_authentication_classes',
    'drf_permission_classes',
    'drf_throttle_scope',
)


def build_audit_event(
    body: str,
    event_type: str,
    data: Mapping[str, object] | None = None,
    *,
    schema_version: str,
    include_usernames: bool = False,
    **overrides: object,
) -> AuditEvent:
    attributes = build_log_attributes(
        event_type,
        data,
        schema_version=schema_version,
        include_usernames=include_usernames,
        **overrides,
    )
    return AuditEvent(
        event_type=str(event_type),
        schema_version=schema_version,
        body=body,
        attributes=attributes,
    )


def build_log_attributes(
    event_type: str,
    data: Mapping[str, object] | None = None,
    *,
    schema_version: str,
    include_usernames: bool = False,
    **overrides: object,
) -> dict[str, object]:
    # Shallow copy is sufficient: source values are only read below (never
    # mutated), and AuditEvent canonicalization deep-freezes attributes at
    # construction, so the built event is immutable regardless of the caller.
    source = dict(data or {})
    source.update(overrides)
    attributes: dict[str, object] = {
        'event_type': str(event_type),
        'schema_version': str(schema_version),
    }
    _add(attributes, 'request_id', source.get('request_id') or get_request_id())
    _add(attributes, 'session.id', source.get('session_id') or get_session_id())
    _add(
        attributes,
        'source.address',
        source.get('source.address') or source.get('srcip'),
    )
    _add(
        attributes,
        'http.request.method',
        source.get('http.request.method') or source.get('method'),
    )
    _add_int(
        attributes,
        'http.response.status_code',
        source.get('http.response.status_code')
        or source.get('status_code')
        or source.get('status'),
    )
    _add(attributes, 'url.full', source.get('url.full') or source.get('url'))
    _add(attributes, 'url.path', source.get('url.path') or source.get('path'))
    # OTel semantics: http.route is the route TEMPLATE/pattern (/api/users/{id}/),
    # not the Django view name. The view name lives in http.route_name.
    _add(
        attributes,
        'http.route',
        source.get('http.route') or source.get('route_pattern') or source.get('route'),
    )
    _add(
        attributes,
        'http.route_name',
        source.get('http.route_name') or source.get('route_name'),
    )
    _add_identity(attributes, source, include_usernames=include_usernames)
    _add_action(attributes, source, str(event_type))
    _add_model(attributes, source, str(event_type))
    for key in _DRF_FIELDS:
        _add(attributes, key, source.get(key))
    _add(attributes, 'request.body', source.get('request.body'))
    _add(
        attributes,
        'request.body.parse_status',
        source.get('request.body.parse_status'),
    )
    _add(attributes, 'outcome', source.get('outcome') or _outcome(event_type))
    _add_int(attributes, 'duration_ns', source.get('duration_ns'))
    _add(attributes, 'trace_id', source.get('trace_id'))
    _add(attributes, 'span_id', source.get('span_id'))
    return attributes


def _add_identity(
    attributes: dict[str, object],
    source: Mapping[str, object],
    *,
    include_usernames: bool,
) -> None:
    actor = source.get('actor')
    actor_data = actor if isinstance(actor, Mapping) else {}
    _add(attributes, 'user.id', source.get('user_id') or actor_data.get('id'))
    if include_usernames:
        actor_name = source.get('username') or actor_data.get('name')
        if actor_name is None and not isinstance(actor, Mapping):
            actor_name = actor
        if actor_name is not None and not isinstance(actor_name, str):
            # OTel user.name must be a string. The raw-actor fallback above can
            # surface a non-Mapping actor (int pk, list, custom object) here;
            # coerce so the emitted value is always a string, never e.g. int 42.
            actor_name = str(actor_name)
        _add(attributes, 'user.name', actor_name)


def _add_action(
    attributes: dict[str, object],
    source: Mapping[str, object],
    event_type: str,
) -> None:
    action = source.get('action')
    action_data = action if isinstance(action, Mapping) else {}
    _add(
        attributes,
        'action.name',
        action_data.get('name') or _action(event_type),
    )
    _add(
        attributes,
        'action.method',
        action_data.get('method') or source.get('method'),
    )
    _add(
        attributes,
        'action.result',
        action_data.get('result') or source.get('outcome') or _outcome(event_type),
    )
    _add(
        attributes,
        'action.type',
        action_data.get('type')
        or (event_type if event_type.startswith('model.') else None),
    )


def _add_model(
    attributes: dict[str, object],
    source: Mapping[str, object],
    event_type: str,
) -> None:
    for key in ('model', 'app_label', 'model_label', 'object_id'):
        _add(attributes, key, source.get(key))
    _add(
        attributes,
        'crud_action',
        source.get('crud_action')
        or (event_type.rsplit('.', 1)[-1] if event_type.startswith('model.') else None),
    )
    changed_fields = source.get('changed_fields')
    # Reject set: its non-deterministic iteration order would make model-change
    # audit output non-deterministic. auditlog supplies an ordered tuple.
    if isinstance(changed_fields, (list, tuple)):
        values = [str(value) for value in changed_fields if str(value)]
        if values:
            attributes['changed_fields'] = values


def _action(event_type: str) -> str | None:
    if event_type.startswith('http.response.'):
        return 'response'
    if event_type.startswith('auth.login.'):
        return 'login'
    if event_type.startswith('auth.logout.'):
        return 'logout'
    if event_type.startswith('model.'):
        return event_type.rsplit('.', 1)[-1]
    return None


def _outcome(event_type: str) -> str | None:
    if event_type.endswith('.success'):
        return 'success'
    if event_type.endswith(('.failed', '.client_error', '.server_error')):
        return 'failure'
    return None


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value in (None, ''):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _add(target: dict[str, object], key: str, value: object) -> None:
    if value not in (None, ''):
        target[key] = value


def _add_int(target: dict[str, object], key: str, value: object) -> None:
    converted = _as_int(value)
    if converted is not None:
        target[key] = converted
