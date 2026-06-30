from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from sec_audit.core.json import json_safe
from sec_audit.core.scrubbers import REDACTED

if TYPE_CHECKING:
    from sec_audit.rules.schema import EventSchema


class SummaryKey:
    EVENT_TYPE = 'event_type'
    REQUEST_ID = 'request_id'
    SESSION_ID = 'session_id'
    SRCIP = 'srcip'
    USER_ID = 'user_id'
    USERNAME = 'username'
    ROUTE_NAME = 'route_name'
    ROUTE_PATTERN = 'route_pattern'
    ROUTE = 'route'
    MODEL_LABEL = 'model_label'
    APP_LABEL = 'app_label'
    MODEL = 'model'
    OBJECT_ID = 'object_id'
    ACTION = 'action'
    CRUD_ACTION = 'crud_action'
    CHANGED_FIELDS = 'changed_fields'
    STATUS = 'status'
    DRF_ACTION = 'drf_action'
    DRF_BASENAME = 'drf_basename'
    DRF_VIEW_CLASS = 'drf_view_class'
    DRF_SERIALIZER_CLASS = 'drf_serializer_class'
    DRF_AUTHENTICATION_CLASSES = 'drf_authentication_classes'
    DRF_PERMISSION_CLASSES = 'drf_permission_classes'
    DRF_THROTTLE_SCOPE = 'drf_throttle_scope'
    ACTOR_ID = 'id'
    ACTOR_NAME = 'name'
    TARGET_APP = 'app'
    TARGET_MODEL = 'model'
    TARGET_OBJECT_ID = 'object_id'


_HISTORY_WHITELIST = (
    SummaryKey.EVENT_TYPE,
    SummaryKey.REQUEST_ID,
    SummaryKey.USER_ID,
    SummaryKey.USERNAME,
    SummaryKey.SESSION_ID,
    SummaryKey.SRCIP,
    SummaryKey.ROUTE_NAME,
    SummaryKey.ROUTE_PATTERN,
    SummaryKey.ROUTE,
    SummaryKey.MODEL_LABEL,
    SummaryKey.APP_LABEL,
    SummaryKey.MODEL,
    SummaryKey.OBJECT_ID,
    SummaryKey.ACTION,
    SummaryKey.CRUD_ACTION,
    SummaryKey.CHANGED_FIELDS,
    SummaryKey.STATUS,
    SummaryKey.DRF_ACTION,
    SummaryKey.DRF_BASENAME,
    SummaryKey.DRF_VIEW_CLASS,
    SummaryKey.DRF_SERIALIZER_CLASS,
    SummaryKey.DRF_AUTHENTICATION_CLASSES,
    SummaryKey.DRF_PERMISSION_CLASSES,
    SummaryKey.DRF_THROTTLE_SCOPE,
)


def _str(value: object) -> str:
    return str(value) if value is not None else ''


def _int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, Mapping) else {}


def _body(value: object) -> object:
    return _mapping(value) if isinstance(value, Mapping) else value


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        # Set iteration order is PYTHONHASHSEED-dependent, which would make the
        # frozen tuple (and any history summary built from it) non-deterministic
        # across processes. Sort by str() to restore a stable order while still
        # accepting sets (RuleEvent ingests arbitrary upstream dicts).
        return tuple(sorted((_freeze(item) for item in value), key=str))
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_thaw(item) for item in value)
    return value


# OTel-namespaced attribute keys (as emitted by django-sec-audit's
# ``build_log_attributes``) aliased to the raw names the scope extractors and
# the ``create_history_summary`` whitelist read. An emitted ``AuditEvent``
# carries only the OTel forms, so without this alias ``source.address`` /
# ``session.id`` / ``user.id`` / ``http.route`` / ``http.route_name`` never
# become the ``srcip`` / ``session_id`` / ``user_id`` / ``route`` /
# ``route_name`` the summary path looks for — silently dropping those scopes,
# notably the primary ``ip`` ban dimension. The rule accessors already fall
# back (e.g. ``source`` reads ``source.address`` or ``srcip``), but the
# summary/whitelist path does not, so the alias must land here in
# ``from_mapping`` where every consumer enters.
_OTEL_TO_RAW_ALIASES = (
    ('session.id', SummaryKey.SESSION_ID),
    ('user.id', SummaryKey.USER_ID),
    ('source.address', SummaryKey.SRCIP),
    ('http.route', SummaryKey.ROUTE),
    ('http.route_name', SummaryKey.ROUTE_NAME),
)


def _normalize_scope_aliases(source: Mapping[str, object]) -> Mapping[str, object]:
    # Fill a raw key only when absent so an explicit raw value always wins.
    # Return ``source`` unchanged when no alias applies, avoiding a copy of the
    # common already-raw event (and preserving an immutable input untouched).
    additions: dict[str, object] = {}
    for otel_key, raw_key in _OTEL_TO_RAW_ALIASES:
        if source.get(raw_key) in (None, ''):
            value = source.get(otel_key)
            if value not in (None, ''):
                additions[raw_key] = value
    if not additions:
        return source
    merged = dict(source)
    merged.update(additions)
    return merged


@dataclass(frozen=True)
class RuleEvent:
    event_type: str
    fields: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        event_type = str(self.event_type)
        data = dict(self.fields)
        data['event_type'] = event_type
        object.__setattr__(self, 'event_type', event_type)
        object.__setattr__(self, 'fields', _freeze(data))

    @classmethod
    def from_mapping(cls, event: Mapping[str, object] | RuleEvent) -> RuleEvent:
        if isinstance(event, cls):
            return event
        if isinstance(event, Mapping):
            source = event
        else:
            # Duck-type the core AuditEvent (or anything exposing a Mapping
            # ``.attributes``) without importing it, so rules stays decoupled
            # from the concrete core type.
            attrs = getattr(event, 'attributes', None)
            source = attrs if isinstance(attrs, Mapping) else {}
        source = _normalize_scope_aliases(source)
        # Fall back to the object's own ``event_type`` (e.g. a directly
        # constructed AuditEvent) when the attributes lack one.
        event_type = source.get('event_type')
        if not event_type:
            event_type = getattr(event, 'event_type', '')
        return cls(event_type=str(event_type or ''), fields=source)

    def to_dict(self) -> dict[str, object]:
        return dict(_thaw(self.fields))

    def get(self, key: str, default: object = None) -> object:
        return self.field(key, default)

    def field(self, key: str, default: object = None) -> object:
        """Return a field value, flat key first then dotted-path lookup.

        Precedence is intentional and stable: a flat top-level key equal to
        ``key`` (e.g. ``'request.body'`` stored verbatim, as events from
        ``django-sec-audit`` use OTel-style flat keys) wins over the nested path
        (``fields['request']['body']``). Only when no flat key matches is ``key``
        split on '.' and resolved as a nested path. ``None`` values are treated
        as absent and fall through to ``default``.
        """
        if key in self.fields:
            value = self.fields[key]
            return value if value is not None else default
        current: object = self.fields
        for part in key.split('.'):
            if not isinstance(current, Mapping) or part not in current:
                return default
            current = current[part]
        return current if current is not None else default

    @property
    def request_id(self) -> str:
        return _str(self.fields.get('request_id'))

    @property
    def session_id(self) -> str:
        return _str(self.fields.get('session_id'))

    @property
    def request(self) -> RequestFields:
        request = _mapping(self.fields.get('request'))
        return RequestFields(
            method=_str(
                self.fields.get('http.request.method') or self.fields.get('method')
            ),
            headers=_mapping(self.field('request.headers')),
            body=_body(
                self.fields.get(
                    'request.body',
                    request.get('body', self.fields.get('body')),
                )
            ),
        )

    @property
    def response(self) -> ResponseFields:
        return ResponseFields(
            status_code=_int(
                self.fields.get('http.response.status_code')
                or self.fields.get('status_code')
                or self.fields.get('status')
            ),
            headers=_mapping(self.field('response.headers')),
        )

    @property
    def proxy(self) -> ProxyFields:
        return ProxyFields(
            headers=_mapping(self.fields.get('proxy_headers')),
            trusted_route=bool(self.fields.get('trusted_route')),
        )

    @property
    def source(self) -> SourceFields:
        address = _str(self.fields.get('source.address') or self.fields.get('srcip'))
        return SourceFields(
            address=address,
            ip=_str(self.fields.get('source.ip') or address),
        )

    @property
    def url(self) -> UrlFields:
        return UrlFields(
            path=_str(self.fields.get('url.path') or self.fields.get('path')),
            full=_str(self.fields.get('url.full') or self.fields.get('url')),
        )

    @property
    def actor(self) -> ActorFields:
        actor = self.fields.get('actor')
        if not isinstance(actor, Mapping):
            return ActorFields(
                id=_str(self.fields.get('user_id')),
                name=_str(actor or self.fields.get('username')),
            )
        return ActorFields(
            id=_str(actor.get('id') or self.fields.get('user_id')),
            name=_str(actor.get('name') or self.fields.get('username')),
        )

    @property
    def model(self) -> ModelFields:
        return ModelFields(
            label=_str(self.fields.get('model_label')),
            name=_str(self.fields.get('model')),
            app_label=_str(self.fields.get('app_label')),
            object_id=_str(self.fields.get('object_id')),
            crud_action=_str(self.fields.get('crud_action')),
        )


@dataclass(frozen=True)
class RequestFields:
    method: str = ''
    headers: Mapping[str, object] = field(default_factory=dict)
    body: object = None


@dataclass(frozen=True)
class ResponseFields:
    status_code: int = 0
    headers: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ProxyFields:
    headers: Mapping[str, object] = field(default_factory=dict)
    trusted_route: bool = False


@dataclass(frozen=True)
class SourceFields:
    address: str = ''
    ip: str = ''


@dataclass(frozen=True)
class UrlFields:
    path: str = ''
    full: str = ''


@dataclass(frozen=True)
class ActorFields:
    id: str = ''
    name: str = ''


@dataclass(frozen=True)
class ModelFields:
    label: str = ''
    name: str = ''
    app_label: str = ''
    object_id: str = ''
    crud_action: str = ''


def create_history_summary(
    event: RuleEvent | Mapping[str, object],
    *,
    schema: EventSchema | None = None,
) -> Mapping[str, object]:
    raw = RuleEvent.from_mapping(event).to_dict()
    summary = {
        key: raw[key] for key in _HISTORY_WHITELIST if raw.get(key) not in (None, '')
    }
    for container, keys in (
        ('actor', (SummaryKey.ACTOR_ID, SummaryKey.ACTOR_NAME)),
        (
            'target',
            (
                SummaryKey.TARGET_APP,
                SummaryKey.TARGET_MODEL,
                SummaryKey.TARGET_OBJECT_ID,
            ),
        ),
    ):
        value = raw.get(container)
        if isinstance(value, Mapping):
            selected = {
                key: value[key] for key in keys if value.get(key) not in (None, '')
            }
            if selected:
                summary[container] = selected
    if schema is not None:
        _apply_schema_projection(summary, raw, schema)
    safe = json_safe(summary)
    return safe if isinstance(safe, Mapping) else {}


def _apply_schema_projection(
    summary: dict[str, object],
    raw: Mapping[str, object],
    schema: EventSchema,
) -> None:
    """Extend the fixed whitelist with this event_type's declared MODEL/SCOPE fields.

    SENSITIVE fields are redacted by EXACT field name (never a substring denylist
    like ``scrub`` — that would silently redact a MODEL field named ``token_count``
    and corrupt the model). Because schema field names cannot collide with reserved
    summary keys (rejected at registration), this only ADDS keys, never overwrites a
    system value. Runs before the summary is returned, so the redaction lands ahead
    of scope extraction and the history-store append.
    """
    sensitive = schema.sensitive_field_names
    for name in schema.projected_field_names:
        value = raw.get(name)
        if value in (None, ''):
            continue
        summary[name] = REDACTED if name in sensitive else value
