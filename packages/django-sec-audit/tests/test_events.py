import json
import logging
from types import SimpleNamespace

from sec_audit.core.config import CoreAuditConfig
from sec_audit.django import runtime as audit_runtime
from sec_audit.django.config import SecAuditSettings
from sec_audit.django.events import (
    EventType,
    Message,
    build_audit_event,
    build_log_attributes,
)
from sec_audit.django.logging.body import capture_request_body
from sec_audit.django.logging.model import forward_auditlog
from sec_audit.django.middleware import AuditMiddleware
from sec_audit.django.runtime import DjangoLoggingRuntime
from sec_audit.logging.formatters import JSONLLogFormatter


class _CaptureRuntime:
    def __init__(self, settings):
        self.config = SecAuditSettings.from_settings(settings)
        self.events = []
        self.emits = []

    def record(self, event, level, *, emit=True):
        self.events.append((event, level))
        self.emits.append(emit)


class _Request:
    method = 'GET'
    path = '/ok/?secret=1'
    path_info = '/ok/'
    headers = {}
    META = {'REMOTE_ADDR': '203.0.113.5'}
    FILES = {}
    content_type = ''
    resolver_match = None
    session = None

    def build_absolute_uri(self, path=None):
        return f'https://example.test{path or self.path}'


class _Response:
    def __init__(self, status_code):
        self.status_code = status_code

    def items(self):
        return []


def _set_runtime(runtime):
    previous = audit_runtime._runtime
    audit_runtime._set_runtime(runtime)
    return previous


def _restore_runtime(previous):
    audit_runtime._runtime = previous


def test_build_audit_event_uses_logging_schema_and_omits_user_name_by_default():
    event = build_audit_event(
        Message.AUTH_LOGIN_SUCCESS,
        EventType.AUTH_LOGIN_SUCCESS,
        {
            'event_type': EventType.AUTH_LOGIN_SUCCESS,
            'schema_version': 'stale',
            'request_id': 'req-1',
            'user_id': '42',
            'username': 'maya@example.test',
        },
        schema_version='2.0',
    )

    assert event.schema_version == '2.0'
    assert event.attributes['schema_version'] == '2.0'
    assert event.attributes['user.id'] == '42'
    assert 'user.name' not in event.attributes


def test_include_usernames_opt_in():
    event = build_audit_event(
        Message.AUTH_LOGIN_SUCCESS,
        EventType.AUTH_LOGIN_SUCCESS,
        {'user_id': '42', 'username': 'maya'},
        schema_version='1.0',
        include_usernames=True,
    )

    assert event.attributes['user.name'] == 'maya'


def test_non_string_actor_is_coerced_to_string_user_name():
    # R9: a raw non-Mapping actor (here an int pk) reaches the user.name fallback.
    # OTel user.name must be a string, so it is coerced, never emitted as int 42.
    event = build_audit_event(
        Message.AUTH_LOGIN_SUCCESS,
        EventType.AUTH_LOGIN_SUCCESS,
        {'actor': 42},
        schema_version='1.0',
        include_usernames=True,
    )

    assert event.attributes['user.name'] == '42'
    assert isinstance(event.attributes['user.name'], str)


def test_success_response_sampled_out_emits_no_http_record(monkeypatch):
    monkeypatch.setattr('sec_audit.django.middleware.random.random', lambda: 0.99)
    runtime = _CaptureRuntime(
        {'SEC_AUDIT': {'core': {'log_ok_responses': True, 'sample_rate': 0}}}
    )
    previous = _set_runtime(runtime)
    try:
        response = AuditMiddleware(lambda request: _Response(200))(_Request())
    finally:
        _restore_runtime(previous)

    assert response.status_code == 200
    assert runtime.events == []


def test_sample_rate_zero_never_emits_even_when_random_returns_zero(monkeypatch):
    # The comparison must be strict `<`: with the old `<=` operator,
    # ``random.random() == 0.0`` at ``sample_rate == 0`` would emit a record,
    # violating the "sample_rate=0 means never" contract.
    monkeypatch.setattr('sec_audit.django.middleware.random.random', lambda: 0.0)
    runtime = _CaptureRuntime(
        {'SEC_AUDIT': {'core': {'log_ok_responses': True, 'sample_rate': 0}}}
    )
    previous = _set_runtime(runtime)
    try:
        AuditMiddleware(lambda request: _Response(200))(_Request())
    finally:
        _restore_runtime(previous)

    assert runtime.events == []


def test_sample_rate_one_always_emits_even_when_random_returns_nearly_one(monkeypatch):
    # ``random.random()`` is in [0.0, 1.0); at sample_rate=1 every success is
    # emitted via the ``>= 1.0`` short-circuit regardless of the draw.
    monkeypatch.setattr('sec_audit.django.middleware.random.random', lambda: 0.999999)
    runtime = _CaptureRuntime(
        {'SEC_AUDIT': {'core': {'log_ok_responses': True, 'sample_rate': 1}}}
    )
    previous = _set_runtime(runtime)
    try:
        AuditMiddleware(lambda request: _Response(200))(_Request())
    finally:
        _restore_runtime(previous)

    assert len(runtime.events) == 1


def test_client_error_emits_one_record_and_path_excludes_query():
    runtime = _CaptureRuntime({'SEC_AUDIT': {'logging': {'schema_version': '9.0'}}})
    previous = _set_runtime(runtime)
    try:
        response = AuditMiddleware(lambda request: _Response(404))(_Request())
    finally:
        _restore_runtime(previous)

    assert response.status_code == 404
    assert len(runtime.events) == 1
    event, level = runtime.events[0]
    assert level == logging.WARNING
    assert event.event_type == EventType.HTTP_RESPONSE_CLIENT_ERROR
    assert event.schema_version == '9.0'
    assert event.attributes['url.path'] == '/ok/'
    assert '?' not in event.attributes['url.path']
    assert isinstance(event.attributes['duration_ns'], int)


def test_formatter_uses_event_timestamps_not_log_record_created():
    event = build_audit_event(
        Message.HTTP_RESPONSE,
        EventType.HTTP_RESPONSE_SUCCESS,
        {'request_id': 'req-1'},
        schema_version='3.0',
    ).observed(222)
    object.__setattr__(event, 'timestamp_ns', 111)
    record = logging.LogRecord('sec_audit.audit', logging.INFO, '', 0, 'msg', (), None)
    record.created = 999.0
    record.audit_event = event
    record.audit_attributes = dict(event.attributes)

    out = JSONLLogFormatter().format_to_dict(record)

    assert out['timestamp'] == 111
    assert out['observed_timestamp'] == 222
    assert out['attributes']['schema_version'] == '3.0'


def test_runtime_catches_projection_failures():
    class _BadLogging:
        def emit_event(self, event, level):
            raise RuntimeError('boom secret=hidden')

    runtime = DjangoLoggingRuntime(
        config=SecAuditSettings.from_settings({}),
        logging=_BadLogging(),
    )
    event = build_audit_event('x', 'x', {}, schema_version='1.0')

    runtime.record(event, logging.INFO)


def test_formatter_fallback_for_malformed_record_is_bounded():
    record = logging.LogRecord('sec_audit.audit', logging.INFO, '', 0, 'msg', (), None)
    record.audit_attributes = ['bad']

    out = json.loads(JSONLLogFormatter().format(record))

    assert out['event_name'] == 'audit.logging.malformed_record'
    assert out['attributes']['event_type'] == 'audit.logging.malformed_record'
    assert list(out['attributes']) == ['event_type', 'schema_version']


def test_body_capture_accepts_json_type_and_missing_length():
    request = SimpleNamespace(
        method='POST',
        META={'CONTENT_LENGTH': '7', 'CONTENT_TYPE': 'application/vnd.api+json'},
        headers={'Content-Length': '7', 'Content-Type': 'application/vnd.api+json'},
        body=b'{"a":1}',
        FILES={},
        content_type='application/vnd.api+json',
    )
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'log_request_bodies': True,
                    'body_field_allowlist': ['a'],
                }
            }
        }
    ).core

    assert capture_request_body(request, config)['request.body'] == {'a': 1}

    # B3: a missing/blank CONTENT_LENGTH no longer skips capture — chunked and
    # streaming HTTP/1.1 bodies omit it. safe_json_body bounds size instead.
    request.META['CONTENT_LENGTH'] = ''
    assert capture_request_body(request, config)['request.body'] == {'a': 1}


def test_body_capture_handles_chunked_request_without_content_length():
    # B3: CONTENT_LENGTH absent from both META and the Content-Length header
    # (true chunked/streaming POST) must still capture a valid JSON body.
    request = SimpleNamespace(
        method='POST',
        META={'CONTENT_TYPE': 'application/json'},
        headers={'Content-Type': 'application/json'},
        body=b'{"amount":10,"note":"hi"}',
        FILES={},
        content_type='application/json',
    )
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'log_request_bodies': True,
                    'body_field_allowlist': ['amount'],
                }
            }
        }
    ).core

    assert capture_request_body(request, config) == {'request.body': {'amount': 10}}


def test_malformed_json_records_only_parse_status():
    request = SimpleNamespace(
        method='POST',
        META={'CONTENT_LENGTH': '8', 'CONTENT_TYPE': 'application/json'},
        headers={'Content-Length': '8', 'Content-Type': 'application/json'},
        body=b'not-json',
        FILES={},
        content_type='application/json',
    )
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'log_request_bodies': True,
                    'body_field_allowlist': ['username'],
                }
            }
        }
    ).core

    assert capture_request_body(request, config) == {
        'request.body.parse_status': 'invalid_json'
    }


def _json_request(raw: bytes, *, content_length=None, content_type='application/json'):
    length = str(len(raw)) if content_length is None else content_length
    return SimpleNamespace(
        method='POST',
        META={'CONTENT_LENGTH': length, 'CONTENT_TYPE': content_type},
        headers={'Content-Length': length, 'Content-Type': content_type},
        body=raw,
        FILES={},
        content_type=content_type,
    )


def _body_core(**core):
    core.setdefault('log_request_bodies', True)
    return SecAuditSettings.from_settings({'SEC_AUDIT': {'core': core}}).core


def test_empty_allowlist_emits_no_body_values():
    # The safe default: bodies are logged, but with no allowlisted fields the
    # operator expects zero body values in the output.
    request = _json_request(b'{"amount":10,"username":"maya"}')
    config = _body_core(body_field_allowlist=[])

    assert capture_request_body(request, config) == {}


def test_allowlist_keeps_only_listed_top_level_fields():
    request = _json_request(b'{"amount":10,"username":"maya","email":"m@x.test"}')
    config = _body_core(body_field_allowlist=['amount'])

    assert capture_request_body(request, config) == {'request.body': {'amount': 10}}


def test_json_array_body_is_unsupported_shape_with_no_body():
    request = _json_request(b'[1,2,3]')
    config = _body_core(body_field_allowlist=['amount'])

    result = capture_request_body(request, config)
    assert result == {'request.body.parse_status': 'unsupported_shape'}
    assert 'request.body' not in result


def test_json_scalar_body_is_unsupported_shape():
    request = _json_request(b'42')
    config = _body_core(body_field_allowlist=['amount'])

    assert capture_request_body(request, config) == {
        'request.body.parse_status': 'unsupported_shape'
    }


def test_oversized_body_by_content_length_is_too_large():
    # max_body_bytes defaults to 4096; a declared length above it is bounded out
    # before the body is read.
    request = _json_request(b'{"amount":10}', content_length='5000')
    config = _body_core(body_field_allowlist=['amount'])

    assert capture_request_body(request, config) == {
        'request.body.parse_status': 'too_large'
    }


def test_allowlisted_sensitive_value_is_still_scrubbed():
    # 'token' is a default sensitive key. Even explicitly allowlisting it must
    # not leak the value in the clear.
    request = _json_request(b'{"token":"super-secret-value"}')
    config = _body_core(body_field_allowlist=['token'])

    body = capture_request_body(request, config)['request.body']
    assert body['token'] != 'super-secret-value'


def test_sensitive_key_allowlist_preserves_benign_field_end_to_end():
    # R10 end-to-end: 'credit_card_last4' compacts to 'creditcardlast4', which the
    # 'creditcard' denylist keyword over-redacts. sensitive_key_allowlist (parsed
    # from SEC_AUDIT core settings, distinct from body_field_allowlist) exempts it
    # from redaction while the full 'credit_card' field stays redacted.
    request = _json_request(
        b'{"credit_card_last4":"4242","credit_card":"4111111111111111"}'
    )
    config = _body_core(
        body_field_allowlist=['credit_card_last4', 'credit_card'],
        sensitive_key_allowlist=['credit_card_last4'],
    )

    assert capture_request_body(request, config) == {
        'request.body': {
            'credit_card_last4': '4242',
            'credit_card': '[REDACTED]',
        }
    }


def test_logout_with_user_is_success(monkeypatch):
    from sec_audit.django.logging import auth as auth_mod

    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    monkeypatch.setattr(
        auth_mod, '_request_base', lambda request: {'srcip': '203.0.113.5'}
    )
    try:
        auth_mod.logout_logger(
            sender=None, request=SimpleNamespace(), user=SimpleNamespace(pk=42)
        )
    finally:
        _restore_runtime(previous)

    event, _ = runtime.events[0]
    assert event.event_type == EventType.AUTH_LOGOUT_SUCCESS
    assert event.attributes['user.id'] == '42'


def test_logout_without_user_is_unknown_not_failed(monkeypatch):
    # B4: an already-anonymous/expired logout (user=None) still succeeded — the
    # actor was simply unknown. It must be auth.logout.unknown, never .failed,
    # and carries no user.id / outcome (no actor to attribute the result to).
    from sec_audit.django.logging import auth as auth_mod

    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    monkeypatch.setattr(
        auth_mod, '_request_base', lambda request: {'srcip': '203.0.113.5'}
    )
    try:
        auth_mod.logout_logger(sender=None, request=SimpleNamespace(), user=None)
    finally:
        _restore_runtime(previous)

    event, _ = runtime.events[0]
    assert event.event_type == EventType.AUTH_LOGOUT_UNKNOWN
    assert event.event_type != EventType.AUTH_LOGOUT_FAILED
    assert 'user.id' not in event.attributes
    assert 'outcome' not in event.attributes


def test_model_event_uses_field_names_only(monkeypatch):
    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    log_entry = SimpleNamespace(
        action=1,
        content_type=SimpleNamespace(model='account', app_label='fintech'),
        object_pk='7',
        actor=SimpleNamespace(pk=42, __str__=lambda self: 'Maya'),
        remote_addr='203.0.113.9',
        changes={'api_key': ['old-secret', 'new-secret']},
    )
    try:
        forward_auditlog(sender=None, log_entry=log_entry)
    finally:
        _restore_runtime(previous)

    event, _ = runtime.events[0]
    assert event.event_type == EventType.MODEL_UPDATE
    assert event.attributes['changed_fields'] == ('api_key',)
    assert 'changes' not in event.attributes
    assert 'user.name' not in event.attributes
    # actor id flows to user.id even with usernames off (N1: actor dict now
    # always carries id); object_pk is no longer emitted as a duplicate (A4).
    assert event.attributes['user.id'] == '42'
    assert event.attributes['object_id'] == '7'
    assert 'object_pk' not in event.attributes


def test_model_actor_str_is_never_called():
    # Controlled actor extraction uses pk/get_username only. Custom user models
    # may implement __str__ to return sensitive data, raise, or hit the DB, so
    # the forwarder must never call it.
    runtime = _CaptureRuntime({'SEC_AUDIT': {'django': {'include_usernames': True}}})
    previous = _set_runtime(runtime)
    str_calls = []

    class _Actor:
        pk = 9

        def get_username(self):
            return 'bob'

        def __str__(self):
            str_calls.append(1)
            return 'SHOULD-NOT-APPEAR'

    log_entry = SimpleNamespace(
        action=1,
        content_type=SimpleNamespace(model='account', app_label='fintech'),
        object_pk='1',
        actor=_Actor(),
        remote_addr='',
        changes={},
    )
    try:
        forward_auditlog(sender=None, log_entry=log_entry)
    finally:
        _restore_runtime(previous)

    assert str_calls == []
    event, _ = runtime.events[0]
    assert event.attributes['user.name'] == 'bob'
    assert event.attributes['user.id'] == '9'


def test_build_log_attributes_includes_request_body():
    attributes = build_log_attributes(
        EventType.HTTP_RESPONSE_SUCCESS,
        {'request.body': {'amount': 10}},
        schema_version='1.0',
    )

    assert attributes['request.body'] == {'amount': 10}


def test_build_log_attributes_includes_parse_status_without_body():
    attributes = build_log_attributes(
        EventType.HTTP_RESPONSE_SUCCESS,
        {'request.body.parse_status': 'invalid_json'},
        schema_version='1.0',
    )

    assert attributes['request.body.parse_status'] == 'invalid_json'
    assert 'request.body' not in attributes


def test_build_runtime_does_not_mutate_prewired_formatters():
    # the configured source reaches the formatter at construction via the
    # ``audit_jsonl_formatter`` factory, NOT by post-construction mutation in
    # ``_build_runtime``. A formatter attached out of band keeps its own config.
    audit_logger = logging.getLogger(audit_runtime.AUDIT_LOGGER_NAME)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONLLogFormatter(config=CoreAuditConfig()))
    audit_logger.addHandler(handler)
    try:
        runtime = audit_runtime._build_runtime(
            {'SEC_AUDIT': {'core': {'source': 'billing-svc'}}}
        )

        assert runtime.config.core.source == 'billing-svc'
        assert handler.formatter.config.source == 'sec-audit'
    finally:
        audit_logger.removeHandler(handler)


def test_authenticated_user_recorded_on_http_event():
    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    request = _Request()
    request.user = SimpleNamespace(
        is_authenticated=True, pk=42, get_username=lambda: 'maya'
    )
    try:
        AuditMiddleware(lambda r: _Response(404))(request)
    finally:
        _restore_runtime(previous)

    event, _ = runtime.events[0]
    assert event.attributes['user.id'] == '42'


def test_anonymous_request_omits_user_id():
    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    request = _Request()
    request.user = SimpleNamespace(
        is_authenticated=False, pk=None, get_username=lambda: ''
    )
    try:
        AuditMiddleware(lambda r: _Response(404))(request)
    finally:
        _restore_runtime(previous)

    event, _ = runtime.events[0]
    assert 'user.id' not in event.attributes


def test_user_resolved_during_view_dispatch_is_captured():
    # DRF/JWT/token authenticators run during get_response, so request.user is
    # only populated after view dispatch. Identity must be captured then, not
    # before get_response.
    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    request = _Request()
    drf_user = SimpleNamespace(
        is_authenticated=True, pk=99, get_username=lambda: 'drf-user'
    )

    def get_response(req):
        req.user = drf_user
        return _Response(404)

    try:
        AuditMiddleware(get_response)(request)
    finally:
        _restore_runtime(previous)

    event, _ = runtime.events[0]
    assert event.attributes['user.id'] == '99'


def test_redirect_response_classified_as_redirect_event():
    # a 3xx is its own event class, not http.response.success.
    runtime = _CaptureRuntime({'SEC_AUDIT': {'core': {'log_ok_responses': True}}})
    previous = _set_runtime(runtime)
    request = _Request()
    try:
        AuditMiddleware(lambda r: _Response(302))(request)
    finally:
        _restore_runtime(previous)

    event, level = runtime.events[0]
    assert event.event_type == EventType.HTTP_RESPONSE_REDIRECT
    assert event.attributes['http.response.status_code'] == 302
    assert level == logging.INFO


def test_redirect_gated_like_success_when_ok_responses_disabled():
    # redirects follow the non-error gate (log_ok_responses defaults False).
    runtime = _CaptureRuntime({'SEC_AUDIT': {}})
    previous = _set_runtime(runtime)
    request = _Request()
    try:
        AuditMiddleware(lambda r: _Response(302))(request)
    finally:
        _restore_runtime(previous)

    assert runtime.events == []


def test_good_response_reaches_engine_when_consumer_present_even_if_logging_off():
    # With a rules/enforcement consumer registered, a 2xx and a 3xx are built and
    # handed to record() even though log_ok_responses is False — emit=False keeps
    # them out of the log while the consumer still sees them.
    runtime = _CaptureRuntime({'SEC_AUDIT': {'core': {'log_ok_responses': False}}})
    previous = _set_runtime(runtime)

    def _consumer(event):
        pass

    audit_runtime.register_rule_event_consumer(_consumer)
    try:
        AuditMiddleware(lambda r: _Response(200))(_Request())
        AuditMiddleware(lambda r: _Response(302))(_Request())
    finally:
        audit_runtime.unregister_rule_event_consumer(_consumer)
        _restore_runtime(previous)

    assert len(runtime.events) == 2
    assert runtime.emits == [False, False]
    assert runtime.events[0][0].event_type == EventType.HTTP_RESPONSE_SUCCESS
    assert runtime.events[1][0].event_type == EventType.HTTP_RESPONSE_REDIRECT


def test_good_response_skipped_when_no_consumer_and_logging_off():
    # No consumer + log_ok_responses False: the event is not even built — today's
    # behavior (and per-request cost) is preserved for logging-only deployments.
    runtime = _CaptureRuntime({'SEC_AUDIT': {'core': {'log_ok_responses': False}}})
    previous = _set_runtime(runtime)
    try:
        AuditMiddleware(lambda r: _Response(200))(_Request())
    finally:
        _restore_runtime(previous)

    assert runtime.events == []


def test_record_emit_false_dispatches_to_consumer_without_logging():
    # The runtime decouples logging from dispatch: emit=False skips emit_event but
    # still feeds the consumer; emit=True does both.
    emitted = []
    received = []

    class _FakeLogging:
        def emit_event(self, event, level):
            emitted.append((event, level))

    rt = DjangoLoggingRuntime(config=None, logging=_FakeLogging())
    event = build_audit_event(
        Message.HTTP_RESPONSE,
        EventType.HTTP_RESPONSE_SUCCESS,
        {'status': 200},
        schema_version='1.0',
    )

    def _consumer(evt):
        received.append(evt)

    audit_runtime.register_rule_event_consumer(_consumer)
    try:
        rt.record(event, logging.INFO, emit=False)
        rt.record(event, logging.INFO, emit=True)
    finally:
        audit_runtime.unregister_rule_event_consumer(_consumer)

    assert received == [event, event]
    assert emitted == [(event, logging.INFO)]


def test_http_route_uses_pattern_and_route_name_uses_view_name():
    # http.route is the OTel route template; the Django view name is
    # carried separately in http.route_name.
    attributes = build_log_attributes(
        EventType.HTTP_RESPONSE_SUCCESS,
        {'route_pattern': '/api/users/{id}/', 'route_name': 'users:detail'},
        schema_version='1.0',
    )
    assert attributes['http.route'] == '/api/users/{id}/'
    assert attributes['http.route_name'] == 'users:detail'


def test_http_route_does_not_fall_back_to_view_name():
    attributes = build_log_attributes(
        EventType.HTTP_RESPONSE_SUCCESS,
        {'route_name': 'users:detail'},
        schema_version='1.0',
    )
    assert 'http.route' not in attributes
    assert attributes['http.route_name'] == 'users:detail'


def test_body_capture_ignores_private_read_started_flag():
    request = SimpleNamespace(
        method='POST',
        META={'CONTENT_LENGTH': '7', 'CONTENT_TYPE': 'application/json'},
        headers={'Content-Length': '7', 'Content-Type': 'application/json'},
        body=b'{"a":1}',
        content_type='application/json',
        streaming=False,
        _read_started=True,
    )
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'log_request_bodies': True,
                    'body_field_allowlist': ['a'],
                }
            }
        }
    ).core

    assert capture_request_body(request, config) == {'request.body': {'a': 1}}


def test_multipart_body_skipped_via_content_type_without_files():
    request = SimpleNamespace(
        method='POST',
        META={
            'CONTENT_LENGTH': '100',
            'CONTENT_TYPE': 'multipart/form-data; boundary=x',
        },
        headers={
            'Content-Length': '100',
            'Content-Type': 'multipart/form-data; boundary=x',
        },
        body=b'',
        content_type='multipart/form-data; boundary=x',
        streaming=False,
    )
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'log_request_bodies': True,
                    'body_field_allowlist': ['a'],
                }
            }
        }
    ).core

    assert capture_request_body(request, config) == {}


def test_body_capture_failure_routes_to_internal_logger_without_traceback():
    class _RaisingBodyRequest:
        method = 'POST'
        content_type = 'application/json'
        streaming = False
        META = {'CONTENT_LENGTH': '5', 'CONTENT_TYPE': 'application/json'}
        headers = {'Content-Length': '5', 'Content-Type': 'application/json'}

        @property
        def body(self):
            raise RuntimeError('read failed')

    captured = []

    class _Grab(logging.Handler):
        def emit(self, record):
            captured.append(record)

    internal = logging.getLogger('sec_audit.internal')
    handler = _Grab()
    internal.addHandler(handler)
    previous_level = internal.level
    internal.setLevel(logging.DEBUG)
    config = SecAuditSettings.from_settings(
        {
            'SEC_AUDIT': {
                'core': {
                    'log_request_bodies': True,
                    'body_field_allowlist': ['a'],
                }
            }
        }
    ).core
    try:
        result = capture_request_body(_RaisingBodyRequest(), config)
    finally:
        internal.removeHandler(handler)
        internal.setLevel(previous_level)

    assert result == {}
    assert captured, 'expected an internal diagnostic record'
    assert captured[-1].name == 'sec_audit.internal'
    assert captured[-1].exc_info is None
