from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Literal, Mapping

from django.http import RawPostDataException

from sec_audit.core.config import CoreAuditConfig
from sec_audit.core.projection import project_value
from sec_audit.core.scrubbers import scrub

logger = logging.getLogger('sec_audit.internal')
DEFAULT_MAX_JSON_BYTES = 4096

BodyParseStatusType = Literal[
    'captured',
    'empty',
    'invalid_json',
    'too_large',
    'not_json',
    'skipped',
    'unsupported_shape',
]


@dataclass(frozen=True)
class BodyParseResult:
    status: BodyParseStatusType
    data: Mapping[str, object] | None = None


def capture_request_body(
    request,
    config: CoreAuditConfig,
    *,
    path: str = '',
) -> dict[str, object]:
    if not config.log_request_bodies:
        return {}
    if request.method.upper() not in config.body_methods:
        return {}
    if config.log_body_paths and not any(
        pattern.search(path) for pattern in config.log_body_paths
    ):
        return {}
    if _is_unsafe_body_request(request):
        return {}
    if not config.body_field_allowlist:
        return {}
    # A declared CONTENT_LENGTH lets us reject oversize bodies before reading,
    # but its absence is not a reason to skip: HTTP/1.1 chunked/streaming POSTs
    # omit it. safe_json_body bounds size via its own len(raw) > max_bytes guard.
    content_length = _content_length(getattr(request, 'META', {}))
    if content_length is not None and content_length > config.max_body_bytes:
        return {'request.body.parse_status': 'too_large'}
    # Read via request.body (never request.read()): body capture runs PRE-dispatch
    # (middleware._prepare_audit_context, before get_response), so the stream must
    # stay intact for the view/DRF. request.body caches into _body and resets the
    # stream so later request.body access works; request.read() would set
    # _read_started and make the view raise RawPostDataException. It is also
    # already memory-bounded: WSGI caps reads at CONTENT_LENGTH via LimitedStream
    # (absent -> 0), and Django itself enforces DATA_UPLOAD_MAX_MEMORY_SIZE on
    # chunked/ASGI bodies, raising RequestDataTooBig without buffering it all.
    try:
        result = safe_json_body(
            request.body,
            dict(request.headers.items()),
            max_bytes=config.max_body_bytes,
        )
    except RawPostDataException:
        logger.debug('Django request body was already consumed')
        return {}
    except Exception:
        logger.debug('Failed to capture Django request body')
        return {}
    if result.status != 'captured':
        if result.status in {'empty', 'not_json', 'skipped'}:
            return {}
        return {'request.body.parse_status': result.status}
    body = {
        key: result.data[key]
        for key in config.body_field_allowlist
        if result.data is not None and key in result.data
    }
    if not body:
        return {}
    return {
        'request.body': project_value(
            scrub(
                body,
                sensitive_keys=config.sensitive_keys,
                value_patterns=config.sensitive_value_patterns,
                allowlist=config.sensitive_key_allowlist,
            )
        )
    }


def safe_json_body(
    raw: bytes,
    headers: Mapping[str, str],
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> BodyParseResult:
    content_type = str(_header(headers, 'Content-Type', '') or '')
    content_type = content_type.lower().split(';')[0].strip()
    if not _is_json_content_type(content_type):
        return BodyParseResult('not_json')

    # A declared Content-Length lets us reject oversize bodies early, but its
    # absence is not a reason to skip: HTTP/1.1 bodies (chunked/streaming) may
    # omit it. The len(raw) > max_bytes guard below bounds size regardless, and
    # capture_request_body already gates on the request's CONTENT_LENGTH.
    content_length = _header(headers, 'Content-Length')
    if content_length is not None:
        try:
            parsed_length = int(content_length)
            if parsed_length < 0 or parsed_length > max_bytes:
                logger.debug('JSON body too large: %s bytes', content_length)
                return BodyParseResult('too_large')
        except (TypeError, ValueError):
            return BodyParseResult('skipped')

    if len(raw) > max_bytes:
        logger.debug('Body exceeded max_bytes after read: %s', len(raw))
        return BodyParseResult('too_large')
    if not raw:
        return BodyParseResult('empty')

    try:
        decoded = raw.decode('utf-8')
    except UnicodeDecodeError:
        logger.debug('JSON body is not valid UTF-8')
        return BodyParseResult('invalid_json')

    try:
        data = json.loads(decoded)
    except (json.JSONDecodeError, TypeError):
        logger.debug('JSON body parse failed')
        return BodyParseResult('invalid_json')
    if not isinstance(data, dict):
        logger.debug('JSON body is not a dict (got %s)', type(data).__name__)
        return BodyParseResult('unsupported_shape')
    if not data:
        return BodyParseResult('empty')
    return BodyParseResult('captured', data)


def extract_json_fields(
    raw: bytes,
    headers: Mapping[str, str],
    field_names=None,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> dict[str, object] | None:
    body = safe_json_body(raw, headers, max_bytes=max_bytes)
    if body.status != 'captured' or body.data is None:
        return None
    if field_names is None:
        return dict(body.data)
    return {key: body.data[key] for key in field_names if key in body.data}


def _is_unsafe_body_request(request) -> bool:
    if getattr(request, 'streaming', False):
        return True
    content_type = str(getattr(request, 'content_type', '') or '').lower()
    if _is_form_content_type(content_type):
        return True
    meta = getattr(request, 'META', {})
    meta_content_type = str(meta.get('CONTENT_TYPE', '') or '').lower()
    return _is_form_content_type(meta_content_type)


def _content_length(meta: Mapping[str, object]) -> int | None:
    try:
        value = int(meta.get('CONTENT_LENGTH'))
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return value


def _header(headers: Mapping[str, str], name: str, default=None):
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return value
    return default


def _is_json_content_type(content_type: str) -> bool:
    return content_type == 'application/json' or (
        content_type.startswith('application/') and content_type.endswith('+json')
    )


def _is_form_content_type(content_type: str) -> bool:
    base = content_type.split(';')[0].strip().lower()
    return base.startswith('multipart/') or base in {
        'application/x-www-form-urlencoded',
        'multipart/form-data',
    }
