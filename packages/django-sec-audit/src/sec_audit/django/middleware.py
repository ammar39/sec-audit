import logging
import random
import time

from sec_audit.core.context import AuditContext, reset_context, set_context
from sec_audit.core.diagnostics import diagnostic_warning
from sec_audit.django.logging.body import capture_request_body
from sec_audit.django.logging.drf import audit_drf_info
from sec_audit.django.logging.identity import _add_user_identity
from sec_audit.django.events import (
    EventType,
    Message,
    build_audit_event,
)
from sec_audit.django.utils.request import (
    request_path as _request_path,
    request_url as _request_url,
)
from sec_audit.django.logging.request_info import build_request_info
from sec_audit.django.logging.routes import audit_route_info, resolve_request_match
from sec_audit.django.logging.sessions import get_audit_session_id
from sec_audit.django.runtime import get_runtime, has_rule_event_consumers


class BaseAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.runtime = get_runtime()
        self.config = self.runtime.config.core

    def _is_ignored_path(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in self.config.ignore_paths)

    def _build_base_info(self, request):
        session_id = get_audit_session_id(
            request, enabled=self.runtime.config.django.emit_session_id
        )
        path = _request_path(request)
        base = build_request_info(
            method=request.method,
            path=path,
            url=_request_url(request, path),
            headers=dict(request.headers.items()),
            meta=request.META,
            config=self.config,
            proxy_config=self.runtime.config.django.trusted_proxy_config,
            session_id=session_id,
        )
        match = resolve_request_match(request)
        base.update(audit_route_info(request, match=match))
        base.update(audit_drf_info(request, self.runtime.config.django, match=match))
        base.update(
            capture_request_body(request, self.config, path=base.get('path', ''))
        )
        return session_id, base, match

    def _prepare_audit_context(self, request):
        """Build request base info and activate the audit context.

        Returns an opaque token (the (session_id, base) pair) on success, or
        ``None`` on failure. Failures here are non-fatal: the request still
        proceeds, just without audit correlation. Raising would break the
        application, so this is wrapped by the caller's try/except.
        """
        session_id, base, _ = self._build_base_info(request)
        context_token = set_context(
            AuditContext(
                request_id=base.get('request_id', ''),
                session_id=session_id,
                url=base.get('url', ''),
                path=base.get('path', ''),
                srcip=base.get('srcip', ''),
                method=request.method,
            )
        )
        return context_token, session_id, base

    def _reset_audit_context(self, token):
        reset_context(token)


class AuditMiddleware(BaseAuditMiddleware):
    def __call__(self, request):
        # check the ignore list against the cheap normalized path
        # BEFORE any session/IP/route/body/DRF work. An ignored endpoint must
        # actually be ignored from a privacy and behavior perspective — not
        # merely have its HTTP response log suppressed after extraction (which
        # can still mint session ids, resolve client IPs, read bodies, etc.).
        #
        # Note: this suppresses only the HTTP response audit. Auth and model
        # events fire from their own receivers (login/logout signals, the
        # auditlog forwarder) and are not gated by ignore_paths; their request
        # context is built independently in logging.identity/_request_base.
        if self._is_ignored_path(_request_path(request)):
            return self.get_response(request)

        # audit work must fail open. The application call
        # (get_response) is NEVER wrapped in try/except — its exceptions
        # propagate normally. Only preparation and recording are fail-open:
        # losing one audit record is preferable to breaking the request.
        started_ns = time.perf_counter_ns()
        prepared = None
        try:
            prepared = self._prepare_audit_context(request)
        except Exception:
            diagnostic_warning(
                'audit.context_prep_failed',
                'Audit context preparation failed; request proceeds unaudited',
            )

        try:
            response = self.get_response(request)
            # Response succeeded: record (fail-open) if we prepared a context.
            if prepared is not None:
                try:
                    self._record_response(request, response, started_ns, prepared)
                except Exception:
                    diagnostic_warning(
                        'audit.response_record_failed',
                        'Audit response recording failed; response is returned as-is',
                    )
            return response
        finally:
            if prepared is not None:
                self._reset_audit_context(prepared[0])

    def _record_response(self, request, response, started_ns, prepared):
        _, _, base = prepared
        duration_ns = time.perf_counter_ns() - started_ns
        if response.status_code in self.config.ignore_status_codes:
            return
        status = response.status_code
        event_base = dict(base)
        event_base['status'] = status
        event_base['duration_ns'] = duration_ns
        # Resolve identity after view dispatch: DRF/JWT/token authenticators
        # run during get_response, so request.user is only final now.
        user = getattr(request, 'user', None)
        if user is not None and getattr(user, 'is_authenticated', False):
            _add_user_identity(event_base, user)
        if status >= 500:
            self._record(
                EventType.HTTP_RESPONSE_SERVER_ERROR,
                event_base,
                logging.ERROR,
                request=request,
            )
        elif status >= 400:
            self._record(
                EventType.HTTP_RESPONSE_CLIENT_ERROR,
                event_base,
                logging.WARNING,
                request=request,
            )
        elif status >= 300:
            # 3xx is a distinct security-relevant class (e.g. a 302 auth
            # redirect) — not a 2xx success. The non-error gate controls only
            # whether it is logged; rules still see it when a consumer is
            # registered (see _record_non_error).
            self._record_non_error(
                EventType.HTTP_RESPONSE_REDIRECT,
                event_base,
                logging.INFO,
                request=request,
            )
        else:
            self._record_non_error(
                EventType.HTTP_RESPONSE_SUCCESS,
                event_base,
                logging.INFO,
                request=request,
            )

    def _record_non_error(self, event_type, data, level, *, request=None):
        emit = self._should_emit_non_error_response()
        # Rules/enforcement must see good responses even when logging is
        # suppressed (log_ok_responses=False or sampled out). Only skip the
        # (expensive) event build when nothing would consume it: no logging
        # AND no registered consumer.
        if not emit and not has_rule_event_consumers():
            return
        self._record(event_type, data, level, request=request, emit=emit)

    def _should_emit_non_error_response(self) -> bool:
        return self.config.log_ok_responses and (
            self.config.sample_rate >= 1.0 or random.random() < self.config.sample_rate
        )

    def _record(
        self,
        event_type,
        data,
        level,
        *,
        request=None,
        emit=True,
    ):
        event = build_audit_event(
            Message.HTTP_RESPONSE,
            event_type,
            data,
            schema_version=self.runtime.config.logging.schema_version,
            include_usernames=self.runtime.config.django.include_usernames,
        )
        self.runtime.record(event, level, emit=emit)
