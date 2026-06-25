"""Ingress enforcement: the block check + the optional safe-rule fast path.

Ordered ABOVE ``AuditMiddleware`` so an active block short-circuits before any
audit work. It owns ONLY the ingress concerns — egress detection/application
happens in the ``record()`` consumer when ``AuditMiddleware`` records the
response. ``get_response`` is never wrapped; only the check/apply follow the
configured fail mode.
"""

from __future__ import annotations

import logging

from django.http import HttpResponse

from sec_audit.django.runtime import get_runtime
from sec_audit.enforcement.actions import BLOCKING_ACTIONS

from sec_audit.django_enforcement import emit as emit_mod
from sec_audit.django_enforcement.projection import synthesize_pre_request_event
from sec_audit.django_enforcement.runtime import get_enforcement_runtime
from sec_audit.django_enforcement.scopes import ingress_summary
from sec_audit.django_enforcement.stores import BlockStoreError

logger = logging.getLogger('sec_audit.enforcement')


class EnforcementMiddleware:
    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request):
        try:
            runtime = get_enforcement_runtime()
        except Exception:
            logger.warning('Enforcement runtime unavailable; proceeding', exc_info=True)
            return self.get_response(request)
        if not runtime.config.enabled:
            return self.get_response(request)
        try:
            deny = self._ingress(runtime, request)
        except Exception as exc:
            # Unexpected enforcement error: fail open (proceed), diagnostic only.
            _safe_emit(runtime, fail_mode='open', error=exc)
            deny = None
        if deny is not None:
            return deny
        return self.get_response(request)

    def _ingress(self, runtime, request):
        config = runtime.config
        path = getattr(request, 'path', '') or ''
        django_cfg = get_runtime().config.django
        summary = ingress_summary(
            request,
            trusted_proxy_config=django_cfg.trusted_proxy_config,
            emit_session_id=django_cfg.emit_session_id,
        )
        scopes = runtime.scope_registry.block_scopes(summary)

        try:
            entry = runtime.block_store.first_active(scopes)
        except BlockStoreError as exc:
            if _fail_closed(config, path):
                _safe_emit(runtime, fail_mode='closed', error=exc)
                return _deny(config.status_code, config.message)
            _safe_emit(runtime, fail_mode='open', error=exc)
            entry = None

        if entry is not None:
            runtime.emitter.emit(
                emit_mod.build_blocked_event(
                    entry, schema_version=runtime.schema_version
                )
            )
            return _deny(entry.status_code, entry.message)

        if config.eval_safe_on_ingress and not config.apply_via_sink:
            return self._eval_safe(runtime, summary)
        return None

    def _eval_safe(self, runtime, summary):
        pre_event = synthesize_pre_request_event(summary)
        try:
            matches = runtime.engine.evaluate(pre_event, enforcement_only=True)
        except Exception:
            logger.warning('Ingress safe-rule eval failed; proceeding', exc_info=True)
            return None
        deny = None
        for match in matches:
            action = runtime.enforcer.resolve_action(match)
            for built in runtime.enforcer.apply(match, action, summary):
                runtime.emitter.emit(built)
            if action.action in BLOCKING_ACTIONS:
                deny = (
                    int(action.status_code or runtime.config.status_code),
                    action.message or runtime.config.message,
                )
        return _deny(*deny) if deny is not None else None


def _fail_closed(config, path: str) -> bool:
    return any(pattern.search(path) for pattern in config.fail_closed_paths)


def _deny(status_code, message) -> HttpResponse:
    return HttpResponse(message, status=int(status_code))


def _safe_emit(runtime, *, fail_mode: str, error) -> None:
    try:
        runtime.emitter.emit(
            emit_mod.build_evaluation_failed_event(
                fail_mode=fail_mode, error=error, schema_version=runtime.schema_version
            )
        )
    except Exception:
        pass
