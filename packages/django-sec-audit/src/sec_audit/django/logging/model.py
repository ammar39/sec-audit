import logging

from auditlog.signals import post_log
from django.dispatch import receiver

from sec_audit.core.context import get_request_id, get_session_id
from sec_audit.core.diagnostics import diagnostic_debug, diagnostic_warning
from sec_audit.django.events import (
    EventType,
    Message,
    build_audit_event,
)
from sec_audit.django.runtime import get_runtime

EVENT_TYPE_MAP = {
    'create': EventType.MODEL_CREATE,
    'update': EventType.MODEL_UPDATE,
    'delete': EventType.MODEL_DELETE,
    'access': EventType.MODEL_ACCESS,
}


@receiver(post_log)
def forward_auditlog(sender, log_entry=None, **kwargs):
    # audit logging must fail open. A model-event receiver can never
    # block the underlying model operation; only the logging work is wrapped.
    try:
        if kwargs.get('error') is not None or log_entry is None:
            # auditlog already failed its own write; this is not our audit loss.
            diagnostic_debug(
                'Audit model-event forwarding skipped after auditlog failure'
            )
            return
        action_map = {0: 'create', 1: 'update', 2: 'delete', 3: 'access'}
        action = action_map.get(log_entry.action, 'unknown')
        data = {
            'model': log_entry.content_type.model if log_entry.content_type else '',
            'app_label': log_entry.content_type.app_label
            if log_entry.content_type
            else '',
            'object_id': str(log_entry.object_pk),
            'crud_action': action,
            'request_id': get_request_id() or '',
            'session_id': get_session_id() or '',
        }
        if data['app_label'] and data['model']:
            data['model_label'] = f'{data["app_label"]}.{data["model"]}'
        if log_entry.actor:
            actor_id = getattr(log_entry.actor, 'pk', None) or getattr(
                log_entry.actor, 'id', None
            )
            username = ''
            if get_runtime().config.django.include_usernames and callable(
                getattr(log_entry.actor, 'get_username', None)
            ):
                username = log_entry.actor.get_username()
            # Keep the actor dict shape consistent with auth events
            # (identity._add_user_identity): id is always set when known, name
            # only when usernames are enabled.
            actor: dict[str, str] = {}
            if actor_id is not None:
                data['user_id'] = str(actor_id)
                actor['id'] = str(actor_id)
            if username:
                actor['name'] = username
            if actor:
                data['actor'] = actor
        if log_entry.remote_addr:
            data['srcip'] = log_entry.remote_addr
        changes = log_entry.changes
        if isinstance(changes, dict):
            data['changed_fields'] = tuple(str(field) for field in changes)
        event_type = EVENT_TYPE_MAP.get(action, 'model.unknown')
        runtime = get_runtime()
        event = build_audit_event(
            Message.MODEL_EVENT,
            event_type,
            data,
            schema_version=runtime.config.logging.schema_version,
            include_usernames=runtime.config.django.include_usernames,
        )
        runtime.record(event, logging.INFO)
    except Exception:
        diagnostic_warning(
            'audit.model_forward_failed',
            'Audit model-event forwarding failed; model operation proceeds',
        )
