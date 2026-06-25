"""Public extension point: a Django signal fired for every emitted
``audit.enforcement.*`` event, so deployments can route alerts to their own
notifier (Slack/PagerDuty/email/queue). The package never makes the outbound
call — it only dispatches. Receivers are invoked via ``send_robust`` (fail-open:
a raising receiver is isolated and never affects enforcement or the response)."""

from __future__ import annotations

from django.dispatch import Signal

# Fired once per emitted enforcement event, AFTER it has been logged.
# Receiver signature:
#   def receiver(sender, *, event, event_type, level, **kwargs): ...
#   - event:      the immutable AuditEvent (read-only; .attributes already scrubbed
#                 + size-bounded by the emit pipeline)
#   - event_type: e.g. 'audit.enforcement.alert' (== event.event_type)
#   - level:      stdlib logging level (WARNING / ERROR / INFO)
enforcement_event = Signal()


def on_enforcement_event(handler, *, events=None, dispatch_uid=None):
    """Connect ``handler`` to enforcement events, optionally filtered to a set of
    event-type strings (e.g. ``{'audit.enforcement.alert'}``). Connected with
    ``weak=False`` so a handler defined in ``AppConfig.ready()`` is not GC'd.
    Returns the connected receiver (the wrapper, when filtered) so callers can
    ``enforcement_event.disconnect(...)`` it later."""
    if events is None:
        enforcement_event.connect(handler, weak=False, dispatch_uid=dispatch_uid)
        return handler
    wanted = set(events)

    def _filtered(sender, *, event_type, **kwargs):
        if event_type in wanted:
            handler(sender=sender, event_type=event_type, **kwargs)

    enforcement_event.connect(_filtered, weak=False, dispatch_uid=dispatch_uid)
    return _filtered
