"""Built-in triggers: the four event sources wired onto the framework-free
``Trigger`` concept. This package imports both ``sec_audit.rules`` and the Django
layer, so it is the correct home for the concrete defaults.

Egress/auth/model all consume the emitted ``AuditEvent`` via
``RuleEvent.from_mapping`` in the ``record()`` consumer; one ``MappingEventBuilder``
(which duck-types ``AuditEvent``) covers all three. The ingress trigger overrides the
``event_type`` to the synthetic pre-request type so ``safe_for_enforcement`` rules
(``LoginThrottleRule``/``RepeatedRouteRule``) can fire before the view runs.
"""

from __future__ import annotations

from sec_audit.rules.triggers import MappingEventBuilder, Trigger

# Synthetic event_type for the ingress (pre-request) fast-path.
PRE_REQUEST_EVENT = 'audit.http.request.pre'

# One pass-through builder shared by the egress/auth/model triggers.
_PASSTHROUGH = MappingEventBuilder()

EGRESS_TRIGGER = Trigger(
    name='http.egress',
    event_types=frozenset(
        {
            'http.response.success',
            'http.response.redirect',
            'http.response.client_error',
            'http.response.server_error',
        }
    ),
    builder=_PASSTHROUGH,
)

AUTH_TRIGGER = Trigger(
    name='auth',
    event_types=frozenset(
        {
            'auth.login.success',
            'auth.login.failed',
            'auth.logout.success',
            'auth.logout.failed',
            'auth.logout.unknown',
        }
    ),
    builder=_PASSTHROUGH,
)

MODEL_TRIGGER = Trigger(
    name='model',
    event_types=frozenset(
        {
            'model.create',
            'model.update',
            'model.delete',
            'model.access',
        }
    ),
    builder=_PASSTHROUGH,
)

INGRESS_TRIGGER = Trigger(
    name='http.ingress',
    event_types=frozenset({PRE_REQUEST_EVENT}),
    builder=MappingEventBuilder(PRE_REQUEST_EVENT),
    enforcement_only=True,
)

DEFAULT_TRIGGERS = (EGRESS_TRIGGER, AUTH_TRIGGER, MODEL_TRIGGER, INGRESS_TRIGGER)
