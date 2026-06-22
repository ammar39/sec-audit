"""The ``record()`` consumer: egress detection + block application for every
event type (HTTP, auth, model) — they all funnel through the logging runtime's
``record``. Fail-open: a failure here never affects the already-returned
response. ``audit.enforcement.*`` events fed back through ``record`` evaluate to
``[]`` (engine skip-list), so there is no feedback loop."""

from __future__ import annotations

import logging

from sec_audit.django_enforcement.runtime import get_enforcement_runtime

logger = logging.getLogger('sec_audit.enforcement')


def consume(event) -> None:
    try:
        runtime = get_enforcement_runtime()
    except Exception:
        logger.warning(
            'Enforcement runtime build failed; event not evaluated', exc_info=True
        )
        return
    if not runtime.config.enabled:
        return
    try:
        runtime.handle_event(event)
    except Exception:
        logger.warning(
            'Enforcement consumer failed; response unaffected', exc_info=True
        )
