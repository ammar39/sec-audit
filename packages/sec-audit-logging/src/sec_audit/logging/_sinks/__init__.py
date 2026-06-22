"""EXPERIMENTAL queue-backed file handlers — NOT part of the supported surface.

The supported production path is stdout JSONL (write the canonical
``JSONLLogFormatter`` output to a ``logging.StreamHandler`` — in Django via the
``audit_jsonl_formatter`` factory — and ship it with Alloy -> Loki).

These handlers are provided for local experimentation only:

* Their API may change or be removed without notice.
* They are intentionally NOT exported from ``sec_audit.logging`` and no core or
  supported code path imports them.
* They do not participate in the SEC_AUDIT config-injection flow; pass
  ``core_config`` explicitly if you need a non-default ``resource.service.name``.

Import them explicitly::

    from sec_audit.logging._sinks import QueuedJSONLHandler
"""

from sec_audit.logging._sinks.queue import QueuedJSONLHandler

__all__ = ['QueuedJSONLHandler']
