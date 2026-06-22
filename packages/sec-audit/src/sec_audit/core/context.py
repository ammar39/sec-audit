from __future__ import annotations

import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditContext:
    request_id: str
    session_id: str
    url: str = ''
    path: str = ''
    srcip: str = ''
    method: str = ''


# A stdlib ``ContextVar`` keeps the framework-neutral core free of Django's
# ``asgiref`` infrastructure while giving correct per-request isolation under
# both sync (thread) and async (task) execution. ``set()`` returns a token and
# ``reset(token)`` restores the previous value, so nested contexts (test
# fixtures, nested calls) survive an inner request instead of being destroyed.
_ctx: ContextVar[AuditContext | None] = ContextVar('sec_audit_context', default=None)


def set_context(ctx: AuditContext) -> Token:
    return _ctx.set(ctx)


def reset_context(token: Token) -> None:
    _ctx.reset(token)


def get_context() -> AuditContext | None:
    return _ctx.get()


def clear_context() -> None:
    _ctx.set(None)


def get_request_id() -> str | None:
    ctx = get_context()
    return ctx.request_id if ctx else None


def get_session_id() -> str | None:
    ctx = get_context()
    return ctx.session_id if ctx else None


def generate_id() -> str:
    # Full UUID4 hex (32 chars, 128 bits). Audit records can be retained for
    # years and aggregated across services, so there is no reason to truncate
    # and every reason to keep collision resistance high.
    return uuid.uuid4().hex
