import uuid

# Namespaced, private key under which the independent audit-session id is stored
# in the Django session. Never read ``request.session.session_key``: that is the
# raw stealable credential. This value is an unrelated random id used only for
# log correlation.
_AUDIT_SESSION_ID_KEY = '_sec_audit_session_id'


def get_audit_session_id(request, *, enabled: bool = True) -> str:
    """Return a stable, independent audit-session id for the request.

    Generates a random id per session (stored under ``_sec_audit_session_id``)
    and reuses it across later requests in the same session. When ``enabled`` is
    False or the request has no session, returns '' so no ``session.id`` is
    emitted. Never derives anything from ``session.session_key``.
    """
    if not enabled:
        return ''
    session = getattr(request, 'session', None)
    if session is None:
        return ''
    value = session.get(_AUDIT_SESSION_ID_KEY)
    if not value:
        value = uuid.uuid4().hex
        session[_AUDIT_SESSION_ID_KEY] = value
        # Ensure SessionMiddleware persists the new id on the response path.
        session.modified = True
    return str(value)


def read_audit_session_id(request) -> str:
    """Return the already-stored audit-session id, or '' if none.

    Read-only counterpart to :func:`get_audit_session_id`: it never mints a new id
    and never writes to the session (no ``session.modified``). The ingress
    enforcement check uses this so a session block (keyed by the audit id egress
    emits) is looked up under the same value — never ``session.session_key``.
    """
    session = getattr(request, 'session', None)
    if session is None:
        return ''
    return str(session.get(_AUDIT_SESSION_ID_KEY) or '')
