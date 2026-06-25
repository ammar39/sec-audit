"""Lightweight request/response doubles for middleware tests (no real WSGI)."""

from django.http import HttpResponse

from sec_audit.django.logging.sessions import _AUDIT_SESSION_ID_KEY


class FakeSession:
    """Dict-like session double exposing the bits the audit/enforcement code reads."""

    def __init__(self, key='', data=None):
        self.session_key = key
        self._data = dict(data or {})
        self.modified = False

    def get(self, name, default=None):
        return self._data.get(name, default)

    def __getitem__(self, name):
        return self._data[name]

    def __setitem__(self, name, value):
        self._data[name] = value


class FakeUser:
    def __init__(self, pk=None):
        self.pk = pk
        self.is_authenticated = pk is not None


class FakeRequest:
    def __init__(
        self,
        *,
        path='/login/',
        method='POST',
        remote_addr='203.0.113.7',
        xff=None,
        session_key='',
        audit_session_id=None,
        user_pk=None,
    ):
        self.path = path
        self.method = method
        self.META = {'REMOTE_ADDR': remote_addr}
        if xff is not None:
            self.META['HTTP_X_FORWARDED_FOR'] = xff
        data = {}
        if audit_session_id is not None:
            data[_AUDIT_SESSION_ID_KEY] = audit_session_id
        self.session = FakeSession(session_key, data)
        self.user = FakeUser(user_pk)


def ok_view(request):
    return HttpResponse('ok', status=200)
