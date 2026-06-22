"""Lightweight request/response doubles for middleware tests (no real WSGI)."""

from django.http import HttpResponse


class FakeSession:
    def __init__(self, key=''):
        self.session_key = key


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
        user_pk=None,
    ):
        self.path = path
        self.method = method
        self.META = {'REMOTE_ADDR': remote_addr}
        if xff is not None:
            self.META['HTTP_X_FORWARDED_FOR'] = xff
        self.session = FakeSession(session_key)
        self.user = FakeUser(user_pk)


def ok_view(request):
    return HttpResponse('ok', status=200)
