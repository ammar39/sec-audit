import time


class WazuhAPISource:
    def __init__(
        self,
        *,
        base_url: str = 'https://localhost:55000',
        username: str = 'admin',
        password: str = 'admin',
        verify_ssl: bool = False,
    ) -> None:
        import httpx

        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self._session = httpx.Client(verify=verify_ssl)
        self._token = None
        self._token_expiry = 0.0

    def _authenticate(self) -> bool:
        now = time.time()
        if self._token and now < self._token_expiry - 30:
            return True
        try:
            resp = self._session.post(
                f'{self.base_url}/security/user/authenticate',
                json={},
                auth=(self.username, self.password),
                timeout=3,
            )
            resp.raise_for_status()
            self._token = resp.json()['data']['token']
            self._token_expiry = now + 3600
            return True
        except Exception:
            return False

    def is_available(self) -> bool:
        return self._authenticate()

    def request(self, method: str, path: str, **kwargs):
        if not self._authenticate():
            return None
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self._token}'
        try:
            resp = self._session.request(
                method,
                f'{self.base_url}{path}',
                headers=headers,
                timeout=kwargs.pop('timeout', 15),
                **kwargs,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return None

    def get_agents(self):
        result = self.request(
            'GET', '/agents', params={'select': 'id,name,status,lastKeepAlive'}
        )
        return (result or {}).get('data', {})

    def get_manager_info(self):
        result = self.request('GET', '/manager/info')
        return (result or {}).get('data', {})
