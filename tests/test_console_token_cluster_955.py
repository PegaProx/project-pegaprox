"""#955 - on a cluster that talks to PVE with an API token, the console never got anywhere.

Every console handler started with a password login to /access/ticket using config.user
and config.pass_, which on a token cluster are the token id and its secret. PVE answered
401 and the handler gave up before it reached the code that would have presented the
token. The helper tests in test_console_endpoint_and_auth.py never ran a handler, so they
passed the whole time.

These drive the handlers themselves - the standalone one on 5001 the reporter hit, the two
on the main port and the polling fallback - with PVE faked at urllib and websocket-client,
answering the way PVE does: 401 for a token posted as a password.

MK Oct 2026
"""
import asyncio
import json
import types
import urllib.error

import pytest
import websocket

from pegaprox.api import vms

_ID = 'root@pam!automation'
_VALUE = 'not-a-real-value'
_BROWSER_TICKET = 'PVEVNC:from-the-browser'


class _TokenManager:
    cluster_type = 'proxmox'
    host = auth_host = '10.0.0.9'
    api_port = 8006
    is_connected = False        # keeps the app's background loops (metrics, broadcast) off it
    _ssl_verify = False
    _using_api_token = True
    _ticket = None

    def __init__(self):
        self._api_token = f'{_ID}={_VALUE}'
        self.config = types.SimpleNamespace(user=_ID, pass_=_VALUE, name='c1', vnc_tunnel=False,
                                            ssh_port=22, ssh_key='')
        self.vncproxy_calls = []

    def get_vnc_ticket(self, node, vmid, vm_type):
        # the manager's own session sends the token, so PVE binds the ticket to it
        self.vncproxy_calls.append((node, vmid, vm_type))
        return {'success': True, 'ticket': 'PVEVNC:issued-under-the-token', 'port': 5907}


class _PasswordManager(_TokenManager):
    _using_api_token = False
    _ticket = 'PVE:root@pam:MANAGER'

    def __init__(self):
        super().__init__()
        self._api_token = None
        self.config.user = 'root@pam'


class _PveWs:
    sock = None

    def settimeout(self, t):
        pass

    def recv(self):
        raise websocket.WebSocketConnectionClosedException('closed by the test')

    def send(self, *a):
        pass

    send_binary = ping = send

    def close(self):
        pass


class _Answer:
    def __init__(self, data):
        self._body = json.dumps({'data': data}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


class _Pve:
    """urllib and websocket-client as PVE answers them."""

    def __init__(self, password_ok=False):
        self.password_ok = password_ok
        self.logins = []
        self.upgrades = []

    def urlopen(self, req, *a, **k):
        url = getattr(req, 'full_url', str(req))
        if url.endswith('/access/ticket'):
            self.logins.append(req.data)
            if not self.password_ok:
                raise urllib.error.HTTPError(url, 401, 'authentication failure', {}, None)
            return _Answer({'ticket': 'PVE:root@pam:FRESH', 'CSRFPreventionToken': 'csrf'})
        if url.endswith('/vncproxy'):
            return _Answer({'ticket': 'PVEVNC:ours', 'port': 5908})
        raise AssertionError(f'unexpected urllib call {url}')

    def opener(self, context=None):
        # pve_opener, the urllib opener the console handlers dial PVE with
        return types.SimpleNamespace(open=self.urlopen)

    def create_connection(self, url, header=None, **k):
        self.upgrades.append((url, dict(header or {})))
        return _PveWs()


@pytest.fixture
def pve(monkeypatch):
    fake = _Pve()
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', fake.opener)
    monkeypatch.setattr(websocket, 'create_connection', fake.create_connection)
    return fake


@pytest.fixture
def cluster(api, seed):
    seed.user('root', role='admin')
    return api.set_manager('c1', _TokenManager())


def _query(passthrough):
    from pegaprox.utils.realtime import create_ws_token
    q = f'token={create_ws_token("root", "admin")}'
    if passthrough:
        q += f'&pve_port=5901&pve_ticket={_BROWSER_TICKET}'
    return q


_PATH = '/api/clusters/c1/vms/pve1/qemu/100/vncwebsocket'


def _assert_token_console(pve, mgr, passthrough):
    assert pve.logins == [], (
        f'the token secret went to /access/ticket as a password: {pve.logins[:1]}')
    assert len(pve.upgrades) == 1, 'the console never reached the PVE websocket'
    url, header = pve.upgrades[0]
    assert header.get('Authorization') == f'PVEAPIToken={_ID}={_VALUE}', header
    assert 'Cookie' not in header, header
    if passthrough:
        assert mgr.vncproxy_calls == [], 'issued a second vncproxy next to the browser one'
        assert 'port=5901' in url and 'vncticket=PVEVNC%3Afrom-the-browser' in url, url
    else:
        assert mgr.vncproxy_calls == [('pve1', 100, 'qemu')]
        assert 'port=5907' in url and 'issued-under-the-token' in url, url


# --- the standalone handler on 5001, the one in the report -------------------

class _Browser:
    """The websockets-library side of vnc_handler: a browser that opens and goes away."""

    def __init__(self, path):
        self.request = types.SimpleNamespace(path=path)
        self.closed = None

    async def close(self, code=1000, reason=''):
        self.closed = (code, reason)

    async def send(self, data):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


@pytest.fixture(scope='module')
def standalone_handler():
    """vnc_handler lives inside start_vnc_websocket_server; take it from there without
    binding a port or letting the start-up kill whatever holds one."""
    import subprocess
    import websockets
    from unittest import mock
    got = {}

    class _Serve:
        def __init__(self, handler, *a, **k):
            got['handler'] = handler

        async def __aenter__(self):
            got['loop'] = asyncio.get_running_loop()
            return self

        async def __aexit__(self, *a):
            return False

    nothing = types.SimpleNamespace(returncode=1, stdout='', stderr='')
    with mock.patch.object(websockets, 'serve', _Serve), \
            mock.patch.object(subprocess, 'run', lambda *a, **k: nothing), \
            mock.patch.object(vms, 'gevent_listen_socket', lambda *a, **k: None):
        vms.start_vnc_websocket_server(port=1, host='127.0.0.1')
    assert 'handler' in got, 'start_vnc_websocket_server never handed its handler over'
    # under gevent the server "thread" shares the OS thread, and asyncio keeps one running
    # loop per OS thread - stop that one before a test runs the handler on a loop of its own
    import gevent
    loop = got['loop']
    loop.call_soon_threadsafe(loop.stop)
    for _ in range(200):
        if not loop.is_running():
            break
        gevent.sleep(0.01)
    yield got['handler']


@pytest.mark.parametrize('passthrough', [True, False], ids=['browser-ticket', 'own-vncproxy'])
def test_the_standalone_console_on_a_token_cluster(cluster, pve, standalone_handler, passthrough):
    browser = _Browser(f'{_PATH}?{_query(passthrough)}')
    asyncio.run(standalone_handler(browser))
    _assert_token_console(pve, cluster, passthrough)


# --- the two handlers on the main port ---------------------------------------

class _SyncBrowser:
    connected = False

    def receive(self, timeout=None):
        return None

    def send(self, data):
        pass

    def close(self, *a, **k):
        pass


@pytest.mark.parametrize('passthrough', [True, False], ids=['browser-ticket', 'own-vncproxy'])
def test_the_flask_sock_console_on_a_token_cluster(api, cluster, pve, passthrough):
    view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__
    with api.app.test_request_context(f'{_PATH}?{_query(passthrough)}'):
        view(_SyncBrowser(), 'c1', 'pve1', 'qemu', 100)
    _assert_token_console(pve, cluster, passthrough)


@pytest.mark.parametrize('passthrough', [True, False], ids=['browser-ticket', 'own-vncproxy'])
def test_the_geventwebsocket_console_on_a_token_cluster(api, cluster, pve, passthrough):
    with api.app.test_request_context(f'{_PATH}?{_query(passthrough)}'):
        vms.handle_vnc_websocket(_SyncBrowser(), 'c1', 'pve1', 'qemu', 100)
    _assert_token_console(pve, cluster, passthrough)


# --- the polling fallback ----------------------------------------------------

@pytest.mark.parametrize('passthrough', [True, False], ids=['browser-ticket', 'own-vncproxy'])
def test_the_polling_console_on_a_token_cluster(api, seed, cluster, pve, passthrough):
    from pegaprox.utils import vnc_polling
    body = {'action': 'open'}
    if passthrough:
        body.update(pve_port=5901, pve_ticket=_BROWSER_TICKET)
    r = api.as_user({'username': 'root', 'role': 'admin'}).post(
        '/api/clusters/c1/vms/pve1/qemu/100/vnc-poll', json=body)
    try:
        assert r.status_code == 200, r.get_json()
    finally:
        pid = (r.get_json() or {}).get('poll_id')
        if pid:
            vnc_polling.drop(pid)
    _assert_token_console(pve, cluster, passthrough)


# --- the same token secret, everywhere else it was posted as a password ------

def test_minting_a_session_ticket_does_not_post_a_token_secret(monkeypatch):
    """The terminal subprocess and the screenshot fallback ask for a session ticket on
    every open; on a token cluster that was one more failed login in the node's auth log."""
    import logging
    from pegaprox.core.manager import PegaProxManager
    posted = []
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', lambda context=None: types.SimpleNamespace(
        open=lambda req, *a, **k: posted.append(req.full_url)))
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host='10.0.0.9', user=_ID, pass_=_VALUE, api_port=8006,
                                     fallback_hosts=[])
    m.current_host = '10.0.0.9'
    m._ssl_verify = False
    m.logger = logging.getLogger('test-955')
    assert m.mint_console_auth_ticket() is None
    assert m.mint_console_auth_ticket(with_csrf=True) == (None, None)
    assert posted == [], posted


def test_the_terminal_says_what_is_missing_instead_of_logging_in(api, cluster, pve):
    r = api.as_user({'username': 'root', 'role': 'admin'}).post(
        '/api/clusters/c1/vms/pve1/qemu/100/termproxy')
    assert r.status_code == 400, r.get_json()
    assert pve.logins == []


# --- and a password cluster keeps doing exactly what it did ------------------

def test_a_password_cluster_still_logs_in_for_its_own_vncproxy(api, seed, monkeypatch):
    seed.user('root', role='admin')
    mgr = api.set_manager('c1', _PasswordManager())
    fake = _Pve(password_ok=True)
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', fake.opener)
    monkeypatch.setattr(websocket, 'create_connection', fake.create_connection)
    view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__
    with api.app.test_request_context(f'{_PATH}?{_query(False)}'):
        view(_SyncBrowser(), 'c1', 'pve1', 'qemu', 100)
    assert len(fake.logins) == 1
    assert mgr.vncproxy_calls == []
    url, header = fake.upgrades[0]
    assert header.get('Cookie') == 'PVEAuthCookie=PVE:root@pam:FRESH', header
    assert 'Authorization' not in header
    assert 'port=5908' in url


def test_a_token_id_counts_before_the_manager_has_connected():
    """connect_to_proxmox sets _api_token; a console opened before that must not fall
    back to the password login either."""
    m = types.SimpleNamespace(_using_api_token=False, _api_token=None,
                              config=types.SimpleNamespace(user=_ID))
    assert vms._console_uses_token(m) is True
    m.config.user = 'root@pam'
    assert vms._console_uses_token(m) is False
