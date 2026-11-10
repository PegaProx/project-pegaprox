"""The upgrade to PVE's vncwebsocket carries one Host header (#1329).

The console handlers passed {"Host": ...} as an extra header, and websocket-client writes
its own Host line from the URL (or from its host option) before the extra headers, so every
upgrade had two. From libpve-http-server-perl 6.0.6 on, pveproxy answers a repeated Host,
Cookie or Content-Length with 400 "invalid duplicate header", and the console closes right
after it opened.

The handlers run as in test_console_token_cluster_955, and what they hand websocket-client
goes through its own handshake builder, so the lines counted are the lines it would send.
Through the SSH tunnel the connection goes to 127.0.0.1. The polling console and the
screenshot tile name the node in their one Host line, the standalone console names the
tunnel it dials, both as before.
"""
import asyncio
import types

import pytest
import websocket
from websocket._handshake import _get_handshake_headers
from websocket._url import parse_url

from pegaprox.api import vms
from test_console_token_cluster_955 import (  # noqa: F401
    _PATH, _PasswordManager, _PveWs, _SyncBrowser, _TokenManager, _Browser, _query, pve,
    standalone_handler)

NODE = '10.0.0.9:8006'
TUNNEL_PORT = 40123
# what pveproxy takes once only; a second Cookie is refused just like a second Host
UNIQUE = ('host', 'cookie', 'content-length')


def _host_lines(url, options):
    host, port, resource, _ = parse_url(url)
    lines, _ = _get_handshake_headers(resource, url, host, port, dict(options))
    return [line.split(':', 1)[1].strip() for line in lines if line.lower().startswith('host:')]


class _Upgrades(list):
    """The Host lines of each upgrade, and in .repeated the UNIQUE headers that came twice."""
    def __init__(self):
        super().__init__()
        self.repeated = []


@pytest.fixture
def sent(pve, monkeypatch):
    """The Host lines of every upgrade the console makes."""
    out = _Upgrades()
    pve.password_ok = True          # a password cluster logs in for its own vncproxy

    def connect(url, **options):
        out.append(_host_lines(url, options))
        host, port, resource, _ = parse_url(url)
        lines, _ = _get_handshake_headers(resource, url, host, port, dict(options))
        names = [line.split(':', 1)[0].strip().lower() for line in lines[1:]]
        out.repeated += [n for n in UNIQUE if names.count(n) > 1]
        return pve.create_connection(url, **options)
    monkeypatch.setattr(websocket, 'create_connection', connect)
    return out


@pytest.fixture(params=[_TokenManager, _PasswordManager], ids=['token', 'password'])
def cluster(request, api, seed):
    seed.user('root', role='admin')
    return api.set_manager('c1', request.param())


@pytest.fixture
def tunnel(monkeypatch):
    from pegaprox.utils import vnc_tunnel
    monkeypatch.setattr(vms, '_vnc_tunnel_wanted', lambda mgr: True)
    monkeypatch.setattr(vnc_tunnel, 'acquire',
                        lambda **k: types.SimpleNamespace(local_port=TUNNEL_PORT, stop=lambda: None))


def test_the_standalone_console_sends_one_host(cluster, sent, standalone_handler):
    asyncio.run(standalone_handler(_Browser(f'{_PATH}?{_query(False)}')))
    assert sent == [[NODE]] and sent.repeated == []


def test_the_standalone_console_through_the_tunnel_sends_one_host(cluster, sent, standalone_handler, tunnel):
    # it dials the tunnel and takes its Host from that URL, as it did before the fix
    asyncio.run(standalone_handler(_Browser(f'{_PATH}?{_query(False)}')))
    assert sent == [[f'127.0.0.1:{TUNNEL_PORT}']] and sent.repeated == []


def test_the_flask_sock_console_sends_one_host(api, cluster, sent):
    view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__
    with api.app.test_request_context(f'{_PATH}?{_query(False)}'):
        view(_SyncBrowser(), 'c1', 'pve1', 'qemu', 100)
    assert sent == [[NODE]] and sent.repeated == []


def test_the_geventwebsocket_console_sends_one_host(api, cluster, sent):
    with api.app.test_request_context(f'{_PATH}?{_query(False)}'):
        vms.handle_vnc_websocket(_SyncBrowser(), 'c1', 'pve1', 'qemu', 100)
    assert sent == [[NODE]] and sent.repeated == []


def _poll(api):
    from pegaprox.utils import vnc_polling
    r = api.as_user({'username': 'root', 'role': 'admin'}).post(
        '/api/clusters/c1/vms/pve1/qemu/100/vnc-poll', json={'action': 'open'})
    pid = (r.get_json() or {}).get('poll_id')
    if pid:
        vnc_polling.drop(pid)
    assert r.status_code == 200, r.get_json()


def test_the_polling_console_sends_one_host(api, cluster, sent):
    _poll(api)
    assert sent == [[NODE]] and sent.repeated == []


def test_the_polling_console_through_the_tunnel_names_the_node_once(api, cluster, sent, tunnel):
    _poll(api)
    assert sent == [[NODE]] and sent.repeated == []


class _Session:
    def post(self, url, **k):
        return types.SimpleNamespace(status_code=200,
                                     json=lambda: {'data': {'ticket': 'PVEVNC:t', 'port': 5907}})


class _ScreenshotManager(_PasswordManager):
    def mint_console_auth_ticket(self, with_csrf=False):
        return 'PVE:root@pam:TILE', 'csrf'

    def _create_session(self):
        return _Session()


@pytest.mark.parametrize('through_tunnel', [False, True], ids=['direct', 'tunnel'])
def test_the_screenshot_tile_sends_one_host(request, sent, through_tunnel):
    if through_tunnel:
        request.getfixturevalue('tunnel')
    with pytest.raises(Exception):          # the fake socket closes before a frame
        vms._screenshot_via_rfb(_ScreenshotManager(), 'pve1', 'qemu', 100, timeout=1)
    assert sent == [[NODE]] and sent.repeated == []
