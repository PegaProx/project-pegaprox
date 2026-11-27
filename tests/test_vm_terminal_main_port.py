"""The VM terminal (PVE termproxy, xterm.js) is a route of the main port.

It used to live inside the SSH console server on port+2, a script the app wrote to disk
and ran as a subprocess. That script asked the app over HTTP who was calling, on a
loopback URL that was not listening once the app was bound to one LAN address (#957),
and it had to be written somewhere writable that was not the shared temp dir (#958).
Now vms.vm_terminal_websocket_proxy serves it in this process and _terminal_relay moves
the bytes: no script on disk, no call back into the app, and the socket checks the guest
itself where port+2 could only ask for the cluster.

What PVE sees stays what it was: only the cluster's own addresses are dialled (SSRF), TLS
is verified when the cluster says so, the cookie is the cluster account's ticket minted
for this terminal and never anything the browser sent, the handshake and the framing are
pve-xtermjs's, and the vncticket, a live console credential, stays out of the log.

The route runs the way flask-sock calls it, with a fake browser socket, and
websocket.create_connection stands in for PVE.

MK Nov 2026
"""
import ast
import json
import logging
import os
import ssl
import types
from urllib.parse import quote, urlencode

import pytest
import websocket

import pegaprox.globals as ppg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# the cluster account's session ticket, minted for each terminal
TICKET = 'PVE:root@pam:65F00000::sig'
# the termproxy ticket the page got from POST .../termproxy
VNCTICKET = 'PVEVNC:3a5f/term+ticket='
TERM = '/api/clusters/cluster_1/vms/pve2/qemu/100/termwebsocket'
PVE_URL = 'wss://10.0.0.1:8006/api2/json/nodes/pve2/qemu/100/vncwebsocket'
NO_AUTH = 'Console auth unavailable for this cluster (needs user/password auth)'


class _Page:
    """The browser end of a flask-sock socket: sends `incoming` in turn, then goes away.
    idle: that many empty reads first, each one a turn for the relay's reader."""

    def __init__(self, *incoming, idle=0):
        self.incoming = list(incoming)
        self.idle = idle
        self.sent = []
        self.closed = None
        self.connected = True

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        if self.idle:
            import gevent
            self.idle -= 1
            gevent.sleep(0.01)
            return None
        if self.incoming:
            return self.incoming.pop(0)
        self.connected = False
        return None

    def close(self, reason=None, message=None):
        self.closed = (reason, message)
        self.connected = False


class _PVE:
    """PVE's end of the terminal socket: answers the handshake with `first`, then hands out
    `frames` and a close."""

    status = 101

    def __init__(self, first='OK', frames=()):
        self.first = first
        self.frames = list(frames)
        self.sent = []
        self.closed = False
        self.sock = self

    def send(self, data):
        self.sent.append(data)

    def settimeout(self, _t):
        pass

    def setsockopt(self, *_a):
        pass

    def recv(self):
        return self.first

    def pending(self):
        return 1

    def recv_data(self):
        if self.frames:
            return websocket.ABNF.OPCODE_TEXT, self.frames.pop(0)
        return websocket.ABNF.OPCODE_CLOSE, b''

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _let_go():
    """A route run outside a real request keeps its socket counted; give it back."""
    import pegaprox.utils.realtime as rt
    before = set(rt._held_ws)
    yield
    for key in set(rt._held_ws) - before:
        rt.release_websocket(key)


@pytest.fixture
def pve(monkeypatch):
    """Every dial to PVE as (url, keyword arguments). refuse: an exception to raise instead
    of connecting; first/frames: what the PVE socket says."""
    ns = types.SimpleNamespace(dials=[], sockets=[], refuse=None, first='OK', frames=[])

    def create_connection(url, **kw):
        ns.dials.append((url, kw))
        if ns.refuse is not None:
            raise ns.refuse
        sock = _PVE(ns.first, ns.frames)
        ns.sockets.append(sock)
        return sock

    monkeypatch.setattr(websocket, 'create_connection', create_connection)
    return ns


def _cluster(api, host='10.0.0.1', fallback=('10.0.0.12', '10.0.0.13'), api_port=8006,
             verify=False, ticket=TICKET):
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = mgr.config.host = host
    mgr.api_port = api_port
    mgr._ssl_verify = verify
    mgr.config.fallback_hosts = list(fallback)
    mgr.config.name = 'c1'
    mgr.mint_console_auth_ticket.return_value = ticket
    api.set_manager('cluster_1', mgr)
    return mgr


def _token(api, user):
    r = api.as_user(user).post('/api/ws/token', json={})
    assert r.status_code == 200, r.data
    return r.get_json()['token']


def _query(auth, host='10.0.0.1', ticket=VNCTICKET, port='5900', user='root@pam'):
    """auth: 'token=...' or 'session=...', then the termproxy answer the page passes on."""
    return f"{auth}&{urlencode({'ticket': ticket, 'port': port, 'host': host, 'user': user})}"


def _terminal(api, query, *incoming, path=TERM, idle=0):
    """One terminal socket, run as flask-sock runs it. The fake browser socket comes back."""
    view = api.app.view_functions['__flask_sock.vm_terminal_websocket_proxy'].__wrapped__
    parts = path.split('/')
    page = _Page(*incoming, idle=idle)
    with api.app.test_request_context(f'{path}?{query}'):
        view(page, parts[3], parts[5], parts[6], int(parts[7]))
    return page


def _said(page):
    return [json.loads(m) for m in page.sent if isinstance(m, str) and m.startswith('{')]


def _errors(page):
    return [m['message'] for m in _said(page) if m.get('status') == 'error']


def _admin(seed):
    return seed.user('root', role='admin')


# --- #957 and #958: nothing of the subprocess is left ------------------------------------

def test_a_bind_to_one_lan_address_leaves_the_terminal_working(api, seed, pve, monkeypatch):
    """#957. The subprocess validated every terminal against PEGAPROX_URL, pinned to
    127.0.0.1, which is not listening when the app is bound to one LAN address. The route
    asks the app nothing over the network: it is the app."""
    import requests
    monkeypatch.setattr(ppg, 'SERVER_BIND_HOST', '192.168.0.234', raising=False)
    asked = []

    def no_http(self, method, url, *a, **kw):
        asked.append(url)
        raise requests.exceptions.ConnectionError('nothing is listening there')
    monkeypatch.setattr(requests.Session, 'request', no_http)
    _cluster(api)

    page = _terminal(api, _query(f'token={_token(api, _admin(seed))}'))

    assert asked == []
    assert [url.split('?')[0] for url, _kw in pve.dials] == [PVE_URL], _said(page)
    assert {'status': 'connected'} in _said(page), _said(page)


def test_no_script_is_written_or_run():
    """#958. The script had to be written somewhere writable, under a predictable name,
    and executed. vms.py starts no program of its own any more, so nothing of it can be
    planted: it imports no subprocess and names no interpreter to run."""
    with open(os.path.join(ROOT, 'pegaprox', 'api', 'vms.py'), encoding='utf-8') as f:
        tree = ast.parse(f.read())
    imported = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in getattr(n, 'names', [])} | {
        (n.module or '').split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert 'subprocess' not in imported
    runs = [ast.unparse(n) for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr == 'executable'
            and isinstance(n.value, ast.Name) and n.value.id == 'sys']
    assert not runs, runs


# --- the guest, not only the cluster ------------------------------------------------------

def _confined(seed):
    """A viewer whose tenant owns another cluster and who holds a VM ACL on guest 100."""
    seed.tenant('t1', clusters=['other'])
    user = seed.user('ops', role='viewer', tenant_id='t1')
    seed.vm_acl('cluster_1', 100, ['ops'])
    return user


def test_the_terminal_of_another_guest_stays_closed(api, seed, pve):
    """Port+2 asked for the cluster and left the guest to the ticket call. The socket asks
    for the guest itself now: an ACL on 100 opens no terminal on 101."""
    mgr = _cluster(api)
    page = _terminal(api, _query(f'token={_token(api, _confined(seed))}'),
                     path=TERM.replace('/100/', '/101/'))

    assert _errors(page) == ['Permission denied']
    assert page.closed and page.closed[0] == 1008
    assert pve.dials == []
    mgr.mint_console_auth_ticket.assert_not_called()


def test_the_terminal_of_the_own_guest_opens(api, seed, pve):
    """Counterproof: the same account on the guest its ACL names."""
    _cluster(api)
    page = _terminal(api, _query(f'token={_token(api, _confined(seed))}'))

    assert _errors(page) == []
    assert [url.split('?')[0] for url, _kw in pve.dials] == [PVE_URL]


# --- what is dialled ----------------------------------------------------------------------

@pytest.mark.parametrize('host', ['10.9.9.9', '10.0.0.1.evil.example', '127.0.0.1', 'localhost'])
def test_only_an_address_of_the_cluster_is_dialled(api, seed, pve, host):
    """The page names the host (CWE-918). Anything but the cluster's own addresses is
    refused before a ticket is minted for it."""
    mgr = _cluster(api)
    page = _terminal(api, _query(f'token={_token(api, _admin(seed))}', host=host))

    assert _errors(page) == [f"Host {host!r} is not a known node of cluster cluster_1."]
    assert pve.dials == []
    mgr.mint_console_auth_ticket.assert_not_called()


def test_a_fallback_address_of_the_cluster_is_dialled(api, seed, pve):
    """Counterproof: another node of the same cluster, as the page gets it from /termproxy."""
    _cluster(api)
    _terminal(api, _query(f'token={_token(api, _admin(seed))}', host='10.0.0.12'))

    assert [url.split('?')[0] for url, _kw in pve.dials] == [PVE_URL.replace('10.0.0.1:', '10.0.0.12:')]


def test_an_ipv6_address_is_bracketed(api, seed, pve):
    """Otherwise the port reads as part of the address and the URL is unusable."""
    _cluster(api, host='fd00::42', fallback=())
    _terminal(api, _query(f'token={_token(api, _admin(seed))}', host='fd00::42'))

    assert [url.split('?')[0] for url, _kw in pve.dials] == [
        'wss://[fd00::42]:8006/api2/json/nodes/pve2/qemu/100/vncwebsocket']


@pytest.mark.parametrize('verify,sslopt', [(False, {'cert_reqs': ssl.CERT_NONE}), (True, {})])
def test_tls_is_verified_when_the_cluster_says_so(api, seed, pve, verify, sslopt):
    """The per-cluster ssl_verify flag decides, as on every other PVE call. With it on, a
    man in the middle gets neither the console nor the cluster account's ticket."""
    _cluster(api, verify=verify)
    _terminal(api, _query(f'token={_token(api, _admin(seed))}'))

    assert [kw['sslopt'] for _url, kw in pve.dials] == [sslopt]


def test_a_redirect_is_not_followed(api, seed, pve):
    """websocket-client would send the cookie on to wherever a 3xx points."""
    _cluster(api)
    _terminal(api, _query(f'token={_token(api, _admin(seed))}'))

    assert [kw['redirect_limit'] for _url, kw in pve.dials] == [0]


# --- whose credential, which protocol -----------------------------------------------------

@pytest.mark.parametrize('way', ['token', 'session'])
def test_pve_gets_the_minted_ticket_and_the_handshake(api, seed, pve, way):
    """C-1: the cookie is the cluster account's ticket, minted here for this terminal; the
    browser never held it. The termproxy ticket goes into the query and the handshake."""
    mgr = _cluster(api)
    user = _admin(seed)
    auth = f'token={_token(api, user)}' if way == 'token' else f'session={api.as_user(user).session_id}'
    page = _terminal(api, _query(auth))

    (url, kw), = pve.dials
    assert url == f"{PVE_URL}?port=5900&vncticket={quote(VNCTICKET, safe='')}"
    assert kw['header'] == {'Cookie': f'PVEAuthCookie={TICKET}'}
    assert pve.sockets[0].sent[0] == f'root@pam:{VNCTICKET}\n'
    assert mgr.mint_console_auth_ticket.call_count == 1
    assert _said(page)[0] == {'status': 'connected'}


def test_a_refused_handshake_is_said_and_closed(api, seed, pve):
    _cluster(api)
    pve.first = 'permission denied - invalid PVEVNC ticket'
    page = _terminal(api, _query(f'token={_token(api, _admin(seed))}'))

    assert len(_errors(page)) == 1 and _errors(page)[0].startswith('PVE rejected:'), _said(page)
    assert page.closed[0] == 1011 and pve.sockets[0].closed
    assert {'status': 'connected'} not in _said(page)


def test_the_input_is_framed_for_pve(api, seed, pve):
    """"0:<length in UTF-8 bytes>:<data>" for input, "1:<cols>:<rows>:" for a resize."""
    _cluster(api)
    _terminal(api, _query(f'token={_token(api, _admin(seed))}'),
              'ls\n', 'grüß', json.dumps({'type': 'resize', 'cols': 132, 'rows': 40}), b'q')

    assert pve.sockets[0].sent[1:] == ['0:3:ls\n', '0:6:grüß', '1:132:40:', '0:1:q']


def test_the_output_reaches_the_page_as_text(api, seed, pve):
    """PVE's raw TTY bytes go out as text frames, a UTF-8 character split over two of them
    whole."""
    _cluster(api)
    pve.frames = [b'gr\xc3', b'\xbc\xc3\x9f\r\n']
    page = _terminal(api, _query(f'token={_token(api, _admin(seed))}'), idle=5)

    assert page.sent[1:] == ['gr', 'üß\r\n'], page.sent


@pytest.mark.parametrize('override', [
    {'ticket': ''}, {'ticket': 'PVEVNC:a\nb'}, {'port': '0'}, {'port': '70000'}, {'port': 'x'},
    {'user': ''}, {'user': 'root@pam:PVEVNC:other'}, {'user': 'root@pam\n'}, {'host': ''},
])
def test_a_termproxy_answer_that_does_not_add_up_opens_nothing(api, seed, pve, override):
    """The user name and ticket become the handshake line: a colon or a newline in them
    would write another one."""
    mgr = _cluster(api)
    page = _terminal(api, _query(f'token={_token(api, _admin(seed))}', **override))

    assert _errors(page) == ['Missing termproxy params']
    assert pve.dials == []
    mgr.mint_console_auth_ticket.assert_not_called()


# --- the log --------------------------------------------------------------------------------

@pytest.mark.parametrize('refuse', [
    None,
    ConnectionRefusedError(111, 'Connection refused'),
    websocket.WebSocketBadStatusException('Handshake status %d %s', 401, 'permission denied'),
])
def test_neither_ticket_reaches_the_log(api, seed, pve, caplog, refuse):
    """The vncticket is a live console credential and rides in the URL; the cookie is root
    on the cluster. Neither is logged, on a session or on a failed dial, nor told to the
    page in an error."""
    caplog.set_level(logging.DEBUG)
    _cluster(api)
    pve.refuse = refuse
    page = _terminal(api, _query(f'token={_token(api, _admin(seed))}'), 'id\n')

    assert pve.dials, 'the terminal never dialled, so this proves nothing'
    logged = '\n'.join(r.getMessage() for r in caplog.records)
    # the log was read, the terminal's own lines are in it
    assert '[TERMPROXY]' in logged, logged
    for secret in (VNCTICKET, quote(VNCTICKET, safe=''), TICKET):
        assert secret not in logged
        assert not any(secret in m for m in _errors(page))
    if refuse is not None:
        assert _errors(page) == [f'PVE WS connect failed: {type(refuse).__name__}']
        assert page.closed[0] == 1011
