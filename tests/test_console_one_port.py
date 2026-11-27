"""The consoles on the main port (VNC, node shell, VM terminal) and what came with them.

The VM terminal lived inside the SSH console server on port+2, which could only ask
whether the caller may see the cluster and left the guest to the termproxy call. It is a
flask-sock route of the main port now, and it asks for THIS guest before it mints a PVE
cookie or dials anything. Its wire format is pinned against a fake PVE websocket.

Around it: the Connection header repair that used to sit in front of the console ports
(#352) runs before routing now, the legacy ports serve the console paths of the same app
and nothing else, consoles leave the request pool and count on budgets of their own, the
app pings every socket, a federation peer dials the main port, and the browser builds
every console URL from the page's own address.

MK Nov 2026
"""
import json
import logging
import pathlib
import re
import socket
import ssl
import time
import types
from urllib.parse import urlencode

import gevent
import gevent.event
import gevent.pool
import pytest
import websocket
from flask import Flask

import pegaprox.utils.realtime as rtu
from pegaprox.api import vms
from pegaprox.core import federation, ha
from pegaprox.core import federation_relay as relay
from pegaprox.utils import ws_lenient
from pegaprox.utils.realtime import create_ws_token

REPO = pathlib.Path(__file__).resolve().parent.parent

TICKET = 'PVEVNC:abc/def+g=='
COOKIE = 'PVE:root@pam:THE-COOKIE'
TERM_PATH = '/api/clusters/cluster_1/vms/pve1/qemu/100/termwebsocket'


@pytest.fixture
def held(monkeypatch):
    """The socket registries of utils/realtime.py are process state: every test starts
    with none held and no request pool registered."""
    monkeypatch.setattr(rtu, '_held_ws', {})
    monkeypatch.setattr(rtu, '_held_ws_sid', {})
    monkeypatch.setattr(rtu, '_held_consoles', set())
    monkeypatch.setattr(rtu, '_held_bodies', {})
    monkeypatch.setattr(rtu, '_request_pools', [])


# --- the VM terminal route ---------------------------------------------------------------

class _Pve:
    """PVE's vncwebsocket as websocket-client hands it back: answers the `user:ticket`
    line with `answer`, then hands out `frames` and echoes every input frame back as raw
    TTY bytes, cut inside the first multi-byte character as a TLS record may cut it."""
    status = 101

    def __init__(self, url, header, frames, answer):
        self.url, self.header, self.answer = url, dict(header or {}), answer
        self.frames = list(frames)
        self.sent = []
        self.closed = False
        # select() in the relay waits on this; the byte nobody reads keeps it readable
        self.sock, self._peer = socket.socketpair()
        self._peer.send(b'x')

    def settimeout(self, t):
        pass

    def recv(self):
        return self.answer

    def send(self, data):
        self.sent.append(data)
        m = re.match(r'0:(\d+):(.*)\Z', data, re.S) if isinstance(data, str) else None
        if m:
            raw = m.group(2).encode('utf-8')
            cut = next((i + 1 for i, b in enumerate(raw) if b >= 0x80), 1)
            self.frames += [raw[:cut], raw[cut:]]

    def recv_data(self):
        if self.frames:
            return websocket.ABNF.OPCODE_BINARY, self.frames.pop(0)
        gevent.sleep(0.01)
        raise websocket.WebSocketTimeoutException('read slice')

    def close(self):
        self.closed = True

    def dispose(self):
        for s in (self.sock, self._peer):
            try:
                s.close()
            except OSError:
                pass


@pytest.fixture
def pve(monkeypatch):
    """Every PVE websocket the code dials, in `pve.dialled`."""
    state = types.SimpleNamespace(dialled=[], frames=[], answer='OK')

    def create(url, header=None, **kw):
        p = _Pve(url, header, state.frames, state.answer)
        p.kwargs = kw
        state.dialled.append(p)
        return p

    monkeypatch.setattr(websocket, 'create_connection', create)
    yield state
    for p in state.dialled:
        p.dispose()


class _Browser:
    """The flask-sock socket of the page. Hands out `incoming`, then waits until `until`
    holds (or 5 s) and goes away."""

    def __init__(self, incoming=(), until=None):
        self.incoming = list(incoming)
        self.until = until
        self.sent = []
        self.closed = None
        self.connected = True
        self.consoles_seen = None

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        if self.consoles_seen is None:
            self.consoles_seen = rtu.consoles_open()
        if self.incoming:
            return self.incoming.pop(0)
        end = time.monotonic() + 5
        while self.until and not self.until(self) and time.monotonic() < end:
            gevent.sleep(0.01)
        self.connected = False
        return None

    def close(self, reason=None, message=None):
        self.closed = (reason, message)
        self.connected = False

    def text(self):
        return ''.join(s for s in self.sent[1:] if isinstance(s, str))


def _cluster(api, ticket=COOKIE):
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = '10.0.0.5'
    mgr.api_port = 8443
    mgr._ssl_verify = False
    mgr.config = types.SimpleNamespace(fallback_hosts=['10.0.0.6', '2001:db8::6'])
    mgr.mint_console_auth_ticket.return_value = ticket
    return api.set_manager('cluster_1', mgr)


def _token(user, role='admin'):
    return create_ws_token(user, role)


def _query(token, **over):
    q = {'token': token, 'ticket': TICKET, 'port': '5901', 'host': '10.0.0.5', 'user': 'root@pam'}
    q.update(over)
    return {k: v for k, v in q.items() if v is not None}


def _terminal(api, query, vmid=100, node='pve1', vm_type='qemu', browser=None):
    view = api.app.view_functions['__flask_sock.vm_terminal_websocket_proxy'].__wrapped__
    browser = browser or _Browser()
    with api.app.test_request_context(f'{TERM_PATH}?{urlencode(query)}'):
        view(browser, 'cluster_1', node, vm_type, vmid)
    return browser


def _refusal(browser):
    """(message the page shows, close code)."""
    assert browser.sent, 'the terminal neither refused nor opened'
    said = json.loads(browser.sent[0])
    assert said.get('status') == 'error', browser.sent
    return said['message'], (browser.closed or (None,))[0]


def _admin(seed, name='root'):
    seed.user(name, role='admin')
    return name


def test_a_terminal_without_a_token_is_refused(api, seed, held, pve):
    mgr = _cluster(api)
    said, code = _refusal(_terminal(api, _query(None)))
    assert said == 'Authentication required' and code == 1008
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


def test_a_terminal_with_a_forged_token_is_refused(api, seed, held, pve):
    _admin(seed)
    mgr = _cluster(api)
    said, _ = _refusal(_terminal(api, _query('not-a-token')))
    assert said == 'Invalid or expired token'
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


def test_a_spent_token_opens_no_second_terminal(api, seed, held, pve):
    _admin(seed)
    _cluster(api)
    tok = _token('root')
    _terminal(api, _query(tok))
    assert len(pve.dialled) == 1
    said, _ = _refusal(_terminal(api, _query(tok)))
    assert said == 'Invalid or expired token' and len(pve.dialled) == 1


def test_a_disabled_account_opens_no_terminal(api, seed, held, pve):
    """A ws token minted while the account was enabled keeps no terminal after."""
    seed.user('dora', role='admin', enabled=False)
    mgr = _cluster(api)
    said, _ = _refusal(_terminal(api, _query(_token('dora'))))
    assert said in ('Permission denied', 'Authentication required')
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


def _acl_only(seed):
    # alice's tenant has another cluster; she reaches cluster_1 through the ACL of VM 100
    # alone, so the cluster gate lets her in and only the guest gate tells 100 from 101
    seed.tenant('tenant_iso', clusters=['cluster_other'])
    seed.user('alice', role='user', tenant_id='tenant_iso', permissions=['vm.console'])
    seed.vm_acl('cluster_1', 100, users=['alice'], inherit_role=True)
    return 'alice'


def test_the_terminal_of_a_guest_the_user_may_not_reach_is_refused(api, seed, held, pve):
    """Port+2 asked for the cluster only. The main-port route asks for the guest, before a
    PVE cookie is minted for it."""
    alice = _acl_only(seed)
    mgr = _cluster(api)
    said, code = _refusal(_terminal(api, _query(_token(alice, 'user')), vmid=101))
    assert said == 'Permission denied' and code == 1008
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


def test_the_terminal_of_her_own_guest_opens(api, seed, held, pve):
    alice = _acl_only(seed)
    _cluster(api)
    _terminal(api, _query(_token(alice, 'user')), vmid=100)
    assert len(pve.dialled) == 1
    assert '/nodes/pve1/qemu/100/vncwebsocket' in pve.dialled[0].url


def test_a_standby_opens_no_terminal_and_spends_no_token(api, seed, held, pve, monkeypatch):
    """#625 - keyboard on a guest is the active's to hand out, refused before the token."""
    _admin(seed)
    mgr = _cluster(api)
    monkeypatch.setattr(ha, 'consoles_here', lambda: False)
    tok = _token('root')
    said, _ = _refusal(_terminal(api, _query(tok)))
    assert said == vms.STANDBY_CONSOLE_ERROR
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called
    assert tok in rtu.ws_tokens, 'the standby spent the token of a console it did not open'


@pytest.mark.parametrize('node, vm_type', [
    ('..', 'qemu'), ('-pve', 'qemu'), ('pve_1', 'qemu'), ('p' * 64, 'qemu'),
    ('pve 1', 'qemu'), ('pve1', 'openvz'), ('pve1', '..'),
])
def test_a_node_or_type_that_is_no_path_segment_of_pve_is_refused(api, seed, held, pve,
                                                                   node, vm_type):
    _admin(seed)
    mgr = _cluster(api)
    said, _ = _refusal(_terminal(api, _query(_token('root')), node=node, vm_type=vm_type))
    assert said == 'Invalid node or vm_type'
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


def test_a_terminal_of_an_unknown_cluster_is_refused(api, seed, held, pve):
    _admin(seed)
    said, _ = _refusal(_terminal(api, _query(_token('root'))))
    assert said == 'Cluster not found' and pve.dialled == []


@pytest.mark.parametrize('over', [
    {'ticket': None}, {'ticket': ''}, {'ticket': 'PVEVNC:a\r\nX-Injected: 1'},
    {'port': None}, {'port': 'abc'}, {'port': '0'}, {'port': '70000'}, {'port': '59 01'},
    {'host': None}, {'host': ''},
    {'user': None}, {'user': 'root@pam:x'}, {'user': 'root@pam\n'}, {'user': 'root\x00'},
], ids=lambda o: repr(o))
def test_missing_or_garbage_termproxy_params_are_refused(api, seed, held, pve, over):
    _admin(seed)
    mgr = _cluster(api)
    said, _ = _refusal(_terminal(api, _query(_token('root'), **over)))
    assert said == 'Missing termproxy params'
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


@pytest.mark.parametrize('host', ['169.254.169.254', '127.0.0.1', '10.0.0.50', 'evil.example',
                                  '10.0.0.5:22'])
def test_the_terminal_dials_no_host_outside_the_cluster(api, seed, held, pve, host):
    """CWE-918 - the page names the host; only the cluster's own addresses are dialled."""
    _admin(seed)
    mgr = _cluster(api)
    said, _ = _refusal(_terminal(api, _query(_token('root'), host=host)))
    assert 'is not a known node of cluster' in said
    assert pve.dialled == [] and not mgr.mint_console_auth_ticket.called


@pytest.mark.parametrize('host, netloc', [('10.0.0.6', '10.0.0.6'),
                                          ('2001:db8::6', '[2001:db8::6]')])
def test_a_fallback_host_of_the_cluster_is_dialled(api, seed, held, pve, host, netloc):
    _admin(seed)
    _cluster(api)
    _terminal(api, _query(_token('root'), host=host))
    assert len(pve.dialled) == 1
    assert pve.dialled[0].url.startswith(f'wss://{netloc}:8443/')


@pytest.mark.parametrize('verify, sslopt', [(False, {'cert_reqs': ssl.CERT_NONE}), (True, {})])
def test_the_terminal_checks_the_pve_certificate_when_the_cluster_asks(api, seed, held, pve,
                                                                      verify, sslopt):
    """The cookie it sends is a PVE session: with ssl_verification on, a MitM between this
    instance and PVE must not get it."""
    _admin(seed)
    mgr = _cluster(api)
    mgr._ssl_verify = verify
    _terminal(api, _query(_token('root')))
    assert pve.dialled[0].kwargs.get('sslopt') == sslopt


def test_a_token_only_cluster_refuses_the_terminal_with_the_reason(api, seed, held, pve):
    """termproxy needs a PVE session cookie, and a cluster on an API token has none to mint."""
    _admin(seed)
    _cluster(api, ticket=None)
    said, code = _refusal(_terminal(api, _query(_token('root'))))
    assert said == 'Console auth unavailable for this cluster (needs user/password auth)'
    assert code == 1011 and pve.dialled == []


def test_a_cookie_that_cannot_be_minted_refuses_the_terminal(api, seed, held, pve):
    _admin(seed)
    mgr = _cluster(api)
    mgr.mint_console_auth_ticket.side_effect = OSError('pve unreachable')
    said, code = _refusal(_terminal(api, _query(_token('root'))))
    assert 'needs user/password auth' in said and code == 1011 and pve.dialled == []


def test_a_full_instance_refuses_the_terminal_before_dialling(api, seed, held, pve, monkeypatch):
    _admin(seed)
    _cluster(api)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 0)
    said, code = _refusal(_terminal(api, _query(_token('root'))))
    assert said == vms.CONSOLES_FULL_ERROR and code == 1013 and pve.dialled == []


def test_a_handshake_pve_refuses_ends_the_terminal(api, seed, held, pve):
    _admin(seed)
    _cluster(api)
    pve.answer = 'NO'
    said, code = _refusal(_terminal(api, _query(_token('root'))))
    assert said.startswith('PVE rejected') and code == 1011
    assert pve.dialled[0].closed


def test_the_terminal_speaks_the_termproxy_protocol(api, seed, held, pve):
    """The URL on the cluster's API port with the ticket quoted, the cookie minted here,
    the `user:ticket` line, input framed by its UTF-8 length, resize without a body, and
    a character PVE split over two frames reaches the page whole."""
    _admin(seed)
    _cluster(api)
    pve.frames = [b'caf\xc3', b'\xa9 ok\r\n']
    typed = 'ls ä€\r'
    browser = _Browser(incoming=[typed, '{"type":"resize","cols":120,"rows":40}', b'pwd\n'],
                       until=lambda b: b.text().endswith('pwd\n'))
    _terminal(api, _query(_token('root')), browser=browser)

    assert len(pve.dialled) == 1
    p = pve.dialled[0]
    assert p.url == ('wss://10.0.0.5:8443/api2/json/nodes/pve1/qemu/100/vncwebsocket'
                     '?port=5901&vncticket=PVEVNC%3Aabc%2Fdef%2Bg%3D%3D')
    assert p.header == {'Cookie': f'PVEAuthCookie={COOKIE}'}
    assert p.kwargs.get('redirect_limit') == 0
    assert p.sent[0] == f'root@pam:{TICKET}\n'
    assert p.sent[1:] == [f'0:{len(typed.encode("utf-8"))}:{typed}', '1:120:40:', '0:4:pwd\n']
    assert p.sent[1].startswith('0:9:')
    assert p.closed

    assert browser.sent[0] == '{"status":"connected"}'
    assert browser.text() == 'café ok\r\n' + typed + 'pwd\n', browser.sent
    assert not any('�' in s for s in browser.sent if isinstance(s, str)), browser.sent
    # it was held as a console while it ran
    assert browser.consoles_seen == 1


# --- the Connection header repair (#352) -------------------------------------------------

_KEY = 'dGhlIHNhbXBsZSBub25jZQ=='


def _upgrade_environ(**over):
    env = {'HTTP_UPGRADE': 'websocket', 'HTTP_SEC_WEBSOCKET_KEY': _KEY,
           'HTTP_CONNECTION': 'keep-alive', 'REMOTE_ADDR': '192.0.2.7'}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


@pytest.mark.parametrize('conn, fixed', [('keep-alive', 'keep-alive, Upgrade'),
                                         (None, 'Upgrade'), ('', 'Upgrade'),
                                         ('close', 'close, Upgrade')])
def test_a_stripped_upgrade_token_is_put_back(conn, fixed):
    env = _upgrade_environ(HTTP_CONNECTION=conn)
    assert ws_lenient.repair_upgrade_environ(env) is True
    assert env['HTTP_CONNECTION'] == fixed


@pytest.mark.parametrize('conn', ['keep-alive, Upgrade', 'Upgrade', 'upgrade', 'UPGRADE, keep-alive'])
def test_a_correct_connection_header_is_left_alone(conn):
    env = _upgrade_environ(HTTP_CONNECTION=conn)
    assert ws_lenient.repair_upgrade_environ(env) is False
    assert env['HTTP_CONNECTION'] == conn


@pytest.mark.parametrize('over', [{'HTTP_UPGRADE': None}, {'HTTP_UPGRADE': 'h2c'},
                                  {'HTTP_SEC_WEBSOCKET_KEY': None},
                                  {'HTTP_SEC_WEBSOCKET_KEY': ''}])
def test_what_is_no_websocket_upgrade_is_not_touched(over):
    """Only Connection is fragile by proxy; the key and the Upgrade header still matter."""
    env = _upgrade_environ(**over)
    assert ws_lenient.repair_upgrade_environ(env) is False
    assert env['HTTP_CONNECTION'] == 'keep-alive'


def test_the_wrapper_hands_the_repaired_environ_on():
    seen = []

    def inner(environ, start_response):
        seen.append(environ.get('HTTP_CONNECTION'))
        return [b'ok']

    assert ws_lenient.LenientUpgrade(inner)(_upgrade_environ(), lambda *a: None) == [b'ok']
    assert seen == ['keep-alive, Upgrade']


_CONSOLE_RULES = [
    ('/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket', '__flask_sock.vnc_websocket_proxy'),
    (TERM_PATH, '__flask_sock.vm_terminal_websocket_proxy'),
    ('/api/clusters/cluster_1/nodes/pve1/shellws', '__flask_sock.node_shell_websocket_proxy'),
]


@pytest.fixture
def which_rule(api, monkeypatch):
    """The real app with its console views (the sock routes and the 426 one) swapped for
    stand-ins that say which of them the request was routed to."""
    names = [r for _, r in _CONSOLE_RULES] + ['vms.vnc_websocket_route']
    assert all(n in api.app.view_functions for n in names), \
        [n for n in names if n not in api.app.view_functions]
    for name in names:
        monkeypatch.setitem(api.app.view_functions, name, lambda _n=name, **kw: (_n, 200))

    def get(path, connection):
        return api.anon().get(path, headers={
            'Upgrade': 'websocket', 'Connection': connection,
            'Sec-WebSocket-Key': _KEY, 'Sec-WebSocket-Version': '13'})
    return get


@pytest.mark.parametrize('path, rule', _CONSOLE_RULES)
def test_an_upgrade_without_its_token_reaches_the_websocket_rule(which_rule, path, rule):
    """Werkzeug routes to a websocket rule only when Connection carries `upgrade`: without
    the repair the VNC console got the 426 of the HTTP rule and the shell and terminal no
    socket at all."""
    r = which_rule(path, 'keep-alive')
    assert r.status_code == 200 and r.get_data(as_text=True) == rule, \
        (r.status_code, r.get_data(as_text=True)[:200])


@pytest.mark.parametrize('path, rule', _CONSOLE_RULES)
def test_a_proper_upgrade_reaches_the_websocket_rule(which_rule, path, rule):
    r = which_rule(path, 'keep-alive, Upgrade')
    assert r.get_data(as_text=True) == rule


def test_a_plain_get_of_the_vnc_path_still_gets_the_http_rule(which_rule, api):
    r = api.anon().get(_CONSOLE_RULES[0][0])
    assert r.get_data(as_text=True) == 'vms.vnc_websocket_route'


# --- the legacy console ports ------------------------------------------------------------

def _through_legacy(path, peer='192.0.2.9'):
    import pegaprox.app as app_mod
    reached = []

    def inner(environ, start_response):
        reached.append(environ['PATH_INFO'])
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'app']

    status = []
    body = app_mod._ConsolePathsOnly(inner, 5001)(
        {'PATH_INFO': path, 'REMOTE_ADDR': peer, 'REQUEST_METHOD': 'GET',
         'HTTP_UPGRADE': 'websocket'},
        lambda s, h: status.append(s))
    return status[0], b''.join(body), reached


@pytest.mark.parametrize('path', [
    '/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket',
    '/api/clusters/c-2/vms/node.a-1/lxc/101/termwebsocket',
    '/api/clusters/cluster_1/nodes/pve1/shellws',
])
def test_a_legacy_port_passes_the_console_paths(path):
    status, body, reached = _through_legacy(path)
    assert status.startswith('200') and body == b'app' and reached == [path]


@pytest.mark.parametrize('path', [
    '/', '', '/api/clusters', '/api/auth/login', '/api/ws/updates', '/api/federation/console',
    '/api/clusters/cluster_1/vms/pve1/qemu/100/vnc-poll',
    '/api/clusters/cluster_1/vms/pve1/qemu/100/start',
    '/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket/../../../../../auth/login',
    '/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket/extra',
    '/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocketx',
    '/x/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket',
    '/api/clusters/cluster_1/vms/pve1/qemu/abc/vncwebsocket',
    '/api/clusters/cluster_1/vms/pve1/openvz/100/vncwebsocket',
    '/api/clusters/cluster_1/vms/pve1/qemu/100/termwebsocket/',
    '/api/clusters/cluster_1/nodes/pve1/shell',
    '/api/clusters/cluster_1/nodes/pve1/shellws/x',
    '/api/clusters/cluster_1/nodes/../../users/shellws',
    '/api/clusters//nodes/pve1/shellws',
])
def test_a_legacy_port_answers_nothing_else(path):
    status, body, reached = _through_legacy(path)
    assert status.startswith('404') and reached == [], (path, status)
    assert b'only answers consoles' in body


def test_a_legacy_port_passes_no_path_with_a_trailing_newline():
    """A '$' also matches before a trailing newline, and PATH_INFO carries one for %0A:
    the filter takes the whole path or nothing."""
    status, _, reached = _through_legacy('/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket\n')
    assert status.startswith('404') and reached == []


@pytest.mark.parametrize('method', ['POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', ''])
def test_a_legacy_port_takes_nothing_but_a_get(method):
    """A websocket upgrade is a GET. A POST of the VNC path would reach the guest action
    route of the main app (vm_action_api) on a port that is there for consoles only."""
    import pegaprox.app as app_mod
    reached = []
    status = []
    body = app_mod._ConsolePathsOnly(lambda e, s: reached.append(1) or [b'app'], 5001)(
        {'PATH_INFO': '/api/clusters/cluster_1/vms/pve1/qemu/100/vncwebsocket',
         'REMOTE_ADDR': '192.0.2.1', 'REQUEST_METHOD': method, 'HTTP_UPGRADE': 'websocket'},
        lambda s, h: status.append(s))
    assert status[0].startswith('404') and reached == [] and b'only answers consoles' in b''.join(body)


@pytest.mark.parametrize('upgrade', [None, '', 'h2c'])
def test_a_legacy_port_takes_no_plain_get(upgrade):
    """The VNC path is also the HTTP rule of the main app that answers 426; a GET that asks
    for no websocket has nothing to do on a console port."""
    import pegaprox.app as app_mod
    env = {'PATH_INFO': '/api/clusters/cluster_1/nodes/pve1/shellws', 'REMOTE_ADDR': '192.0.2.1',
           'REQUEST_METHOD': 'GET'}
    if upgrade is not None:
        env['HTTP_UPGRADE'] = upgrade
    reached, status = [], []
    app_mod._ConsolePathsOnly(lambda e, s: reached.append(1) or [b'app'], 5002)(
        env, lambda s, h: status.append(s))
    assert status[0].startswith('404') and reached == []


def test_a_legacy_port_notes_a_client_once(caplog):
    import pegaprox.app as app_mod
    wrapped = app_mod._ConsolePathsOnly(lambda e, s: [b''], 5002)
    env = {'PATH_INFO': '/api/clusters/c/nodes/pve1/shellws', 'REMOTE_ADDR': '192.0.2.10',
           'REQUEST_METHOD': 'GET', 'HTTP_UPGRADE': 'websocket'}
    with caplog.at_level(logging.INFO):
        for _ in range(3):
            wrapped(dict(env), lambda *a: None)
        wrapped(dict(env, REMOTE_ADDR='192.0.2.11'), lambda *a: None)
    notes = [r.getMessage() for r in caplog.records if 'legacy port 5002' in r.getMessage()]
    assert len(notes) == 2, notes


@pytest.mark.parametrize('value, on', [(None, True), ('1', True), ('yes', True), ('true', True),
                                       ('0', False), ('false', False), ('no', False),
                                       ('off', False), (' OFF ', False), ('False', False)])
def test_the_legacy_ports_can_be_turned_off(monkeypatch, value, on):
    import pegaprox.app as app_mod
    if value is None:
        monkeypatch.delenv('PEGAPROX_LEGACY_CONSOLE_PORTS', raising=False)
    else:
        monkeypatch.setenv('PEGAPROX_LEGACY_CONSOLE_PORTS', value)
    assert app_mod.legacy_console_ports_on() is on


def test_the_legacy_path_pattern_takes_the_whole_path():
    """The filter matches the whole path (fullmatch), so neither end can carry more."""
    import pegaprox.app as app_mod
    pat = app_mod._CONSOLE_PATHS
    assert pat.fullmatch('/api/clusters/c/nodes/n/shellws')
    assert not pat.fullmatch('/api/clusters/c/nodes/n/shellws/more')
    assert not pat.fullmatch('/prefix/api/clusters/c/nodes/n/shellws')
    assert not pat.fullmatch('/api/clusters/c/nodes/n/shellws\n')
    src = open(app_mod.__file__).read()
    assert '_CONSOLE_PATHS.fullmatch(' in src and '_CONSOLE_PATHS.match(' not in src


# --- console budgets ---------------------------------------------------------------------

class _Sock:
    """A simple-websocket socket as far as _hang_up looks: .sock."""

    def __init__(self):
        self.sock, self.client = socket.socketpair()
        self.client.setblocking(False)

    def hung_up(self):
        try:
            return self.client.recv(1) == b''
        except BlockingIOError:
            return False

    def dispose(self):
        self.sock.close()
        self.client.close()


@pytest.fixture
def socks():
    made = []

    def make():
        s = _Sock()
        made.append(s)
        return s
    yield make
    for s in made:
        s.dispose()


_tiny = Flask('console-budgets')


def _hold(user, ws, console, sid=None):
    with _tiny.test_request_context('/'):
        return rtu.hold_websocket(user, ws, sid=sid, console=console)


def test_consoles_of_an_account_past_its_cap_hang_up_the_oldest(held, socks, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 2)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 100)
    a, b, c = socks(), socks(), socks()
    assert _hold('alice', a, True) and _hold('alice', b, True)
    assert _hold('alice', c, True)
    assert a.hung_up(), 'the oldest console of the account is still open past the cap'
    assert not b.hung_up() and not c.hung_up()
    assert rtu.consoles_open() == 2


def test_consoles_do_not_count_against_the_socket_cap(held, socks, monkeypatch):
    """Several console tabs must not hang up the live-update socket of the same account."""
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 1)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 5)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 100)
    live = socks()
    assert _hold('alice', live, False)
    consoles = [socks() for _ in range(4)]
    for c in consoles:
        assert _hold('alice', c, True)
    assert not live.hung_up(), 'consoles hung up the live-update socket'
    assert not any(c.hung_up() for c in consoles)


def test_live_sockets_do_not_hang_up_consoles(held, socks, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 1)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 5)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 100)
    consoles = [socks(), socks()]
    for c in consoles:
        _hold('alice', c, True)
    first, second = socks(), socks()
    _hold('alice', first, False)
    _hold('alice', second, False)
    assert first.hung_up() and not second.hung_up()
    assert not any(c.hung_up() for c in consoles), 'a live-update socket hung up a console'
    assert rtu.consoles_open() == 2


def test_a_full_instance_refuses_the_new_console_and_hangs_up_nobody(held, socks, monkeypatch):
    """Instance-wide the new one is refused, not somebody else's hung up."""
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 5)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 2)
    a, b = socks(), socks()
    assert _hold('alice', a, True) is True
    assert _hold('bob', b, True) is True
    late = socks()
    assert _hold('carol', late, True) is False
    assert not any(s.hung_up() for s in (a, b, late))
    assert rtu.consoles_open() == 2
    held_ws = [ws for _, ws in rtu._held_ws.values()]
    assert late not in held_ws


def test_a_full_instance_lets_an_account_replace_its_own_console(held, socks, monkeypatch):
    """A reconnect is never refused because of the dead socket the account left behind:
    on a full instance its own oldest console makes room, nobody else's."""
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', 5)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 2)
    a, b, again = socks(), socks(), socks()
    assert _hold('alice', a, True) is True
    assert _hold('bob', b, True) is True
    assert _hold('alice', again, True) is True
    assert a.hung_up() and not b.hung_up() and not again.hung_up()
    assert rtu.consoles_open() == 2


def test_a_full_instance_still_takes_a_live_socket(held, socks, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 1)
    _hold('alice', socks(), True)
    assert _hold('bob', socks(), False) is True


def test_a_released_console_frees_its_slot(held, socks, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 1)
    with _tiny.test_request_context('/'):
        assert rtu.hold_websocket('alice', socks(), console=True)
        assert rtu.consoles_open() == 1
        _tiny.process_response(_tiny.response_class())     # the route returned
    assert rtu.consoles_open() == 0
    assert _hold('bob', socks(), True) is True


def test_a_session_that_ends_hangs_up_its_consoles(held, socks, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 100)
    mine, other = socks(), socks()
    _hold('alice', mine, True, sid='s-gone')
    _hold('alice', other, True, sid='s-kept')
    rtu.end_session_channels('alice', sids={'s-gone'})
    assert mine.hung_up(), 'the console of an ended session is still open'
    assert not other.hung_up()
    assert rtu.consoles_open() == 1


def test_a_slow_body_does_not_count_consoles(held, socks, monkeypatch):
    monkeypatch.setattr(rtu, 'MAX_WS_PER_USER', 2)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 100)
    for _ in range(5):
        _hold('alice', socks(), True)
    key = rtu.hold_body('alice')
    assert key is not None, 'consoles took the slow-body budget'
    rtu.release_body(key)
    _hold('alice', socks(), False)
    _hold('alice', socks(), False)
    assert rtu.hold_body('alice') is None


# --- a console leaves the request pool ---------------------------------------------------

def _in_pool(pool, body):
    """Run body() in a greenlet of `pool`; what it returns and the greenlet."""
    out = {}
    go = gevent.event.Event()

    def run():
        out['value'] = body()
        go.wait(5)

    g = pool.spawn(run)
    for _ in range(200):
        if 'value' in out:
            break
        gevent.sleep(0.01)
    return out, g, go


def test_a_console_gives_its_request_slot_back(held):
    pool = gevent.pool.Pool(2)
    rtu.register_request_pool(pool)

    def body():
        me = gevent.getcurrent()
        before = (me in pool, pool.free_count())
        left = rtu._leave_request_pool()
        return before, left, me in pool, pool.free_count()

    out, g, go = _in_pool(pool, body)
    before, left, still_in, free_after = out['value']
    assert before == (True, 1)
    assert left is True and not still_in and free_after == 2
    # the slot is really free: two more requests fit while the console still runs
    blockers = [gevent.Greenlet(gevent.sleep, 5) for _ in range(2)]
    for b in blockers:
        pool.add(b, blocking=False)
    with pytest.raises(gevent.pool.PoolFull):
        pool.add(gevent.Greenlet(gevent.sleep, 5), blocking=False)
    for b in blockers:
        b.kill()
    go.set()
    g.join(5)
    assert g.dead
    # and the end of the console releases nothing a second time
    assert pool._semaphore.counter == 2
    more = [gevent.Greenlet(gevent.sleep, 5) for _ in range(2)]
    for b in more:
        pool.add(b, blocking=False)
    with pytest.raises(gevent.pool.PoolFull):
        pool.add(gevent.Greenlet(gevent.sleep, 5), blocking=False)
    for b in more:
        b.kill()
    assert pool.free_count() <= pool.size


def test_a_greenlet_of_no_pool_leaves_nothing(held):
    rtu.register_request_pool(gevent.pool.Pool(2))
    assert rtu._leave_request_pool() is False


@pytest.mark.parametrize('console', [True, False])
def test_only_a_console_leaves_the_pool(held, socks, monkeypatch, console):
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 100)
    pool = gevent.pool.Pool(4)
    rtu.register_request_pool(pool)
    ws = socks()

    def body():
        _hold('alice', ws, console)
        return gevent.getcurrent() in pool

    out, g, go = _in_pool(pool, body)
    assert out['value'] is (not console)
    go.set()
    g.join(5)
    assert pool._semaphore.counter == 4


def test_a_console_the_instance_refuses_keeps_its_slot(held, socks, monkeypatch):
    """It is about to be closed; it leaves the pool by ending."""
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', 0)
    pool = gevent.pool.Pool(4)
    rtu.register_request_pool(pool)
    ws = socks()
    out, g, go = _in_pool(pool, lambda: (_hold('alice', ws, True), gevent.getcurrent() in pool))
    assert out['value'] == (False, True)
    go.set()
    g.join(5)
    assert pool._semaphore.counter == 4


# --- the app pings every socket ----------------------------------------------------------

def test_the_app_pings_its_sockets_no_faster_than_a_hub_may_stall(api):
    """The console ports pinged every 30 s. simple-websocket hangs up when the pong is not
    back by the next ping, so a shorter interval would end consoles on a busy hub."""
    opts = api.app.config.get('SOCK_SERVER_OPTIONS') or {}
    interval = opts.get('ping_interval')
    assert isinstance(interval, (int, float)) and not isinstance(interval, bool), opts
    assert interval >= 30, opts


# --- federation ---------------------------------------------------------------------------

def test_the_console_token_says_the_consoles_are_on_one_port(api, seed, monkeypatch):
    from pegaprox.utils.auth import RELAY_ENVIRON
    _admin(seed)
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    monkeypatch.delenv('PEGAPROX_BEHIND_PROXY', raising=False)
    client = api.as_user({'username': 'root', 'role': 'admin'})
    r = client.post('/api/clusters/cluster_1/console-token', json={},
                    environ_base={RELAY_ENVIRON: {'session': client.session_id, 'site': 'a',
                                                  'home': 'h' * 32, 'sh': 'x'}})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    got = r.get_json()
    assert got['single_port'] is True
    assert got['reverse_proxy'] is False and got['token']


def test_the_console_token_route_still_answers_relayed_requests_only(api, seed):
    _admin(seed)
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    r = api.as_user({'username': 'root', 'role': 'admin'}).post(
        '/api/clusters/cluster_1/console-token', json={})
    assert r.status_code == 404 and r.get_json()['code'] == 'FED_RELAY_ONLY'


class _Dialled(Exception):
    pass


@pytest.mark.parametrize('url, kind, main_port, port', [
    ('https://b.example:5000', 'vnc', True, 5000),
    ('https://b.example:5000', 'shell', True, 5000),
    ('https://b.example:5000', 'term', True, 5000),
    ('https://b.example:5000', 'vnc', False, 5001),
    ('https://b.example:5000', 'shell', False, 5002),
    ('https://b.example:5000', 'term', False, 5002),
    ('https://b.example', 'vnc', True, 443),
    ('https://b.example', 'vnc', False, 444),
])
def test_a_site_is_dialled_on_the_port_it_serves_consoles_on(monkeypatch, url, kind, main_port, port):
    dialled = []

    def connect(addr, timeout=None, **kw):
        dialled.append(addr)
        raise _Dialled()

    monkeypatch.setattr(socket, 'create_connection', connect)
    monkeypatch.setattr(federation, '_url_ok', lambda u: True)
    with pytest.raises(_Dialled):
        relay.open_console({'url': url}, kind, '/api/clusters/pve1/nodes/n1/shellws',
                           'token=t', main_port)
    assert dialled == [('b.example', port)]


# --- the browser builds every console URL from its own address ---------------------------

def _code(path):
    """The source without its comments: full-line // comments and ` // ` tails (a URL's
    `//` sits between a protocol and `${`, never between spaces)."""
    text = (REPO / path).read_text(encoding='utf-8')
    text = re.sub(r'(?m)^\s*//.*$', '', text)
    text = re.sub(r'\s//\s.*$', '', text, flags=re.M)
    return text


_FRONTENDS = ['web/src/node_modals.js', 'plugins/client_portal/portal.html']
_CONSOLE_URL = re.compile(r'`[^`]*/(?:vncwebsocket|termwebsocket|shellws)\b[^`]*`')


@pytest.mark.parametrize('path, count', [('web/src/node_modals.js', 3),
                                         ('plugins/client_portal/portal.html', 1)])
def test_every_console_socket_url_is_the_pages_own_address(path, count):
    urls = _CONSOLE_URL.findall(_code(path))
    assert len(urls) == count, urls
    for u in urls:
        assert re.match(r'`\$\{\w+\}//\$\{window\.location\.host\}/api/clusters/', u), u


@pytest.mark.parametrize('path', _FRONTENDS)
def test_no_console_port_of_its_own_is_left(path):
    code = _code(path)
    assert not re.search(r'[pP]ort(?:Num)?\)?\s*\+\s*[12]\b', code), \
        re.search(r'.{0,80}[pP]ort(?:Num)?\)?\s*\+\s*[12]\b.{0,40}', code).group(0)
    assert 'window.location.hostname' not in code
    assert 'wsPort' not in code


def test_the_stable_mode_poll_url_is_not_prefixed_twice():
    """API_URL carries the origin: prefixed again it was https://h:5000https://h:5000/api/..."""
    code = _code('web/src/node_modals.js')
    m = re.search(r'const pollUrl = `([^`]*)`', code)
    assert m, 'no pollUrl in the console modal'
    assert m.group(1).startswith('${API_URL}/clusters/'), m.group(1)
    assert not re.search(r'location\.(?:host|protocol)\}?\$\{API_URL\}', code)
    assert 'window.location.origin' in (REPO / 'web/src/constants.js').read_text(encoding='utf-8')
