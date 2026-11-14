"""cluster-creds answers the SSH console server only, and the node shell route keeps the
cluster account's session to itself.

GET /api/internal/cluster-creds/<cluster> has one caller, the SSH console server this
process starts: the legacy ?session= login of its node shell takes the node addresses
from it, its guest terminal (PVE termproxy) the allow-list and a fresh PVE ticket of the
cluster account. Nothing in the page or a plugin calls it. It now asks the same proof
/api/ws/token/validate asks before it hands out a cluster context, the per-start secret
the console server gets in its environment, and the console server sends it on both
calls. The checks behind it (node.shell, unconfined, SSH switch) run as before.

POST /api/clusters/<cluster>/nodes/<node>/shell put the manager's own PVEAuthCookie into
its answer. Nobody read it; the VNC and term tickets dropped theirs long ago.

The script of the console server runs here with its calls answered by the real app, as
in test_node_shell_ssh_switch. paramiko stops at the connect, the PVE socket likewise.

MK Nov 2026
"""
import asyncio
import json
import types

import pytest

from test_ha_v2_surface import _Resp, _ssh_server
from test_node_shell_target_1143 import _Talking, _let_go, _token  # noqa: F401
from test_node_shell_ssh_switch import APP, OFF, SHELL, TERM, _cluster, dialled  # noqa: F401

TICKET = 'PVE:root@pam:65F00000::sig'
CREDS = '/api/internal/cluster-creds/cluster_1'


def _proof():
    from pegaprox.api.realtime import CONSOLE_SERVER_HEADER, console_server_secret
    return {CONSOLE_SERVER_HEADER: console_server_secret()}


def _creds(api, user, query='', headers=None):
    """cluster-creds the way the console server calls it: the browser's session as the
    cookie `session`, plus whatever headers it sends."""
    client = api.app.test_client()
    client.set_cookie('session', api.as_user(user).session_id, domain='localhost')
    return client.get(CREDS + query, headers=headers or {}, base_url='http://localhost')


def _operator(seed):
    """node.shell on a cluster its tenant owns, no VM ACL or pool: a node shell is his."""
    seed.tenant('t3', clusters=['cluster_1'])
    return seed.user('opr', role='viewer', tenant_id='t3', permissions=['node.shell'])


def _admin(seed):
    return seed.user('root', role='admin')


# --- a browser session --------------------------------------------------------------------

@pytest.mark.parametrize('query', ['', '?console=term', '?node=pve2'])
@pytest.mark.parametrize('make', [_admin, _operator], ids=['admin', 'operator'])
def test_a_browser_session_gets_nothing_from_cluster_creds(api, seed, query, make):
    mgr = _cluster(api, ssh_off=False)
    r = _creds(api, make(seed), query)
    assert r.status_code == 403, r.data
    body = r.get_json()
    assert body['code'] == 'CONSOLE_SERVER_ONLY', body
    assert 'node_ips' not in body and 'pve_auth_ticket' not in body
    assert TICKET not in r.get_data(as_text=True)
    # nothing was looked up or minted for it
    mgr.mint_console_auth_ticket.assert_not_called()
    mgr._get_node_ip.assert_not_called()


def test_a_wrong_or_empty_proof_is_no_proof(api, seed, monkeypatch):
    from pegaprox.api import realtime
    from pegaprox.api.realtime import CONSOLE_SERVER_HEADER
    mgr = _cluster(api, ssh_off=False)
    user = _admin(seed)
    right = _proof()[CONSOLE_SERVER_HEADER]
    for wrong in ('', ' ', 'x' * len(right), right[:-1] + '?', right + 'x', right.lower()):
        if wrong == right:
            continue
        r = _creds(api, user, headers={CONSOLE_SERVER_HEADER: wrong})
        assert r.status_code == 403 and 'pve_auth_ticket' not in r.get_json(), repr(wrong)
    # and a process without a secret matches nothing, an empty header least of all
    monkeypatch.setattr(realtime, '_CONSOLE_SERVER_SECRET', '')
    for sent in ('', right):
        r = _creds(api, user, headers={CONSOLE_SERVER_HEADER: sent})
        assert r.status_code == 403, repr(sent)
    mgr.mint_console_auth_ticket.assert_not_called()


def test_the_console_server_gets_its_answer(api, seed):
    """Counterproof: the same session with the proof gets the addresses and the ticket."""
    mgr = _cluster(api, ssh_off=False)
    r = _creds(api, _operator(seed), '?node=pve2', headers=_proof())
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['node_ips']['pve2'] == '10.0.0.12' and body['pve_auth_ticket'] == TICKET
    assert mgr.mint_console_auth_ticket.call_count == 1


def test_the_checks_behind_the_proof_still_decide(api, seed):
    """node.shell, the confinement and the SSH switch answer the console server as before."""
    mgr = _cluster(api, ssh_off=False)
    seed.tenant('t9', clusters=['cluster_1'])
    plain = seed.user('plain', role='user', tenant_id='t9')
    r = _creds(api, plain, headers=_proof())
    assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied', r.data

    seed.tenant('t1', clusters=['other'])
    confined = seed.user('ops', role='viewer', tenant_id='t1', permissions=['node.shell'])
    seed.vm_acl('cluster_1', 100, ['ops'])
    r = _creds(api, confined, headers=_proof())
    assert r.status_code == 403 and 'whole cluster' in r.get_json()['error'], r.data
    mgr.mint_console_auth_ticket.assert_not_called()

    mgr.config.ssh_disabled = True
    r = _creds(api, _admin(seed), headers=_proof())
    assert r.status_code == 409 and r.get_json()['code'] == 'SSH_DISABLED', r.data
    mgr.mint_console_auth_ticket.assert_not_called()
    # the guest terminal is no SSH and keeps its answer
    r = _creds(api, _admin(seed), '?console=term', headers=_proof())
    assert r.status_code == 200 and r.get_json()['pve_auth_ticket'] == TICKET, r.data


# --- the console server, run against the app ----------------------------------------------

def _script(api, monkeypatch, tmp_path, query, path=SHELL, websockets=None, secret=True):
    """One connection to the console server, its calls answered by the app. (what it said,
    [(path, status, sent the proof)])"""
    from pegaprox.api.realtime import CONSOLE_SERVER_HEADER, console_server_secret
    monkeypatch.setenv('PEGAPROX_URL', APP)
    if secret:
        monkeypatch.setenv('PEGAPROX_CONSOLE_SECRET', console_server_secret())
    else:
        monkeypatch.delenv('PEGAPROX_CONSOLE_SECRET', raising=False)
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', str(tmp_path / 'known_hosts'))
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    ns, _asked = _ssh_server({})
    client = api.app.test_client()
    asked = []

    def get(url, cookies=None, headers=None, **kw):
        assert url.startswith(APP), url
        for name, value in (cookies or {}).items():
            client.set_cookie(name, value, domain='localhost')
        r = client.get(url[len(APP):], headers=headers or {}, base_url='http://localhost')
        proof = (headers or {}).get(CONSOLE_SERVER_HEADER) == console_server_secret()
        asked.append((url[len(APP):].split('?')[0], r.status_code, proof))
        return _Resp(r.status_code, r.get_json(silent=True))

    ns['requests'] = types.SimpleNamespace(get=get, exceptions=ns['requests'].exceptions)
    if websockets is not None:
        ns['websockets'] = websockets
    ws = _Talking(f'{path}?{query}', json.dumps({'username': 'root', 'password': 'pw'}))
    asyncio.run(ns['ssh_handler'](ws))
    said = [json.loads(m) for m in ws.sent if isinstance(m, str) and m.startswith('{')]
    return said, asked


def _addresses(said):
    return [m['ip'] for m in said if m.get('status') == 'need_credentials']


def _cluster_of(api, auth):
    """'token' is an API-token cluster, no PVE ticket to mint; 'password' mints one."""
    mgr = _cluster(api, ssh_off=False)
    if auth == 'token':
        mgr.mint_console_auth_ticket.return_value = None
    else:
        mgr.config.user, mgr.config.pass_ = 'root@pam', 'secret'
    return mgr


@pytest.mark.parametrize('auth', ['token', 'password'])
def test_the_legacy_session_shell_still_opens(api, seed, dialled, monkeypatch, tmp_path, auth):
    _cluster_of(api, auth)
    user = _operator(seed)
    said, asked = _script(api, monkeypatch, tmp_path, f'session={api.as_user(user).session_id}')
    assert _addresses(said) == ['10.0.0.12'], said
    assert dialled == [('10.0.0.12', 22)]
    assert asked == [('/api/auth/validate', 200, True), (CREDS, 200, True)], asked


def test_the_legacy_session_shell_needs_the_proof(api, seed, dialled, monkeypatch, tmp_path):
    """Counterproof: a console server without the secret is a browser to the app here."""
    _cluster_of(api, 'token')
    user = _operator(seed)
    said, asked = _script(api, monkeypatch, tmp_path, f'session={api.as_user(user).session_id}',
                          secret=False)
    assert ('/api/internal/cluster-creds/cluster_1', 403, False) in asked, asked
    assert _addresses(said) == [] and dialled == []


@pytest.mark.parametrize('auth', ['token', 'password'])
def test_the_token_shell_still_opens(api, seed, dialled, monkeypatch, tmp_path, auth):
    _cluster_of(api, auth)
    said, asked = _script(api, monkeypatch, tmp_path, f'token={_token(api, _operator(seed))}')
    assert _addresses(said) == ['10.0.0.12'], said
    assert dialled == [('10.0.0.12', 22)]
    assert asked == [('/api/ws/token/validate', 200, True)], asked


def _pve():
    tried = []

    async def connect(url, additional_headers=None, **kw):
        tried.append((url.split('?')[0], (additional_headers or {}).get('Cookie')))
        raise ConnectionRefusedError('stopped by the test')
    return tried, types.SimpleNamespace(connect=connect)


@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_guest_terminal_still_gets_its_ticket(api, seed, dialled, monkeypatch, tmp_path, way):
    """Both logins of the guest terminal reach PVE with the cluster account's ticket,
    the session login through cluster-creds?console=term."""
    _cluster_of(api, 'password')
    user = _operator(seed)
    q = f'token={_token(api, user)}' if way == 'token' else f'session={api.as_user(user).session_id}'
    tried, websockets = _pve()
    said, asked = _script(api, monkeypatch, tmp_path,
                          f'{q}&ticket=PVEVNC:x&port=5900&host=10.0.0.1&user=root@pam',
                          path=TERM, websockets=websockets)
    assert tried == [('wss://10.0.0.1:8006/api2/json/nodes/pve2/qemu/100/vncwebsocket',
                      f'PVEAuthCookie={TICKET}')], (said, asked)
    assert all(proof for _p, _s, proof in asked), asked
    if way == 'session':
        assert (CREDS, 200, True) in asked, asked
    assert dialled == []


def test_the_guest_terminal_of_a_token_cluster_says_why(api, seed, dialled, monkeypatch, tmp_path):
    """An API-token cluster has no ticket for PVE's terminal socket: that sentence, as before."""
    _cluster_of(api, 'token')
    user = _operator(seed)
    tried, websockets = _pve()
    said, asked = _script(api, monkeypatch, tmp_path,
                          f'session={api.as_user(user).session_id}&ticket=PVEVNC:x&port=5900'
                          f'&host=10.0.0.1&user=root@pam', path=TERM, websockets=websockets)
    assert (CREDS, 200, True) in asked, asked
    assert tried == []
    assert [m['message'] for m in said if m.get('status') == 'error'] == [
        'Console auth unavailable for this cluster (needs user/password auth)'], said


# --- the node shell route -------------------------------------------------------------------

def test_the_node_shell_answer_carries_no_session_cookie(api, seed):
    """The manager's own get_node_shell_ticket behind the route, PVE's termproxy answer
    faked: the termproxy ticket goes out, the cluster account's session does not."""
    from pegaprox.core.manager import PegaProxManager
    mgr = _cluster(api, ssh_off=False)
    mgr.is_connected = True
    mgr._ticket = 'PVE:root@pam:SERVICE::sig'

    class _Session:
        def post(self, url, timeout=None):
            return types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': {
                'ticket': 'PVEVNC:term', 'port': 5900, 'user': 'root@pam'}})
    mgr._create_session = lambda: _Session()
    mgr.get_node_shell_ticket = types.MethodType(PegaProxManager.get_node_shell_ticket, mgr)

    r = api.as_user(_operator(seed)).post('/api/clusters/cluster_1/nodes/pve2/shell', json={})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert 'pve_auth_cookie' not in body, body
    assert 'PVE:root@pam:SERVICE::sig' not in r.get_data(as_text=True)
    assert body['ticket'] == 'PVEVNC:term' and body['port'] == 5900 and body['node'] == 'pve2'
