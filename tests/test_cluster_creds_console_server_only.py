"""cluster-creds is gone, the cluster account's session stays in this process, and the node
shell and the guest terminal still open on the main port.

GET /api/internal/cluster-creds/<cluster> had one caller, the SSH console server on
port+2: the legacy ?session= login of its node shell took the node addresses from it, its
guest terminal a fresh PVE ticket of the cluster account. It answered only that server,
which proved itself with a per-start secret. The server is gone, both consoles are routes
of this app, and the route went with it: nobody can ask for the addresses or the ticket,
with or without the header that once opened it. The checks it ran (node.shell, the
confinement, the SSH switch) are the main port shell's own.

The termproxy ticket call and POST /api/clusters/<cluster>/nodes/<node>/shell never put
the cluster account's PVEAuthCookie into their answer (C-1): the terminal mints it next to
the PVE socket, and the browser never holds it.

The routes run as flask-sock calls them. paramiko stops at the connect, so "dialled" is
the SSH login; websocket.create_connection stands in for PVE.

MK Nov 2026
"""
import json
import secrets
import types

import paramiko
import pytest

import pegaprox.api.vms as vms
from test_vm_terminal_main_port import _Page, _let_go, _query, _terminal, pve  # noqa: F401

TICKET = 'PVE:root@pam:65F00000::sig'
CREDS = '/api/internal/cluster-creds/cluster_1'
ADDRESSES = {'pve1': '10.0.0.1', 'pve2': '10.0.0.12', 'pve3': '10.0.0.13'}
SHELL = '/api/clusters/cluster_1/nodes/pve2/shellws'
PVE_URL = 'wss://10.0.0.1:8006/api2/json/nodes/pve2/qemu/100/vncwebsocket'
NO_AUTH = 'Console auth unavailable for this cluster (needs user/password auth)'


def _proof():
    """The header the SSH console server proved itself with, and a value of the shape its
    secret had. It opens nothing any more."""
    return {'X-PegaProx-Console-Server': secrets.token_urlsafe(32)}


def _creds(api, user, query='', headers=None):
    """cluster-creds the way the console server called it: the browser's session as the
    cookie `session`, plus whatever headers it sent."""
    client = api.app.test_client()
    client.set_cookie('session', api.as_user(user).session_id, domain='localhost')
    return client.get(CREDS + query, headers=headers or {}, base_url='http://localhost')


@pytest.fixture
def dialled(monkeypatch):
    """(host, port) of every SSH login of the shell; the login itself fails."""
    seen = []

    class _Client(paramiko.SSHClient):
        def connect(self, hostname=None, port=22, **kw):
            seen.append((hostname, port))
            raise paramiko.AuthenticationException('stopped by the test')

    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    return seen


def _cluster(api, ssh_off=False, auth='password'):
    """A cluster whose nodes answer at ADDRESSES. 'token' signs in with an API token and
    has no ticket to mint, 'password' mints one."""
    from pegaprox.core.manager import PegaProxManager
    mgr = api.make_fake_manager('cluster_1')
    mgr.id = 'cluster_1'
    mgr.host = mgr.config.host = '10.0.0.1'
    mgr.api_port = 8006
    mgr._ssl_verify = False
    mgr.nodes = {n: {'node': n, 'status': 'online'} for n in ADDRESSES}
    mgr.member_node_ip.side_effect = ADDRESSES.get
    mgr._get_node_ip.side_effect = ADDRESSES.get
    mgr.connect_to_proxmox.return_value = True
    cfg = mgr.config
    cfg.name = 'c1'
    cfg.fallback_hosts = []
    cfg.ssh_disabled = ssh_off
    cfg.ssh_port = 22
    cfg.ssh_key = ''
    if auth == 'token':
        cfg.user, cfg.pass_ = 'pegaprox@pve!shell', 'token-secret'
        mgr.mint_console_auth_ticket.return_value = None
    else:
        cfg.user, cfg.pass_ = 'root@pam', 'secret'
        mgr.mint_console_auth_ticket.return_value = TICKET
    mgr.ssh_blocked_reason = types.MethodType(PegaProxManager.ssh_blocked_reason, mgr)
    api.set_manager('cluster_1', mgr)
    return mgr


def _operator(seed):
    """node.shell on a cluster its tenant owns, no VM ACL or pool: a node shell is his."""
    seed.tenant('t3', clusters=['cluster_1'])
    return seed.user('opr', role='viewer', tenant_id='t3', permissions=['node.shell'])


def _admin(seed):
    return seed.user('root', role='admin')


def _token(api, user):
    r = api.as_user(user).post('/api/ws/token', json={})
    assert r.status_code == 200, r.data
    return r.get_json()['token']


def _shell(api, query, path=SHELL):
    """One node shell socket on the main port, the login dialog answered."""
    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    parts = path.split('/')
    page = _Page(json.dumps({'username': 'root', 'password': 'pw'}))
    with api.app.test_request_context(f'{path}?{query}'):
        view(page, parts[3], parts[5])
    return [json.loads(m) for m in page.sent if isinstance(m, str) and m.startswith('{')]


def _addresses(said):
    return [m['ip'] for m in said if m.get('status') == 'need_credentials']


def _errors(said):
    return [m['message'] for m in said if m.get('status') == 'error']


# --- the route ----------------------------------------------------------------------------

@pytest.mark.parametrize('headers', [None, 'proof'], ids=['session', 'with-the-old-proof'])
@pytest.mark.parametrize('query', ['', '?console=term', '?node=pve2'])
@pytest.mark.parametrize('make', [_admin, _operator], ids=['admin', 'operator'])
def test_cluster_creds_answers_nobody(api, seed, query, make, headers):
    mgr = _cluster(api)
    r = _creds(api, make(seed), query, headers=_proof() if headers else None)

    assert r.status_code == 404, r.data
    text = r.get_data(as_text=True)
    assert 'node_ips' not in text and 'pve_auth_ticket' not in text and TICKET not in text
    # nothing was looked up or minted for it
    mgr.mint_console_auth_ticket.assert_not_called()
    mgr._get_node_ip.assert_not_called()
    mgr.member_node_ip.assert_not_called()


def test_the_same_session_is_good_elsewhere(api, seed):
    """Counterproof: the 404 is the route, not a session the app refused."""
    _cluster(api)
    client = api.app.test_client()
    client.set_cookie('session', api.as_user(_operator(seed)).session_id, domain='localhost')

    r = client.get('/api/auth/validate', base_url='http://localhost')
    assert r.status_code == 200 and r.get_json()['valid'] is True, r.data


# --- the checks it ran, on the main port shell --------------------------------------------

def test_the_checks_decide_the_main_port_shell(api, seed, dialled, pve):
    """node.shell, the confinement and the SSH switch, as cluster-creds answered them."""
    from pegaprox.api.helpers import NODE_SHELL_SSH_OFF
    mgr = _cluster(api)
    seed.tenant('t9', clusters=['cluster_1'])
    plain = seed.user('plain', role='user', tenant_id='t9')
    assert _errors(_shell(api, f'token={_token(api, plain)}')) == ['Permission denied']

    # the tenant owns the cluster, the account holds a VM ACL there: confined, and only the
    # confinement stops it
    seed.tenant('t2', clusters=['cluster_1'])
    confined = seed.user('portal', role='viewer', tenant_id='t2', permissions=['node.shell'])
    seed.vm_acl('cluster_1', 101, ['portal'])
    assert _errors(_shell(api, f'token={_token(api, confined)}')) == [
        'Access denied: this action affects the whole cluster']

    mgr.config.ssh_disabled = True
    said = _shell(api, f'token={_token(api, _admin(seed))}')
    assert _errors(said) == [NODE_SHELL_SSH_OFF] and _addresses(said) == []
    assert dialled == []

    # the guest terminal is no SSH and keeps its answer
    _terminal(api, _query(f'token={_token(api, _admin(seed))}'))
    assert [url.split('?')[0] for url, _kw in pve.dials] == [PVE_URL]
    mgr.mint_console_auth_ticket.assert_called_once()


@pytest.mark.parametrize('auth', ['token', 'password'])
@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_shell_still_opens_on_the_clicked_node(api, seed, dialled, way, auth):
    """Both logins of the shell, on a token cluster and on a password one: the address of
    the node it was opened for, without cluster-creds."""
    _cluster(api, auth=auth)
    user = _operator(seed)
    q = f'token={_token(api, user)}' if way == 'token' else f'session={api.as_user(user).session_id}'
    said = _shell(api, q)

    assert _addresses(said) == ['10.0.0.12'], said
    assert dialled == [('10.0.0.12', 22)]


# --- the guest terminal -------------------------------------------------------------------

@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_guest_terminal_still_gets_its_ticket(api, seed, dialled, pve, way):
    """Both logins of the guest terminal reach PVE with the cluster account's ticket,
    minted in this process: cluster-creds?console=term handed it out before."""
    mgr = _cluster(api)
    user = _operator(seed)
    q = f'token={_token(api, user)}' if way == 'token' else f'session={api.as_user(user).session_id}'
    _terminal(api, _query(q))

    assert [(url.split('?')[0], kw['header']) for url, kw in pve.dials] == [
        (PVE_URL, {'Cookie': f'PVEAuthCookie={TICKET}'})]
    assert mgr.mint_console_auth_ticket.call_count == 1
    assert dialled == []


def test_the_guest_terminal_of_a_token_cluster_says_why(api, seed, pve):
    """An API-token cluster has no ticket for PVE's terminal socket: that sentence, as before."""
    _cluster(api, auth='token')
    page = _terminal(api, _query(f'session={api.as_user(_operator(seed)).session_id}'))

    assert pve.dials == []
    assert [m['message'] for m in map(json.loads, page.sent) if m.get('status') == 'error'] == [NO_AUTH]
    assert page.closed == (1011, NO_AUTH)


# --- the answers of the ticket calls ------------------------------------------------------

def test_the_node_shell_answer_carries_no_session_cookie(api, seed):
    """The manager's own get_node_shell_ticket behind the route, PVE's termproxy answer
    faked: the termproxy ticket goes out, the cluster account's session does not."""
    from pegaprox.core.manager import PegaProxManager
    mgr = _cluster(api)
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


def test_the_termproxy_answer_carries_no_session_cookie(api, seed, monkeypatch):
    """C-1. The ticket call logs in to PVE as the cluster account for the termproxy ticket;
    that login's session ticket is root on the cluster and stays here, only the termproxy
    ticket for this guest goes to the page."""
    import io
    from contextlib import contextmanager

    import pegaprox.core.manager as manager_mod
    mgr = _cluster(api)
    mgr.auth_host = '10.0.0.1'
    asked = []

    class _Opener:
        @contextmanager
        def open(self, req, timeout=None):
            url = req.full_url
            asked.append(url.split('/api2/json')[1])
            if url.endswith('/access/ticket'):
                data = {'ticket': TICKET, 'CSRFPreventionToken': 'csrf', 'username': 'root@pam'}
            else:
                assert req.get_header('Cookie') == f'PVEAuthCookie={TICKET}'
                data = {'ticket': 'PVEVNC:term', 'port': 5900, 'user': 'root@pam'}
            yield io.BytesIO(json.dumps({'data': data}).encode())
    monkeypatch.setattr(manager_mod, 'pve_opener', lambda _ctx: _Opener())

    r = api.as_user(_admin(seed)).post('/api/clusters/cluster_1/vms/pve2/qemu/100/termproxy', json={})

    assert r.status_code == 200, r.data
    assert asked == ['/access/ticket', '/nodes/pve2/qemu/100/termproxy']
    body = r.get_json()
    assert body['ticket'] == 'PVEVNC:term' and body['port'] == 5900 and body['host'] == '10.0.0.1'
    text = r.get_data(as_text=True)
    assert TICKET not in text and 'csrf' not in text
