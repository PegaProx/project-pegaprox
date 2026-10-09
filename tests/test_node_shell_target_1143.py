"""The node shell: who it opens for and which node it logs in on (#1143).

The main port route (/shellws, the shell's way in behind a reverse proxy) read only
?session=, and the page sends a ws token: every attempt ended in "Authentication
required". It takes the token first now and the session as fallback, as both VNC
sockets do, with every check after that as it was.

Behind that it looked the node up with a cluster_port nobody had set, the NameError
was caught and the SSH login went to the cluster's connection host - another node,
under the clicked one's name. The SSH server on port+2 did the same whenever the
page's ?ip= did not happen to match: the validate answer never named the node. Both
take the address the server resolves for that node now, refuse without one, and
neither ?ip= nor the host field of the dialog moves the shell.

The flask-sock handler runs as flask-sock calls it and the SSH server's coroutine as
the script runs it; paramiko is stopped at the connect, so "dialled" is the host the
login went to. Every refusal has its counterproof next to it.

MK Oct 2026
"""
import asyncio
import json
import types

import paramiko
import pytest

import pegaprox.api.vms as vms
from test_console_server_ticket import _confined, _console_server, _mgr, _operator, _portal, _validate
from test_ha_v2_surface import SHELL, _AsyncWS, _Resp, _ssh_server

CONNECTION_HOST = '10.0.0.1'
# pve1 is the node the cluster is connected through, the other two are not
ADDRESSES = {'pve1': '10.0.0.1', 'pve2': '10.0.0.12', 'pve3': '10.0.0.13'}
NO_ADDRESS = 'Could not find the address of node'


class _Browser:
    """The flask-sock socket: the credentials when asked, everything said kept."""

    def __init__(self, *incoming):
        self.incoming = list(incoming)
        self.sent = []

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        return self.incoming.pop(0) if self.incoming else None

    def close(self, *a, **k):
        pass


@pytest.fixture(autouse=True)
def _let_go():
    """A handler run outside a real request keeps its socket counted; give it back."""
    import pegaprox.utils.realtime as rt
    before = set(rt._held_ws)
    yield
    for key in set(rt._held_ws) - before:
        rt.release_websocket(key)


@pytest.fixture
def dialled(monkeypatch):
    """The hosts the shell's SSH login went to; the login itself fails."""
    hosts = []

    class _Client:
        def connect(self, hostname=None, **kw):
            hosts.append(hostname)
            raise paramiko.AuthenticationException('stopped by the test')

        def close(self):
            pass

    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    return hosts


def _cluster(api, addresses=None):
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = mgr.config.host = CONNECTION_HOST
    mgr.api_port = 8006
    mgr.nodes = {n: {'node': n, 'status': 'online'} for n in ADDRESSES}
    mgr.connect_to_proxmox.return_value = True
    table = ADDRESSES if addresses is None else addresses
    mgr.member_node_ip.side_effect = lambda n: table.get(n)
    api.set_manager('cluster_1', mgr)
    return mgr


def _token(api, user):
    r = api.as_user(user).post('/api/ws/token', json={})
    assert r.status_code == 200, r.data
    return r.get_json()['token']


def _shell(api, query, node='pve2', host=None):
    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    creds = {'username': 'root', 'password': 'pw'}
    if host is not None:
        creds['host'] = host
    ws = _Browser(json.dumps(creds))
    with api.app.test_request_context(f'/api/clusters/cluster_1/nodes/{node}/shellws?{query}'):
        view(ws, 'cluster_1', node)
    return [json.loads(m) for m in ws.sent]


def _errors(said):
    return [m['message'] for m in said if m.get('status') == 'error']


def _asked_for(said):
    return [m['ip'] for m in said if m.get('status') == 'need_credentials']


# --- 1. the ws token on the main port --------------------------------------------------------

def test_a_ws_token_opens_the_shell(api, seed, dialled):
    _cluster(api)
    said = _shell(api, f'token={_token(api, seed.user("root", role="admin"))}')
    assert _asked_for(said) == ['10.0.0.12'], said
    assert dialled == ['10.0.0.12']


def test_a_token_opens_one_shell_only(api, seed, dialled):
    _cluster(api)
    tok = _token(api, seed.user('root', role='admin'))
    assert _asked_for(_shell(api, f'token={tok}')) == ['10.0.0.12']
    said = _shell(api, f'token={tok}')
    assert said == [{'status': 'error', 'message': 'Invalid or expired token'}]
    assert dialled == ['10.0.0.12']


def test_a_token_nobody_minted_opens_nothing(api, seed, dialled):
    mgr = _cluster(api)
    assert _shell(api, 'token=made-up') == [{'status': 'error', 'message': 'Invalid or expired token'}]
    mgr.connect_to_proxmox.assert_not_called()
    assert dialled == []


def test_a_bad_token_is_not_rescued_by_a_session(api, seed, dialled):
    """As on the VNC sockets: a token that was sent decides, a session next to it is not
    tried instead."""
    root = seed.user('root', role='admin')
    _cluster(api)
    sid = api.as_user(root).session_id
    assert _errors(_shell(api, f'token=made-up&session={sid}')) == ['Invalid or expired token']
    assert dialled == []
    # counterproof: that session on its own opens the shell
    assert _asked_for(_shell(api, f'session={sid}')) == ['10.0.0.12']


def test_no_credentials_open_nothing(api, seed, dialled):
    mgr = _cluster(api)
    for query in ('', 'token=', 'session='):
        assert _shell(api, query) == [{'status': 'error', 'message': 'Authentication required'}], query
    mgr.connect_to_proxmox.assert_not_called()
    assert dialled == []


def test_a_cookie_an_sse_token_or_an_expired_token_open_nothing(api, seed, dialled):
    """The socket reads no cookie (another site's page would send it along), an SSE token
    is no ws token, and a ws token past its minute is spent."""
    import pegaprox.utils.realtime as rt
    mgr = _cluster(api)
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    ws = _Browser()
    with api.app.test_request_context('/api/clusters/cluster_1/nodes/pve2/shellws',
                                      headers={'Cookie': f'session={c.session_id}; session_id={c.session_id}'}):
        view(ws, 'cluster_1', 'pve2')
    assert [json.loads(m) for m in ws.sent] == [{'status': 'error', 'message': 'Authentication required'}]
    sse = c.post('/api/sse/token', json={}).get_json()['token']
    assert _errors(_shell(api, f'token={sse}')) == ['Invalid or expired token']
    tok = _token(api, root)
    with rt.ws_tokens_lock:
        rt.ws_tokens[tok]['expires'] -= rt.WS_TOKEN_TTL + 1
    assert _errors(_shell(api, f'token={tok}')) == ['Invalid or expired token']
    mgr.connect_to_proxmox.assert_not_called()
    assert dialled == []


@pytest.mark.parametrize('role, opens', [('viewer', False), ('admin', True)])
def test_a_ws_token_minted_by_an_api_token_acts_under_its_role(api, seed, dialled, role, opens):
    """An admin's API token capped at viewer: the shell is the token's, not its owner's (#1116)."""
    from pegaprox.utils import auth as authmod
    _cluster(api)
    seed.user('root', role='admin')
    res = authmod.create_api_token('root', f'ci-{role}', role=role)
    r = api.anon().post('/api/ws/token', headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 200, r.data
    said = _shell(api, f"token={r.get_json()['token']}")
    if opens:
        assert _asked_for(said) == ['10.0.0.12'], said
    else:
        assert _errors(said) == ['Permission denied'] and dialled == [], said


def test_the_session_still_opens_the_shell(api, seed, dialled):
    _cluster(api)
    sid = api.as_user(seed.user('root', role='admin')).session_id
    said = _shell(api, f'session={sid}')
    assert _asked_for(said) == ['10.0.0.12'] and dialled == ['10.0.0.12'], said
    assert _errors(_shell(api, 'session=made-up')) == ['Invalid session']


@pytest.mark.parametrize('make', [_confined, _portal])
def test_a_confined_callers_token_opens_no_shell(api, seed, dialled, make):
    mgr = _cluster(api)
    said = _shell(api, f'token={_token(api, make(seed))}')
    assert _errors(said) and _errors(said)[0] in (
        'Access denied: this action affects the whole cluster', 'Access denied to this cluster'), said
    mgr.connect_to_proxmox.assert_not_called()
    assert dialled == []


def test_a_cluster_operators_token_opens_the_shell(api, seed, dialled):
    """Counterproof: node.shell through a tenant that owns the cluster, no ACL or pool."""
    _cluster(api)
    assert _asked_for(_shell(api, f'token={_token(api, _operator(seed))}')) == ['10.0.0.12']
    assert dialled == ['10.0.0.12']


def test_a_token_without_node_shell_opens_no_shell(api, seed, dialled):
    mgr = _cluster(api)
    seed.tenant('t3', clusters=['cluster_1'])
    viewer = seed.user('vic', role='viewer', tenant_id='t3')
    assert _errors(_shell(api, f'token={_token(api, viewer)}')) == ['Permission denied']
    mgr.connect_to_proxmox.assert_not_called()
    assert dialled == []


def test_a_token_minted_before_the_account_was_disabled_opens_no_shell(api, seed, dialled):
    _cluster(api)
    tok = _token(api, seed.user('root', role='admin'))
    seed.user('root', role='admin', enabled=False)
    assert _errors(_shell(api, f'token={tok}')) == ['Invalid session']
    assert dialled == []


def test_the_shell_ends_with_the_session_the_token_was_minted_under(api, seed, dialled, monkeypatch):
    """hold_websocket gets the token's session (#1038): signing that session out hangs the
    shell up, signing out another one does not."""
    import pegaprox.utils.realtime as rt
    hung_up = []
    monkeypatch.setattr(rt, '_hang_up', hung_up.append)
    held = []
    real_hold = rt.hold_websocket
    monkeypatch.setattr(vms, 'hold_websocket', lambda user, ws, sid=None: (held.append(ws), real_hold(user, ws, sid=sid)))
    root = seed.user('root', role='admin')
    c = api.as_user(root)
    other = api.as_user(root).session_id
    tok = c.post('/api/ws/token', json={}).get_json()['token']
    _shell(api, f'token={tok}')
    assert len(held) == 1
    rt.end_session_channels('root', sids=[other])
    assert hung_up == []
    rt.end_session_channels('root', sids=[c.session_id])
    assert hung_up == held


# --- 2. the node it logs in on ----------------------------------------------------------------

@pytest.mark.parametrize('node', sorted(ADDRESSES))
def test_the_shell_logs_in_on_the_clicked_node(api, seed, dialled, node):
    """pve1 is the connection host's own node and lands there; the other two do not."""
    _cluster(api)
    said = _shell(api, f'token={_token(api, seed.user("root", role="admin"))}', node=node)
    assert _asked_for(said) == [ADDRESSES[node]], said
    assert [m['node'] for m in said if m.get('status') == 'need_credentials'] == [node]
    assert dialled == [ADDRESSES[node]]


@pytest.mark.parametrize('ip', [CONNECTION_HOST, '10.0.0.13', '203.0.113.9'])
def test_the_page_cannot_move_the_shell(api, seed, dialled, ip):
    """Not with ?ip=, not with the dialog's host: another node's address, the connection
    host and a host outside the cluster all end on pve2's own."""
    _cluster(api)
    root = seed.user('root', role='admin')
    said = _shell(api, f'token={_token(api, root)}&ip={ip}', host=ip)
    assert _asked_for(said) == ['10.0.0.12'] and dialled == ['10.0.0.12'], said
    # and over the session as well
    _shell(api, f'session={api.as_user(root).session_id}&ip={ip}', host=ip)
    assert dialled == ['10.0.0.12', '10.0.0.12']


def test_no_address_no_shell(api, seed, dialled):
    mgr = _cluster(api, addresses={'pve1': '10.0.0.1', 'pve3': '10.0.0.13'})
    root = seed.user('root', role='admin')
    said = _shell(api, f'token={_token(api, root)}&ip={CONNECTION_HOST}')
    assert said == [{'status': 'error', 'message': f'{NO_ADDRESS} pve2'}]
    assert dialled == [], 'the login went to the connection host'
    mgr.member_node_ip.assert_called_with('pve2')
    # counterproof: a node of the same cluster with an address still opens
    assert _asked_for(_shell(api, f'token={_token(api, root)}', node='pve3')) == ['10.0.0.13']
    assert dialled == ['10.0.0.13']


def test_a_lookup_that_fails_is_no_shell(api, seed, dialled):
    mgr = _cluster(api)
    mgr.member_node_ip.side_effect = RuntimeError('cluster unreachable')
    said = _shell(api, f'token={_token(api, seed.user("root", role="admin"))}')
    assert _errors(said) == [f'{NO_ADDRESS} pve2'] and dialled == []


def test_a_name_that_is_no_node_of_the_cluster_is_no_shell(api, seed, dialled):
    mgr = _cluster(api)
    root = seed.user('root', role='admin')
    assert _errors(_shell(api, f'token={_token(api, root)}', node='pve9')) == [f'{NO_ADDRESS} pve9']
    mgr.member_node_ip.assert_not_called()
    assert dialled == []
    # counterproof: a member is looked up
    _shell(api, f'token={_token(api, root)}', node='pve3')
    mgr.member_node_ip.assert_called_once_with('pve3')


def test_the_lookup_reads_no_undefined_port(api):
    """The NameError behind the stand-in: nothing in the handler reads cluster_port, and
    nothing falls back to the configured host."""
    import ast
    import inspect
    import textwrap
    src = inspect.getsource(api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__)
    tree = ast.parse(textwrap.dedent(src))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not names & {'cluster_port', 'cluster_host'}, names & {'cluster_port', 'cluster_host'}
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == 'host']
    assert 'node_ip = node_shell_address(manager, node)' in src


# --- 2a. the manager's lookup has no stand-in either --------------------------------------------

class _Answer:
    def __init__(self, code, data=None):
        self.status_code = code
        self._data = data

    def json(self):
        return {'data': self._data}


@pytest.fixture
def down(monkeypatch):
    """pve1 is down: its SSH port refuses, no DNS knows a name. What was looked up and
    knocked on is kept."""
    import socket
    seen = {'names': [], 'knocks': []}

    class _Socket:
        def __init__(self, *a, **kw):
            pass

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            seen['knocks'].append(addr[:2])
            return 111

        def close(self):
            pass

    def _no_dns(name, *a, **kw):
        seen['names'].append(name)
        raise socket.gaierror('no such name')

    monkeypatch.setattr(socket, 'socket', _Socket)
    monkeypatch.setattr(socket, 'getaddrinfo', _no_dns)
    return seen


def _looking_up(host, config_host=None, local='pve10'):
    """What PegaProxManager._get_node_ip_impl reads: cluster/status names the node it is
    connected through, every other read of the node fails."""
    import logging

    def api_get(url, **kw):
        if url.endswith('/cluster/status'):
            return _Answer(200, [{'type': 'node', 'name': local, 'ip': '10.0.0.10', 'local': 1},
                                 {'type': 'node', 'name': 'pve1', 'ip': '10.0.0.1', 'local': 0}])
        return _Answer(595)
    return types.SimpleNamespace(
        is_connected=True, host=host, api_port=8006, logger=logging.getLogger('test'),
        config=types.SimpleNamespace(host=config_host or host, ssh_port=22, ssh_disabled=False),
        _api_get=api_get)


@pytest.mark.parametrize('host', ['pve10.lab', 'pve1-old.lab', 'backup-pve1.lab'])
def test_a_host_whose_name_merely_contains_the_node_is_not_the_node(down, host):
    """The last resort "the node is the connected host" was a substring test, so pve1's
    lookup answered pve10.lab when pve1 was down: a shell, an update or a hardening run for
    pve1 went to another node."""
    from pegaprox.core.manager import PegaProxManager
    assert PegaProxManager._get_node_ip_impl(_looking_up(host), 'pve1') is None
    assert down['names'] == ['pve1']


def test_in_a_failover_the_configured_host_is_not_the_one_connected_to(down):
    """pve1 is the configured host and down, the cluster is reached through pve2: pve1's
    name handed back pve2's address."""
    from pegaprox.core.manager import PegaProxManager
    fake = _looking_up('pve2.lab', config_host='pve1.lab', local='pve2')
    assert PegaProxManager._get_node_ip_impl(fake, 'pve1') == 'pve1.lab'


@pytest.mark.parametrize('node', ['pve10', 'pve10.lab'])
def test_the_connected_host_still_stands_for_its_own_name(down, node):
    """Counterproof: cluster/status names no node local, the node is the host's own name."""
    from pegaprox.core.manager import PegaProxManager
    fake = _looking_up('pve10.lab', local='pve99')
    assert PegaProxManager._get_node_ip_impl(fake, node) == 'pve10.lab'


def test_the_shell_of_a_node_that_is_down_does_not_open_on_its_neighbour(api, seed, dialled, down):
    """The same through the main port shell: pve1 is down, the cluster is connected through
    pve10.lab. The login went there under pve1's name."""
    from pegaprox.core.manager import PegaProxManager
    mgr = _cluster(api)
    mgr.nodes = {'pve1': {}, 'pve10': {}}
    fake = _looking_up('pve10.lab')
    mgr.member_node_ip.side_effect = lambda n: PegaProxManager._get_node_ip_impl(fake, n)
    root = seed.user('root', role='admin')
    said = _shell(api, f'token={_token(api, root)}', node='pve1')
    assert _errors(said) == [f'{NO_ADDRESS} pve1'] and dialled == [], (said, dialled)
    # counterproof: the node it is connected through opens on that host
    assert _asked_for(_shell(api, f'token={_token(api, root)}', node='pve10')) == ['pve10.lab']
    assert dialled == ['pve10.lab']


# --- 2b. the SSH server on port+2 -------------------------------------------------------------

class _Talking(_AsyncWS):
    def __init__(self, path, *incoming):
        super().__init__(path)
        self.incoming = list(incoming)

    async def recv(self):
        if self.incoming:
            return self.incoming.pop(0)
        raise ConnectionError('nothing more to say')


def _run_script(monkeypatch, tmp_path, answers, path=f'{SHELL}?token=t', host=None):
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', str(tmp_path / 'known_hosts'))
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    ns, asked = _ssh_server(answers)
    hosts = []

    class _Client(paramiko.SSHClient):
        def connect(self, hostname, **kw):
            hosts.append(hostname)
            raise paramiko.AuthenticationException('stopped by the test')

    fake = types.SimpleNamespace(**vars(paramiko))
    fake.SSHClient = _Client
    ns['paramiko'] = fake
    creds = {'username': 'root', 'password': 'pw'}
    if host is not None:
        creds['host'] = host
    ws = _Talking(path, json.dumps(creds))
    asyncio.run(ns['ssh_handler'](ws))
    said = [json.loads(m) for m in ws.sent if isinstance(m, str) and m.startswith('{')]
    return said, ws, hosts, asked


def _validated(node_ips, host='192.0.2.1'):
    return {'/api/ws/token/validate': _Resp(200, {'valid': True, 'known_hosts_only': False,
                                                  'cluster_context': {'host': host, 'node_ips': node_ips}})}


def test_the_ssh_server_logs_in_on_the_address_the_app_named(monkeypatch, tmp_path):
    said, ws, hosts, asked = _run_script(monkeypatch, tmp_path,
                                         _validated({'_fallback_0': '192.0.2.1', 'n1': '192.0.2.11'}))
    assert _asked_for(said) == ['192.0.2.11'] and hosts == ['192.0.2.11'], said
    # it asks the app for this node's shell, which is what makes the app look the node up
    assert len(asked) == 1 and '&node=n1&shell=node' in asked[0]


def test_the_ssh_server_opens_nothing_without_the_nodes_address(monkeypatch, tmp_path):
    """The connection host and a fallback host are known, the node's address is not."""
    said, ws, hosts, _asked = _run_script(monkeypatch, tmp_path, _validated({'_fallback_0': '192.0.2.5'}))
    assert said == [{'status': 'error', 'message': f'{NO_ADDRESS} n1'}]
    assert ws.closed == (1008, 'node address unknown')
    assert hosts == [], 'the login went to the connection host'


@pytest.mark.parametrize('ip', ['192.0.2.1', '192.0.2.5', '203.0.113.9'])
def test_neither_ip_nor_the_dialog_moves_the_ssh_servers_shell(monkeypatch, tmp_path, ip):
    """The connection host and a fallback host passed the old allow-list and took the
    shell there; a host outside it was refused. All three end on the node now."""
    said, ws, hosts, _asked = _run_script(
        monkeypatch, tmp_path, _validated({'_fallback_0': '192.0.2.5', 'n1': '192.0.2.11'}),
        path=f'{SHELL}?token=t&ip={ip}', host=ip)
    assert _asked_for(said) == ['192.0.2.11'] and hosts == ['192.0.2.11'], said


def test_a_key_of_the_context_is_no_node(monkeypatch, tmp_path):
    path = '/api/clusters/c1/nodes/_fallback_0/shellws?token=t'
    said, ws, hosts, _asked = _run_script(monkeypatch, tmp_path, _validated({'_fallback_0': '192.0.2.5'}), path=path)
    assert said == [{'status': 'error', 'message': f'{NO_ADDRESS} _fallback_0'}] and hosts == []


def test_the_legacy_session_path_takes_the_nodes_address_too(monkeypatch, tmp_path):
    def run(node_ips):
        return _run_script(monkeypatch, tmp_path, {
            '/api/auth/validate': _Resp(200, {'valid': True}),
            '/api/internal/cluster-creds/': _Resp(200, {'host': '192.0.2.1', 'node_ips': node_ips}),
        }, path=f'{SHELL}?session=s&ip=192.0.2.1', host='192.0.2.1')

    said, _ws, hosts, _asked = run({'n1': '192.0.2.11', 'n2': '192.0.2.12'})
    assert _asked_for(said) == ['192.0.2.11'] and hosts == ['192.0.2.11'], said
    # cluster-creds' own stand-in for "no node found" is no node either
    said, ws, hosts, _asked = run({'_default': '192.0.2.1'})
    assert _errors(said) == [f'{NO_ADDRESS} n1'] and hosts == []


def _query(url):
    from urllib.parse import parse_qs, urlparse
    return parse_qs(urlparse(url).query)


def test_the_token_adds_nothing_to_the_validate_call(monkeypatch, tmp_path):
    """The page's token went into the validate URL as it came, so ?token=t%26shell%3Dx put
    a shell=x ahead of shell=node, and /validate reads the first: no node.shell check, no
    confinement check. Before this change the shell then opened on the connection host."""
    _said, _ws, _hosts, asked = _run_script(monkeypatch, tmp_path, _validated({'n1': '192.0.2.11'}),
                                            path=f'{SHELL}?token=t%26shell%3Dx%26node%3Dn9')
    q = _query(asked[0])
    assert q['token'] == ['t&shell=x&node=n9'], q
    assert q['shell'] == ['node'] and q['node'] == ['n1'], q


def test_the_vm_terminals_token_adds_nothing_either():
    from test_ha_v2_surface import CID, TERM
    ns, asked = _ssh_server({'/api/ws/token/validate': _Resp(401)})
    asyncio.run(ns['ssh_handler'](_AsyncWS(f'{TERM}?token=t%26cluster_id%3Dother&ticket=x&port=5900&host=h&user=u')))
    q = _query(asked[0])
    assert q['token'] == ['t&cluster_id=other'] and q['cluster_id'] == [CID], q


def _app_behind(api, ns):
    """The script's calls answered by the app itself, as our own console server."""
    from pegaprox.api.realtime import CONSOLE_SERVER_HEADER, console_server_secret
    answered = []

    def get(url, headers=None, **kw):
        path = url[len(ns['PEGAPROX_URL']):]
        r = api.anon().get(path, headers=headers or {})
        answered.append((path.split('?')[0], r.status_code))
        return _Resp(r.status_code, r.get_json(silent=True) or {})
    ns['requests'] = types.SimpleNamespace(get=get, exceptions=ns['requests'].exceptions)
    ns['CONSOLE_HEADERS'] = {CONSOLE_SERVER_HEADER: console_server_secret()}
    return answered


def _port2(api, monkeypatch, tmp_path, query, node='pve2'):
    from urllib.parse import quote
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', str(tmp_path / 'known_hosts'))
    ns, _asked = _ssh_server({})
    answered = _app_behind(api, ns)
    hosts = []

    class _Client(paramiko.SSHClient):
        def connect(self, hostname, **kw):
            hosts.append(hostname)
            raise paramiko.AuthenticationException('stopped by the test')

    fake = types.SimpleNamespace(**vars(paramiko))
    fake.SSHClient = _Client
    ns['paramiko'] = fake
    ws = _Talking(f'/api/clusters/cluster_1/nodes/{quote(node)}/shellws?{query}',
                  json.dumps({'username': 'root', 'password': 'pw'}))
    asyncio.run(ns['ssh_handler'](ws))
    said = [json.loads(m) for m in ws.sent if isinstance(m, str) and m.startswith('{')]
    return said, answered, hosts


def _port2_cluster(api):
    mgr = _cluster(api)
    mgr.config.fallback_hosts = []
    mgr.config.ssh_port = 22
    mgr._ssl_verify = False
    mgr.mint_console_auth_ticket.return_value = None
    return mgr


def test_the_ssh_server_and_the_app_open_the_clicked_node(api, seed, monkeypatch, tmp_path):
    """Both halves together: the script's validate call answered by the app."""
    _port2_cluster(api)
    root = seed.user('root', role='admin')
    for node in ('pve2', 'pve3'):
        said, answered, hosts = _port2(api, monkeypatch, tmp_path, f'token={_token(api, root)}', node=node)
        assert answered == [('/api/ws/token/validate', 200)]
        assert _asked_for(said) == [ADDRESSES[node]] and hosts == [ADDRESSES[node]], said


def test_a_token_that_adds_a_shell_gets_no_further_than_validate(api, seed, monkeypatch, tmp_path):
    """A viewer of the cluster without node.shell. Her token with a shell=x behind it was a
    valid token for /validate and skipped its node.shell check (200)."""
    from urllib.parse import quote
    mgr = _port2_cluster(api)
    seed.tenant('t3', clusters=['cluster_1'])
    viewer = seed.user('vic', role='viewer', tenant_id='t3')
    said, answered, hosts = _port2(api, monkeypatch, tmp_path,
                                   'token=' + quote(_token(api, viewer) + '&shell=x', safe=''))
    assert answered == [('/api/ws/token/validate', 401)], answered
    assert _asked_for(said) == [] and hosts == []
    mgr.member_node_ip.assert_not_called()
    # counterproof: her token as it is gets the node.shell refusal
    said, answered, _hosts = _port2(api, monkeypatch, tmp_path, f'token={_token(api, viewer)}')
    assert answered == [('/api/ws/token/validate', 403)]
    assert _errors(said) == ['No access to cluster cluster_1']


# --- 2c. the main app's half: the validate call names the node's address ----------------------

def _shell_cluster(api, addresses):
    mgr = _mgr(api)
    mgr.nodes = {'pve1': {}, 'pve2': {}}
    mgr.member_node_ip.side_effect = lambda n: addresses.get(n)
    return mgr


def test_the_validate_call_of_a_node_shell_names_the_nodes_address(api, seed):
    mgr = _shell_cluster(api, {'pve2': '10.0.0.12'})
    root = seed.user('root', role='admin')
    r = _validate(api, _token(api, root), '&node=pve2&shell=node', headers=_console_server())
    assert r.status_code == 200, r.data
    ctx = r.get_json()['cluster_context']
    assert ctx['node_ips'] == {'pve2': '10.0.0.12'} and ctx['host'] == '10.0.0.1'
    mgr.member_node_ip.assert_called_once_with('pve2')
    # counterproof: the VM terminal asks no node shell, so nothing is probed for it
    r = _validate(api, _token(api, root), '&node=pve2', headers=_console_server())
    assert r.status_code == 200 and r.get_json()['cluster_context']['node_ips'] == {}
    assert mgr.member_node_ip.call_count == 1


@pytest.mark.parametrize('node', ['pve1', 'pve9', '_fallback_0'])
def test_the_validate_call_names_no_address_it_does_not_have(api, seed, node):
    """pve1 is a member without an address, the other two are no members at all."""
    mgr = _shell_cluster(api, {'pve2': '10.0.0.12', 'pve9': '10.0.0.99'})
    mgr.config.fallback_hosts = ['10.0.0.5']
    r = _validate(api, _token(api, seed.user('root', role='admin')), f'&node={node}&shell=node',
                  headers=_console_server())
    assert r.status_code == 200, r.data
    assert r.get_json()['cluster_context']['node_ips'] == {'_fallback_0': '10.0.0.5'}
    if node != 'pve1':
        mgr.member_node_ip.assert_not_called()


# --- the helper and the XCP-ng lookup ---------------------------------------------------------

def test_the_helper_resolves_only_members():
    from unittest.mock import MagicMock
    from pegaprox.api.helpers import node_shell_address
    pve = MagicMock(cluster_type='proxmox', nodes={'pve1': {}})
    pve.member_node_ip.side_effect = {'pve1': '10.0.0.11', 'pve2': '10.0.0.12'}.get
    assert node_shell_address(pve, 'pve1') == '10.0.0.11'
    # pve2 resolves, but the cluster does not list it
    assert node_shell_address(pve, 'pve2') is None
    # a manager that cannot list its nodes names no address at all
    pve.nodes = {}
    assert node_shell_address(pve, 'pve1') is None
    for bad in (None, '', 7):
        assert node_shell_address(pve, bad) is None
    # an XCP-ng pool answers membership from XAPI itself
    xcp = MagicMock(cluster_type='xcpng', nodes={})
    xcp.member_node_ip.side_effect = {'xh1': '10.1.1.11'}.get
    assert node_shell_address(xcp, 'xh1') == '10.1.1.11' and node_shell_address(xcp, 'xh2') is None


def _pool(hosts):
    from pegaprox.core.xcpng import XcpngManager
    x = object.__new__(XcpngManager)
    x.logger = types.SimpleNamespace(warning=lambda *a, **k: None)
    x.config = types.SimpleNamespace(host='10.1.1.1')
    host = types.SimpleNamespace(
        get_all=lambda: list(hosts),
        get_hostname=lambda h: hosts[h][0],
        get_name_label=lambda h: hosts[h][1],
        get_address=lambda h: hosts[h][2])
    x._api = lambda: types.SimpleNamespace(host=host)
    return x


def test_an_xcp_ng_host_resolves_by_hostname_or_label_and_nothing_stands_in():
    x = _pool({'r1': ('xh1', 'Host One', '10.1.1.11'), 'r2': ('xh2', 'Host Two', '10.1.1.12')})
    assert x.member_node_ip('xh2') == '10.1.1.12' and x.member_node_ip('Host One') == '10.1.1.11'
    assert x.member_node_ip('xh9') is None
    # counterproof: the older lookup hands the pool's own host back for that name
    assert x._get_host_ip('xh9') == '10.1.1.1'
    x._api = lambda: None
    assert x.member_node_ip('xh1') is None and x._get_host_ip('xh1') == '10.1.1.1'


def test_cluster_creds_lists_no_stand_in_for_an_xcp_ng_host(api, seed):
    mgr = api.make_fake_manager('cluster_1', cluster_type='xcpng')
    mgr.host = '10.1.1.1'
    mgr.api_port = 443
    mgr.get_nodes.return_value = [{'node': 'xh1'}, {'node': 'xh2'}]
    mgr.member_node_ip.side_effect = {'xh1': '10.1.1.11'}.get
    mgr._get_host_ip.return_value = '10.1.1.1'
    mgr.mint_console_auth_ticket.return_value = None
    mgr.config.ssh_port = 22
    mgr._ssl_verify = False
    api.set_manager('cluster_1', mgr)
    sid = api.as_user(seed.user('root', role='admin')).session_id
    client = api.app.test_client()
    client.set_cookie('session', sid, domain='localhost')
    r = client.get('/api/internal/cluster-creds/cluster_1', base_url='http://localhost')
    assert r.status_code == 200, r.data
    assert r.get_json()['node_ips'] == {'xh1': '10.1.1.11'}
    mgr._get_host_ip.assert_not_called()


# --- the address the dialog shows before the shell server names one ----------------------------

def _user(seed):
    seed.tenant('t4', clusters=['cluster_1'])
    return seed.user('uma', role='user', tenant_id='t4')


def test_the_node_ip_lookup_resolves_no_name_outside_the_cluster(api, seed, down, monkeypatch):
    """GET .../nodes/<node>/ip is the shell's first call, and node.view, a plain user's
    permission, reaches it. Any name went to the full lookup: this server resolved it and
    knocked on port 22 of what came back."""
    import socket
    from pegaprox.core.manager import PegaProxManager
    mgr = _cluster(api)
    fake = _looking_up(CONNECTION_HOST, local='pve1')
    mgr._get_node_ip.side_effect = lambda n: PegaProxManager._get_node_ip_impl(fake, n)
    mgr.member_node_ip.side_effect = lambda n: PegaProxManager._get_node_ip_impl(fake, n)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda name, *a, **k: (
        down['names'].append(name) or [(socket.AF_INET, 1, 6, '', ('198.51.100.7', 8006))]))
    c = api.as_user(_user(seed))
    r = c.get('/api/clusters/cluster_1/nodes/scan-me.example/ip')
    assert r.status_code == 200, r.data
    assert r.get_json() == {'ip': CONNECTION_HOST, 'node': 'scan-me.example', 'source': 'cluster_host_fallback'}
    assert down['names'] == [] and down['knocks'] == [], down
    # counterproof: a node of the cluster is looked up, the same way
    r = c.get('/api/clusters/cluster_1/nodes/pve2/ip')
    assert r.get_json() == {'ip': '198.51.100.7', 'node': 'pve2', 'source': 'manager_get_node_ip'}
    assert down['names'] == ['pve2']


def test_an_xcp_ng_host_it_does_not_find_is_said_to_be_a_stand_in(api, seed):
    """The pool's host stood in under the source of a real address, so the dialog showed
    it as the node's (the page drops a *_fallback source)."""
    mgr = api.make_fake_manager('cluster_1', cluster_type='xcpng')
    mgr.host = '10.1.1.1'
    mgr._get_host_ip.return_value = '10.1.1.1'
    mgr.member_node_ip.side_effect = {'xh1': '10.1.1.11'}.get
    api.set_manager('cluster_1', mgr)
    c = api.as_user(_user(seed))
    assert c.get('/api/clusters/cluster_1/nodes/xh9/ip').get_json() == {
        'ip': '10.1.1.1', 'node': 'xh9', 'source': 'xcpng_fallback'}
    assert c.get('/api/clusters/cluster_1/nodes/xh1/ip').get_json() == {
        'ip': '10.1.1.11', 'node': 'xh1', 'source': 'xapi_host_address'}
