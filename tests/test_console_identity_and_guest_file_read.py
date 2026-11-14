"""Who a console opens for, read how, and who may read a guest's files (#1059, #1101, #1116).

#1116 - POST /api/ws/token records the role of the API token that minted it, and the
three VNC handlers then authorized the stored account instead. An admin-owned token
held to viewer or to a tenant role opened a console on every VM of every tenant.

#1101 - the same handlers read the account with load_users().get(name, {}). When that
whole-table read fails it answers {}, and {} is a role-less viewer in the default
tenant, whose empty cluster list means every cluster.

#1059 - guest-file-read hands back any file of the guest, read as root by the agent,
and asked for vm.view.

The handlers run for real: the HTTP route through the app, the flask-sock one through
its view, the standalone one on 5001 as its coroutine. PVE is faked at the websocket
they dial, so "a console opened" means "the handler dialled PVE".

NS Oct 2026
"""
import asyncio
import time
import types

import pytest
import websocket

import pegaprox.utils.auth as authmod
import pegaprox.utils.rbac as rbac
from pegaprox.api import vms

_PASSTHROUGH = 'pve_port=5901&pve_ticket=PVEVNC:from-the-browser'


class _TokenCluster:
    """A cluster on an API token. With the browser's vncproxy ticket passed through, a
    handler logs in nowhere and goes straight to the PVE websocket."""
    cluster_type = 'proxmox'
    host = auth_host = '10.0.0.9'
    api_port = 8006
    is_connected = False        # keeps the app's background loops off it
    _ssl_verify = False
    _using_api_token = True
    _ticket = None

    def __init__(self, cid):
        self.cluster_id = cid
        self._api_token = 'root@pam!c=not-a-secret'
        self.config = types.SimpleNamespace(user='root@pam!c', pass_='not-a-secret', name=cid,
                                            vnc_tunnel=False, ssh_port=22, ssh_key='')


class _PveSocket:
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


@pytest.fixture
def dialled(monkeypatch):
    calls = []

    def _create(url, header=None, **k):
        calls.append(url)
        return _PveSocket()

    def _no_login(req, *a, **k):
        raise AssertionError(f'unexpected PVE call {getattr(req, "full_url", req)}')

    monkeypatch.setattr(websocket, 'create_connection', _create)
    monkeypatch.setattr('pegaprox.core.manager.pve_opener',
                        lambda context=None: types.SimpleNamespace(open=_no_login))
    return calls


class _Browser:
    """The websockets-library side of the standalone handler."""

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


class _SyncBrowser:
    connected = False

    def __init__(self):
        self.sent = []

    def receive(self, timeout=None):
        return None

    def send(self, data):
        self.sent.append(data)

    def close(self, *a, **k):
        pass


@pytest.fixture(scope='module')
def standalone():
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
    import gevent
    loop = got['loop']
    loop.call_soon_threadsafe(loop.stop)
    for _ in range(200):
        if not loop.is_running():
            break
        gevent.sleep(0.01)
    yield got['handler']


KINDS = ['http', 'flask_sock', 'standalone']


def _opens(kind, api, standalone, dialled, cid, auth_query):
    """True when the handler got past authorization."""
    path = f'/api/clusters/{cid}/vms/pve1/qemu/100/vncwebsocket?{auth_query}&{_PASSTHROUGH}'
    if kind == 'http':
        # a plain GET that passed the gate is answered 426, upgrade required
        r = api.anon().get(path)
        assert r.status_code in (401, 403, 426), r.get_data(as_text=True)
        return r.status_code == 426
    before = len(dialled)
    if kind == 'flask_sock':
        view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__
        with api.app.test_request_context(path):
            view(_SyncBrowser(), cid, 'pve1', 'qemu', 100)
    else:
        asyncio.run(standalone(_Browser(path)))
    return len(dialled) > before


@pytest.fixture
def estate(api, seed):
    """acme owns cluster_1, other owns cluster_far. ops is a role of acme."""
    seed.tenant('acme', clusters=['cluster_1'])
    seed.tenant('other', clusters=['cluster_far'])
    for cid in ('cluster_1', 'cluster_far'):
        api.set_manager(cid, _TokenCluster(cid))
        with rbac._pool_cache_lock:
            rbac._pool_membership_cache[cid] = {'data': {}, 'timestamp': time.time(),
                                                'refreshing': False}
    assert rbac.save_custom_roles({
        'global': {'auditor': {'name': 'auditor', 'permissions': ['vm.view', 'cluster.view']}},
        'tenants': {'acme': {'ops': {'name': 'ops', 'permissions': [
            'vm.view', 'vm.console', 'cluster.view', 'node.view', 'node.shell']}}},
    })
    rbac.invalidate_roles_cache()
    return seed


def _api_ws_token(api, owner, role):
    """A ws token minted the way a script does it: with an API token, through the route."""
    res = authmod.create_api_token(owner, f'ci-{role}', role=role)
    assert 'token' in res, res
    r = api.anon().post('/api/ws/token', headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 200, r.get_data(as_text=True)
    return 'token=' + r.get_json()['token']


def _session_ws_token(api, user):
    r = api.as_user(user).post('/api/ws/token')
    assert r.status_code == 200, r.get_data(as_text=True)
    return 'token=' + r.get_json()['token']


# --- #1116: the console is the token's, not its owner's -----------------------------

@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('role', ['viewer', 'ops'])
def test_an_admins_scoped_token_opens_no_console_outside_its_reach(
        api, estate, standalone, dialled, kind, role):
    estate.user('root', role='admin', tenant_id='acme')
    q = _api_ws_token(api, 'root', role)
    assert not _opens(kind, api, standalone, dialled, 'cluster_far', q), (
        f'a {role} token of an admin opened a console on another tenant\'s cluster')


@pytest.mark.parametrize('kind', KINDS)
def test_an_admins_token_without_console_rights_opens_no_console(
        api, estate, standalone, dialled, kind):
    estate.user('root', role='admin', tenant_id='acme')
    q = _api_ws_token(api, 'root', 'auditor')
    assert not _opens(kind, api, standalone, dialled, 'cluster_1', q), (
        'a token whose role carries no vm.console opened one through its owner')


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('role', ['viewer', 'ops'])
def test_a_scoped_token_still_opens_the_consoles_it_reaches(
        api, estate, standalone, dialled, kind, role):
    estate.user('root', role='admin', tenant_id='acme')
    q = _api_ws_token(api, 'root', role)
    assert _opens(kind, api, standalone, dialled, 'cluster_1', q)


@pytest.mark.parametrize('kind', KINDS)
def test_an_admin_token_and_an_admin_keep_every_console(api, estate, standalone, dialled, kind):
    root = estate.user('root', role='admin', tenant_id='acme')
    assert _opens(kind, api, standalone, dialled, 'cluster_far', _api_ws_token(api, 'root', 'admin'))
    assert _opens(kind, api, standalone, dialled, 'cluster_far', _session_ws_token(api, root))


@pytest.mark.parametrize('kind', KINDS)
def test_a_signed_in_viewer_keeps_the_console_of_their_tenant(api, estate, standalone, dialled, kind):
    vera = estate.user('vera', role='viewer', tenant_id='acme')
    assert _opens(kind, api, standalone, dialled, 'cluster_1', _session_ws_token(api, vera))
    assert not _opens(kind, api, standalone, dialled, 'cluster_far', _session_ws_token(api, vera))


# --- #1101: an account read that failed is not a default-tenant viewer ---------------

@pytest.mark.parametrize('kind', KINDS)
def test_a_user_table_read_that_came_back_empty_opens_no_foreign_console(
        api, estate, standalone, dialled, kind, monkeypatch):
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    own, foreign = _session_ws_token(api, alice), _session_ws_token(api, alice)
    # what load_users() answers when the whole-table read fails
    monkeypatch.setattr(vms, 'load_users', lambda *a, **k: {})
    assert not _opens(kind, api, standalone, dialled, 'cluster_far', foreign), (
        'an empty user table read made a tenant user a default-tenant viewer')
    assert _opens(kind, api, standalone, dialled, 'cluster_1', own)


class _Unreadable:
    """The account store answers nothing about anyone."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def get_user(self, username):
        raise RuntimeError('database is locked')


@pytest.mark.parametrize('kind', KINDS)
def test_an_account_that_cannot_be_read_opens_no_console(
        api, estate, standalone, dialled, kind, monkeypatch):
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    q = _session_ws_token(api, alice)
    monkeypatch.setattr(vms, 'load_users', lambda *a, **k: {})
    real = authmod.get_db()
    monkeypatch.setattr(authmod, 'get_db', lambda: _Unreadable(real))
    assert not _opens(kind, api, standalone, dialled, 'cluster_far', q)


def _ticket_cluster(api):
    m = api.make_fake_manager(
        cluster_id='cluster_1',
        get_vnc_ticket={'success': True, 'ticket': 'PVEVNC:t', 'port': 5900},
        get_spice_ticket={'success': True, 'data': {'host': 'pvespiceproxy:x', 'password': 'p'}})
    m.config.name = 'c1'
    api.set_manager('cluster_1', m)
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {'data': {}, 'timestamp': time.time(),
                                                    'refreshing': False}
    return m


_TICKETS = {'console': ('get', 'get_vnc_ticket'), 'spice': ('get', 'get_spice_ticket')}


@pytest.mark.parametrize('route', sorted(_TICKETS))
def test_a_failed_user_table_read_hands_out_no_console_ticket(api, estate, monkeypatch, route):
    """The REST tickets keep their cluster gate on the account's own row, so here the
    empty read 'only' turned a role without vm.console into a viewer who has it."""
    m = _ticket_cluster(api)
    aud = estate.user('aud', role='auditor', tenant_id='acme')
    monkeypatch.setattr(authmod, 'load_users', lambda *a, **k: {})
    verb, method = _TICKETS[route]
    r = getattr(api.as_user(aud), verb)(f'/api/clusters/cluster_1/vms/pve1/qemu/100/{route}')
    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    getattr(m, method).assert_not_called()


@pytest.mark.parametrize('route', sorted(_TICKETS))
def test_a_viewer_still_gets_a_console_ticket(api, estate, route):
    m = _ticket_cluster(api)
    vera = estate.user('vera', role='viewer', tenant_id='acme')
    verb, method = _TICKETS[route]
    r = getattr(api.as_user(vera), verb)(f'/api/clusters/cluster_1/vms/pve1/qemu/100/{route}')
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    getattr(m, method).assert_called_once()


def _esxi(linked):
    from unittest.mock import MagicMock
    import pegaprox.globals as ppglobals
    m = MagicMock(name='esx1')
    m.name = 'esx1'
    m.linked_clusters = list(linked)
    m.get_vm.return_value = {'name': 'guest'}
    m.get_vm_console_ticket.return_value = {'data': {'ticket': 'wss://esx/ticket'}}
    ppglobals.vmware_managers['esx1'] = m
    return m


def test_a_failed_user_table_read_opens_no_esxi_console_of_another_tenant(api, estate, monkeypatch):
    """No cluster gate in front of this one: the tenant check inside the per-VM function
    is the only one, and {} sits in the default tenant, which reaches everything."""
    m = _esxi(['cluster_far'])
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    monkeypatch.setattr(authmod, 'load_users', lambda *a, **k: {})
    r = api.as_user(alice).post('/api/vmware/esx1/vms/vm-7/console')
    assert r.status_code == 403, r.get_data(as_text=True)[:200]
    m.get_vm_console_ticket.assert_not_called()


def test_an_esxi_console_of_ones_own_tenant_still_opens(api, estate):
    m = _esxi(['cluster_1'])
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    r = api.as_user(alice).post('/api/vmware/esx1/vms/vm-7/console')
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    m.get_vm_console_ticket.assert_called_once()


def _esxi_readable(linked):
    """An ESXi manager whose detail/perf calls return real dicts to jsonify."""
    m = _esxi(linked)
    m.get_vm.return_value = {'data': {'name': 'guest', 'vm': 'vm-7'}}
    m.get_vm_guest_info.return_value = {'data': {'hostname': 'guest'}}
    m.get_vm_performance.return_value = {'data': {'cpu': 1}}
    m.list_vms.return_value = {'data': [{'vm': 'vm-7', 'name': 'guest'}]}
    m.get_vms.return_value = {'data': [{'vm': 'vm-7', 'name': 'guest'}]}
    return m


# The console is not the only ESXi route that answers for a VM. detail, performance
# and watch gate the tenant through check_vmware_access, which read the whole users
# table: the same empty read #1101 fixed for the console reached a foreign tenant's
# ESXi inventory through every one of them.
@pytest.mark.parametrize('suffix', ['', '/performance'])
def test_a_failed_user_table_read_reads_no_esxi_vm_of_another_tenant(
        api, estate, monkeypatch, suffix):
    m = _esxi_readable(['cluster_far'])
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    monkeypatch.setattr(authmod, 'load_users', lambda *a, **k: {})
    r = api.as_user(alice).get(f'/api/vmware/esx1/vms/vm-7{suffix}')
    assert r.status_code == 403, r.get_data(as_text=True)[:200]


def test_a_failed_user_table_read_watches_no_esxi_vm_of_another_tenant(
        api, estate, monkeypatch):
    _esxi_readable(['cluster_far'])
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    monkeypatch.setattr(authmod, 'load_users', lambda *a, **k: {})
    r = api.as_user(alice).post('/api/vmware/esx1/vms/vm-7/watch')
    assert r.status_code == 403, r.get_data(as_text=True)[:200]


@pytest.mark.parametrize('suffix', ['', '/performance'])
def test_an_esxi_vm_of_ones_own_tenant_still_reads(api, estate, suffix):
    _esxi_readable(['cluster_1'])
    alice = estate.user('alice', role='viewer', tenant_id='acme')
    r = api.as_user(alice).get(f'/api/vmware/esx1/vms/vm-7{suffix}')
    assert r.status_code == 200, r.get_data(as_text=True)[:200]


def _node_shell(api, session_id):
    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    ws = _SyncBrowser()
    with api.app.test_request_context(
            f'/api/clusters/cluster_1/nodes/pve1/shellws?session={session_id}'):
        view(ws, 'cluster_1', 'pve1')
    return ' '.join(str(s) for s in ws.sent)


def test_an_account_that_cannot_be_read_opens_no_node_shell(api, estate, monkeypatch):
    """Was closed before by luck (an empty record has no node.shell); stays as a guard."""
    root = estate.user('root', role='admin', tenant_id='acme')
    sid = api.as_user(root).session_id
    monkeypatch.setattr(vms, 'load_users', lambda *a, **k: {})
    real = authmod.get_db()
    monkeypatch.setattr(authmod, 'get_db', lambda: _Unreadable(real))
    said = _node_shell(api, sid)
    assert 'Invalid session' in said or 'Permission denied' in said, said


def test_an_admin_still_gets_past_the_node_shell_gate(api, estate, monkeypatch):
    root = estate.user('root', role='admin', tenant_id='acme')
    sid = api.as_user(root).session_id
    import pegaprox.globals as ppglobals
    ppglobals.cluster_managers.pop('cluster_1', None)
    said = _node_shell(api, sid)
    # past every permission check, the next thing it wants is the cluster itself
    assert 'Cluster not found' in said or 'paramiko' in said, said


# --- the SSH server's validate call takes the same identity ---------------------------

def test_a_custom_role_token_is_held_to_what_its_owner_has_today(api, estate):
    """A tenant role keeps its name on a token, so no numeric floor ever ran for it on
    this route: a token minted while its owner was an admin kept node.shell after the
    owner was made a viewer."""
    estate.user('lead', role='admin', tenant_id='acme')
    res = authmod.create_api_token('lead', 'ci-ops', role='ops')
    assert 'token' in res, res
    estate.user('lead', role='viewer', tenant_id='acme')
    r = api.anon().post('/api/ws/token', headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 200, r.get_data(as_text=True)
    tok = r.get_json()['token']
    v = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&shell=node')
    assert v.status_code == 403, v.get_data(as_text=True)


def test_a_signed_in_user_keeps_the_node_shell_their_tenant_grants(api, estate):
    """Not every caller of this route is a token. A signed-in account was floored by its
    own login role as well, which threw away a tenant override that grants node.shell:
    the in-process shell let them in and the SSH server's shell did not."""
    olga = estate.user('olga', role='viewer', tenant_id='acme',
                       tenant_permissions={'acme': {'role': 'user', 'extra': ['node.shell']}})
    tok = _session_ws_token(api, olga).split('=', 1)[1]
    v = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&shell=node')
    assert v.status_code == 200, v.get_data(as_text=True)


def test_a_viewer_token_of_an_admin_gets_no_node_shell(api, estate):
    estate.user('root', role='admin', tenant_id='acme')
    tok = _api_ws_token(api, 'root', 'viewer').split('=', 1)[1]
    v = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&shell=node')
    assert v.status_code == 403, v.get_data(as_text=True)


# --- #1059: the guest agent's file read --------------------------------------------

def _agent_cluster(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.host, m.api_port = '10.0.0.9', 8006
    m._api_post.return_value = types.SimpleNamespace(
        status_code=200, text='',
        json=lambda: {'data': {'content': 'root:$6$secret:19000::::::', 'truncated': False}})
    api.set_manager('cluster_1', m)
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache['cluster_1'] = {
            'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(), 'refreshing': False}
    return m


_READ = '/api/clusters/cluster_1/vms/pve1/qemu/100/guest-file-read'


def test_a_viewer_reads_no_guest_file(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    vera = seed.user('vera', role='viewer', tenant_id='acme')
    m = _agent_cluster(api)
    r = api.as_user(vera).post(_READ, json={'file': '/etc/shadow'})
    assert r.status_code == 403, r.get_data(as_text=True)
    m._api_post.assert_not_called()


def test_a_pool_grant_without_config_reads_no_guest_file(api, seed):
    """A grant on the pool makes its guests visible (vm.view), which was all this asked."""
    seed.tenant('home', clusters=['cluster_home'])
    paul = seed.user('paul', role='user', tenant_id='home')
    seed.pool('cluster_1', 'pool_1', 'paul', ['pool.view', 'vm.start', 'vm.console'])
    m = _agent_cluster(api)
    r = api.as_user(paul).post(_READ, json={'file': '/etc/shadow'})
    assert r.status_code == 403, r.get_data(as_text=True)
    m._api_post.assert_not_called()


@pytest.mark.parametrize('role', ['user', 'admin'])
def test_an_operator_and_an_admin_still_read_guest_files(api, seed, role):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('ops1', role=role, tenant_id='acme')
    m = _agent_cluster(api)
    r = api.as_user(u).post(_READ, json={'file': '/etc/hostname'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['content'].startswith('root:')
    m._api_post.assert_called_once()


def test_a_pool_grant_with_config_still_reads_guest_files(api, seed):
    seed.tenant('home', clusters=['cluster_home'])
    paul = seed.user('paul', role='user', tenant_id='home')
    seed.pool('cluster_1', 'pool_1', 'paul', ['pool.view', 'vm.config'])
    _agent_cluster(api)
    r = api.as_user(paul).post(_READ, json={'file': '/etc/hostname'})
    assert r.status_code == 200, r.get_data(as_text=True)
