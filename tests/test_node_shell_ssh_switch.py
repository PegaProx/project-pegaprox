"""The node shell stays closed on a cluster with SSH switched off.

The switch is there to stop every SSH connection to the cluster's nodes, and its own
description names the node shell first. Neither shell asked it: both log in with what the
operator types into the dialog, outside _ssh_connect where the switch is read. The main
port handler refuses now before it looks the node up. The SSH server on port+2 is refused
by the main app's two answers it opens a shell with, the ws token check and cluster-creds,
so its own code decides nothing.

The guest terminal (PVE termproxy, a PVE API socket and no SSH) is not the switch's
business and stays open; it reads cluster-creds too and says so with console=term.

The script of the SSH server runs here with its calls to the main app answered by the real
app. paramiko is stopped at the connect, so "dialled" is (host, port) of the login.

MK Nov 2026
"""
import asyncio
import json
import types

import paramiko
import pytest

import pegaprox.api.vms as vms
from test_ha_v2_surface import _Resp, _ssh_server
from test_node_shell_target_1143 import _Talking, _let_go, _shell, _token  # noqa: F401

OFF = 'SSH is switched off for this cluster'
APP = 'http://pegaprox.test'
ADDRESSES = {'pve1': '10.0.0.1', 'pve2': '10.0.0.12', 'pve3': '10.0.0.13'}
SHELL = '/api/clusters/cluster_1/nodes/pve2/shellws'
TERM = '/api/clusters/cluster_1/vms/pve2/qemu/100/termwebsocket'


@pytest.fixture
def dialled(monkeypatch):
    seen = []

    class _Client(paramiko.SSHClient):
        def connect(self, hostname=None, port=22, **kw):
            seen.append((hostname, port))
            raise paramiko.AuthenticationException('stopped by the test')

    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    return seen


def _cluster(api, ssh_off, port=22, kind='pve', ssh_key=''):
    """A cluster whose nodes answer at ADDRESSES. 'pve' asks the manager's own rule,
    'pool' (XCP-ng) has none and answers by the switch alone."""
    from pegaprox.core.manager import PegaProxManager
    mgr = api.make_fake_manager('cluster_1', cluster_type='proxmox' if kind == 'pve' else 'xcpng')
    mgr.id = 'cluster_1'
    mgr.host = mgr.config.host = '10.0.0.1'
    mgr.api_port = 8006
    mgr._ssl_verify = False
    mgr.nodes = {n: {'node': n, 'status': 'online'} for n in ADDRESSES}
    mgr._cached_nodes = [{'node': n} for n in ADDRESSES]
    mgr.get_nodes.return_value = [{'node': n} for n in ADDRESSES]
    mgr.member_node_ip.side_effect = ADDRESSES.get
    mgr._get_node_ip.side_effect = ADDRESSES.get
    mgr.connect_to_proxmox.return_value = True
    mgr.mint_console_auth_ticket.return_value = 'PVE:root@pam:65F00000::sig'
    cfg = mgr.config
    cfg.name = 'c1'
    cfg.fallback_hosts = []
    cfg.ssh_disabled = ssh_off
    cfg.ssh_port = port
    cfg.ssh_key = ssh_key
    # an API token, no SSH password: the shell's login is the operator's own
    cfg.user, cfg.pass_ = 'pegaprox@pve!shell', 'token-secret'
    if kind == 'pve':
        mgr.ssh_blocked_reason = types.MethodType(PegaProxManager.ssh_blocked_reason, mgr)
    else:
        del mgr.ssh_blocked_reason
    api.set_manager('cluster_1', mgr)
    return mgr


def _admin(seed):
    return seed.user('root', role='admin')


def _script(api, monkeypatch, tmp_path, query, path=SHELL, websockets=None):
    """The SSH server's handler for one connection, its calls to the main app answered by
    the app itself. (what it said, the paths it asked)"""
    from pegaprox.api.realtime import console_server_secret
    monkeypatch.setenv('PEGAPROX_URL', APP)
    monkeypatch.setenv('PEGAPROX_CONSOLE_SECRET', console_server_secret())
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', str(tmp_path / 'known_hosts'))
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    ns, _asked = _ssh_server({})
    client = api.app.test_client()
    asked = []

    def get(url, cookies=None, headers=None, **kw):
        assert url.startswith(APP), url
        asked.append(url[len(APP):])
        for name, value in (cookies or {}).items():
            client.set_cookie(name, value, domain='localhost')
        r = client.get(url[len(APP):], headers=headers or {}, base_url='http://localhost')
        return _Resp(r.status_code, r.get_json(silent=True))

    ns['requests'] = types.SimpleNamespace(get=get, exceptions=ns['requests'].exceptions)
    if websockets is not None:
        ns['websockets'] = websockets
    ws = _Talking(f'{path}?{query}', json.dumps({'username': 'root', 'password': 'pw'}))
    asyncio.run(ns['ssh_handler'](ws))
    said = [json.loads(m) for m in ws.sent if isinstance(m, str) and m.startswith('{')]
    return said, asked


def _errors(said):
    return [m['message'] for m in said if m.get('status') == 'error']


def _way(api, seed, way):
    """The query the SSH server's shell is opened with: the page's ws token, or the old
    ?session= of the same account."""
    user = _admin(seed)
    if way == 'token':
        return f'token={_token(api, user)}'
    return f'session={api.as_user(user).session_id}'


# --- the switch closes every way in -------------------------------------------------------

@pytest.mark.parametrize('kind,ssh_key', [('pve', ''), ('pve', 'KEY'), ('pool', '')],
                         ids=['pve', 'pve-with-key', 'xcp-ng'])
def test_the_main_port_shell_stays_closed(api, seed, dialled, kind, ssh_key):
    mgr = _cluster(api, ssh_off=True, kind=kind, ssh_key=ssh_key)
    said = _shell(api, f'token={_token(api, _admin(seed))}')
    assert dialled == []
    assert [m['status'] for m in said] == ['error'], said
    assert OFF in said[0]['message']
    # refused before the node was looked up or the cluster asked anything
    mgr.member_node_ip.assert_not_called()
    mgr.connect_to_proxmox.assert_not_called()


@pytest.mark.parametrize('way', ['token', 'session'])
@pytest.mark.parametrize('kind', ['pve', 'pool'], ids=['pve', 'xcp-ng'])
def test_the_ssh_server_shell_stays_closed(api, seed, dialled, monkeypatch, tmp_path, way, kind):
    _cluster(api, ssh_off=True, kind=kind)
    said, asked = _script(api, monkeypatch, tmp_path, _way(api, seed, way))
    assert dialled == []
    assert 'need_credentials' not in [m.get('status') for m in said], said
    errors = _errors(said)
    assert len(errors) == 1 and OFF in errors[0], said
    # it is the main app's answer that closed it
    assert any(p.startswith(('/api/ws/token/validate', '/api/internal/cluster-creds/')) for p in asked)


def test_the_two_answers_say_why_and_look_nothing_up(api, seed, monkeypatch):
    """What the SSH server gets: 409 SSH_DISABLED with the sentence the page shows, no
    node address, no PVE ticket, and no lookup of the node first. The page opens its login
    dialog again for a message with Login, auth or Host in it; this one is final."""
    from pegaprox.api.realtime import CONSOLE_SERVER_HEADER, console_server_secret
    mgr = _cluster(api, ssh_off=True)
    user = _admin(seed)
    tok = _token(api, user)
    r = api.anon().get(f'/api/ws/token/validate?token={tok}&cluster_id=cluster_1&node=pve2&shell=node',
                       headers={CONSOLE_SERVER_HEADER: console_server_secret()})
    client = api.app.test_client()
    client.set_cookie('session', api.as_user(user).session_id, domain='localhost')
    c = client.get('/api/internal/cluster-creds/cluster_1', base_url='http://localhost')
    for answer in (r, c):
        assert answer.status_code == 409, answer.data
        body = answer.get_json()
        assert body['code'] == 'SSH_DISABLED' and OFF in body['error']
        assert not any(w in body['error'] for w in ('Login', 'auth', 'Host'))
        assert 'node_ips' not in body and 'cluster_context' not in body
    mgr.member_node_ip.assert_not_called()
    mgr._get_node_ip.assert_not_called()
    mgr.mint_console_auth_ticket.assert_not_called()


# --- counterproof: without the switch the shell opens, on the cluster's port -------------------

@pytest.mark.parametrize('port', [22, 2222])
def test_the_main_port_shell_opens_without_the_switch(api, seed, dialled, port):
    _cluster(api, ssh_off=False, port=port)
    said = _shell(api, f'token={_token(api, _admin(seed))}')
    assert [m['ip'] for m in said if m.get('status') == 'need_credentials'] == ['10.0.0.12']
    assert dialled == [('10.0.0.12', port)]


@pytest.mark.parametrize('port', [22, 2222])
@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_ssh_server_shell_opens_without_the_switch(api, seed, dialled, monkeypatch, tmp_path,
                                                       way, port):
    _cluster(api, ssh_off=False, port=port)
    said, _asked = _script(api, monkeypatch, tmp_path, _way(api, seed, way))
    assert [m['ip'] for m in said if m.get('status') == 'need_credentials'] == ['10.0.0.12'], said
    assert dialled == [('10.0.0.12', port)]


@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_guest_terminal_is_no_business_of_the_switch(api, seed, dialled, monkeypatch,
                                                          tmp_path, way):
    """The PVE termproxy console goes to PVE's API socket, no SSH: with the switch on it gets
    its allow-list and its ticket as before and goes on to connect to PVE."""
    _cluster(api, ssh_off=True)
    tried = []

    async def connect(url, **kw):
        tried.append(url.split('?')[0])
        raise ConnectionRefusedError('stopped by the test')

    said, asked = _script(api, monkeypatch, tmp_path,
                          f'{_way(api, seed, way)}&ticket=PVEVNC:x&port=5900&host=10.0.0.1&user=root@pam',
                          path=TERM, websockets=types.SimpleNamespace(connect=connect))
    assert tried == ['wss://10.0.0.1:8006/api2/json/nodes/pve2/qemu/100/vncwebsocket'], (said, asked)
    assert not any(OFF in e for e in _errors(said))
    assert dialled == []
