"""The node shell stays closed on a cluster with SSH switched off.

The switch is there to stop every SSH connection to the cluster's nodes, and its own
description names the node shell first. Neither shell asked it: both log in with what the
operator types into the dialog, outside _ssh_connect where the switch is read. The main
port handler, the only node shell since the SSH server on port+2 is gone, refuses now
before it looks the node up. /api/ws/token/validate, which that server opened its shell
with, still answers a node shell on such a cluster with the reason.

The guest terminal (PVE termproxy, a PVE API socket and no SSH) is not the switch's
business and stays open; it moved from port+2 to the main port as well.

paramiko is stopped at the connect, so "dialled" is (host, port) of the login, and
websocket-client is stopped at the connect to PVE.

MK Nov 2026
"""
import json
import types

import paramiko
import pytest

import pegaprox.api.vms as vms
from test_node_shell_target_1143 import _let_go, _shell, _token  # noqa: F401

OFF = 'SSH is switched off for this cluster'
ADDRESSES = {'pve1': '10.0.0.1', 'pve2': '10.0.0.12', 'pve3': '10.0.0.13'}
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


def _shell_by(api, seed, way, node='pve2'):
    """The main port shell, opened with the page's ws token or the old ?session= of the
    same account."""
    user = _admin(seed)
    if way == 'token':
        return _shell(api, f'token={_token(api, user)}', node=node)
    return _shell(api, f'session={api.as_user(user).session_id}', node=node)


def _errors(said):
    return [m['message'] for m in said if m.get('status') == 'error']


class _Page:
    def __init__(self):
        self.sent = []
        self.closed = None

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        return None

    def close(self, reason=None, message=None):
        self.closed = (reason, message)


def _terminal(api, query):
    view = api.app.view_functions['__flask_sock.vm_terminal_websocket_proxy'].__wrapped__
    ws = _Page()
    with api.app.test_request_context(f'{TERM}?{query}'):
        view(ws, 'cluster_1', 'pve2', 'qemu', 100)
    return [json.loads(m) for m in ws.sent], ws


# --- the switch closes the shell -----------------------------------------------------------

@pytest.mark.parametrize('way', ['token', 'session'])
@pytest.mark.parametrize('kind,ssh_key', [('pve', ''), ('pve', 'KEY'), ('pool', '')],
                         ids=['pve', 'pve-with-key', 'xcp-ng'])
def test_the_main_port_shell_stays_closed(api, seed, dialled, kind, ssh_key, way):
    mgr = _cluster(api, ssh_off=True, kind=kind, ssh_key=ssh_key)
    said = _shell_by(api, seed, way)
    assert dialled == []
    assert [m['status'] for m in said] == ['error'], said
    assert OFF in said[0]['message']
    # refused before the node was looked up or the cluster asked anything
    mgr.member_node_ip.assert_not_called()
    mgr.connect_to_proxmox.assert_not_called()


def test_the_validate_answer_says_why_and_looks_nothing_up(api, seed):
    """What /api/ws/token/validate answers a node shell on such a cluster: 409 SSH_DISABLED
    with the sentence the page shows, no node address, no PVE ticket, and no lookup of the
    node first. The page opens its login dialog again for a message with Login, auth or
    Host in it; this one is final. cluster-creds, the other answer, is gone."""
    mgr = _cluster(api, ssh_off=True)
    user = _admin(seed)
    r = api.anon().get(f'/api/ws/token/validate?token={_token(api, user)}&cluster_id=cluster_1'
                       '&node=pve2&shell=node')
    assert r.status_code == 409, r.data
    body = r.get_json()
    assert body['code'] == 'SSH_DISABLED' and OFF in body['error']
    assert not any(w in body['error'] for w in ('Login', 'auth', 'Host'))
    assert 'node_ips' not in body and 'cluster_context' not in body
    mgr.member_node_ip.assert_not_called()
    mgr._get_node_ip.assert_not_called()
    mgr.mint_console_auth_ticket.assert_not_called()
    assert api.as_user(user).get('/api/internal/cluster-creds/cluster_1').status_code == 404
    # counterproof: the guest terminal's call (no shell=node) is not the switch's business
    r = api.anon().get(f'/api/ws/token/validate?token={_token(api, user)}&cluster_id=cluster_1&node=pve2')
    assert r.status_code == 200, r.data


# --- counterproof: without the switch the shell opens, on the cluster's port -------------------

@pytest.mark.parametrize('port', [22, 2222])
@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_main_port_shell_opens_without_the_switch(api, seed, dialled, port, way):
    _cluster(api, ssh_off=False, port=port)
    said = _shell_by(api, seed, way)
    assert [m['ip'] for m in said if m.get('status') == 'need_credentials'] == ['10.0.0.12'], said
    assert dialled == [('10.0.0.12', port)]


@pytest.mark.parametrize('way', ['token', 'session'])
def test_the_guest_terminal_is_no_business_of_the_switch(api, seed, dialled, monkeypatch, way):
    """The PVE termproxy console goes to PVE's API socket, no SSH: with the switch on it
    gets its ticket and goes on to connect to PVE, now from the main port."""
    import websocket
    _cluster(api, ssh_off=True)
    tried = []

    def connect(url, **kw):
        tried.append((url.split('?')[0], kw.get('header')))
        raise ConnectionRefusedError('stopped by the test')
    monkeypatch.setattr(websocket, 'create_connection', connect)
    user = _admin(seed)
    auth = f'token={_token(api, user)}' if way == 'token' else f'session={api.as_user(user).session_id}'
    said, ws = _terminal(api, f'{auth}&ticket=PVEVNC:x&port=5900&host=10.0.0.1&user=root@pam')
    assert tried == [('wss://10.0.0.1:8006/api2/json/nodes/pve2/qemu/100/vncwebsocket',
                      {'Cookie': 'PVEAuthCookie=PVE:root@pam:65F00000::sig'})], said
    assert _errors(said) == ['PVE WS connect failed: ConnectionRefusedError']
    assert ws.closed == (1011, 'PVE WS connect failed: ConnectionRefusedError')
    assert not any(OFF in e for e in _errors(said))
    assert dialled == []
