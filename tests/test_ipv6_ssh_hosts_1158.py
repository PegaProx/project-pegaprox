"""SSH to an IPv6 host takes the plain address, and the pin checks the one it dials (#1158).

PegaProxManager.host is bracketed for URLs. Handed on as it is to a socket, to paramiko or
to ssh, '[2001:db8::10]' does not resolve, so on an IPv6-only control plane every node
command through _ssh_exec, the console's SSH tunnel, adding and removing a node, the deep
storage rescan and the SSH leg of the migration engine failed.

Besides "it connects now" these hold: the transport guard, the host-key pin and the
connect see the same name whichever spelling came in, so brackets are no way around a
pinned key, and a host typed into the join form is still only an address or a name.
The wire, paramiko and the subprocess are stubs, nothing leaves the machine.
"""
import shlex
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

paramiko = pytest.importorskip('paramiko')

import pegaprox.utils.ssh as ssh_mod
import pegaprox.utils.ssh_security as sshsec
from pegaprox.core import ha_transport

V6 = '2001:db8::10'
BRACKETED = f'[{V6}]'
CID = 'c1'


@pytest.fixture(autouse=True)
def known_hosts(tmp_path, monkeypatch):
    # nothing in here may pin into the checkout's config/.ssh_known_hosts
    path = tmp_path / 'known_hosts'
    monkeypatch.setattr(sshsec, '_KNOWN_HOSTS', str(path))
    return path


def _pin(path, name, key):
    keys = paramiko.hostkeys.HostKeys()
    keys.add(name, key.get_name(), key)
    keys.save(str(path))


class _Transport:
    """A paramiko.Transport without a wire: presents state.presented and notes every
    credential that would have gone out."""

    def __init__(self, state):
        self._state = state

    def connect(self):
        pass

    def get_remote_server_key(self):
        return self._state.presented

    def auth_interactive(self, user, handler):
        self._state.sent.append('ki')

    def auth_password(self, user, password):
        self._state.sent.append('password')

    def is_authenticated(self):
        return False

    def close(self):
        pass


# --- _ssh_exec, behind _pve_node_exec and its 248 callers --------------------------------

@pytest.fixture
def wire(monkeypatch):
    """Where each way out of _ssh_exec goes. All of them fail, so a call runs down to the
    sshpass leg, which answers."""
    import socket
    seen = types.SimpleNamespace(tcp=[], guard=[], m3=[], argv=None, cmd_host=None)

    def tcp(addr, timeout=None, **kw):
        seen.tcp.append(addr)
        raise OSError('no network in a test')

    class _Client:
        def load_host_keys(self, *a):
            pass

        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, hostname, **kw):
            seen.m3.append(hostname)
            raise OSError('no network in a test')

    def node_cmd(argv, **kw):
        seen.argv, seen.cmd_host = list(argv), kw.get('host')
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')

    monkeypatch.setattr(socket, 'create_connection', tcp)
    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(ha_transport, 'guard_ssh', lambda host, cmd='', again=False: seen.guard.append(host))
    monkeypatch.setattr(ha_transport, 'node_cmd', node_cmd)
    return seen


@pytest.mark.parametrize('spelling', [BRACKETED, V6], ids=['bracketed', 'plain'])
def test_every_way_out_of_ssh_exec_dials_the_plain_address(wire, spelling):
    rc, out, _ = ssh_mod._ssh_exec(spelling, 'root', 'pw', 'uptime')

    assert (rc, out) == (0, 'ok')
    # the two keyboard-interactive ways open their own socket, then paramiko's connect,
    # then sshpass + ssh
    assert wire.tcp == [(V6, 22), (V6, 22)]
    assert wire.m3 == [V6]
    assert wire.argv[-5:] == ['-l', 'root', '--', V6, 'uptime']
    assert wire.cmd_host == V6
    # and the guard was asked about the host that is dialled, not about a spelling of it
    assert wire.guard == [V6]


def test_brackets_around_anything_but_an_address_stay_on(wire):
    odd = '[-oProxyCommand=touch /tmp/x]'
    ssh_mod._ssh_exec(odd, 'root', 'pw', 'uptime')

    assert wire.tcp[0] == (odd, 22)
    # behind the '--', where ssh reads no option
    assert wire.argv[-3:-1] == ['--', odd]


@pytest.mark.parametrize('given,want', [
    ('[fe80::1%eth0]', 'fe80::1%eth0'),
    ('[fe80::1%vmbr0.20]', 'fe80::1%vmbr0.20'),
    ('[fe80::1%$(id)]', '[fe80::1%$(id)]'),
    ('[fe80::1%-oProxyCommand=x]', '[fe80::1%-oProxyCommand=x]'),
    ('[fe80::1% eth0]', '[fe80::1% eth0]'),
])
def test_a_zone_comes_off_its_brackets_only_as_an_interface_name(given, want):
    # ipaddress itself takes any text after '%'
    assert ssh_mod.bare_host(given) == want


@pytest.fixture
def pinned_node(monkeypatch, known_hosts, wire):
    """V6 has a pinned key; the node presents state.presented."""
    import socket
    state = types.SimpleNamespace(sent=[], presented=None, refused=[],
                                  pinned=paramiko.ECDSAKey.generate())
    _pin(known_hosts, V6, state.pinned)
    monkeypatch.setattr(socket, 'create_connection', lambda addr, timeout=None, **kw: object())
    monkeypatch.setattr(paramiko, 'Transport', lambda sock: _Transport(state))
    real = ssh_mod.verify_transport_host_key

    def verify(transport, hostname, pm, port=22):
        try:
            return real(transport, hostname, pm, port=port)
        except Exception as e:
            state.refused.append((hostname, type(e).__name__))
            raise
    monkeypatch.setattr(ssh_mod, 'verify_transport_host_key', verify)
    return state


@pytest.mark.parametrize('spelling', [BRACKETED, V6], ids=['bracketed', 'plain'])
def test_a_pinned_key_holds_whichever_spelling_comes_in(pinned_node, wire, spelling):
    pinned_node.presented = paramiko.ECDSAKey.generate()

    ssh_mod._ssh_exec(spelling, 'root', 'pw', 'uptime')

    # both keyboard-interactive ways met the pin under the plain name and stopped before
    # a password went out. With the brackets kept, '[2001:db8::10]' was a host never
    # seen before and its key was taken on first use
    assert pinned_node.refused == [(V6, 'BadHostKeyException')] * 2
    assert pinned_node.sent == []
    # the ssh fallback checks the same file for the same name
    assert f'UserKnownHostsFile={sshsec._KNOWN_HOSTS}' in wire.argv
    assert wire.argv[-2] == V6


def test_the_pinned_key_itself_gets_through(pinned_node, wire):
    """Counterproof: the refusal above is the pin talking, not a fake that cannot pass."""
    pinned_node.presented = pinned_node.pinned

    ssh_mod._ssh_exec(BRACKETED, 'root', 'pw', 'uptime')

    assert pinned_node.refused == []
    assert pinned_node.sent == ['ki', 'ki']


# --- the console's SSH tunnel ------------------------------------------------------------

@pytest.mark.parametrize('given,dialled', [(BRACKETED, V6), (V6, V6), ('10.0.0.7', '10.0.0.7'),
                                           ('pve1.lab', 'pve1.lab')])
def test_the_console_tunnel_logs_in_at_the_plain_address(monkeypatch, given, dialled):
    from pegaprox.utils import vnc_tunnel
    tried = []

    def connect(self, **kw):
        tried.append(kw['hostname'])
        raise paramiko.AuthenticationException('not in a test')
    monkeypatch.setattr(paramiko.SSHClient, 'connect', connect)

    with pytest.raises(paramiko.AuthenticationException):
        vnc_tunnel.SshVncTunnelPool()._get_or_create_client(CID, given, 'root', 22, '', 'pw')
    assert tried == [dialled]


# --- adding and removing a node ----------------------------------------------------------

@pytest.mark.parametrize('typed', [BRACKETED, V6, '2001:DB8:0:0::10', '[2001:0db8::0010]'])
def test_a_typed_ipv6_node_address_becomes_one_plain_form(typed):
    from pegaprox.api.vms import _validate_host
    assert _validate_host(typed) == V6


@pytest.mark.parametrize('typed', ['10.0.0.5', 'pve1', 'pve1.lab.example'])
def test_names_and_ipv4_come_back_as_typed(typed):
    from pegaprox.api.vms import _validate_host
    assert _validate_host(typed) == typed


@pytest.mark.parametrize('typed', [
    '[-oProxyCommand=touch x]', '-oProxyCommand=x', 'fe80::1%eth0', '[fe80::1%eth0]',
    'fe80::1%;id', '[2001:db8::10]:22', '2001:db8::10;id', '[2001:db8::g]',
    '[[2001:db8::10]]', 'pve1:22', '[pve1]', '[10.0.0.5]', 'a b', '$(id)', '', None])
def test_anything_else_typed_there_is_refused(typed):
    from pegaprox.api.vms import _validate_host
    assert _validate_host(typed) is None


class _AuthFailed(Exception):
    pass


@pytest.fixture
def admin(api, seed):
    seed.user('root', role='admin')
    return api.as_user({'username': 'root', 'role': 'admin'})


@pytest.fixture
def node_ssh(api, monkeypatch):
    """The SSH client the join and removal routes build. Records where it is sent; the
    login is refused unless a test lets it through."""
    import pegaprox.api.vms as vms
    client = MagicMock(name='node-ssh')
    client.connect.side_effect = _AuthFailed('not in a test')
    fake = MagicMock(AuthenticationException=_AuthFailed,
                     SSHException=type('SSHErr', (Exception,), {}))
    fake.SSHClient.return_value = client
    monkeypatch.setattr(vms, 'get_paramiko', lambda: fake)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda *a, **k: None)
    monkeypatch.setattr(vms, 'secure_ssh_client', lambda pm: client)
    mgr = api.make_fake_manager(CID)
    mgr.host, mgr.api_port = BRACKETED, 8006
    mgr.config.name = 'lab'
    mgr.config.host = V6
    api.set_manager(CID, mgr)
    client.mgr = mgr
    return client


@pytest.fixture
def no_waiting(monkeypatch):
    """The join and removal routes sleep through a shell session and start a thread for
    the follow-up; neither belongs in a test."""
    import pegaprox.api.vms as vms

    class _Time:
        def __getattr__(self, name):
            return getattr(time, name)

        @staticmethod
        def sleep(_s):
            pass

    class _Threads:
        def __getattr__(self, name):
            return getattr(threading, name)

        class Thread:
            def __init__(self, *a, **k):
                pass

            def start(self):
                pass

    monkeypatch.setattr(vms, 'time', _Time())
    monkeypatch.setattr(vms, 'threading', _Threads())
    monkeypatch.setattr(vms, 'save_config', lambda *a, **k: None)


@pytest.mark.parametrize('typed', [BRACKETED, V6])
def test_the_join_check_reaches_an_ipv6_node(admin, node_ssh, typed):
    r = admin.post(f'/api/clusters/{CID}/nodes/join/test',
                   json={'node_ip': typed, 'username': 'root', 'password': 'pw'})

    assert node_ssh.connect.call_args.args[0] == V6
    assert r.status_code == 502 and r.get_json()['code'] == 'UPSTREAM_AUTH'


def test_an_option_typed_as_the_node_never_reaches_ssh(admin, node_ssh):
    r = admin.post(f'/api/clusters/{CID}/nodes/join/test',
                   json={'node_ip': '[-oProxyCommand=touch x]', 'password': 'pw'})

    assert r.status_code == 400
    assert not node_ssh.connect.called


def _join_info(ring0):
    body = {'data': {'nodelist': [{'pve_fp': 'AA:BB:CC', 'ring0_addr': ring0}]}}
    return types.SimpleNamespace(status_code=200, json=lambda: body, text='')


@pytest.mark.parametrize('node_ip,dialled,ring0,line', [
    (BRACKETED, V6, '2001:db8::1', 'pvecm add 2001:db8::1 --fingerprint AA:BB:CC'),
    ('10.0.0.5', '10.0.0.5', '10.0.0.1;touch /tmp/x',
     "pvecm add '10.0.0.1;touch /tmp/x' --fingerprint AA:BB:CC"),
])
def test_joining_a_node_sends_one_pvecm_add(admin, node_ssh, no_waiting, node_ip, dialled,
                                            ring0, line):
    node_ssh.connect.side_effect = None
    shell = MagicMock(name='shell')
    shell.recv_ready.return_value = False
    node_ssh.invoke_shell.return_value = shell
    node_ssh.mgr._create_session.return_value.get.return_value = _join_info(ring0)

    r = admin.post(f'/api/clusters/{CID}/nodes/join',
                   json={'node_ip': node_ip, 'username': 'root', 'password': 'pw'})

    assert r.status_code == 200, r.get_json()
    assert node_ssh.connect.call_args.args[0] == dialled
    sent = [c.args[0] for c in shell.send.call_args_list if c.args[0].startswith('pvecm add')]
    # a plain address goes out exactly as before; anything else the cluster says is one word
    assert sent == [line + '\n']
    assert shlex.split(sent[0])[2] == ring0


class _Out:
    def __init__(self, payload=b''):
        self._payload = [payload]
        self.channel = types.SimpleNamespace(recv_exit_status=lambda: 0)

    def read(self, *_):
        return self._payload.pop() if self._payload else b''


def test_removing_a_node_dials_both_nodes_plain(admin, node_ssh, no_waiting):
    mgr = node_ssh.mgr
    mgr.nodes_in_maintenance = {}
    nodes = {'data': [{'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]}
    mgr._create_session.return_value.get.return_value = types.SimpleNamespace(
        status_code=200, json=lambda: nodes)
    # what _get_node_ip handed back for the node it is connected through (#1158)
    mgr._get_node_ip.side_effect = {'pve1': '[2001:db8::11]', 'pve2': '[2001:db8::12]'}.get
    mgr.config.ssh_user, mgr.config.ssh_key = 'root', ''
    mgr.config.excluded_nodes = []
    # saved before, with the brackets still on
    mgr.config.fallback_hosts = ['[2001:db8::12]', '2001:db8::11']
    mgr.ssh_password_to_offer.return_value = 'pw'
    node_ssh.connect.side_effect = None
    node_ssh.exec_command.side_effect = lambda cmd, timeout=None: (MagicMock(), _Out(), _Out())

    r = admin.delete(f'/api/clusters/{CID}/nodes/pve2/cluster-membership', json={'confirm': True})

    assert r.status_code == 200, r.get_json()
    assert [c.args[0] for c in node_ssh.connect.call_args_list] == ['2001:db8::11', '2001:db8::12']
    # the removed node is no fallback any more, whichever way it was written down
    assert mgr.config.fallback_hosts == ['2001:db8::11']


# --- the deep storage rescan -------------------------------------------------------------

def _pve(host):
    """A bare manager with what the rescan touches. A real one would connect."""
    from pegaprox.core.manager import PegaProxManager
    from pegaprox.models.tasks import PegaProxConfig
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = PegaProxConfig({'name': 'lab', 'host': host, 'user': 'root@pam', 'pass': 'pw',
                               'ssh_key': ''})
    m.id = CID
    m.current_host = None
    m._using_api_token = False
    quiet = lambda *a, **k: None
    m.logger = types.SimpleNamespace(info=quiet, debug=quiet, warning=quiet, error=quiet,
                                     critical=quiet)
    m._last_ssh_block_logged = None
    m.is_connected = True
    # pve1 resolves (bracketed, as the connected node came back), pve2 does not
    m.member_node_ip = lambda node: {'pve1': BRACKETED}.get(node)

    def get(url, **k):
        if url.endswith('/storage/lvm1'):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': {
                'type': 'lvm', 'vgname': 'vg1'}})
        if url.endswith('/nodes'):
            return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                {'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]})
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': {}})
    m._create_session = lambda: types.SimpleNamespace(get=get)
    return m


@pytest.mark.parametrize('cluster_host,pve2', [
    (V6, None),
    ('10.0.0.1', None),          # was 'pve2.0.0.1'
    ('pve1.lab', 'pve2.lab'),    # a name keeps its guess
])
def test_the_deep_rescan_dials_plain_and_guesses_only_from_a_name(api, admin, monkeypatch,
                                                                  cluster_host, pve2):
    from pegaprox import globals as _g
    tried = []

    def connect(self, **kw):
        tried.append(kw['hostname'])
        raise paramiko.AuthenticationException('not in a test')
    monkeypatch.setattr(paramiko.SSHClient, 'connect', connect)
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4))
    api.set_manager(CID, _pve(cluster_host))

    r = admin.post(f'/api/clusters/{CID}/datacenter/storage/lvm1/rescan', json={'deep_scan': True})

    assert r.status_code == 200, r.get_data(as_text=True)
    assert tried == [V6] + ([pve2] if pve2 else [])
    if not pve2:
        second = r.get_json()['results'][1]['actions']
        assert {'action': 'ssh_connect', 'status': 'failed',
                'error': 'no address known for node pve2'} in second


# --- the migration engine ----------------------------------------------------------------

class _Net:
    def __init__(self, ifaces, nodes=None):
        self.host, self.api_port = BRACKETED, 8006
        self.nodes = nodes or {}
        self._ifaces = ifaces

    def _api_get(self, url):
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': self._ifaces})


@pytest.mark.parametrize('ifaces,nodes,want', [
    ([{'type': 'bridge', 'iface': 'vmbr0', 'address6': '2001:db8::21'}], None, '2001:db8::21'),
    # IPv4 first, as it always was
    ([{'type': 'bridge', 'address': '10.0.0.21', 'address6': '2001:db8::21'}], None, '10.0.0.21'),
    ([{'type': 'bridge', 'address6': '2001:db8::21'}, {'type': 'bridge', 'address': '10.0.0.22'}],
     None, '10.0.0.22'),
    ([], {'pve-a': {'ip': '[2001:db8::24]'}}, '2001:db8::24'),
    # no bridge address and no resolver: the connected host stands in only on a one-node cluster
    ([{'type': 'eth', 'address6': '2001:db8::23'}], {'pve-a': {}}, V6),
])
def test_the_migration_engine_finds_an_ipv6_node_plain(ifaces, nodes, want):
    from pegaprox.core import xhm
    assert xhm._resolve_pve_node_ip(_Net(ifaces, nodes), 'pve-a') == want


@pytest.mark.parametrize('same_key', [False, True], ids=['other-key', 'pinned-key'])
def test_the_migration_engine_pins_the_address_it_dials(monkeypatch, known_hosts, same_key):
    from pegaprox.core import xhm
    state = types.SimpleNamespace(sent=[], pinned=paramiko.ECDSAKey.generate())
    state.presented = state.pinned if same_key else paramiko.ECDSAKey.generate()
    _pin(known_hosts, f'[{V6}]:2222', state.pinned)
    dialled = []

    def transport(addr):
        dialled.append(addr)
        return _Transport(state)

    def connect(self, hostname, **kw):
        dialled.append((hostname, kw.get('port')))
        raise paramiko.AuthenticationException('not in a test')
    monkeypatch.setattr(paramiko, 'Transport', transport)
    monkeypatch.setattr(paramiko.SSHClient, 'connect', connect)

    with pytest.raises(paramiko.AuthenticationException):
        xhm._connect_ssh(BRACKETED, 'root', 'pw', port=2222)

    assert dialled == [(V6, 2222), (V6, 2222)]
    # the pin under '[2001:db8::10]:2222' decides, the password goes only to that key
    assert state.sent == (['ki'] if same_key else [])


@pytest.mark.parametrize('given,want', [
    (V6, f'[{V6}]'), (BRACKETED, f'[{V6}]'), ('10.0.0.20', '10.0.0.20'),
    ('esx1.lab', 'esx1.lab'), ('[-oX]', '[-oX]')])
def test_an_ipv6_esxi_host_goes_into_scp_in_brackets(given, want):
    from pegaprox.core import xhm
    assert xhm._scp_host(given) == want


class _Stream:
    def __init__(self, payload=b''):
        self._payload = payload
        self.channel = types.SimpleNamespace(recv_exit_status=lambda: 0)

    def read(self):
        return self._payload


class _NodeShell:
    def __init__(self, listing):
        self.commands, self._listing = [], listing

    def exec_command(self, cmd, timeout=None, **kw):
        self.commands.append(cmd)
        if cmd.lstrip().startswith('ls '):
            return _Stream(), _Stream(self._listing), _Stream()
        return _Stream(), _Stream(), _Stream()

    def close(self):
        pass


class _Esxi:
    is_connected = True
    host = V6
    config = types.SimpleNamespace(ssh_user='root', pass_='pw', ssh_key='', ssh_port=22)

    def get_vm_disks_for_export(self, vmid):
        return {'data': {'name': 'web01', 'guest_os': 'ubuntu64Guest', 'memory_mb': 2048,
                         'cpu_count': 2,
                         'disks': [{'vmdk_file': '[datastore1] web01/web01.vmdk',
                                    'capacity_bytes': 8 * 1024 ** 3, 'capacity_gb': 8,
                                    'label': 'Hard disk 1'}]}}


@pytest.mark.parametrize('listing', [b'web01.vmdk\n', b''], ids=['sshfs', 'scp-fallback'])
def test_the_esxi_to_pve_leg_names_an_ipv6_esxi_host_in_brackets(monkeypatch, listing):
    from pegaprox.core import xhm
    shell = _NodeShell(listing)
    monkeypatch.setitem(xhm.cluster_managers, 'esxi1', _Esxi())
    monkeypatch.setitem(xhm.cluster_managers, 'pve1', _Esxi())
    monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, node: '10.0.0.9')
    monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 900, raising=False)
    monkeypatch.setattr(xhm, '_connect_ssh', lambda *a, **kw: shell)
    task = xhm.XHMigrationTask(
        mid='deadbeef', direction='esxi_to_pve', source_cluster='esxi1', source_node='esx-a',
        source_vmid=42, target_cluster='pve1', target_node='pve-a', target_storage='local')

    xhm._run_esxi_to_pve(task)

    remote = [w for c in shell.commands if c.startswith(('sshfs', 'IFS=')) for w in shlex.split(c)
              if w.startswith('root@')]
    assert remote, shell.commands
    # one shell word each, the address in brackets so its colons are not the path separator
    # (scp's path carries a second quoting for the ESXi side)
    for word in remote:
        target, sep, path = word.partition(']:')
        assert (target, sep) == (f'root@[{V6}', ']:'), word
        assert path.strip("'").startswith('/vmfs/volumes/datastore1'), word


def test_no_scp_target_of_the_engine_is_built_from_the_bare_esxi_host():
    """The ESXi-to-XCP-ng leg runs scp on this host with an argv; same rule there."""
    from pegaprox.core import xhm
    src = open(xhm.__file__, encoding='utf-8').read()
    assert '@{esxi_host}' not in src and "'@' + esxi_host" not in src
