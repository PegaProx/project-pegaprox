"""Node commands log in on the cluster's SSH port, on every way out.

The cluster's ssh_port reached _ssh_connect and a few routes, and nothing else. The
password leg of _pve_node_exec (_ssh_exec: two keyboard-interactive sockets, paramiko's
connect and the sshpass fallback) and the manager's command-line ssh family (the HA
checks, the SSH fence, the in-band BMC read) all knocked on 22, so on a cluster whose
nodes listen elsewhere they failed every time. The hardening report printed '22' for
every node as well.

Port 22, or none set, keeps the argv it always had: no '-p'. For any other port the
host-key pin is the [host]:port entry, the name OpenSSH and paramiko give it.

Sockets, paramiko and the subprocess are stubs, nothing leaves the machine.
"""
import types
from unittest.mock import MagicMock

import pytest

paramiko = pytest.importorskip('paramiko')

import pegaprox.core.manager as mgrmod
import pegaprox.utils.ssh as ssh_mod
import pegaprox.utils.ssh_security as sshsec
from pegaprox.core import ha_transport
from pegaprox.models.tasks import PegaProxConfig

NODE_IP = '10.0.0.7'
UNSET = [22, None, 0, '']


def _port_of(argv):
    """The port OpenSSH dials for this argv: the last -p before '--', else 22."""
    opts = argv[:argv.index('--')] if '--' in argv else argv
    ports = [opts[i + 1] for i, a in enumerate(opts[:-1]) if a == '-p']
    return int(ports[-1]) if ports else 22


@pytest.fixture(autouse=True)
def known_hosts(tmp_path, monkeypatch):
    path = tmp_path / 'known_hosts'
    monkeypatch.setattr(sshsec, '_KNOWN_HOSTS', str(path))
    return path


# --- _pve_node_exec and the _ssh_exec behind it ------------------------------------------

class _Cfg:
    def __init__(self, ssh_port):
        self.user, self.pass_ = 'root@pam', 'pw'
        self.ssh_user, self.ssh_key = '', ''
        self.ssh_port = ssh_port


class _Mgr:
    id = 'c1'
    host = '10.0.0.1'
    api_port = 8006
    nodes = {'n1': {'node': 'n1', 'status': 'online'}}

    def __init__(self, ssh_port):
        self.config = _Cfg(ssh_port)

    def _is_node_blocked(self, node): return (False, 0)
    def _register_node_failure(self, node): pass
    def _reset_node_failures(self, node): pass
    def _get_node_ip(self, node): return NODE_IP
    def ssh_diagnose(self, node): return None
    def _api_post(self, *a, **k): raise RuntimeError('no API exec in a test')


class _Transport:
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


@pytest.fixture
def wire(monkeypatch):
    """Every way out of _ssh_exec, recorded. The sockets and paramiko's connect fail, so a
    call runs down to the sshpass leg, which answers."""
    import socket
    ssh_mod._node_ip_cache.clear()
    monkeypatch.setattr(ssh_mod, '_node_key_refused', {})
    seen = types.SimpleNamespace(tcp=[], m3=[], argv=None, sent=[], presented=None)

    def tcp(addr, timeout=None, **kw):
        seen.tcp.append(addr)
        raise OSError('no network in a test')

    class _Client:
        def load_host_keys(self, *a):
            pass

        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, hostname, port=22, **kw):
            seen.m3.append((hostname, port))
            raise OSError('no network in a test')

    def node_cmd(argv, **kw):
        seen.argv = list(argv)
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')

    monkeypatch.setattr(socket, 'create_connection', tcp)
    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(ha_transport, 'guard_ssh', lambda *a, **k: None)
    monkeypatch.setattr(ha_transport, 'node_cmd', node_cmd)
    yield seen
    ssh_mod._node_ip_cache.clear()


def test_every_way_out_of_a_node_command_dials_the_clusters_port(wire):
    rc, out, _ = ssh_mod._pve_node_exec(_Mgr(2222), 'n1', 'uptime')

    assert (rc, out) == (0, 'ok')
    assert wire.tcp == [(NODE_IP, 2222), (NODE_IP, 2222)]
    assert wire.m3 == [(NODE_IP, 2222)]
    assert _port_of(wire.argv) == 2222
    assert wire.argv[-5:] == ['-l', 'root', '--', NODE_IP, 'uptime']


@pytest.mark.parametrize('port', UNSET, ids=['22', 'none', 'zero', 'empty'])
def test_a_cluster_without_its_own_port_keeps_22_and_its_argv(wire, port):
    rc, out, _ = ssh_mod._pve_node_exec(_Mgr(port), 'n1', 'uptime')

    assert (rc, out) == (0, 'ok')
    assert wire.tcp == [(NODE_IP, 22), (NODE_IP, 22)]
    assert wire.m3 == [(NODE_IP, 22)]
    assert '-p' not in wire.argv


@pytest.fixture
def node_key(monkeypatch, wire):
    """The keyboard-interactive sockets connect, and the node presents wire.presented."""
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda addr, timeout=None, **kw: object())
    monkeypatch.setattr(paramiko, 'Transport', lambda sock: _Transport(wire))
    return wire


def _pins(path):
    keys = paramiko.hostkeys.HostKeys()
    keys.load(str(path))
    return sorted(keys.keys())


def test_a_node_seen_first_is_pinned_under_host_and_port(node_key, known_hosts):
    node_key.presented = paramiko.ECDSAKey.generate()

    ssh_mod._pve_node_exec(_Mgr(2222), 'n1', 'uptime')

    assert _pins(known_hosts) == [f'[{NODE_IP}]:2222']


def test_on_22_the_pin_stays_under_the_bare_host(node_key, known_hosts):
    node_key.presented = paramiko.ECDSAKey.generate()

    ssh_mod._pve_node_exec(_Mgr(None), 'n1', 'uptime')

    assert _pins(known_hosts) == [NODE_IP]


def test_the_pin_under_host_and_port_stops_another_key_before_a_password(node_key, known_hosts):
    pinned = paramiko.hostkeys.HostKeys()
    key = paramiko.ECDSAKey.generate()
    pinned.add(f'[{NODE_IP}]:2222', key.get_name(), key)
    pinned.save(str(known_hosts))
    node_key.presented = paramiko.ECDSAKey.generate()

    ssh_mod._pve_node_exec(_Mgr(2222), 'n1', 'uptime')

    # read under the bare host this was a node never seen, and its key taken on first use
    assert node_key.sent == []
    assert _pins(known_hosts) == [f'[{NODE_IP}]:2222']


def test_the_pinned_key_itself_gets_through(node_key, known_hosts):
    """Counterproof: the refusal above is the pin, not a fake that cannot pass."""
    pinned = paramiko.hostkeys.HostKeys()
    key = paramiko.ECDSAKey.generate()
    pinned.add(f'[{NODE_IP}]:2222', key.get_name(), key)
    pinned.save(str(known_hosts))
    node_key.presented = key

    ssh_mod._pve_node_exec(_Mgr(2222), 'n1', 'uptime')

    assert node_key.sent == ['ki', 'ki']


# --- the manager's command-line ssh family -----------------------------------------------

def _mgr(ssh_port, ha_config=None):
    data = {'name': 'lab', 'host': NODE_IP, 'user': 'root@pam', 'pass': 'pw'}
    if ssh_port is not None:
        data['ssh_port'] = ssh_port
    m = mgrmod.PegaProxManager.__new__(mgrmod.PegaProxManager)
    m.id = 'c1'
    m.config = PegaProxConfig(data)
    m.ha_config = ha_config or {}
    m.logger = MagicMock()
    return m


@pytest.fixture
def recorded(monkeypatch):
    calls = []

    def fake_node_cmd(argv, **kw):
        calls.append((list(argv), kw.get('host')))
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')
    monkeypatch.setattr(mgrmod, 'node_cmd', fake_node_cmd)
    real_run = mgrmod.subprocess.run
    monkeypatch.setattr(mgrmod.subprocess, 'run',
                        lambda argv, *a, **k: types.SimpleNamespace(returncode=0)
                        if argv[:1] == ['which'] else real_run(argv, *a, **k))
    return calls


KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n'

FAMILY = [
    ('_ssh_run_command_output', lambda m: m._ssh_run_command_output(NODE_IP, 'root', 'uptime')),
    ('_ssh_run_command_with_key_output',
     lambda m: m._ssh_run_command_with_key_output(NODE_IP, 'root', 'uptime', KEY)),
    ('_ssh_run_command_with_password_output',
     lambda m: m._ssh_run_command_with_password_output(NODE_IP, 'root', 'uptime', 'pw')),
    ('_ssh_run_command', lambda m: m._ssh_run_command(NODE_IP, 'root', 'uptime')),
    ('_ssh_run_command_with_key', lambda m: m._ssh_run_command_with_key(NODE_IP, 'root', 'uptime', KEY)),
    ('_ssh_run_command_with_password',
     lambda m: m._ssh_run_command_with_password(NODE_IP, 'root', 'uptime', 'pw')),
]


@pytest.mark.parametrize('name,call', FAMILY, ids=[f[0] for f in FAMILY])
def test_the_manager_family_dials_the_clusters_port(recorded, name, call):
    assert call(_mgr(2222))
    argv, host = recorded[-1]

    assert _port_of(argv) == 2222, argv
    # the port is an option of ssh, never behind the '--' that ends them
    assert argv[argv.index('--'):] == ['--', NODE_IP, 'uptime'] and host == NODE_IP


@pytest.mark.parametrize('port', [22, None, 0], ids=['22', 'unset', 'zero'])
@pytest.mark.parametrize('name,call', FAMILY, ids=[f[0] for f in FAMILY])
def test_the_manager_family_keeps_22_without_a_port_of_its_own(recorded, name, call, port):
    assert call(_mgr(port))
    argv, _ = recorded[-1]

    assert '-p' not in argv, argv


FENCE = {'fencing': {'pve2': {'type': 'ssh', 'host': '10.0.0.12', 'user': 'root'}}}


@pytest.fixture
def fence(monkeypatch, recorded):
    class _Time:
        def __getattr__(self, name):
            import time
            return getattr(time, name)

        @staticmethod
        def sleep(_s):
            pass
    monkeypatch.setattr(mgrmod, 'time', _Time())

    def run(ssh_port):
        assert _mgr(ssh_port, ha_config=FENCE)._ha_fence_node('pve2') is True
        assert len(recorded) == 1
        return recorded[0]
    return run


def test_the_ssh_fence_powers_off_on_the_clusters_port(fence):
    argv, host = fence(2222)
    hkc, kh = mgrmod.cli_hostkey_opts()

    assert argv == ['ssh', '-o', 'ConnectTimeout=5', '-o', f'StrictHostKeyChecking={hkc}',
                    '-o', f'UserKnownHostsFile={kh}', '-p', '2222',
                    '--', 'root@10.0.0.12', 'poweroff']
    assert host == '10.0.0.12'


@pytest.mark.parametrize('port', [22, None], ids=['22', 'unset'])
def test_the_ssh_fence_on_22_is_the_command_it_always_was(fence, port):
    argv, host = fence(port)
    hkc, kh = mgrmod.cli_hostkey_opts()

    assert argv == ['ssh', '-o', 'ConnectTimeout=5', '-o', f'StrictHostKeyChecking={hkc}',
                    '-o', f'UserKnownHostsFile={kh}',
                    '--', 'root@10.0.0.12', 'poweroff']
    assert host == '10.0.0.12'


# --- the hardening report ----------------------------------------------------------------

@pytest.fixture
def audit(api, seed):
    seed.user('root', role='admin')
    admin = api.as_user({'username': 'root', 'role': 'admin'})

    def run(**cfg):
        mgr = api.make_fake_manager('c1')
        mgr.host, mgr.api_port = '10.0.0.1', 8006
        for k, v in cfg.items():
            setattr(mgr.config, k, v)

        def get(url, **kw):
            if url.endswith('/api2/json/nodes'):
                return types.SimpleNamespace(status_code=200, json=lambda: {'data': [
                    {'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]})
            return types.SimpleNamespace(status_code=404, json=lambda: {'data': {}})
        mgr._create_session.return_value.get.side_effect = get
        mgr.get_node_apt_updates.return_value = []
        api.set_manager('c1', mgr)

        r = admin.get('/api/clusters/c1/security/audit')
        assert r.status_code == 200, r.get_json()
        return {n: s['port'] for n, s in r.get_json()['ssh']['nodes'].items()}
    return run


def test_the_hardening_report_shows_the_clusters_ssh_port(audit):
    assert audit(ssh_port=2222) == {'pve1': '2222', 'pve2': '2222'}


@pytest.mark.parametrize('port', [22, None, 0], ids=['22', 'unset', 'zero'])
def test_the_hardening_report_says_22_without_a_port_of_its_own(audit, port):
    assert audit(ssh_port=port) == {'pve1': '22', 'pve2': '22'}
