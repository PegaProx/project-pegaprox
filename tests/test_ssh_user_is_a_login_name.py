"""An SSH login name never reaches the ssh command line as an option.

A cluster's ssh_user (and the user part of its API user) was put on the ssh, sshpass and
scp command line as `user@host` with nothing in front of it. A value starting with '-' is
then read by OpenSSH as an option, not as a user. It was stored through the cluster
config routes with no format check, and the V2P route took esxi_user from the request
the same way.

Now the name is checked where it is stored (add, re-configure, PUT, PATCH, restore, the
V2P start) and again where the command line is built, and it travels as the value of
'-l' with '--' before the host. The marker values below are inert: they only have to
look like an option.

Aikido 797415240.
"""
import contextlib
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.api.clusters as clusters_api
import pegaprox.core.manager as mgrmod
from pegaprox.models.tasks import PegaProxConfig


OPTION_USER = '-oPegaProxMarker=yes'
HOST = '10.20.0.5'

# OpenSSH options that take an argument (ssh.c getopt string)
_WITH_ARG = set('BbcDEeFIiJLlmOopQRSWw')


def _ssh_parse(argv):
    """(options, destination) the way OpenSSH reads its argv: options up to '--' or the
    destination, and without '--' the options after the destination too."""
    i = argv.index('ssh') + 1 if 'ssh' in argv else argv.index('scp') + 1
    args = argv[i:]
    opts, dest, terminated, k = [], None, False, 0
    while k < len(args):
        a = args[k]
        if not terminated and a == '--':
            terminated = True
            k += 1
            continue
        if not terminated and a.startswith('-') and len(a) > 1:
            j = 1
            while j < len(a):
                if a[j] in _WITH_ARG:
                    if a[j + 1:]:
                        opts.append((a[j], a[j + 1:]))
                    else:
                        k += 1
                        opts.append((a[j], args[k] if k < len(args) else ''))
                    break
                opts.append((a[j], None))
                j += 1
            k += 1
            continue
        if dest is None:
            dest = a
            k += 1
            if terminated:
                break
            continue
        break
    return opts, dest


def _marker_is_an_option(argv):
    opts, _ = _ssh_parse(argv)
    return any(c == 'o' and v and 'PegaProxMarker' in v for c, v in opts)


# --- the shared exec helper: paramiko first, then sshpass + ssh ---------------------

@pytest.fixture
def system_ssh_only(monkeypatch):
    """Paramiko fails to connect, so _ssh_exec takes its sshpass fallback; the argv it
    builds is recorded instead of run."""
    import paramiko
    import socket
    import pegaprox.core.ha_transport as ha_transport

    monkeypatch.setattr(socket, 'create_connection',
                        lambda *a, **k: (_ for _ in ()).throw(OSError('no network in tests')))
    fake_client = MagicMock()
    fake_client.return_value.connect.side_effect = OSError('no network in tests')
    monkeypatch.setattr(paramiko, 'SSHClient', fake_client)
    monkeypatch.setattr(ha_transport, 'guard_ssh', lambda *a, **k: None)
    calls = []

    def fake_node_cmd(argv, **kw):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')
    monkeypatch.setattr(ha_transport, 'node_cmd', fake_node_cmd)
    return calls


def test_ssh_exec_never_hands_an_option_shaped_user_to_ssh(system_ssh_only):
    from pegaprox.utils.ssh import _ssh_exec
    rc, _, err = _ssh_exec(HOST, OPTION_USER, 'pw', 'uptime')
    for argv in system_ssh_only:
        assert not _marker_is_an_option(argv), f'the user became an ssh option: {argv}'
    assert not system_ssh_only, 'an invalid user name still reached a command line'
    assert rc != 0 and 'user name' in err


def test_ssh_exec_passes_a_valid_user_with_l_and_ends_the_options(system_ssh_only):
    from pegaprox.utils.ssh import _ssh_exec
    rc, out, _ = _ssh_exec(HOST, 'pegaprox', 'pw', 'uptime')
    assert rc == 0 and out == 'ok'
    argv = system_ssh_only[-1]
    assert argv[-5:] == ['-l', 'pegaprox', '--', HOST, 'uptime']
    opts, dest = _ssh_parse(argv)
    assert ('l', 'pegaprox') in opts and dest == HOST


# --- the manager's command-line SSH family ------------------------------------------

def _mgr(user='root@pam', **cfg):
    data = {'name': 'lab', 'host': HOST, 'user': user, 'pass': 'pw'}
    data.update(cfg)
    m = mgrmod.PegaProxManager.__new__(mgrmod.PegaProxManager)
    m.id = 'c1'
    m.config = PegaProxConfig(data)
    m.ha_config = {}
    m.logger = MagicMock()
    return m


@pytest.fixture
def recorded(monkeypatch):
    calls = []

    def fake_node_cmd(argv, **kw):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')
    monkeypatch.setattr(mgrmod, 'node_cmd', fake_node_cmd)
    # the password step looks for sshpass first; answer as if it is installed
    real_run = mgrmod.subprocess.run
    monkeypatch.setattr(mgrmod.subprocess, 'run',
                        lambda argv, *a, **k: types.SimpleNamespace(returncode=0)
                        if argv[:1] == ['which'] else real_run(argv, *a, **k))
    return calls


KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n'

FAMILY = [
    ('_ssh_run_command_output', lambda m, u: m._ssh_run_command_output(HOST, u, 'uptime')),
    ('_ssh_run_command_with_key_output',
     lambda m, u: m._ssh_run_command_with_key_output(HOST, u, 'uptime', KEY)),
    ('_ssh_run_command_with_password_output',
     lambda m, u: m._ssh_run_command_with_password_output(HOST, u, 'uptime', 'pw')),
    ('_ssh_run_command', lambda m, u: m._ssh_run_command(HOST, u, 'uptime')),
    ('_ssh_run_command_with_key', lambda m, u: m._ssh_run_command_with_key(HOST, u, 'uptime', KEY)),
    ('_ssh_run_command_with_password',
     lambda m, u: m._ssh_run_command_with_password(HOST, u, 'uptime', 'pw')),
]


@pytest.mark.parametrize('name,call', FAMILY, ids=[f[0] for f in FAMILY])
def test_the_manager_family_refuses_an_option_shaped_user(recorded, name, call):
    m = _mgr(ssh_user=OPTION_USER)
    result = call(m, OPTION_USER)
    for argv in recorded:
        assert not _marker_is_an_option(argv), f'{name}: the user became an ssh option: {argv}'
    assert not recorded, f'{name}: an invalid user name still reached a command line'
    assert not result


@pytest.mark.parametrize('name,call', FAMILY, ids=[f[0] for f in FAMILY])
def test_the_manager_family_still_runs_for_a_valid_user(recorded, name, call):
    m = _mgr()
    assert call(m, 'root')
    argv = recorded[-1]
    opts, dest = _ssh_parse(argv)
    assert ('l', 'root') in opts and dest == HOST, argv
    assert argv[argv.index('--') + 1] == HOST


def test_the_api_user_part_is_checked_too(recorded):
    """Several callers derive the user from config.user ('name@realm'), not ssh_user."""
    m = _mgr(user=OPTION_USER + '@pve')
    ssh_user = (m.config.user or 'root').split('@')[0]
    assert m._ssh_run_command_output(HOST, ssh_user, 'uptime') is None
    assert not recorded


# --- the content sync: scp in a root shell on the source node -----------------------

def test_content_sync_does_not_put_a_bad_user_into_the_node_shell(monkeypatch):
    m = _mgr(ssh_user='root;id')
    m.is_connected = True
    m._get_syncable_storage = lambda *a, **k: ({}, None)
    m.get_node_status = lambda: {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    m.member_node_ip = lambda n: {'pve1': '10.20.0.1', 'pve2': '10.20.0.2'}[n]
    m._resolve_storage_path = lambda *a, **k: '/var/lib/vz/template/iso'
    m.ssh_password_to_offer = lambda host=None: 'pw'
    sent = []

    def connect(ip):
        client = MagicMock()

        def exec_command(cmd, timeout=None):
            sent.append(cmd)
            out = MagicMock()
            out.channel.recv_exit_status.return_value = 1
            out.read.return_value = b''
            return MagicMock(), out, MagicMock()
        client.exec_command.side_effect = exec_command
        # the sftp relay after a failed scp: no relay in these tests
        client.open_sftp.side_effect = OSError('no sftp in tests')
        return client
    m._ssh_connect = connect

    m.sync_content_to_nodes('pve1', 'local', 'debian-12.iso')

    assert not [c for c in sent if 'root;id' in c], sent


def test_content_sync_quotes_and_ends_the_options_for_a_valid_user(monkeypatch):
    m = _mgr(ssh_user='root')
    m.is_connected = True
    m._get_syncable_storage = lambda *a, **k: ({}, None)
    m.get_node_status = lambda: {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    m.member_node_ip = lambda n: {'pve1': '10.20.0.1', 'pve2': '10.20.0.2'}[n]
    m._resolve_storage_path = lambda *a, **k: '/var/lib/vz/template/iso'
    m.ssh_password_to_offer = lambda host=None: ''
    sent = []

    def connect(ip):
        client = MagicMock()

        def exec_command(cmd, timeout=None):
            sent.append(cmd)
            out = MagicMock()
            out.channel.recv_exit_status.return_value = 0
            out.read.return_value = b''
            return MagicMock(), out, MagicMock()
        client.exec_command.side_effect = exec_command
        # the sftp relay after a failed scp: no relay in these tests
        client.open_sftp.side_effect = OSError('no sftp in tests')
        return client
    m._ssh_connect = connect

    res = m.sync_content_to_nodes('pve1', 'local', 'debian-12.iso')

    scp = [c for c in sent if c.startswith('scp ')]
    assert scp and ' -- ' in scp[0] and 'root@10.20.0.2:' in scp[0], sent
    assert res and res[0].get('method') == 'scp', res


# --- where it is stored: the cluster routes ----------------------------------------

@pytest.fixture
def cluster(api, seed):
    seed.db.save_cluster('c1', dict(name='lab', host=HOST, user='root@pam', ssl_verification=False,
                                    fallback_hosts=[], ssh_user='', ssh_key='', ssh_port=22,
                                    cluster_type='proxmox', api_port=8006, **{'pass': 'pw'}))
    m = mgrmod.PegaProxManager('c1', PegaProxConfig(seed.db.get_cluster('c1')))
    api.set_manager('c1', m)
    admin = seed.user('root', role='admin')
    return types.SimpleNamespace(api=api, seed=seed, mgr=m, c=api.as_user(admin), db=seed.db)


@pytest.mark.parametrize('method,url', [('put', '/api/clusters/c1'), ('patch', '/api/clusters/c1/config')])
@pytest.mark.parametrize('bad', [OPTION_USER, 'root id', 'root;id', 'a@b', '.hidden', 'ro\not'])
def test_the_config_routes_refuse_a_user_that_is_no_login_name(cluster, method, url, bad):
    r = getattr(cluster.c, method)(url, json={'ssh_user': bad})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert cluster.mgr.config.ssh_user == ''
    assert (cluster.db.get_cluster('c1')['ssh_user'] or '') == ''


@pytest.mark.parametrize('method,url', [('put', '/api/clusters/c1'), ('patch', '/api/clusters/c1/config')])
@pytest.mark.parametrize('good', ['pegaprox', 'svc.backup', 'ops_1', 'Admin', ''])
def test_the_config_routes_store_a_real_user_name(cluster, method, url, good):
    r = getattr(cluster.c, method)(url, json={'ssh_user': good})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert cluster.mgr.config.ssh_user == good
    assert (cluster.db.get_cluster('c1')['ssh_user'] or '') == good


def test_surrounding_whitespace_is_trimmed_not_stored(cluster):
    r = cluster.c.put('/api/clusters/c1', json={'ssh_user': ' pegaprox\n'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert cluster.mgr.config.ssh_user == 'pegaprox'


class _NoConnect:
    """Stands in for the manager add/re-configure build: connecting always works, so a
    refusal can only come from the check under test."""
    built = []

    def __init__(self, cluster_id, config):
        self.config = config
        self.cluster_type = 'proxmox'
        _NoConnect.built.append(config)

    def connect_to_proxmox(self):
        return True

    def start(self):
        pass

    def stop(self):
        pass


@pytest.fixture
def no_connect(monkeypatch):
    _NoConnect.built = []
    monkeypatch.setattr(clusters_api, 'PegaProxManager', _NoConnect)
    monkeypatch.setattr(clusters_api, 'save_config', lambda: True)
    return _NoConnect


def test_adding_a_cluster_refuses_an_option_shaped_ssh_user(api, seed, no_connect):
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post('/api/clusters', json={'name': 'new', 'host': HOST, 'user': 'root@pam',
                                      'pass': 'pw', 'ssh_user': OPTION_USER})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert not no_connect.built, 'a manager was built with the bad user'


def test_adding_a_cluster_with_a_real_ssh_user_still_works(api, seed, no_connect):
    c = api.as_user(seed.user('root', role='admin'))
    r = c.post('/api/clusters', json={'name': 'new', 'host': HOST, 'user': 'root@pam',
                                      'pass': 'pw', 'ssh_user': 'pegaprox'})
    assert r.status_code == 201, r.get_data(as_text=True)
    assert no_connect.built[-1].ssh_user == 'pegaprox'


# --- restore --------------------------------------------------------------------------

from test_ha_api import ha_env, _admin  # noqa: E402,F401
from test_ha_claim import claimed, pve, me  # noqa: E402,F401
from test_ha_settings_writers import _restore, ROW  # noqa: E402


def test_a_restore_does_not_bring_back_a_bad_ssh_user(claimed):
    result = _restore(claimed, {'c7': dict(ROW, name='restored', ssh_user=OPTION_USER, ha_settings={})})
    assert (claimed.db.get_cluster('c7')['ssh_user'] or '') == ''
    assert any('ssh_user' in e for e in result.get('errors', [])), result


def test_a_restore_keeps_a_real_ssh_user(claimed):
    _restore(claimed, {'c7': dict(ROW, name='restored', ssh_user='pegaprox', ha_settings={})})
    assert claimed.db.get_cluster('c7')['ssh_user'] == 'pegaprox'


# --- the V2P start: esxi_user and esxi_host come from the request -------------------

import pegaprox.api.vmware as vmwareapi  # noqa: E402


def _handler(name):
    fn = getattr(vmwareapi, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


@pytest.fixture
def v2p(api, monkeypatch):
    started = []
    fake = MagicMock()
    fake.host = 'esxi01.lab'
    fake.get_vm.return_value = {'data': {'name': 'vm1', 'nics': []}}
    monkeypatch.setitem(vmwareapi.vmware_managers, 'v1', fake)
    monkeypatch.setitem(vmwareapi.cluster_managers, 'c1', MagicMock())
    monkeypatch.setattr(vmwareapi, 'user_can_access_vmware_vm', lambda *a, **k: True)
    monkeypatch.setattr(vmwareapi, 'caller_is_scoped', lambda *a, **k: False)
    monkeypatch.setattr(vmwareapi, 'check_cluster_access', lambda *a, **k: (True, None))
    monkeypatch.setattr(vmwareapi, 'build_authz_user', lambda *a, **k: {'username': 'dana', 'role': 'admin'})
    monkeypatch.setattr(vmwareapi, '_run_v2p_migration', lambda task: started.append(task))
    monkeypatch.setattr(vmwareapi, 'log_audit', lambda *a, **k: None)

    def start(body):
        from flask import request as _rq
        base = {'target_cluster': 'c1', 'target_node': 'pve1', 'target_storage': 'local-lvm',
                'esxi_password': 'pw'}
        base.update(body)
        with api.app.test_request_context('/', base_url='http://localhost', json=base):
            _rq.session = {'user': 'dana', 'role': 'admin'}
            resp = _handler('start_vmware_migration')('v1', 'vm-1')
        status = resp[1] if isinstance(resp, tuple) else resp.status_code
        return status, started
    return start


def test_v2p_refuses_an_option_shaped_esxi_user(v2p):
    status, started = v2p({'esxi_user': OPTION_USER})
    assert status == 400
    assert not started


@pytest.mark.parametrize('host', ['esxi01.lab\nUser x', '-oPegaProxMarker=yes', 'esxi01.lab x', 'a/b'])
def test_v2p_refuses_an_esxi_host_that_is_no_host(v2p, host):
    # the host is pinned to the registered server (#1106): register the bad one, so it is
    # the shape check that refuses it and not the pin
    vmwareapi.vmware_managers['v1'].host = host
    status, started = v2p({'esxi_host': host})
    assert status == 400
    assert not started


@pytest.mark.parametrize('body', [{}, {'esxi_user': 'root', 'esxi_host': '10.30.0.9'},
                                  {'esxi_host': 'esx_01.lab'}, {'esxi_host': 'fd00::9'}])
def test_v2p_still_starts_with_a_real_user_and_host(v2p, body):
    # the host is pinned to the registered server (#1106): register the one the body names
    if body.get('esxi_host'):
        vmwareapi.vmware_managers['v1'].host = body['esxi_host']
    status, started = v2p(body)
    assert status == 202
    assert started


def test_the_local_esxi_exec_passes_the_user_with_l(monkeypatch):
    import pegaprox.core.ha_transport as ha_transport
    from pegaprox.core.v2p import _ssh_esxi_exec
    calls = []
    monkeypatch.setattr(ha_transport, 'node_cmd',
                        lambda argv, **kw: calls.append(list(argv)) or
                        types.SimpleNamespace(returncode=0, stdout='', stderr=''))

    rc, _, _ = _ssh_esxi_exec('esxi01.lab', OPTION_USER, 'pw', 'uptime')
    assert rc != 0 and not calls

    rc, _, _ = _ssh_esxi_exec('esxi01.lab', 'root', 'pw', 'uptime')
    assert rc == 0
    opts, dest = _ssh_parse(calls[-1])
    assert ('l', 'root') in opts and dest == 'esxi01.lab'


# --- the validator itself ------------------------------------------------------------

@pytest.mark.parametrize('value,ok', [
    ('root', True), ('pegaprox', True), ('svc.backup', True), ('_svc', True), ('a' * 64, True),
    ('', False), (None, False), ('-l', False), (OPTION_USER, False), ('.x', False), ('a b', False),
    ('a@b', False), ('a;b', False), ('a\n', False), ('a' * 65, False), (7, False),
])
def test_validate_ssh_user(value, ok):
    from pegaprox.utils.sanitization import validate_ssh_user
    assert validate_ssh_user(value) is ok
