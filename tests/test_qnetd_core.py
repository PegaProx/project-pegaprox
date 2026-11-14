"""QNetd hosts and the QDevice setup of a cluster (core/qnetd.py).

The nodes are fake shells that answer the scripts the way corosync-qdevice-net-certutil,
PVE's perl and systemctl would; the QNetd host is a fake helper that speaks the helper
protocol. The perl that writes corosync.conf runs for real against stand-ins of
PVE::Cluster and PVE::Corosync, so what it writes is what pvecm writes, and hostile input
is shown to reach it as data, not code. Offline throughout.
MK Oct 2026
"""
import base64
import json
import os
import shlex
import shutil
import socket
import subprocess
import threading
import types

import pytest

from pegaprox.core import qnetd

from test_alert_events import NOW, _open, _rule, _rules, sent  # noqa: F401  (sent is a fixture)

PERL = shutil.which('perl')
CA = b'-----BEGIN CERTIFICATE-----\nQ0EgY2VydA==\n-----END CERTIFICATE-----\n'
CRQ = b'-----BEGIN NEW CERTIFICATE REQUEST-----\nY3Jx\n-----END NEW CERTIFICATE REQUEST-----\n'
CRT = b'-----BEGIN CERTIFICATE-----\nY2x1c3RlciBjZXJ0\n-----END CERTIFICATE-----\n'
P12 = b'\x30\x82\x05\x00' + b'THE-CLUSTER-PRIVATE-KEY' * 20
UUID = '4c4c4544-0042-3510-8053-b4c04f4d3132'


@pytest.fixture(autouse=True)
def _clean():
    qnetd.reset_for_tests()
    yield
    qnetd.reset_for_tests()


# --- validation -------------------------------------------------------------------------

@pytest.mark.parametrize('bad', ['-oProxyCommand=x', 'a;b', '$(id)', 'a b', '127.0.0.1', '::1', '0.0.0.0',
                                 'fe80::1%eth0', 'fe80::1', '', None, 'x' * 300, '`id`', "a'b"])
def test_an_address_the_nodes_cannot_safely_get_is_refused(bad):
    assert qnetd.clean_address(bad) is None


def test_an_address_comes_back_bare():
    assert qnetd.clean_address('[2001:db8::5]') == '2001:db8::5'
    assert qnetd.clean_address(' qnetd.example.org ') == 'qnetd.example.org'
    assert qnetd.clean_address('192.0.2.7') == '192.0.2.7'


@pytest.mark.parametrize('name,ok', [('pve', True), ('Lab-2', True), ('a' * 15, True), ('a' * 16, False),
                                     ('-pve', False), ('pve-', False), ('pve_1', False), ('p.v', False),
                                     ('x;id', False), ('', False)])
def test_a_cluster_name_follows_pve_rule(name, ok):
    assert bool(qnetd.clean_cluster_name(name)) is ok


# --- corosync.conf through PVE's own perl -----------------------------------------------

STUB_CLUSTER = r'''package PVE::Cluster;
use strict; use warnings; use JSON::PP;
sub cfs_read_file {
    my ($f) = @_; die "wrong file $f\n" if $f ne "corosync.conf";
    open(my $fh, "<", $ENV{STUB_CONF}) or die "no conf\n"; local $/; return decode_json(<$fh>);
}
sub cfs_lock_file {
    my ($f, $t, $code) = @_;
    open(my $l, ">>", $ENV{STUB_LOCK}); print $l "$f $t\n"; close $l;
    eval { $code->() };
    return;
}
1;
'''
STUB_COROSYNC = r'''package PVE::Corosync;
use strict; use warnings; use JSON::PP;
sub atomic_write_conf {
    my ($conf) = @_;
    $conf->{main}->{totem}->{config_version}++;
    open(my $fh, ">", $ENV{STUB_CONF}) or die; print $fh JSON::PP->new->canonical->encode($conf); close $fh;
}
1;
'''


@pytest.fixture
def pve_perl(tmp_path):
    if PERL is None:
        pytest.skip('no perl here')
    lib = tmp_path / 'lib' / 'PVE'
    lib.mkdir(parents=True)
    (lib / 'Cluster.pm').write_text(STUB_CLUSTER)
    (lib / 'Corosync.pm').write_text(STUB_COROSYNC)
    conf = tmp_path / 'corosync.json'
    conf.write_text(json.dumps({'main': {'totem': {'cluster_name': 'pve', 'config_version': 4},
                                         'quorum': {'provider': 'corosync_votequorum'}}}))
    env = dict(os.environ, PERL5LIB=str(tmp_path / 'lib'), STUB_CONF=str(conf),
               STUB_LOCK=str(tmp_path / 'lock.txt'))

    def run(script):
        return subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True,
                              timeout=30, cwd=str(tmp_path))
    return types.SimpleNamespace(run=run, conf=conf, lock=tmp_path / 'lock.txt', dir=tmp_path,
                                 read=lambda: json.loads(conf.read_text()))


def test_the_device_section_is_the_one_pvecm_writes(pve_perl):
    p = pve_perl.run(qnetd.conf_add_script('192.0.2.7', 5403))
    assert p.returncode == 0, p.stderr
    conf = pve_perl.read()
    assert conf['main']['quorum']['device'] == {
        'model': 'net', 'votes': 1,
        'net': {'tls': 'on', 'host': '192.0.2.7', 'algorithm': 'ffsplit'}}
    assert conf['main']['totem']['config_version'] == 5          # through atomic_write_conf
    assert pve_perl.lock.read_text().split() == ['corosync.conf', '10']


def test_another_port_is_written_beside_the_host_and_ipv6_stays_bare(pve_perl):
    p = pve_perl.run(qnetd.conf_add_script('[2001:db8::7]', 15403))
    assert p.returncode == 0, p.stderr
    net = pve_perl.read()['main']['quorum']['device']['net']
    assert net['host'] == '2001:db8::7' and str(net['port']) == '15403'


def test_an_existing_device_is_not_overwritten(pve_perl):
    conf = pve_perl.read()
    conf['main']['quorum']['device'] = {'model': 'net', 'net': {'host': '198.51.100.1'}}
    pve_perl.conf.write_text(json.dumps(conf))
    p = pve_perl.run(qnetd.conf_add_script('192.0.2.7', 5403))
    assert p.returncode != 0 and 'already configured' in p.stderr
    assert pve_perl.read()['main']['quorum']['device']['net']['host'] == '198.51.100.1'


def test_hostile_host_reaches_the_perl_as_data_and_is_refused_there(pve_perl, monkeypatch):
    """The Python check is switched off here to prove the layer under it: the value is
    quoted for bash, arrives in @ARGV, and the perl's own allowlist refuses it."""
    canary = pve_perl.dir / 'pwned'
    hostile = f'$(touch {canary}); `touch {canary}`; "; system("touch {canary}"); #'
    monkeypatch.setattr(qnetd, 'clean_address', lambda v: v)
    script = qnetd.conf_add_script(hostile, 5403)
    argv = shlex.split(script)
    assert argv[0:2] == ['perl', '-e'] and argv[3] == '--' and argv[4] == hostile and argv[5] == '5403'
    p = pve_perl.run(script)
    assert p.returncode != 0 and 'invalid QNetd host' in p.stderr
    assert not canary.exists()
    assert 'device' not in pve_perl.read()['main']['quorum']


def test_the_python_check_refuses_hostile_input_before_any_command_is_built():
    for bad in ('$(id)', '-e', "x'; rm -rf /; '", '127.0.0.1'):
        with pytest.raises(ValueError):
            qnetd.conf_add_script(bad, 5403)
    with pytest.raises(ValueError):
        qnetd.conf_add_script('192.0.2.7', '5403; id')
    for bad in ('pve;id', '$(id)', 'a' * 16):
        with pytest.raises(ValueError):
            qnetd.crq_script(bad)
    with pytest.raises(ValueError):
        qnetd.own_vm_script("x' -e . /etc/shadow")


def test_rollback_takes_out_only_the_entry_it_wrote(pve_perl):
    assert pve_perl.run(qnetd.conf_add_script('192.0.2.7', 5403)).returncode == 0
    p = pve_perl.run(qnetd.conf_del_script('198.51.100.9'))
    assert p.returncode != 0 and 'another QNetd host' in p.stderr
    assert 'device' in pve_perl.read()['main']['quorum']
    p = pve_perl.run(qnetd.conf_del_script('192.0.2.7'))
    assert p.returncode == 0, p.stderr
    assert 'device' not in pve_perl.read()['main']['quorum']


def test_the_read_script_reports_name_device_and_two_node(pve_perl):
    p = pve_perl.run(qnetd.conf_read_script())
    assert p.returncode == 0, p.stderr
    assert qnetd._kv(p.stdout) == {'name': 'pve', 'device': '0', 'two_node': '0'}


def test_the_port_probe_takes_the_host_as_an_argument(tmp_path, monkeypatch):
    canary = tmp_path / 'pwned'
    monkeypatch.setattr(qnetd, 'clean_address', lambda v: v)
    script = qnetd.probe_script(f'x/$(touch {canary})', 5403)
    p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30)
    assert 'port=0' in p.stdout and not canary.exists()
    # the source address probe gets it as data too, and finds no route for it
    assert qnetd._kv(p.stdout).get('src') == ''


def test_the_staged_scripts_carry_no_payload_and_clean_up(tmp_path):
    """The certificate bundle is never part of a command: the script reads stdin into a
    mktemp directory and removes it on the way out, also when the import fails."""
    for script in (qnetd.ca_import_script(), qnetd.p12_import_script(), qnetd.crt_import_script('pve')):
        assert 'base64 -d > "$d/' in script and "trap 'rm -rf \"$d\"' EXIT" in script
        assert 'umask 077' in script and 'mktemp -d' in script
    fake = tmp_path / 'bin'
    fake.mkdir()
    seen = tmp_path / 'seen'
    (fake / 'corosync-qdevice-net-certutil').write_text(
        f'#!/bin/bash\nf="$3"; stat -c %a "$(dirname "$f")" > {seen}; cat "$f" >> {seen}; echo "$f" > {seen}.path; exit 3\n')
    os.chmod(fake / 'corosync-qdevice-net-certutil', 0o755)
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    p = subprocess.run(['bash', '-c', qnetd.p12_import_script()], input=base64.b64encode(P12) + b'\n',
                       env=env, capture_output=True, timeout=30)
    assert p.returncode == 3
    lines = seen.read_bytes()
    assert lines.startswith(b'700\n') and P12 in lines
    staged = (tmp_path / 'seen.path').read_text().strip()
    assert staged.startswith(str(tmp_path)) and not os.path.exists(os.path.dirname(staged))


# --- transports -------------------------------------------------------------------------

def _one_line_server(path, answer):
    """A Unix socket that takes one request line and gives `answer`; got['req'] is what came."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    got = {}

    def serve():
        c, _a = srv.accept()
        buf = b''
        while not buf.endswith(b'\n'):
            chunk = c.recv(4096)
            if not chunk:
                break
            buf += chunk
        got['req'] = json.loads(buf)
        c.sendall(answer)
        c.close()
        srv.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return got, t


def test_the_local_helper_is_asked_on_its_socket_without_sudo(tmp_path):
    path = str(tmp_path / 'local.sock')
    got, t = _one_line_server(path, b'{"ok": true, "crt_b64": "eA=="}\n')
    ans = qnetd.LocalTransport(path).call('sign', name='pve', data={'crq_b64': 'Y3Jx'})
    t.join(5)
    assert got['req'] == {'op': 'sign', 'name': 'pve', 'crq_b64': 'Y3Jx'} and ans['ok'] is True
    assert qnetd.LocalTransport().path == qnetd.LOCAL_SOCKET == '/run/pegaprox-qnetd/local.sock'


def test_a_helper_call_with_a_bad_name_is_never_made(monkeypatch):
    def no_socket(*a, **k):
        raise AssertionError('a socket was opened')
    monkeypatch.setattr(qnetd.socket, 'socket', no_socket)
    with pytest.raises(qnetd.HelperError):
        qnetd.LocalTransport('/nonexistent.sock').call('sign', name='pve;id', data={'crq_b64': 'Y3Jx'})
    with pytest.raises(qnetd.HelperError):
        qnetd.LocalTransport('/nonexistent.sock').call('rm')


@pytest.mark.parametrize('out', [b'', b'sudo: a password is required\n', b'[1]\n', b'{"protocol": 1}\n',
                                 b'x' * (qnetd.ANSWER_MAX + 2)])
def test_an_answer_outside_the_protocol_is_an_error(tmp_path, out):
    path = str(tmp_path / 'local.sock')
    _got, t = _one_line_server(path, out)
    with pytest.raises(qnetd.HelperError):
        qnetd.LocalTransport(path).call('version')
    t.join(5)


def test_an_older_helper_is_outdated():
    assert qnetd._version_info({'ok': True, 'protocol': 0})['outdated'] is True
    assert qnetd._version_info({'ok': True})['outdated'] is True
    assert qnetd._version_info({'ok': True, 'protocol': qnetd.PROTOCOL})['outdated'] is False


def test_the_sidecar_speaks_one_line_each_way(tmp_path):
    path = str(tmp_path / 'helper.sock')
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    got = {}

    def serve():
        c, _a = srv.accept()
        buf = b''
        while not buf.endswith(b'\n'):
            buf += c.recv(4096)
        got['req'] = json.loads(buf)
        c.sendall(b'{"ok": true, "protocol": 1, "qnetd_installed": true}\n')
        c.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    ans = qnetd.SidecarTransport(path).call('version')
    t.join(5)
    srv.close()
    assert got['req'] == {'op': 'version'} and ans['protocol'] == 1


class _Chan:
    def __init__(self, rc):
        self.rc, self.closed = rc, False

    def shutdown_write(self):
        self.closed = True

    def recv_exit_status(self):
        return self.rc


class _File:
    def __init__(self, data=b'', chan=None):
        self._data, self.channel, self.written = data, chan, b''

    def read(self, n=-1):
        out, self._data = self._data, b''
        return out

    def write(self, b):
        self.written += b if isinstance(b, bytes) else b.encode()

    def flush(self):
        pass


class _Client:
    def __init__(self, answers):
        self.answers, self.cmds, self.stdin = answers, [], []
        self.connected = None

    def connect(self, **kw):
        self.connected = kw

    def exec_command(self, cmd, timeout=None):
        self.cmds.append(cmd)
        rc, out = next(((rc, out) for k, (rc, out) in self.answers.items() if k in cmd), (0, b''))
        chan = _Chan(rc)
        stdin = _File(chan=chan)
        self.stdin.append(stdin)
        return stdin, _File(out, chan), _File(b'', chan)

    def close(self):
        pass


def test_the_ssh_transport_pins_the_host_key_and_sends_secrets_on_stdin_only(monkeypatch):
    import pegaprox.utils.ssh_security as sec
    client = _Client({'id -u': (0, b'1000\n'), 'sign': (0, b'{"ok": true, "crt_b64": "eA=="}')})
    made = []
    monkeypatch.setattr(sec, 'secure_ssh_client', lambda pk: made.append(pk) or client)
    monkeypatch.setattr(sec, 'persist_host_keys', lambda c: None)
    tr = qnetd.SshTransport({'ssh_host': '[2001:db8::9]', 'ssh_port': 2222, 'ssh_user': 'qadmin',
                             'password': 'hunter2-secret'})
    ans = tr.call('sign', name='pve', data={'crq_b64': 'Y3Jx'})
    assert made and ans['ok']
    assert client.connected['hostname'] == '2001:db8::9' and client.connected['port'] == 2222
    assert client.connected['allow_agent'] is False and client.connected['look_for_keys'] is False
    sign = next(c for c in client.cmds if 'sign' in c)
    assert sign == f"sudo -n {qnetd.HELPER_PATH} sign --name pve"
    assert all('hunter2' not in c and 'Y3Jx' not in c for c in client.cmds)
    assert json.loads(client.stdin[client.cmds.index(sign)].written) == {'crq_b64': 'Y3Jx'}


# --- a cluster and a QNetd host to set up against ----------------------------------------

class FakeShell:
    def __init__(self, node, cluster):
        self.node, self.cluster, self.calls = node, cluster, []

    def run(self, script, data=None, timeout=None, limit=None):
        self.calls.append((script, data))
        return self.cluster.answer(self.node, script, data)

    def close(self):
        pass


class FakeCluster:
    def __init__(self, nodes=('pve1', 'pve2'), name='pve', device=False):
        self.nodes, self.name, self.device = list(nodes), name, device
        self.pkg = {n: True for n in nodes}
        self.port = {n: True for n in nodes}
        # the address each node sends from towards the QNetd (ip route get ... src)
        self.src = {n: f'10.0.0.{i + 1}' for i, n in enumerate(nodes)}
        self.store = {n: False for n in nodes}
        self.vm_hit = ''
        self.fail = {}             # what -> rc
        self.shells = {}
        self.conf_written = False

    def entries(self):
        out = [{'type': 'cluster', 'name': self.name, 'quorate': 1, 'nodes': len(self.nodes)}]
        out += [{'type': 'node', 'name': n, 'online': 1, 'ip': f'10.0.0.{i + 1}'} for i, n in enumerate(self.nodes)]
        return out

    def answer(self, node, script, data):
        def r(what, rc, out='', err=''):
            if what in self.fail:
                return self.fail[what], '', f'{what} broke'
            return rc, out, err
        if script.startswith('q() {'):
            return r('probe', 0, f"pkg={int(self.pkg[node])}\ncertutil={int(self.pkg[node])}\n"
                                 f"store={int(self.store[node])}\nport={int(self.port[node])}\n"
                                 f"src={self.src.get(node) or ''}\n")
        if 'cfs_read_file' in script and 'atomic_write_conf' not in script:
            return r('conf_read', 0, f"name={self.name}\ndevice={int(self.device)}\ntwo_node=0\n")
        if script.startswith('grep -r -l'):
            return (0, self.vm_hit, 'rc=0') if self.vm_hit else (1, '', 'rc=1')
        if 'device} = $qdev_section' in script:
            rc = self.fail.get('conf_add', 0)
            if rc == 0:
                self.conf_written = True
            return rc, 'written', '' if rc == 0 else 'conf_add broke'
        if 'delete $quorum_section->{device}' in script:
            self.conf_written = False
            return 0, 'removed', ''
        if '-i -c' in script:
            return r('ca', 0)
        if ' -r -n ' in script:
            return r('crq', 0, base64.b64encode(CRQ).decode())
        if ' -M -c ' in script:
            return r('crt', 0, base64.b64encode(P12).decode())
        if ' -m -c ' in script:
            return r('p12', 0)
        if script == qnetd.START_SCRIPT:
            return r('start', 0)
        if script == qnetd.RELOAD_SCRIPT:
            return r('reload', 0)
        if script == qnetd.CLEANUP_SCRIPT:
            return 0, '', ''
        if script == qnetd.APT_SCRIPT:
            self.pkg[node] = True
            return r('apt', 0)
        if script == qnetd.STORE_RESET_SCRIPT:
            return r('store_reset', 0)
        if script == qnetd.REMOVE_SCRIPT:
            return r('remove', 0, 'Removed Qdevice.')
        return 99, '', f'unexpected script {script[:40]}'

    def all_calls(self):
        return [(n, s, d) for n, sh in self.shells.items() for s, d in sh.calls]


class FakeFirewall:
    """The helper's firewall op (protocol 2) on a stand-in rule table: what it added per
    cluster tag, and the addresses a rule of somebody else allows already."""

    def __init__(self, backend='ufw', managed=True, blocking=True, port=5403, manual=''):
        self.backend, self.managed, self.blocking, self.port, self.manual = backend, managed, blocking, port, manual
        self.rules = {}
        self.foreign = set()
        self.calls = []

    def allowed(self, source):
        return self.blocking is False or source in self.foreign or any(source in r for r in self.rules.values())

    def __call__(self, name, data):
        self.calls.append((name, dict(data)))
        mine = self.rules.setdefault(name, [])
        ans = {'ok': True, 'backend': self.backend, 'managed': self.managed, 'port': self.port,
               'blocking': self.blocking, 'added': [], 'removed': [], 'manual': self.manual}
        if data['action'] == 'allow':
            if not self.managed and self.blocking is not False:
                return {'ok': False, 'code': 'firewall_unmanaged', 'error': f'open it by hand: {self.manual}'}
            if self.managed:
                for s in data['sources']:
                    if s not in mine and s not in self.foreign:
                        mine.append(s)
                        ans['added'].append({'source': s, 'port': self.port})
        elif data['action'] == 'remove':
            for s in list(mine):
                if 'sources' not in data or s in data['sources']:
                    mine.remove(s)
                    ans['removed'].append({'source': s, 'port': self.port})
        ans['rules'] = [{'source': s, 'port': self.port} for s in mine]
        return ans


class FakeHelper:
    kind = 'ssh'

    def __init__(self):
        self.answers = {
            'version': {'ok': True, 'protocol': qnetd.PROTOCOL, 'qnetd_installed': True, 'certutil_installed': True,
                        'ops': list(qnetd.OPS), 'package_manager': 'apt'},
            'status': {'ok': True, 'active': True, 'clusters': [], 'raw': '', 'certificates': []},
            'uuid': {'ok': True, 'product_uuid': UUID},
            'ca': {'ok': True, 'ca_b64': base64.b64encode(CA).decode()},
            'init': {'ok': True, 'active': True},
            'sign': {'ok': True, 'crt_b64': base64.b64encode(CRT).decode()},
            'firewall': FakeFirewall(backend='none', managed=False, blocking=False),
        }
        self.calls = []

    def call(self, op, name=None, data=None):
        qnetd._request(op, name, data)
        self.calls.append((op, name, data))
        ans = self.answers[op]
        if isinstance(ans, Exception):
            raise ans
        if callable(ans):
            return ans(name, data)
        return dict(ans)

    def session(self):
        from contextlib import contextmanager

        @contextmanager
        def cm():
            yield self.call
        return cm()


@pytest.fixture
def world(db, monkeypatch):
    from pegaprox.globals import cluster_managers
    from unittest.mock import MagicMock
    c = FakeCluster()
    h = FakeHelper()
    mgr = MagicMock(name='mgr')
    mgr.cluster_type, mgr.is_connected = 'proxmox', True
    mgr.config.name = 'Lab'
    monkeypatch.setattr(qnetd, '_cluster_status', lambda m: c.entries())

    def shell(m, node):
        if node not in c.nodes:
            raise qnetd.NodeError(f'node {node}: unknown')
        s = c.shells[node] = FakeShell(node, c)
        return s
    monkeypatch.setattr(qnetd, '_open_shell', shell)
    monkeypatch.setattr(qnetd, 'transport_for', lambda rec: h)
    db.save_qnetd_host('aaaaaaaaaaaa', {'name': 'witness', 'kind': 'ssh', 'address': '192.0.2.50', 'port': 5403,
                                        'ssh_host': '192.0.2.50', 'ssh_port': 22, 'ssh_user': 'root'},
                       password='pw')
    cluster_managers['c1'] = mgr
    audits = []
    import pegaprox.utils.audit as audit
    monkeypatch.setattr(audit, 'log_audit', lambda *a, **k: audits.append((a, k)))
    yield types.SimpleNamespace(cluster=c, helper=h, mgr=mgr, db=db, audits=audits,
                                rec=lambda: qnetd.get_qnetd('aaaaaaaaaaaa'))
    cluster_managers.pop('c1', None)


def _checks(report):
    return {c['id']: c['ok'] for c in report['checks']}


def _agree(world, opts=None, cid='c1', mgr=None):
    """The options of a setup with the consent to the plan as it reads now (what the admin
    saw and agreed to)."""
    opts = dict(opts or {})
    got = qnetd.plan(cid, mgr or world.mgr, world.rec(), opts)
    opts.setdefault('consents', {})[cid] = got['plan']['digest']
    return opts


def test_a_two_node_cluster_passes_the_preflight(world):
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert report['ok'] is True, report['checks']
    assert report['cluster_name'] == 'pve' and report['node_count'] == 2
    assert all(v is True for v in _checks(report).values())
    assert [n['port_open'] for n in report['nodes']] == [True, True]


def test_an_odd_node_count_is_refused(world):
    world.cluster.nodes.append('pve3')
    world.cluster.pkg['pve3'] = world.cluster.port['pve3'] = True
    world.cluster.store['pve3'] = False
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert report['ok'] is False and _checks(report)['node_count_even'] is False


def test_the_qnetd_host_as_a_guest_of_the_cluster_is_refused(world):
    world.cluster.vm_hit = '/etc/pve/nodes/pve2/qemu-server/104.conf\n'
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert report['ok'] is False
    msg = next(c['message'] for c in report['checks'] if c['id'] == 'not_own_vm')
    assert 'VM 104' in msg
    grep = next(s for n, s, d in world.cluster.all_calls() if s.startswith('grep -r -l'))
    assert UUID in grep
    # one grep for the whole cluster, on one node
    assert sum(1 for n, s, d in world.cluster.all_calls() if s.startswith('grep -r -l')) == 1


def test_an_unknown_host_identity_needs_a_confirmation(world):
    world.helper.answers['uuid'] = {'ok': True, 'product_uuid': ''}
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert report['ok'] is False and report['needs_confirmation'] is True
    assert qnetd.inspect('c1', world.mgr, world.rec(), confirm_unverified=True)['ok'] is True


def test_a_name_another_cluster_uses_on_that_qnetd_is_refused(world):
    world.db.save_qnetd_attachment('c2', 'aaaaaaaaaaaa', 'pve', 'admin')
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['name_unique'] is False
    world.db.delete_qnetd_attachment('c2')
    world.helper.answers['status'] = {'ok': True, 'active': True, 'clusters': [{'name': 'pve', 'nodes': []}]}
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['name_unique'] is False


def test_an_outdated_or_stopped_qnetd_is_not_ready(world):
    world.helper.answers['version'] = {'ok': True, 'protocol': 0, 'qnetd_installed': True}
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert _checks(report)['qnetd_ready'] is False
    assert any('outdated' in c['message'] for c in report['checks'] if c['id'] == 'qnetd_ready')
    assert not any(op == 'sign' for op, *_ in world.helper.calls)
    world.helper.answers['version'] = {'ok': True, 'protocol': qnetd.PROTOCOL, 'qnetd_installed': True}
    world.helper.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['qnetd_ready'] is False


def test_missing_packages_and_a_closed_port_fail_unless_installing(world):
    world.cluster.pkg['pve2'] = False
    world.cluster.port['pve1'] = False
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert _checks(report)['packages'] is False and _checks(report)['qnetd_port'] is False
    world.cluster.port['pve1'] = True
    assert qnetd.inspect('c1', world.mgr, world.rec(), install_packages=True)['ok'] is True


def test_a_cluster_with_a_device_or_a_node_as_qnetd_is_refused(world):
    world.cluster.device = True
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['no_qdevice'] is False
    world.cluster.device = False
    world.db.save_qnetd_host('aaaaaaaaaaaa', dict(world.rec(), address='10.0.0.2'))
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['not_a_node'] is False


def test_a_changed_ca_is_refused(world):
    world.db.set_qnetd_ca_pin('aaaaaaaaaaaa', 'f' * 64)
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert _checks(report)['qnetd_ready'] is False
    assert any('not the one PegaProx pinned' in c['message'] for c in report['checks'])


# --- setup, rollback, remove ------------------------------------------------------------

def _run(job, fn, *args):
    """A job, run here instead of on a thread, with launch's bookkeeping."""
    qnetd.register(job)
    try:
        fn(job, *args)
    finally:
        qnetd._release(job)
    return job.view()


def test_a_setup_relays_every_file_and_attaches_the_cluster(world):
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '198.51.100.20')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    assert view['state'] == 'done', view
    steps = [s['step'] for s in view['steps'] if s['state'] == 'ok']
    # nothing to set up on the QNetd host and no firewall asked for: neither step runs
    assert steps == ['plan', 'preflight', 'qnetd_init', 'qnetd_ca', 'node_ca', 'node_crq', 'qnetd_sign', 'node_crt',
                     'node_p12', 'corosync_conf', 'qdevice_start', 'corosync_reload']
    calls = world.cluster.all_calls()
    # the CA and the bundle went to both nodes on stdin, the CRQ to the helper, the CRT to one node
    assert sorted(n for n, s, d in calls if '-i -c' in s and d == base64.b64encode(CA) + b'\n') == ['pve1', 'pve2']
    assert sorted(n for n, s, d in calls if ' -m -c ' in s and d == base64.b64encode(P12) + b'\n') == ['pve1', 'pve2']
    assert [n for n, s, d in calls if ' -M -c ' in s] == ['pve1']
    sign = [c for c in world.helper.calls if c[0] == 'sign']
    assert sign == [('sign', 'pve', {'crq_b64': base64.b64encode(CRQ).decode(), 'replace': False})]
    assert world.cluster.conf_written
    att = world.db.list_qnetd_attachments(cluster_id='c1')
    assert att and att[0]['qnetd_id'] == 'aaaaaaaaaaaa' and att[0]['cluster_name'] == 'pve'
    assert world.rec()['ca_sha256']
    assert any(a[0][1] == 'qdevice.setup' for a in world.audits)


def test_the_cluster_key_is_never_on_a_command_line_or_in_the_log(world):
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '198.51.100.20')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    b64 = base64.b64encode(P12).decode()
    for _n, script, _d in world.cluster.all_calls():
        assert b64 not in script and 'THE-CLUSTER-PRIVATE-KEY' not in script
    dumped = json.dumps(view)
    assert b64 not in dumped and 'THE-CLUSTER-PRIVATE-KEY' not in dumped
    assert all('THE-CLUSTER' not in repr(a) for a in world.audits)


def test_a_failure_before_corosync_conf_cleans_the_nodes(world):
    world.cluster.fail['p12'] = 1
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    row = view['clusters']['c1']
    assert view['state'] == 'failed' and row['failed_step'] == 'node_p12' and row['rolled_back'] is True
    calls = world.cluster.all_calls()
    assert sorted(n for n, s, d in calls if s == qnetd.CLEANUP_SCRIPT) == ['pve1', 'pve2']
    # nothing was written, so nothing is taken out of corosync.conf
    assert not any('delete $quorum_section' in s for n, s, d in calls)
    assert world.db.list_qnetd_attachments(cluster_id='c1') == []


def test_a_failure_after_corosync_conf_takes_the_entry_out_again(world):
    world.cluster.fail['start'] = 1
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    row = view['clusters']['c1']
    assert row['failed_step'] == 'qdevice_start' and row['rolled_back'] is True
    assert not world.cluster.conf_written
    calls = [s for n, s, d in world.cluster.all_calls()]
    i_del = next(i for i, s in enumerate(calls) if 'delete $quorum_section' in s)
    assert qnetd.RELOAD_SCRIPT in calls[i_del:]
    assert any(s['step'] == 'rollback' and s['state'] == 'ok' for s in view['steps'])


def test_an_old_certificate_of_the_name_is_replaced_only_when_asked(world):
    # a helper of an older build: its status does not list the certificates, so the plan
    # cannot tell and sign's own refusal is what stops the run
    del world.helper.answers['status']['certificates']
    world.helper.answers['sign'] = {'ok': False, 'code': 'name_exists',
                                    'error': 'this QNetd holds a certificate for a cluster named "pve"'}
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), _agree(world))
    row = view['clusters']['c1']
    assert row['failed_step'] == 'qnetd_sign' and row['code'] == 'name_exists' and row['rolled_back'] is True
    world.helper.answers['sign'] = {'ok': True, 'crt_b64': base64.b64encode(CRT).decode()}
    world.helper.calls.clear()
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(),
                _agree(world, {'replace_certificate': True}))
    assert view['state'] == 'done'
    assert [c[2]['replace'] for c in world.helper.calls if c[0] == 'sign'] == [True]
    body = qnetd._request('sign', 'pve', {'crq_b64': 'Y3Jx', 'replace': 'yes'})
    assert 'replace' not in body


def test_a_helper_that_turned_outdated_since_the_preflight_signs_nothing(world, monkeypatch):
    real = qnetd.inspect
    opts = _agree(world)

    def then_downgrade(*a, **k):
        report = real(*a, **k)
        if not k.get('plan'):
            world.helper.answers['version'] = {'ok': True, 'protocol': qnetd.PROTOCOL - 1, 'qnetd_installed': True}
        return report
    monkeypatch.setattr(qnetd, 'inspect', then_downgrade)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), opts)
    assert view['clusters']['c1']['failed_step'] == 'qnetd_sign'
    assert not any(c[0] == 'sign' for c in world.helper.calls)
    assert view['clusters']['c1']['rolled_back'] is True


def test_a_failure_on_the_qnetd_side_changes_no_node(world):
    world.helper.answers['init'] = {'ok': False, 'error': 'apt-get failed'}
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    row = view['clusters']['c1']
    assert row['failed_step'] == 'qnetd_init' and row['rolled_back'] is None
    assert not any(s == qnetd.CLEANUP_SCRIPT for n, s, d in world.cluster.all_calls())


def test_a_preflight_that_fails_in_the_job_changes_nothing(world):
    world.cluster.nodes.append('pve3')
    world.cluster.pkg['pve3'] = world.cluster.port['pve3'] = True
    world.cluster.store['pve3'] = False
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world))
    # the plan the admin agreed to holds, but it does not pass: the job stops there
    assert view['clusters']['c1']['failed_step'] == 'plan'
    assert not any(op in ('init', 'sign') for op, *_ in world.helper.calls)


def test_missing_packages_are_installed_when_asked_and_stale_stores_replaced(world):
    world.cluster.pkg['pve2'] = False
    world.cluster.store['pve1'] = True
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world, {'install_packages': True}))
    assert view['state'] == 'done', view['steps']
    calls = world.cluster.all_calls()
    assert [n for n, s, d in calls if s == qnetd.APT_SCRIPT] == ['pve2']
    assert [n for n, s, d in calls if s == qnetd.STORE_RESET_SCRIPT] == ['pve1']


def test_bulk_goes_on_past_a_cluster_that_fails(world):
    from pegaprox.globals import cluster_managers
    from unittest.mock import MagicMock
    bad = MagicMock(name='bad')
    bad.cluster_type, bad.is_connected = 'xcpng', True
    cluster_managers['c9'] = bad
    try:
        opts = _agree(world, _agree(world, {}, 'c9', bad))
        job = qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c9', 'c1'], 'admin', '')
        view = _run(job, qnetd.run_bulk, world.rec(), opts)
    finally:
        cluster_managers.pop('c9', None)
    assert view['clusters']['c9']['state'] == 'failed' and view['clusters']['c1']['state'] == 'done'
    assert view['state'] == 'partial'


def test_one_job_at_a_time_per_qnetd_and_per_cluster():
    a = qnetd.register(qnetd.Job('bulk', 'aaaaaaaaaaaa', ['c1', 'c2'], 'admin', ''))
    with pytest.raises(qnetd.Busy):
        qnetd.register(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c3'], 'admin', ''))
    with pytest.raises(qnetd.Busy):
        qnetd.register(qnetd.Job('remove', None, ['c2'], 'admin', ''))
    qnetd.register(qnetd.Job('setup', 'bbbbbbbbbbbb', ['c3'], 'admin', ''))
    assert qnetd.busy_with('c1') == f'bulk job {a.id}'
    qnetd._release(a)
    assert qnetd.busy_with('c1') is None


def test_remove_is_pvecm_on_one_node_and_drops_the_attachment(world):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    job = qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_remove)
    assert view['state'] == 'done'
    calls = world.cluster.all_calls()
    assert [(n, s) for n, s, d in calls] == [('pve1', 'pvecm qdevice remove')]
    assert world.db.list_qnetd_attachments(cluster_id='c1') == []


def test_remove_of_a_cluster_without_a_qdevice_still_drops_the_record(world):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    world.cluster.answer = lambda node, script, data: (2, '', 'No QDevice configured!')
    view = _run(qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_remove)
    assert view['state'] == 'done' and world.db.list_qnetd_attachments(cluster_id='c1') == []


def test_a_remove_that_fails_keeps_the_record(world):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    world.cluster.fail['remove'] = 255
    view = _run(qnetd.Job('remove', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_remove)
    assert view['state'] == 'failed' and world.db.list_qnetd_attachments(cluster_id='c1')


# --- status, the cache and the alert -------------------------------------------------------

def test_status_is_read_once_per_fresh_window(world):
    rec = world.rec()
    qnetd.status(rec, now=1000.0)
    qnetd.status(rec, now=1000.0 + qnetd.FRESH - 1)
    assert sum(1 for c in world.helper.calls if c[0] == 'status') == 1
    qnetd.status(rec, now=1000.0 + qnetd.FRESH + 1)
    assert sum(1 for c in world.helper.calls if c[0] == 'status') == 2


def test_the_alert_view_reads_the_cache_only_and_waits_for_a_streak(world):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    rec = world.rec()
    assert qnetd.alert_view('c1', now=NOW)[0]['state'] == 'unknown'
    qnetd.status(rec, now=NOW)
    calls = len(world.helper.calls)
    assert qnetd.alert_view('c1', now=NOW + 5)[0]['state'] == 'ok'
    assert len(world.helper.calls) == calls
    world.helper.answers['version'] = qnetd.HelperError('SSH to the QNetd host failed (timeout)')
    qnetd.status(rec, max_age=0, now=NOW + 60)
    assert qnetd.alert_view('c1', now=NOW + 61)[0]['state'] == 'unknown'
    qnetd.status(rec, max_age=0, now=NOW + 120)
    row = qnetd.alert_view('c1', now=NOW + 121)[0]
    # the rule says down; what went wrong is the QNetd hosts panel's (admins only)
    assert row['state'] == 'down' and 'error' not in row and 'name' not in row
    assert qnetd.alert_view('c1', now=NOW + 120 + qnetd.SERVE_MAX + 1)[0]['state'] == 'unknown'


def test_the_qnetd_rule_raises_one_alert_per_host_and_clears_it(world, seed, monkeypatch, sent):
    from pegaprox.background import alert_events as E
    seed.user('root', role='admin')
    world.mgr.is_connected = False            # nothing of the cluster is needed
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    monkeypatch.setattr(qnetd, 'kick_refresh', lambda now=None, cluster_ids=None: False)
    _rules(monkeypatch, _rule('qnetd', rid='rq', qnetd_by='root'))
    rec = world.rec()
    world.helper.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
    for t in (0, 60):
        qnetd.status(rec, max_age=0, now=NOW + t)
    E.check_event_alerts(now=NOW + 61)
    rows = _open(world.db, 'rq')
    assert len(rows) == 1 and rows[0]['object_key'] == 'qnetd:aaaaaaaaaaaa'
    assert 'corosync-qnetd is not running' in rows[0]['message']
    assert sent.names() == ['QNetd host inactive']
    E.check_event_alerts(now=NOW + 62)
    assert len(_open(world.db, 'rq')) == 1 and len(sent.names()) == 1
    world.helper.answers['status'] = {'ok': True, 'active': True, 'clusters': []}
    qnetd.status(rec, max_age=0, now=NOW + 120)
    E.check_event_alerts(now=NOW + 121)
    assert _open(world.db, 'rq') == [] and sent.names()[-1] == 'Resolved: QNetd host'


def test_a_qnetd_rule_watches_the_cluster_whole(monkeypatch):
    from pegaprox.background import alert_events as E
    rule = {'metric': 'qnetd', 'target_type': 'node', 'target_id': 'pve1'}
    # outside a request nobody is an administrator (test_qnetd_followups has the routes)
    assert 'administrator' in E.normalize_rule(dict(rule), {})
    monkeypatch.setattr(E, '_qnetd_caller', lambda: 'root')
    assert E.normalize_rule(rule, {}) is None
    assert rule['target_type'] == 'cluster' and rule['target_id'] is None and rule['operator'] == 'event'
    assert rule['qnetd_by'] == 'root'
    assert 'qnetd' in E.EVENT_METRICS and 'qnetd' in E.DB_ONLY


def test_kick_refresh_only_reads_attached_hosts_that_went_stale(world, monkeypatch):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    started = []

    class T:
        def __init__(self, target, **kw):
            self.target = target

        def start(self):
            started.append(self)
            self.target()
    monkeypatch.setattr(qnetd.threading, 'Thread', T)
    assert qnetd.kick_refresh(now=NOW) is True and len(started) == 1
    assert qnetd.cached_status('aaaaaaaaaaaa', now=NOW + 1) is not None
    assert qnetd.kick_refresh(now=NOW + 1) is False
    assert qnetd.kick_refresh(now=NOW + qnetd.REFRESH_EVERY) is True and len(started) == 2
    # a host none of the clusters asked about is not read
    assert qnetd.kick_refresh(now=NOW + 2 * qnetd.REFRESH_EVERY, cluster_ids=['c9']) is False
