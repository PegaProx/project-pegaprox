"""The QDevice/QNetd code against hostile peers: what a hostile cluster, a hostile or hung QNetd host
or node, and a stranger on the QNetd port could do. Each finding has a test that failed on
the code before its fix, and guards that show the fix leaves the rest as it was. Offline:
fake shells, fake SSH clients, the helper's stand-in binaries.
MK Oct 2026
"""
import os
import shutil
import signal
import socket
import subprocess
import threading
import time

import pytest

from pegaprox.core import qnetd

# the fake cluster, QNetd helper and world of the core tests; db comes from conftest
from test_qnetd_core import UUID, _agree, _checks, _run, pve_perl, world  # noqa: F401
from test_qnetd_helper import H, NSS, FakeBins, start_sidecar, short_dir, wait_for
from test_qnetd_packaging import QBox, ok


@pytest.fixture(autouse=True)
def _clean():
    qnetd.reset_for_tests()
    yield
    qnetd.reset_for_tests()


# --- one name, two clusters -------------------------------------------------------------
# corosync-qnetd matches a client certificate to its cluster name the way a host name is
# matched, without regard to case, and the helper looks for an older certificate the same
# way. A preflight that compares the names exactly lets a second cluster named PVE onto a
# QNetd that serves pve; with replace_certificate the helper then signs it, and each of
# the two clusters holds a certificate the QNetd takes for the other one.

def test_a_name_that_differs_only_in_case_from_an_attached_cluster_is_a_clash(world):
    world.db.save_qnetd_attachment('c2', 'aaaaaaaaaaaa', 'PVE', 'admin')
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert _checks(report)['name_unique'] is False
    assert report['ok'] is False


def test_a_name_that_differs_only_in_case_from_a_connected_cluster_is_a_clash(world):
    world.helper.answers['status'] = {'ok': True, 'active': True,
                                      'clusters': [{'name': 'PVE', 'nodes': []}]}
    assert _checks(qnetd.inspect('c1', world.mgr, world.rec()))['name_unique'] is False


def test_a_case_clash_stops_the_setup_before_any_node_changes(world):
    world.db.save_qnetd_attachment('c2', 'aaaaaaaaaaaa', 'Pve', 'admin')
    job = qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', '')
    view = _run(job, qnetd.run_setup, world.rec(), _agree(world, {'replace_certificate': True}))
    assert view['clusters']['c1']['failed_step'] == 'plan'
    assert not any(op == 'sign' for op, *_ in world.helper.calls)


# --- the QNetd host on a node of the cluster itself ---------------------------------------
# The guest check greps the VM configs for the QNetd host's SMBIOS UUID. A QNetd host that is
# a node of the cluster (reached at an address /cluster/status does not list) or a privileged
# container on one reports that node's own UUID, which no VM config holds: it passed as "no
# guest", and its vote would fall with that node.

def _node_uuid(world, node, value):
    real = world.cluster.answer

    def answer(n, script, data):
        rc, out, err = real(n, script, data)
        if script.startswith('q() {') and n == node:
            out += f'uuid={value}\n'
        return rc, out, err
    world.cluster.answer = answer


def test_the_probe_reads_the_smbios_uuid_of_every_node():
    script = qnetd.probe_script('192.0.2.50', 5403)
    assert '/sys/class/dmi/id/product_uuid' in script and 'uuid=' in script


def test_a_qnetd_host_with_the_uuid_of_a_node_is_refused(world):
    _node_uuid(world, 'pve2', UUID.upper())
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert _checks(report)['not_own_vm'] is False and report['ok'] is False
    msg = next(c['message'] for c in report['checks'] if c['id'] == 'not_own_vm')
    assert 'pve2' in msg
    # a hard no: confirming an unverified host does not wave it through
    assert qnetd.inspect('c1', world.mgr, world.rec(), confirm_unverified=True)['ok'] is False


def test_other_node_uuids_leave_the_guest_check_as_it_was(world):
    _node_uuid(world, 'pve1', '11111111-2222-3333-4444-555555555555')
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert report['ok'] is True, report['checks']
    assert any(s.startswith('grep -r -l') for _n, s, _d in world.cluster.all_calls())


# --- a stranger on the QNetd port ---------------------------------------------------------
# corosync-qnetd's default (-s on) lets a client go without TLS: then no certificate is asked
# for, and anybody who reaches the port joins the vote of any cluster name it likes. Every
# QDevice PegaProx sets up speaks TLS, so the sidecar, which PegaProx runs itself, requires it.

def test_the_sidecar_runs_qnetd_with_tls_required(tmp_path):
    host = FakeBins(tmp_path)
    d = short_dir()
    sock = os.path.join(d, 'sock', 'helper.sock')
    proc = start_sidecar(host, sock)
    try:
        assert wait_for(sock, proc), proc.communicate(timeout=10)
        end = time.monotonic() + 10
        calls = []
        while not calls and time.monotonic() < end:
            calls = [c for c in host.calls() if c.startswith('corosync-qnetd ')]
            time.sleep(0.05)
        argv = calls[0].split()
        assert '-s' in argv and argv[argv.index('-s') + 1] == 'req'
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(20)
            except Exception:
                proc.kill()
        proc.communicate(timeout=10)
        shutil.rmtree(d, ignore_errors=True)



def _real_qnetd():
    if NSS is None:
        return None
    for d in ('bin', 'sbin'):
        q = os.path.join(os.path.dirname(NSS['bin']), d, 'corosync-qnetd')
        t = os.path.join(os.path.dirname(NSS['bin']), d, 'corosync-qnetd-tool')
        if os.access(q, os.X_OK) and os.access(t, os.X_OK):
            return q, t
    return None


@pytest.mark.skipif(_real_qnetd() is None, reason='no real corosync-qnetd here (CI): set PEGAPROX_TEST_NSS_ROOT')
def test_the_real_qnetd_takes_the_sidecar_argv_and_requires_tls(tmp_path):
    """The man page names the mode "required", the binary takes only on, off and req: the
    argv the sidecar builds, run by the real corosync-qnetd (on loopback, a free port)."""
    qbin, tool = _real_qnetd()
    run = short_dir()
    try:
        bins = tmp_path / 'bin'
        bins.mkdir()
        for name, path in (('certutil', NSS['certutil']), ('corosync-qnetd', qbin), ('corosync-qnetd-tool', tool)):
            os.symlink(path, str(bins / name))
        conf = tmp_path / 'conf'
        conf.mkdir()
        env = {'PEGAPROX_QNETD_CONFIG_DIR': str(conf), 'PEGAPROX_QNETD_BIN_DIR': str(bins),
               'PEGAPROX_QNETD_RUN_DIR': run}
        host = H.Host('sidecar', env)
        H.ensure_db(host)
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        argv = H.qnetd_argv(host, host.need('corosync-qnetd')) + ['-l', '127.0.0.1', '-p', str(port)]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/')
        try:
            out, end = '', time.monotonic() + 15
            while time.monotonic() < end and proc.poll() is None:
                p = subprocess.run([tool, '-s', '-p', host.ipc_socket], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
                if p.returncode == 0:
                    out = p.stdout
                    break
                time.sleep(0.2)
            assert proc.poll() is None, proc.communicate(timeout=10)
            tls = next((ln for ln in out.splitlines() if ln.startswith('TLS:')), '')
            assert 'Required' in tls, out
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
            proc.communicate(timeout=10)
    finally:
        shutil.rmtree(run, ignore_errors=True)

# --- a host that answers a byte at a time -------------------------------------------------
# The reads had a timeout for each read, not for the command: a QNetd host or a node that
# drips its answer kept a status read (and the per-host lock behind it) or a setup job
# (and its claims on the QNetd host and the cluster) for as long as it liked.

class _DripChan:
    def __init__(self, give_up=15.0):
        self.closed = threading.Event()
        self.give_up = time.monotonic() + give_up

    def close(self):
        self.closed.set()

    def shutdown_write(self):
        pass

    def recv_exit_status(self):
        return -1 if self.closed.is_set() else 0


class _DripOut:
    def __init__(self, chan):
        self.channel = chan

    def read(self, n=-1):
        if self.channel.closed.is_set() or time.monotonic() > self.channel.give_up:
            return b''
        time.sleep(0.05)
        return b' '


class _Quiet:
    def __init__(self, chan):
        self.channel = chan

    def read(self, n=-1):
        return b''

    def write(self, b):
        pass

    def flush(self):
        pass


class _DripClient:
    def __init__(self):
        self.chans = []

    def exec_command(self, cmd, timeout=None):
        chan = _DripChan()
        self.chans.append(chan)
        return _Quiet(chan), _DripOut(chan), _Quiet(chan)


def _in_thread(fn, wait):
    box = {}

    def go():
        try:
            box['value'] = fn()
        except BaseException as e:      # what the call raised is the result here
            box['error'] = e
    t = threading.Thread(target=go, daemon=True)
    started = time.monotonic()
    t.start()
    t.join(wait)
    return t.is_alive(), time.monotonic() - started, box


def test_a_qnetd_host_that_drips_its_answer_is_cut_off_at_the_deadline(monkeypatch):
    monkeypatch.setitem(qnetd.OP_TIMEOUT, 'version', 1)
    client = _DripClient()
    tr = qnetd.SshTransport({'ssh_host': '192.0.2.50', 'ssh_user': 'root', 'password': 'pw'})
    alive, took, box = _in_thread(lambda: tr._call_on(client, '', 'version'), wait=6)
    assert not alive, 'the read went on past its deadline'
    assert isinstance(box.get('error'), qnetd.HelperError)
    assert client.chans and client.chans[0].closed.is_set()
    assert took < 6


def test_a_node_that_drips_its_answer_cannot_hold_a_job(monkeypatch):
    shell = qnetd.NodeShell.__new__(qnetd.NodeShell)
    shell.node, shell._client, shell._prefix = 'pve1', _DripClient(), ''
    alive, took, box = _in_thread(lambda: shell.run('pvecm qdevice remove', timeout=0.5), wait=6)
    assert not alive, 'the node command went on past its deadline'
    rc, _out, err = box['value']
    assert rc == 124 and 'no answer' in err
    assert shell._client.chans[0].closed.is_set()



def test_the_deadline_holds_on_a_real_ssh_channel():
    """The same against paramiko itself: an SSH server in this process that sends a byte
    every 50 ms, so no single read ever times out."""
    paramiko = pytest.importorskip('paramiko')

    class Server(paramiko.ServerInterface):
        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_auth_none(self, username):
            return paramiko.AUTH_SUCCESSFUL

        def get_allowed_auths(self, username):
            return 'none'

        def check_channel_exec_request(self, channel, command):
            def drip():
                try:
                    for _ in range(400):
                        if channel.closed:
                            return
                        channel.send(b'x')
                        time.sleep(0.05)
                    channel.send_exit_status(0)
                    channel.close()
                except Exception:
                    pass
            threading.Thread(target=drip, daemon=True).start()
            return True

    a, b = socket.socketpair()
    server = paramiko.Transport(b)
    server.add_server_key(paramiko.RSAKey.generate(1024))
    threading.Thread(target=lambda: server.start_server(server=Server()), daemon=True).start()
    client = paramiko.Transport(a)
    try:
        client.start_client(timeout=10)
        client.auth_none('root')

        class Client:
            def exec_command(self, cmd, timeout=None):
                ch = client.open_session()
                ch.settimeout(timeout)
                ch.exec_command(cmd)
                return ch.makefile_stdin('wb'), ch.makefile('rb'), ch.makefile_stderr('rb')
        started = time.monotonic()
        with pytest.raises(socket.timeout):
            qnetd._exec_bounded(Client(), 'version', b'', 1.5, qnetd.ANSWER_MAX)
        assert time.monotonic() - started < 6
    finally:
        client.close()
        server.close()

# --- a corosync.conf write whose answer never came back -----------------------------------
# PVE's perl may have written the QDevice entry when the login drops or the 60 s run out.
# The rollback then left the entry in place and took the certificates and the daemon off
# every node: a cluster with a quorum.device nobody serves, which pvecm qdevice setup and
# the next preflight both refuse until somebody removes it by hand.

def _conf_add_then(world, rc, err, writes=True):
    real = world.cluster.answer

    def answer(n, script, data):
        if 'device} = $qdev_section' in script:
            if writes:
                world.cluster.conf_written = True
            return rc, '', err
        return real(n, script, data)
    world.cluster.answer = answer


def test_a_conf_write_with_no_answer_is_still_taken_out_again(world):
    _conf_add_then(world, 124, 'no answer within 60 s')
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), _agree(world))
    row = view['clusters']['c1']
    assert row['failed_step'] == 'corosync_conf'
    assert not world.cluster.conf_written, 'the entry the write may have made is still in corosync.conf'
    calls = [s for _n, s, _d in world.cluster.all_calls()]
    i_del = next(i for i, s in enumerate(calls) if 'delete $quorum_section' in s)
    assert qnetd.RELOAD_SCRIPT in calls[i_del:]


def test_the_rollback_perl_says_whether_there_was_an_entry(pve_perl):
    p = pve_perl.run(qnetd.conf_del_script('192.0.2.7'))
    assert p.returncode == 0 and p.stdout.split() == ['absent'], p.stderr
    assert pve_perl.read()['main']['totem']['config_version'] == 4      # nothing written
    assert pve_perl.run(qnetd.conf_add_script('192.0.2.7', 5403)).returncode == 0
    p = pve_perl.run(qnetd.conf_del_script('192.0.2.7'))
    assert p.returncode == 0 and p.stdout.split() == ['removed'], p.stderr
    assert 'device' not in pve_perl.read()['main']['quorum']


def test_a_conf_write_that_had_not_gone_through_reloads_nothing(world):
    _conf_add_then(world, 124, 'no answer within 60 s', writes=False)
    real = world.cluster.answer

    def answer(n, script, data):
        if 'delete $quorum_section->{device}' in script:
            return 0, 'absent\n', ''
        return real(n, script, data)
    world.cluster.answer = answer
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), _agree(world))
    assert view['clusters']['c1']['rolled_back'] is True
    assert any(s['step'] == 'rollback' and 'no QDevice entry' in s['message'] for s in view['steps'])
    assert not any(s == qnetd.RELOAD_SCRIPT for _n, s, _d in world.cluster.all_calls())


def test_a_conf_write_refused_for_an_existing_device_takes_nothing_out(world):
    _conf_add_then(world, 255, 'Qdevice already configured, must be removed before setting up new one!',
                   writes=False)
    view = _run(qnetd.Job('setup', 'aaaaaaaaaaaa', ['c1'], 'admin', ''), qnetd.run_setup, world.rec(), _agree(world))
    assert view['clusters']['c1']['failed_step'] == 'corosync_conf'
    # that entry is somebody else's: the rollback leaves it alone
    assert not any('delete $quorum_section' in s for _n, s, _d in world.cluster.all_calls())


# --- what the QNetd listing may carry to a root terminal ----------------------------------
# The cluster names in corosync-qnetd-tool's listing are what the clients sent; a client
# without TLS sends any bytes it likes. install.sh --purge printed them to the admin's
# terminal as they came, escape sequences included.

def test_purge_does_not_print_terminal_controls_from_the_listing(tmp_path):
    box = QBox(tmp_path)
    ok(box.run())
    box.host.listing('Cluster "evil\x1b]2;owned\x07\x1b[2J":\n    Algorithm:\t\tFifty-Fifty split\n')
    out = box.run('--uninstall', '--purge')
    assert out.returncode == 1 and 'evil' in out.stderr
    assert '\x1b' not in out.stderr and '\x07' not in out.stderr
    assert os.path.exists(box.host.db)


# --- the transport errors of an SSH QNetd host stay helper errors ------------------------

def test_a_dropped_login_during_a_helper_call_is_a_helper_error():
    class Broken:
        def exec_command(self, cmd, timeout=None):
            raise EOFError('the transport went away')
    tr = qnetd.SshTransport({'ssh_host': '192.0.2.50', 'ssh_user': 'root', 'password': 'pw'})
    with pytest.raises(qnetd.HelperError):
        tr._call_on(Broken(), '', 'version')


def test_socket_timeouts_still_read_as_timeouts():
    class Slow:
        def exec_command(self, cmd, timeout=None):
            raise socket.timeout()
    tr = qnetd.SshTransport({'ssh_host': '192.0.2.50', 'ssh_user': 'root', 'password': 'pw'})
    with pytest.raises(qnetd.HelperError) as e:
        tr._call_on(Slow(), '', 'version')
    assert 'within' in str(e.value)


# --- a stored root login moved to another host ----------------------------------------------
# The SSH password or key of a QNetd host is never handed back. An edit that only changed
# ssh_host or ssh_port kept it, and the next Check sent it to the new address: an admin
# session (or a token, or a forged request) could read the root login of the QNetd host by
# pointing it at a machine of its own. As for PBS, the ESXi servers and the clusters, a move
# needs the secret typed again.

from test_qnetd_api import _host, env  # noqa: E402,F401


def test_moving_the_ssh_host_needs_the_secret_typed_again(env):
    hid = _host(env)['id']
    for move in ({'ssh_host': '203.0.113.66'}, {'ssh_port': 2222}, {'ssh_host': '203.0.113.66', 'password': ''}):
        r = env.admin.put(f'/api/qnetd/hosts/{hid}', json=move)
        assert r.status_code == 400, (move, r.data)
    rec = qnetd.get_qnetd(hid)
    assert (rec['ssh_host'], rec['ssh_port'], rec['password']) == ('192.0.2.50', 22, 'hunter2-secret')
    r = env.admin.put(f'/api/qnetd/hosts/{hid}', json={'ssh_host': '203.0.113.66', 'password': 'typed-again'})
    assert r.status_code == 200, r.data
    rec = qnetd.get_qnetd(hid)
    assert (rec['ssh_host'], rec['password']) == ('203.0.113.66', 'typed-again')
    # a rename or another QNetd address leaves the login where it is and needs nothing typed
    assert env.admin.put(f'/api/qnetd/hosts/{hid}', json={'name': 'other', 'address': '192.0.2.77'}).status_code == 200


def test_a_second_stored_secret_is_typed_again_or_dropped_on_a_move(env, monkeypatch):
    import pegaprox.core.qnetd as q
    monkeypatch.setattr(q, '_load_key', lambda pk, text: object())
    key = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n'
    hid = _host(env, ssh_key=key)['id']
    r = env.admin.put(f'/api/qnetd/hosts/{hid}', json={'ssh_host': '203.0.113.66', 'password': 'typed-again'})
    assert r.status_code == 400, 'the stored key would go to the new host'
    r = env.admin.put(f'/api/qnetd/hosts/{hid}', json={'ssh_host': '203.0.113.66', 'password': 'typed-again',
                                                       'ssh_key': ''})
    assert r.status_code == 200, r.data
    rec = qnetd.get_qnetd(hid)
    assert (rec['password'], rec['ssh_key']) == ('typed-again', '')


# --- an answer that is JSON only by the letter --------------------------------------------
# A hostile QNetd host answers with JSON the parser chokes on in ways other than ValueError:
# nesting deeper than the recursion limit, or Infinity where the protocol number goes. Both
# went past the HelperError handlers, and the preflight of every cluster against that host
# ended in a 500 instead of a check that says what is wrong.

@pytest.mark.parametrize('raw', [b'[' * 200000, b'{"ok": true, "protocol": Infinity}',
                                 b'{"ok": true, "protocol": NaN}'], ids=['deep', 'infinity', 'nan'])
def test_a_hostile_helper_answer_is_a_helper_error(raw):
    try:
        ans = qnetd._parse_answer(raw)
    except qnetd.HelperError:
        return
    # what got through is at least no protocol anybody can act on
    assert qnetd._version_info(ans)['outdated'] is True


def test_a_hostile_version_answer_fails_the_check_and_not_the_preflight(world):
    real = world.helper.call

    def call(op, name=None, data=None):
        if op == 'version':
            # what _parse_answer lets through, or the HelperError it raises instead
            return qnetd._parse_answer(b'{"ok": true, "protocol": 1e999, "qnetd_installed": true}')
        return real(op, name, data)
    world.helper.call = call
    report = qnetd.inspect('c1', world.mgr, world.rec())
    assert _checks(report)['qnetd_ready'] is False and report['ok'] is False
