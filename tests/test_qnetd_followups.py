"""Follow-ups to the QDevice/QNetd work after its first review.

  1. kind 'local' reaches the root helper through a root-owned systemd socket
     (pegaprox-qnetd-helper.socket, Accept=yes) instead of sudo: no sudoers rule, and no
     drop-in that took NoNewPrivileges off the whole PegaProx unit. The helper answers
     one request per connection (`serve`), in the line protocol of the sidecar, and only
     to root and the PegaProx service user.
  2. A corosync-qnetd the helper installs itself requires TLS (-s req); one that was there
     before is left alone, and status says whether the running one requires it.
  3. The qnetd alert rule is an administrator's: nobody else sets it up, it names no QNetd
     host, address or error, and no rule makes PegaProx read a QNetd host more often than
     the status cache does.
  4. The helper goes onto an ssh host only into directories only root can change.
  5. and 6. the UI and the docs say what the code does.

Offline throughout: stand-in binaries, fake SSH clients, socket pairs.
MK Oct 2026
"""
import base64
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import types

import pytest

from pegaprox.core import qnetd

from test_alert_events import NOW, _open, _rule, _rules, sent  # noqa: F401  (sent is a fixture)
from test_qnetd_api import env  # noqa: F401
from test_qnetd_core import world  # noqa: F401
from test_qnetd_helper import H, HELPER, ROOT, FakeBins, make_crq, short_dir, slurp

ME = pwd.getpwuid(os.getuid()).pw_name
_POPEN = subprocess.Popen


@pytest.fixture(autouse=True)
def _clean():
    qnetd.reset_for_tests()
    yield
    qnetd.reset_for_tests()


@pytest.fixture
def host(tmp_path):
    return FakeBins(tmp_path)


def _read_line(sock, wait=30):
    sock.settimeout(wait)
    out = b''
    while b'\n' not in out:
        chunk = sock.recv(65536)
        if not chunk:
            break
        out += chunk
    return out


def _serve(host, request=None, raw=None, service_user=ME):
    """One request through `pegaprox-qnetd-helper serve` as systemd starts it for a
    connection of the socket unit: the connection is stdin and stdout."""
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    env = host.env(**({'PEGAPROX_QNETD_SERVICE_USER': service_user} if service_user else {}))
    proc = subprocess.Popen([sys.executable, '-I', HELPER, 'serve'], stdin=theirs, stdout=theirs,
                            stderr=subprocess.PIPE, env=env, cwd=host.base)
    theirs.close()
    try:
        ours.sendall(raw if raw is not None else (json.dumps(request) + '\n').encode())
        out = _read_line(ours)
    finally:
        ours.close()
    _out, err = proc.communicate(timeout=30)
    line = out.split(b'\n', 1)[0]
    return proc.returncode, (json.loads(line) if line.strip() else None), err


# --- 1. the helper on a systemd socket -------------------------------------------------------

def test_serve_answers_one_request_on_the_connection_systemd_hands_over(host):
    assert host.helper('init')[0] == 0
    rc, ans, err = _serve(host, {'op': 'version'})
    assert rc == 0, err
    assert ans['ok'] is True and ans['protocol'] == H.PROTOCOL and ans['mode'] == 'systemd'
    rc, ans, _err = _serve(host, {'op': 'sign', 'name': 'pve', 'crq_b64': base64.b64encode(make_crq('pve')).decode()})
    assert ans['ok'] is True and H.parse_cert(base64.b64decode(ans['crt_b64']))[0] == 'pve'
    assert ans['crt_b64'] and slurp(os.path.join(host.db, 'cluster-pve.crt')) == base64.b64decode(ans['crt_b64'])


def test_serve_speaks_the_line_protocol_of_the_sidecar(host):
    assert host.helper('init')[0] == 0
    for req in ({}, {'op': 'bogus'}, {'op': 'version', 'name': 'x'}, {'op': 'status', 'extra': 1},
                {'op': 'sign', 'name': 'x;id', 'crq_b64': 'AA=='}, {'op': 7}):
        _rc, ans, _err = _serve(host, req)
        assert ans['ok'] is False and ans['code'] == 'bad_request', req
    _rc, ans, _err = _serve(host, raw=b'{"op": "version", "pad": "' + b'x' * (70 * 1024) + b'"}\n')
    assert ans['ok'] is False and 'too large' in ans['error']


@pytest.mark.skipif(os.geteuid() == 0, reason='runs as root')
def test_serve_answers_root_and_the_service_user_only(host):
    assert host.helper('init')[0] == 0
    # the service user is pegaprox (or whatever the test names): this test's own user is
    # neither, nor root
    for who in (None, 'nobody'):
        rc, ans, _err = _serve(host, {'op': 'version'}, service_user=who)
        assert ans is not None and ans['ok'] is False and ans['code'] == 'refused', (who, ans)
        assert 'protocol' not in ans


def test_serve_takes_its_request_from_a_socket_only(host):
    proc = subprocess.run([sys.executable, '-I', HELPER, 'serve'], input=b'{"op": "version"}\n',
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=host.env(
                              PEGAPROX_QNETD_SERVICE_USER=ME), timeout=30, cwd=host.base)
    ans = json.loads(proc.stdout.decode().splitlines()[0])
    assert proc.returncode == 1 and ans['ok'] is False and ans['code'] == 'bad_request'
    # and serve takes nothing else on its command line
    rc, ans = host.helper('serve', 'now')
    assert rc == 1 and ans['code'] == 'bad_request'


def test_the_service_user_is_never_taken_from_the_environment_as_root(monkeypatch):
    monkeypatch.setattr(H.os, 'geteuid', lambda: 0)
    with pytest.raises(H.Refused):
        H.Host('systemd', {'PEGAPROX_QNETD_SERVICE_USER': 'someone'})
    assert 'PEGAPROX_QNETD_SERVICE_USER' in H.OVERRIDES


class _AcceptYes:
    """A Unix socket that starts `pegaprox-qnetd-helper serve` for every connection, as
    systemd does with pegaprox-qnetd-helper.socket (Accept=yes)."""

    def __init__(self, host, path):
        self.host, self.path = host, path
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(4)
        self.srv.settimeout(0.5)
        self.stop = threading.Event()
        self.procs = []
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stop.is_set():
            try:
                conn, _a = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.procs.append(_POPEN(
                [sys.executable, '-I', HELPER, 'serve'], stdin=conn, stdout=conn, stderr=subprocess.DEVNULL,
                env=self.host.env(PEGAPROX_QNETD_SERVICE_USER=ME), cwd=self.host.base))
            conn.close()

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.srv.close()
        for p in self.procs:
            p.wait(30)


def test_the_local_transport_is_a_socket_client_of_the_helper(host, monkeypatch):
    """PegaProx asks the helper through the socket, never through sudo or any process."""
    assert host.helper('init')[0] == 0
    d = short_dir()
    srv = _AcceptYes(host, os.path.join(d, 'local.sock'))

    def no_process(*a, **k):
        raise AssertionError('the local transport started a process')
    monkeypatch.setattr(subprocess, 'run', no_process)
    monkeypatch.setattr(subprocess, 'Popen', no_process)
    try:
        tr = qnetd.LocalTransport(os.path.join(d, 'local.sock'))
        assert tr.kind == 'local'
        info = qnetd._version_info(qnetd._ok(tr.call('version'), 'version'))
        assert info['protocol'] == qnetd.PROTOCOL and not info['outdated']
        with tr.session() as call:
            crt = qnetd._ok(call('sign', name='pve', data={'crq_b64': base64.b64encode(make_crq('pve')).decode()}),
                            'sign')['crt_b64']
            assert qnetd._ok(call('ca'), 'ca')['ca_b64']
        assert H.parse_cert(base64.b64decode(crt))[0] == 'pve'
    finally:
        srv.close()
        shutil.rmtree(d, ignore_errors=True)


def test_no_local_socket_says_how_to_set_it_up(tmp_path, monkeypatch):
    monkeypatch.setattr(qnetd, 'LOCAL_SOCKET', str(tmp_path / 'missing.sock'))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('ran a process'))
    got = qnetd.transports_available()
    assert got['local']['available'] is False and 'install.sh' in got['local']['reason']
    assert 'sudo' not in json.dumps(got)
    with pytest.raises(qnetd.HelperError) as e:
        qnetd.LocalTransport(str(tmp_path / 'missing.sock')).call('version')
    assert 'install.sh' in str(e.value)


@pytest.mark.parametrize('kind', ['local', 'sidecar'])
def test_a_helper_socket_that_drips_its_answer_is_cut_off_at_the_deadline(tmp_path, monkeypatch, kind):
    """Each recv has its timeout; a socket that sends a byte now and then would hold the
    caller (a job, the status lock of a host) as long as it liked."""
    monkeypatch.setattr(qnetd, 'OP_TIMEOUT', dict(qnetd.OP_TIMEOUT, version=1))
    d = short_dir()
    path = os.path.join(d, 'drip.sock')
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    stop = threading.Event()

    def drip():
        c, _a = srv.accept()
        c.recv(4096)
        while not stop.is_set():
            try:
                c.sendall(b' ')
            except OSError:
                break
            time.sleep(0.2)
        c.close()
    threading.Thread(target=drip, daemon=True).start()
    tr = qnetd.LocalTransport(path) if kind == 'local' else qnetd.SidecarTransport(path)
    out = {}

    def ask():
        try:
            tr.call('version')
        except qnetd.HelperError as e:
            out['err'] = str(e)
    t = threading.Thread(target=ask, daemon=True)
    started = time.monotonic()
    t.start()
    t.join(6)
    stop.set()
    srv.close()
    shutil.rmtree(d, ignore_errors=True)
    assert not t.is_alive(), 'the call is still waiting for the dripping socket'
    assert 'err' in out and time.monotonic() - started < 5


# --- 2. TLS on a QNetd the helper installed ---------------------------------------------------

@pytest.mark.parametrize('before,after', [
    ('', '-s req'),
    ('-p 5404 -d', '-p 5404 -d -s req'),
    ('-s on -p 5404', '-p 5404 -s req'),
    ('-p 5404 -son', '-p 5404 -s req'),
    ('-ds on -m 50', '-d -m 50 -s req'),
    ('-S sock_listen_backlog=10 -s off', '-S sock_listen_backlog=10 -s req'),
    ('-s req', '-s req'),
])
def test_tls_is_required_with_the_other_options_kept(before, after):
    assert ' '.join(H.tls_words(before.split())) == after


@pytest.mark.parametrize('before', ['-p', '-s'])
def test_options_that_do_not_parse_are_left_alone(before):
    assert H.tls_words(before.split()) is None


def _defaults(host, text=None):
    path = os.path.join(host.base, 'etc', 'default', 'corosync-qnetd')
    if text is not None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(text)
    return path


def _stash(host, *names):
    stash = os.path.join(host.bin, 'apt-stash')
    os.makedirs(stash, exist_ok=True)
    for name in names:
        shutil.move(os.path.join(host.bin, name), os.path.join(stash, name))


PACKAGE_DEFAULTS = ('# Corosync Qdevice Network daemon init script configuration file\n'
                    'COROSYNC_QNETD_OPTIONS="-p 5404 -d"\n'
                    'COROSYNC_QNETD_RUNAS=""\n')


def test_a_qnetd_the_helper_installs_requires_tls(host):
    path = _defaults(host, PACKAGE_DEFAULTS)
    _stash(host, 'certutil', 'corosync-qnetd')
    rc, ans = host.helper('init')
    assert rc == 0 and ans['installed'] is True and ans['tls_set'] is True, ans
    with open(path) as fh:
        text = fh.read()
    assert 'COROSYNC_QNETD_OPTIONS="-p 5404 -d -s req"\n' in text
    assert text.startswith('# Corosync Qdevice') and 'COROSYNC_QNETD_RUNAS=""\n' in text
    assert oct(os.stat(path).st_mode & 0o777) == '0o644'
    calls = host.calls()
    # restarted after the package's own start, so the option is in force
    assert calls.index('systemctl enable --now corosync-qnetd.service') < \
        calls.index('systemctl restart corosync-qnetd.service')


def test_a_qnetd_that_was_there_keeps_its_options(host):
    path = _defaults(host, 'COROSYNC_QNETD_OPTIONS=""\n')
    rc, ans = host.helper('init')
    assert rc == 0 and ans['tls_set'] is False
    assert slurp(path) == b'COROSYNC_QNETD_OPTIONS=""\n'
    assert not [c for c in host.calls() if c.startswith('systemctl restart')]
    # nor where only the NSS tools were missing: corosync-qnetd was there
    os.unlink(os.path.join(host.db, 'qnetd-cacert.crt'))
    _stash(host, 'certutil')
    rc, ans = host.helper('init')
    assert rc == 0 and ans['installed'] is True and ans['tls_set'] is False
    assert slurp(path) == b'COROSYNC_QNETD_OPTIONS=""\n'


def test_a_fresh_install_without_the_file_gets_one(host):
    os.makedirs(os.path.join(host.base, 'etc', 'default'))
    _stash(host, 'certutil', 'corosync-qnetd')
    rc, ans = host.helper('init')
    assert rc == 0 and ans['tls_set'] is True
    assert slurp(_defaults(host)) == b'COROSYNC_QNETD_OPTIONS="-s req"\n'


def test_options_the_helper_cannot_read_are_never_rewritten(host):
    weird = 'COROSYNC_QNETD_OPTIONS="$(cat /etc/extra)" # set by hand\n'
    path = _defaults(host, weird)
    _stash(host, 'certutil', 'corosync-qnetd')
    rc, ans = host.helper('init')
    assert rc == 0 and ans['tls_set'] is False
    assert slurp(path).decode() == weird


@pytest.mark.parametrize('line,want', [
    ('TLS:\t\t\t\tRequired (client certificate required)\n', True),
    ('TLS:\t\t\t\tSupported (client certificate required)\n', False),
    ('TLS:\t\t\t\tUnsupported\n', False),
    ('garbage\n', None),
])
def test_status_says_whether_the_running_qnetd_requires_tls(host, line, want):
    assert host.helper('init')[0] == 0
    with open(os.path.join(host.bin, 'status.txt'), 'w') as fh:
        fh.write('QNetd address:\t\t\t*:5403\n' + line + 'Connected clients:\t\t0\n')
    rc, ans = host.helper('status')
    assert rc == 0 and ans['tls_required'] is want
    # a QNetd that does not run says nothing about it
    host.flag('state-active', on=False)
    assert host.helper('status')[1]['tls_required'] is None


def test_the_status_view_and_the_check_carry_tls_required(world):
    world.helper.answers['status'] = {'ok': True, 'active': True, 'clusters': [], 'raw': '',
                                      'tls_required': False}
    view = qnetd.status(world.rec(), now=NOW)
    assert view['tls_required'] is False
    assert qnetd.public_status(view, now=NOW)['tls_required'] is False
    assert qnetd.check_host(world.rec())['tls_required'] is False
    world.helper.answers['status'] = {'ok': True, 'active': True, 'clusters': [], 'raw': '', 'tls_required': True}
    assert qnetd.status(world.rec(), max_age=0, now=NOW + 1)['tls_required'] is True
    # anything but a boolean from the host is no answer
    world.helper.answers['status'] = {'ok': True, 'active': True, 'clusters': [], 'raw': '', 'tls_required': 'yes'}
    assert qnetd.status(world.rec(), max_age=0, now=NOW + 2)['tls_required'] is None


# --- 3. the qnetd alert rule is an administrator's ------------------------------------------

def test_only_an_administrator_sets_up_the_qnetd_rule(env):
    from pegaprox.api.alerts import load_cluster_alerts
    ops = env.api.as_user(env.seed.user('ops', role='user', permissions=['cluster.config', 'alert.manage']))
    r = ops.post('/api/clusters/c1/alerts', json={'name': 'q', 'metric': 'qnetd'})
    assert r.status_code == 400 and 'administrator' in r.get_json()['error']
    assert not [a for a in load_cluster_alerts().get('c1', []) if a.get('metric') == 'qnetd']
    r = env.admin.post('/api/clusters/c1/alerts', json={'name': 'q', 'metric': 'qnetd', 'qnetd_by': 'ops'})
    assert r.status_code == 200, r.data
    rule = r.get_json()['alert']
    assert rule['qnetd_by'] == 'root'
    # the rule an admin set up is not someone else's to change, nor a rule of theirs to turn into one
    r = ops.put(f"/api/clusters/c1/alerts/{rule['id']}", json={'name': 'mine now', 'channels': ['hook9']})
    assert r.status_code == 400
    own = ops.post('/api/clusters/c1/alerts', json={'name': 'cpu', 'metric': 'cpu', 'threshold': 90}).get_json()['alert']
    r = ops.put(f"/api/clusters/c1/alerts/{own['id']}", json={'metric': 'qnetd'})
    assert r.status_code == 400
    kept = {a['id']: a for a in load_cluster_alerts()['c1']}
    assert kept[rule['id']]['name'] == 'q' and kept[own['id']]['metric'] == 'cpu'
    # an admin changing it again owns it from then on; leaving the metric drops the mark
    r = env.admin.put(f"/api/clusters/c1/alerts/{rule['id']}", json={'metric': 'cpu', 'threshold': 90})
    assert r.status_code == 200 and 'qnetd_by' not in r.get_json()['alert']


def test_the_global_alert_routes_keep_the_qnetd_rule_an_administrators(env):
    """/api/alerts reads the cluster rules too (load_alerts_config): it must not create a
    qnetd rule for a non-admin, nor change an admin's or turn one into it."""
    from pegaprox.api.alerts import load_cluster_alerts
    ops = env.api.as_user(env.seed.user('ops', role='user', permissions=['cluster.config', 'alert.manage']))
    r = ops.post('/api/alerts', json={'name': 'q', 'cluster_id': 'c1', 'metric': 'qnetd'})
    assert r.status_code == 400 and 'administrator' in r.get_json()['error']
    r = env.admin.post('/api/alerts', json={'name': 'q', 'cluster_id': 'c1', 'metric': 'qnetd',
                                            'qnetd_by': 'ops'})
    assert r.status_code == 201 and r.get_json()['qnetd_by'] == 'root', r.data
    rule = env.admin.post('/api/clusters/c1/alerts', json={'name': 'q', 'metric': 'qnetd'}).get_json()['alert']
    own = ops.post('/api/clusters/c1/alerts', json={'name': 'cpu', 'metric': 'cpu', 'threshold': 90}).get_json()['alert']
    r = ops.put(f"/api/alerts/{rule['id']}", json={'name': 'mine now'})
    assert r.status_code == 400
    r = ops.put(f"/api/alerts/{own['id']}", json={'metric': 'qnetd'})
    assert r.status_code == 400
    kept = {a['id']: a for a in load_cluster_alerts()['c1']}
    assert kept[rule['id']]['name'] == 'q' and kept[rule['id']]['qnetd_by'] == 'root'
    assert kept[own['id']]['metric'] == 'cpu'


def _admin_rule(**kw):
    return _rule('qnetd', **dict({'rid': 'rq', 'qnetd_by': 'root'}, **kw))


def test_a_qnetd_rule_no_administrator_set_up_watches_nothing(world, seed, monkeypatch, sent):
    """POST /api/alerts takes any metric from an alert.manage holder: such a rule reads
    no QNetd host and raises nothing."""
    from pegaprox.background import alert_events as E
    seed.user('root', role='admin')
    seed.user('ops', role='user', permissions=['alert.manage'])
    world.mgr.is_connected = False
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    kicked = []
    monkeypatch.setattr(qnetd, 'kick_refresh', lambda now=None, cluster_ids=None: kicked.append(cluster_ids))
    world.helper.answers['status'] = {'ok': True, 'active': False, 'clusters': []}
    for t in (0, 60):
        qnetd.status(world.rec(), max_age=0, now=NOW + t)
    for rule in (_rule('qnetd', rid='rq'), _admin_rule(qnetd_by='ops'), _admin_rule(qnetd_by='gone'),
                 _admin_rule(qnetd_by='')):
        _rules(monkeypatch, rule)
        E.check_event_alerts(now=NOW + 61)
        assert _open(world.db) == [] and kicked == [] and sent.names() == [], rule
    # a lowered admin (a tenant mapping takes them down to user) is no administrator either
    seed.user('ladmin', role='admin', tenant_permissions={'default': {'role': 'user'}})
    _rules(monkeypatch, _admin_rule(qnetd_by='ladmin'))
    E.check_event_alerts(now=NOW + 61)
    assert _open(world.db) == [] and kicked == []
    _rules(monkeypatch, _admin_rule())
    E.check_event_alerts(now=NOW + 61)
    assert len(_open(world.db, 'rq')) == 1 and kicked == [['c1']]


def test_the_qnetd_incident_names_no_host_address_or_error(world, seed, monkeypatch, sent):
    """Whoever sees the cluster's alerts (any user with the cluster) learns that its QNetd
    host is down, not which host, where it is or what it said."""
    from pegaprox.background import alert_events as E
    seed.user('root', role='admin')
    world.mgr.is_connected = False
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    monkeypatch.setattr(qnetd, 'kick_refresh', lambda now=None, cluster_ids=None: False)
    _rules(monkeypatch, _admin_rule())
    world.helper.answers['version'] = qnetd.HelperError('SSH to the QNetd host 192.0.2.50 failed (timeout)')
    for t in (0, 60):
        qnetd.status(world.rec(), max_age=0, now=NOW + t)
    E.check_event_alerts(now=NOW + 61)
    rows = _open(world.db, 'rq')
    assert len(rows) == 1 and rows[0]['object_key'] == 'qnetd:aaaaaaaaaaaa'
    shown = json.dumps(rows) + json.dumps([vars(x) if hasattr(x, '__dict__') else x for x in sent.push],
                                          default=str) + json.dumps(sent.mail) + json.dumps(sent.hooks, default=str)
    for secret in ('witness', '192.0.2.50', 'timeout', 'SSH to'):
        assert secret not in shown, secret
    assert 'does not answer' in rows[0]['message']
    notes = json.dumps(E.source_status(['c1']))
    assert 'witness' not in notes and '192.0.2.50' not in notes


def test_qnetd_rules_read_a_host_no_more_often_than_its_status_cache(world, seed, monkeypatch):
    """Rules on two clusters that vote through the same QNetd host, ticks every five
    seconds: that host is read once per REFRESH_EVERY, and a host no rule watches never."""
    from unittest.mock import MagicMock
    from pegaprox.background import alert_events as E
    from pegaprox.globals import cluster_managers
    seed.user('root', role='admin')
    world.mgr.is_connected = False
    for cid in ('c2', 'c3'):
        m = MagicMock(name=cid)
        m.cluster_type, m.is_connected = 'proxmox', False
        cluster_managers[cid] = m
    world.db.save_qnetd_host('bbbbbbbbbbbb', {'name': 'other', 'kind': 'ssh', 'address': '192.0.2.60', 'port': 5403,
                                              'ssh_host': '192.0.2.60', 'ssh_port': 22, 'ssh_user': 'root'},
                             password='pw')
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    world.db.save_qnetd_attachment('c2', 'aaaaaaaaaaaa', 'pve2', 'admin')
    world.db.save_qnetd_attachment('c3', 'bbbbbbbbbbbb', 'pve3', 'admin')

    class T:
        def __init__(self, target, **kw):
            self.target = target

        def start(self):
            self.target()
    monkeypatch.setattr(qnetd.threading, 'Thread', T)
    _rules(monkeypatch, _admin_rule(), _admin_rule(rid='rq2', cluster_id='c2'),
           _admin_rule(rid='rq3', cluster_id='c3', qnetd_by='nobody'))
    try:
        for k in range(0, 27):
            E.check_event_alerts(now=NOW + 5 * k)
    finally:
        for cid in ('c2', 'c3'):
            cluster_managers.pop(cid, None)
    assert qnetd.REFRESH_EVERY >= qnetd.FRESH
    reads = [c for c in world.helper.calls if c[0] == 'status']
    # 0, 60 and 120 s: one read of the shared host each time, none of the other one
    assert len(reads) == 3
    assert qnetd.cached_status('bbbbbbbbbbbb', now=NOW + 130) is None


def test_the_alert_view_carries_no_name_address_or_error(world):
    world.db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    world.helper.answers['version'] = qnetd.HelperError('SSH to 192.0.2.50 failed')
    for t in (0, 60):
        qnetd.status(world.rec(), max_age=0, now=NOW + t)
    rows = qnetd.alert_view('c1', now=NOW + 61)
    assert rows and rows[0]['state'] == 'down'
    assert set(rows[0]) <= {'qnetd_id', 'state', 'read_at'}


# --- the background read of an ssh host passes the HA transport guard as a read -----------------

class _GuardSsh:
    """An SSH client from the real secure_ssh_client (so guard_client wraps it), answering
    the helper like a QNetd host."""

    def __init__(self):
        self.cmds = []

    def load_host_keys(self, *_a):
        pass

    def set_missing_host_key_policy(self, *_a):
        pass

    def connect(self, **kw):
        pass

    def get_transport(self):
        return types.SimpleNamespace(getpeername=lambda: ('192.0.2.50', 22))

    def exec_command(self, cmd, timeout=None):
        self.cmds.append(cmd)
        ans = {'id -u': b'0\n',
               'version': b'{"ok": true, "protocol": %d, "qnetd_installed": true, "certutil_installed": true}'
                          % qnetd.PROTOCOL,
               'status': b'{"ok": true, "active": true, "clusters": [], "raw": ""}',
               'ca': b'{"ok": true, "ca_b64": "' + base64.b64encode(
                   b'-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n') + b'"}'}
        out = next((v for k, v in ans.items() if cmd.endswith(k)), b'')

        class Chan:
            def shutdown_write(self):
                pass

            def recv_exit_status(self):
                return 0

            def close(self):
                pass

        class F:
            def __init__(self, data):
                self.data, self.channel = data, Chan()

            def read(self, n=-1):
                d, self.data = self.data, b''
                return d

            def write(self, b):
                pass

            def flush(self):
                pass
        return F(b''), F(out), F(b'')

    def close(self):
        pass


def test_the_background_status_read_of_an_ssh_host_passes_the_guard(db, monkeypatch):
    """In an automatic HA group every SSH command asks the transport guard, and a plain
    thread with no confirmed step is refused: the status read the alert loop starts has
    to say it reads (ha.reading), or every ssh QNetd host reads as down there."""
    from pegaprox.core import ha, ha_transport
    import pegaprox.utils.concurrent as conc
    import pegaprox.utils.ssh_security as sec
    client = _GuardSsh()
    monkeypatch.setattr(conc, 'get_paramiko', lambda: types.SimpleNamespace(SSHClient=lambda: client))
    monkeypatch.setattr(sec, 'apply_host_key_policy', lambda c, p: c)
    monkeypatch.setattr(sec, 'persist_host_keys', lambda c: None)
    asked = []

    def guard(action, kind=None, need=None, again=False):
        asked.append(action)
        if not getattr(ha._guard_tls, 'reading', 0):
            raise ha.GuardRefused(action, ha.GUARD_NO_TOKEN)
    monkeypatch.setattr(ha, 'guard_on', lambda: True)
    monkeypatch.setattr(ha, 'guard', guard)
    db.save_qnetd_host('aaaaaaaaaaaa', {'name': 'witness', 'kind': 'ssh', 'address': '192.0.2.50', 'port': 5403,
                                        'ssh_host': '192.0.2.50', 'ssh_port': 22, 'ssh_user': 'root'}, password='pw')
    db.save_qnetd_attachment('c1', 'aaaaaaaaaaaa', 'pve', 'admin')
    # the SSH exit of the transport really asks the guard: a read outside ha.reading is refused
    with pytest.raises(qnetd.HelperError):
        qnetd.SshTransport(qnetd.get_qnetd('aaaaaaaaaaaa')).call('version')
    assert asked and all(a.startswith('SSH 192.0.2.50') for a in asked)
    done = threading.Event()
    real_start = threading.Thread.start

    def start(self):
        real_start(self)
        if self.name == 'qnetd-status':
            self.join(30)
            done.set()
    monkeypatch.setattr(threading.Thread, 'start', start)
    assert qnetd.kick_refresh(now=time.time(), cluster_ids=['c1']) is True
    assert done.wait(30)
    view = qnetd.cached_status('aaaaaaaaaaaa')
    assert view is not None and view['ok'] is True and view['active'] is True, view
    assert ha_transport.guard_client  # the client came from the guarded factory


# --- 4. the helper goes onto an ssh host only into root's directories ---------------------------

class _InstallClient:
    def __init__(self, probe):
        self.probe, self.cmds, self.sftp = probe, [], []

    def connect(self, **kw):
        pass

    def exec_command(self, cmd, timeout=None):
        self.cmds.append(cmd)
        if cmd == 'id -u':
            out = b'0\n'
        elif 'stat -c' in cmd:
            out = self.probe.encode()
        elif 'mktemp -d' in cmd:
            out = b'/tmp/tmp.Qx1\n'
        else:
            out = b''

        class Chan:
            def shutdown_write(self):
                pass

            def recv_exit_status(self):
                return 0

            def close(self):
                pass

        class F:
            def __init__(self, data):
                self.data, self.channel = data, Chan()

            def read(self, n=-1):
                d, self.data = self.data, b''
                return d

            def write(self, b):
                pass

            def flush(self):
                pass
        return F(b''), F(out), F(b'')

    def open_sftp(self):
        self.sftp.append(True)
        raise AssertionError('sftp opened')

    def close(self):
        pass


def _install_with(monkeypatch, probe):
    import pegaprox.utils.ssh_security as sec
    client = _InstallClient(probe)
    monkeypatch.setattr(sec, 'secure_ssh_client', lambda pk: client)
    monkeypatch.setattr(sec, 'persist_host_keys', lambda c: None)
    tr = qnetd.SshTransport({'ssh_host': '192.0.2.50', 'ssh_user': 'root', 'password': 'pw'})
    return tr, client


@pytest.mark.parametrize('probe,why', [
    ('/usr/lib/pegaprox dir 1000 755\n/usr/lib/pegaprox/qnetd dir 0 755\n', 'uid 1000'),
    ('/usr/lib/pegaprox dir 0 755\n/usr/lib/pegaprox/qnetd dir 0 775\n', 'writable by group or others'),
    ('/usr/lib/pegaprox dir 0 757\n/usr/lib/pegaprox/qnetd none\n', 'writable by group or others'),
    ('/usr/lib/pegaprox link\n/usr/lib/pegaprox/qnetd dir 0 755\n', 'symlink'),
    ('/usr/lib/pegaprox dir 0 755\n/usr/lib/pegaprox/qnetd other\n', 'not a directory'),
    ('/usr/lib/pegaprox dir 0 755\n', 'could not be checked'),
    ('', 'could not be checked'),
])
def test_the_helper_is_never_installed_into_a_directory_others_control(monkeypatch, probe, why):
    tr, client = _install_with(monkeypatch, probe)
    with pytest.raises(qnetd.HelperError) as e:
        tr.install_helper(b'#!/usr/bin/python3 -I\nPROTOCOL = 1\n')
    assert why in str(e.value) and 'refus' in str(e.value)
    assert not client.sftp
    assert not [c for c in client.cmds if c.startswith(('install ', 'sudo -n install')) or ' install -o ' in c]


def test_the_helper_goes_in_where_the_directories_are_roots_or_missing(monkeypatch):
    tr, client = _install_with(monkeypatch, '/usr/lib/pegaprox dir 0 755\n/usr/lib/pegaprox/qnetd none\n')
    with pytest.raises(AssertionError, match='sftp opened'):
        tr.install_helper(b'#!/usr/bin/python3 -I\nPROTOCOL = 1\n')
    assert client.sftp


def test_the_directory_probe_runs_in_a_real_shell(tmp_path):
    base = tmp_path / 'pegaprox'
    (base / 'qnetd').mkdir(parents=True)
    os.chmod(base, 0o750)
    os.chmod(base / 'qnetd', 0o775)
    link = tmp_path / 'link'
    os.symlink(str(base), str(link))
    flat = tmp_path / 'flat'
    flat.write_text('x')
    dirs = [str(base), str(base / 'qnetd'), str(link), str(flat), str(tmp_path / 'none')]
    p = subprocess.run(['sh', '-c', qnetd.dir_probe_script(dirs)], stdout=subprocess.PIPE, timeout=30)
    assert p.returncode == 0
    uid = os.getuid()
    assert p.stdout.decode().splitlines() == [
        f'{base} dir {uid} 750', f'{base}/qnetd dir {uid} 775', f'{link} link', f'{flat} other',
        f'{tmp_path}/none none']
    problems = qnetd.unsafe_dirs(p.stdout.decode(), dirs)
    # every one but the missing one; as root the first is fine (0750, root's)
    assert len(problems) == (4 if uid else 3)
    assert not [p for p in problems if '/none' in p]


# --- 5. the UI -------------------------------------------------------------------------------

def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _en():
    src = _src('web', 'src', 'translations.js')
    start = src.index('            en: {')
    return dict(re.findall(r"^\s+(\w+): '(.*)',$", src[start:src.index('            zh: {')], re.M))


def test_the_qnetd_rule_is_offered_to_administrators_only():
    dash = _src('web', 'src', 'dashboard.js')
    assert "{(isAdmin || alertMetricSel === 'qnetd') && <option value=\"qnetd\">{t('qnetdAlertTitle')}</option>}" in dash
    assert "alertMetricSel === 'qnetd' ? `${t('qnetdAlertHelp')} ${t('qnetdAlertAdminNote')}`" in dash


def test_no_sudo_for_the_local_kind_in_the_ui():
    en = _en()
    for key in ('qnetdKindLocal', 'qnetdKindLocalDesc', 'qnetdKindLocalHa'):
        assert 'sudo' not in en[key].lower(), key
    assert 'witness' in en['qnetdKindLocalHa']


from test_qnetd_ui import (HOST_ID, _check, _host, _open_wizard, _plan_reads, _report,  # noqa: E402,F401
                           _settings_panel, _settled, _to_review, browser, open_app)


def test_runtime_a_move_of_the_ssh_login_asks_for_the_secret_first(open_app):
    app = open_app(hosts=[_host()])
    panel = _settings_panel(app)
    card = panel.locator(f'[data-qnetd-host="{HOST_ID}"]')
    card.wait_for(timeout=5000)
    card.locator('[data-qnetd-edit]').click()
    form = panel.locator('[data-qnetd-form="edit"]')
    form.wait_for(timeout=3000)
    hint = form.locator('[data-qnetd-retype]')
    assert hint.count() == 1 and 'typed again' in hint.inner_text()
    app.page.fill('#qnetd-ssh-port', '2222')
    form.locator('[data-qnetd-save]').click()
    refused = form.locator('[data-qnetd-refused]')
    refused.wait_for(timeout=3000)
    assert 'typed again' in refused.inner_text()
    assert not any(c[0] == 'PUT' for c in app.server.calls)
    app.page.fill('#qnetd-password', 'typed-again')
    form.locator('[data-qnetd-save]').click()
    app.page.wait_for_timeout(800)
    puts = [b for p, bs in app.server.bodies.items() if p == f'/api/qnetd/hosts/{HOST_ID}' for b in bs]
    assert puts and puts[-1]['ssh_port'] == 2222 and puts[-1]['password'] == 'typed-again'
    assert not app.errors, app.errors


def _with_guest_check(ok, message, needs_confirmation):
    rep = _report()
    rep['checks'] = [c for c in rep['checks'] if c['id'] != 'not_own_vm'] + [_check('not_own_vm', ok, message)]
    rep['ok'] = False
    rep['needs_confirmation'] = needs_confirmation
    return rep


def test_runtime_a_qnetd_host_on_a_node_is_never_offered_for_confirmation(open_app):
    rep = _with_guest_check(False, 'The QNetd host has the SMBIOS UUID of node pve2: it is that node or runs in '
                                   'a container on it, and its vote would fall with it', True)
    app = open_app(hosts=[_host(attached=False)], reports={'c1': rep})
    _page, dialog = _open_wizard(app)
    _to_review(dialog)
    dialog.locator('[data-qdev-preflight="fail"]').wait_for(timeout=5000)
    assert 'pve2' in dialog.locator('[data-qdev-check="not_own_vm"]').inner_text()
    assert dialog.locator('[data-qdev-confirm-guest]').count() == 0
    assert dialog.locator('[data-qdev-start]').is_disabled()
    assert not app.errors, app.errors


def test_runtime_an_unverified_host_is_offered_for_confirmation(open_app):
    rep = _with_guest_check(None, 'The QNetd host has no readable SMBIOS UUID: PegaProx cannot tell whether it '
                                  'is a guest of this cluster. Confirm that it is not', True)
    app = open_app(hosts=[_host(attached=False)], reports={'c1': rep})
    _page, dialog = _open_wizard(app)
    _to_review(dialog)
    dialog.locator('[data-qdev-preflight="fail"]').wait_for(timeout=5000)
    box = dialog.locator('[data-qdev-confirm-guest]')
    assert box.count() == 1
    # the confirmation is an option of the plan: read again with it, and that plan passes
    # (the server's report is ok then, the check itself stays unknown)
    app.server.q_reports['c1'] = dict(rep, ok=True)
    box.check()
    _settled(dialog)
    dialog.locator('[data-qdev-preflight="pass"]').wait_for(timeout=5000)
    assert 'confirm_unverified_host=1' in _plan_reads(app)[-1]
    consent = dialog.locator('[data-qdev-consent]')
    assert not consent.is_checked()
    consent.check()
    assert not dialog.locator('[data-qdev-start]').is_disabled()
    assert not app.errors, app.errors


@pytest.mark.parametrize('tls,shown', [(False, 1), (True, 0), (None, 0)])
def test_runtime_a_qnetd_that_lets_clients_skip_tls_is_flagged(open_app, tls, shown):
    h = _host()
    h['status']['tls_required'] = tls
    app = open_app(hosts=[h])
    panel = _settings_panel(app)
    card = panel.locator(f'[data-qnetd-host="{HOST_ID}"]')
    card.wait_for(timeout=5000)
    assert card.locator('[data-qnetd-tls-warn]').count() == shown
    if shown:
        text = card.locator('[data-qnetd-tls-warn]').inner_text()
        assert '-s req' in text and 'COROSYNC_QNETD_OPTIONS' in text
    assert not app.errors, app.errors


# --- 6. the docs -------------------------------------------------------------------------------

def test_the_docs_name_the_controls_as_the_ui_shows_them():
    doc = _src('docs', 'qdevice.md')
    en = _en()
    for key in ('qdevSetup', 'qdevRemove', 'qdevInstallPackages', 'qdevReplaceCert', 'qdevStart', 'qdevCheckAgain',
                'qdevConfirmNotGuest', 'qnetdAddHost', 'qnetdCheck', 'qnetdReadStatus', 'qnetdBulkSetup',
                'qnetdResetCaPin', 'qnetdHostsTitle', 'qnetdKindLocal', 'qnetdKindSsh', 'qnetdKindSidecar',
                'qnetdAddress', 'qnetdAlertTitle', 'qdevBulkPickEven', 'qdevBulkRetry', 'qdevCertReplace',
                'qdevChkCertOnFile'):
        assert f'**{en[key]}**' in doc, (key, en[key])
    # names the UI never had
    for gone in ('**install packages**', '**replace the certificate**', '**Bulk setup**'):
        assert gone not in doc, gone


def test_the_docs_describe_the_socket_tls_updates_and_removal():
    doc = _src('docs', 'qdevice.md')
    for want in ('pegaprox-qnetd-helper.socket', 'pegaprox-qnetd-helper@.service', '/run/pegaprox-qnetd/local.sock',
                 'SO_PEERCRED', '-s req', 'COROSYNC_QNETD_OPTIONS', 'TLS required', 'HA pair', 'witness',
                 'mktemp -d', 'git clone', '--uninstall', '--purge', 'systemctl disable --now'):
        assert want in doc, want
    # the local kind has no sudo rule and no drop-in any more; only the old ones are named, as
    # what install.sh takes away
    local = doc[doc.index('### On the PegaProx host'):doc.index('### On the witness host')]
    assert 'sudoers' not in local.replace('/etc/sudoers.d/pegaprox-qnetd', '')
    assert 'NoNewPrivileges=no' not in doc
    assert not re.search(r'^sudo ', doc, re.M), 'commands are shown as run by root'
