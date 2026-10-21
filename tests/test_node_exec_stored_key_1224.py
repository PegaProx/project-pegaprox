"""_pve_node_exec never offered the cluster's stored SSH key (#1224).

Its SSH leg went straight to _ssh_exec, which authenticates by password only. On a cluster
connected with an API token and an SSH key, a node that takes keys only (PasswordAuthentication
no) answered every command with a refused login, and the ESXi import read that as "qemu-img
not detected". The key goes first now, through the manager's own _ssh_connect, and a node that
refuses it is not offered it again on every poll of the console tiles.

What the key leg must not bring along: a login to a name the cluster does not list, a
login before the HA guard was asked, a local queue or a dropped connection booked against
the node, two log lines per poll, a caller held for three times its timeout.
MK
"""
import io
import logging
import socket
import threading
import time
import types

import pytest

from pegaprox.utils import ssh as ssh_mod

KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n'
EVIL = '203.0.113.66'


class _Chan:
    def __init__(self, rc, ready):
        self.rc, self.ready = rc, ready
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def exit_status_ready(self):
        return self.ready

    def recv_exit_status(self):
        return self.rc


class _File:
    def __init__(self, data, chan, silent=False):
        self._buf = io.BytesIO(data)
        self.channel = chan
        self.silent = silent

    def read(self, n=-1):
        if self.silent:
            # a command that prints nothing: paramiko waits out the channel's timeout
            ssh_mod.time.sleep(self.channel.timeout or 0)
            raise socket.timeout()
        return self._buf.read(n)


class _Client:
    """What _ssh_connect hands out, as far as a node command uses it."""

    def __init__(self, out=b'', err=b'', rc=0, ready=True, silent=False):
        self.out, self.err, self.rc, self.ready, self.silent = out, err, rc, ready, silent
        self.cmds, self.closed = [], False

    def exec_command(self, cmd, timeout=None):
        self.cmds.append((cmd, timeout))
        ch = _Chan(self.rc, self.ready)
        ch.settimeout(timeout)      # as paramiko's exec_command does
        return None, _File(self.out, ch, self.silent), _File(self.err, ch, self.silent)

    def close(self):
        self.closed = True


class _Cfg:
    def __init__(self, **kw):
        self.user = kw.get('user', 'ops@pve!pegaprox')      # a token id: pass_ is its secret
        self.pass_ = kw.get('pass_', 'the-token-secret')
        self.ssh_user = kw.get('ssh_user', '')
        self.ssh_key = kw.get('ssh_key', KEY)
        self.ssh_disabled = kw.get('ssh_disabled', False)


class _Mgr:
    """A PVE manager as _pve_node_exec sees it. `answers`: what each _ssh_connect call does,
    a _Client or a failure kind ('auth', 'unreachable', 'host_key', 'key', 'error', and
    'dropped' for a connection that ended in the login)."""

    nodes = {'pve1': {'node': 'pve1'}, 'pve2': {'node': 'pve2'}}

    def __init__(self, answers=(), diag=None, cid='c1', **cfg):
        self.id = cid
        self.host = '10.0.0.1'
        self.api_port = 8006
        self.config = _Cfg(**cfg)
        self.answers = list(answers)
        self.connects = []
        self.failures = []
        self.resets = []
        self._diag = diag

    def _is_node_blocked(self, node): return (False, 0)
    def _register_node_failure(self, node): self.failures.append(node)
    def _reset_node_failures(self, node): self.resets.append(node)
    def _get_node_ip(self, node): return '10.0.0.7'
    def ssh_diagnose(self, node): return self._diag
    def _api_post(self, *a, **k): raise RuntimeError('no API exec')

    def _ssh_connect(self, host, failure=None, **kw):
        self.connects.append((host, kw))
        answer = self.answers.pop(0) if self.answers else 'auth'
        if isinstance(answer, _Client):
            return answer
        if answer == 'dropped':
            failure.update(kind='auth', detail='Authentication failed: transport shut down or saw EOF',
                           refused=False)
            return None
        failure.update(kind=answer, detail={'auth': 'Authentication failed.',
                                            'unreachable': 'timed out',
                                            'host_key': 'Host key for server 10.0.0.7 does not match',
                                            'key': 'unsupported key format'}.get(answer, 'Error reading SSH protocol banner'))
        return None


class _Clock:
    def __init__(self):
        self.now = 5000.0

    def monotonic(self):
        return self.now

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += s


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    """No node addresses or refused keys from another test, and a clock of our own."""
    ssh_mod._node_ip_cache.clear()
    monkeypatch.setattr(ssh_mod, '_node_key_refused', {}, raising=False)
    clock = _Clock()
    monkeypatch.setattr(ssh_mod, 'time', clock)
    yield clock
    ssh_mod._node_ip_cache.clear()


def _no_password_leg(monkeypatch):
    sent = []
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda host, user, pw, cmd, **k: sent.append((host, user, pw)) or (0, 'pw-ok', ''))
    return sent


# --- the key goes first ---------------------------------------------------------------

def test_a_token_cluster_with_a_key_runs_the_command_with_the_key(monkeypatch):
    sent = _no_password_leg(monkeypatch)
    client = _Client(out=b'/usr/bin/qemu-img\n', rc=0)
    m = _Mgr(answers=[client])
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'command -v qemu-img', timeout=5)
    assert (rc, out) == (0, '/usr/bin/qemu-img\n'), err
    assert sent == [], 'the password leg ran although the key got in'
    host, kw = m.connects[0]
    assert host == '10.0.0.7'
    # one attempt, the connect budget of the password leg, and the login this path uses
    assert kw['retries'] == 1 and kw['connect_timeout'] == 8 and kw['login'] == 'root'
    assert client.cmds == [('command -v qemu-img', 5)]
    assert client.closed, 'the client was left open'
    assert m.resets == ['pve1'] and m.failures == []


def test_the_configured_ssh_user_is_the_login_for_the_key_too(monkeypatch):
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=[_Client(out=b'ok')], ssh_user='pegaprox')
    ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert m.connects[0][1]['login'] == 'pegaprox'


def test_the_key_leg_names_the_node_so_a_port_of_its_own_is_dialled(monkeypatch):
    """node_endpoints: several nodes can sit behind one address on different ports, so
    _ssh_connect needs the node name to pick the port."""
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=[_Client(out=b'ok')])
    ssh_mod._pve_node_exec(m, 'pve2', 'true')
    assert m.connects[0][1]['node'] == 'pve2'


def test_the_exit_status_and_stderr_come_back_as_the_node_said_them(monkeypatch):
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=[_Client(out=b'', err=b'pvesm: storage does not exist\n', rc=2)])
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'pvesm path x:1')
    assert rc == 2 and 'storage does not exist' in err


def test_the_output_of_the_key_leg_is_capped(monkeypatch):
    _no_password_leg(monkeypatch)
    monkeypatch.setattr(ssh_mod, '_SSH_OUTPUT_CAP', 64)
    m = _Mgr(answers=[_Client(out=b'x' * 5000)])
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'cat big')
    assert out.startswith('x' * 64) and 'truncated' in out and len(out) < 200


def test_a_command_without_an_exit_status_does_not_hold_the_caller_for_ever(monkeypatch, _fresh):
    """recv_exit_status alone waits until the command ends; a hung qm monitor behind a
    console tile would have held its request for good."""
    _no_password_leg(monkeypatch)
    client = _Client(out=b'', rc=0, ready=False)
    m = _Mgr(answers=[client])
    start = _fresh.now
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'qm monitor 101', timeout=20)
    assert rc == 124 and 'within 20s' in err
    assert _fresh.now - start <= 21
    assert client.closed


def test_a_silent_hung_command_holds_the_caller_for_its_timeout_once(monkeypatch, _fresh):
    """stdout, then stderr, then the exit status: each waited the whole timeout, so a qm
    monitor that hung without a byte held its console tile for three times its 20 s."""
    _no_password_leg(monkeypatch)
    client = _Client(rc=0, ready=False, silent=True)
    m = _Mgr(answers=[client])
    start = _fresh.now
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'qm monitor 101', timeout=20)
    assert rc == 124
    assert _fresh.now - start <= 21, f'held for {_fresh.now - start:.0f}s'
    assert client.closed


def test_a_command_that_fails_on_a_node_that_let_us_in_does_not_mark_the_node_dead(monkeypatch):
    """The node answered the login; what the command printed is about somewhere else. The
    SSHFS mount's own ssh says 'Connection timed out' about the ESXi host, not this node."""
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=[_Client(err=b'ssh: connect to host esx1 port 22: Connection timed out\n', rc=1)])
    ssh_mod._pve_node_exec(m, 'pve1', 'sshfs ...')
    assert m.failures == [] and m.resets == ['pve1']


# --- what still stops before any connection ---------------------------------------------

@pytest.mark.parametrize('code', ['SSH_NO_CREDENTIALS', 'SSH_DISABLED'])
def test_the_credential_gate_still_answers_before_the_key(monkeypatch, code):
    """A stored key is a credential now, and the gate still decides first: switched off
    or nothing to log in with means no connection at all. Once it lets the call through,
    the key is what goes."""
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=[_Client(out=b'ok')], diag=(code, 'not over SSH'))
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert rc == 1 and err == 'not over SSH'
    assert m.connects == [] and sent == []
    m._diag = None
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert (rc, out) == (0, 'ok') and len(m.connects) == 1 and sent == []


# --- a node that does not take the key ----------------------------------------------------

def test_a_refused_key_without_a_password_is_one_failed_login_and_counts(monkeypatch):
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=['auth'])
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert rc == 1 and sent == []
    assert len(m.connects) == 1
    assert m.failures == ['pve1'], 'a refused login with nothing after it must reach the breaker'
    assert 'refused' in err and "'root'" in err and 'Authentication failed.' in err
    assert 'api token' in err.lower()
    assert 'the-token-secret' not in err


def test_a_refused_key_is_not_offered_again_on_the_next_polls(monkeypatch, _fresh):
    """The console tiles poll node commands. A node that refused the key is not offered it
    on every poll - one failed login per tile and poll is what a fail2ban bans for."""
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=['auth'] * 10)
    for _ in range(5):
        rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
        assert rc == 1
        _fresh.now += 20
    assert len(m.connects) == 1, f'{len(m.connects)} key logins in five polls'
    assert sent == []
    assert 'offered again in' in err
    # an hour on, the key is offered again
    _fresh.now += 3600
    ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert len(m.connects) == 2


def test_a_connection_that_ended_in_the_login_is_no_refused_key(monkeypatch):
    """An sshd restart or PerSourcePenalties drop the connection during the login; paramiko
    calls that an AuthenticationException too. It is no answer about the key: the next
    command offers it again, and a running import's commands are not skipped for 5 min."""
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=['dropped', _Client(out=b'ok')])
    rc, _out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert rc == 1 and 'saw EOF' in err
    rc, out, _ = ssh_mod._pve_node_exec(m, 'pve1', 'qm set 101 --boot order=scsi0')
    assert len(m.connects) == 2 and (rc, out) == (0, 'ok')


def test_a_refused_key_falls_back_to_the_password_once_and_then_goes_there_directly(monkeypatch):
    """Key and password stored, the node takes only the password: one refused key, then the
    password. The polls after it do not start with the key again."""
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=['auth'] * 5, user='root@pam', pass_='root-pw')
    for _ in range(4):
        rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
        assert (rc, out) == (0, 'pw-ok')
    assert len(m.connects) == 1
    assert sent == [('10.0.0.7', 'root', 'root-pw')] * 4
    # the password leg decides about the node, the refused key alone does not count
    assert m.failures == []


def test_another_key_is_offered_at_once(monkeypatch):
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=['auth', _Client(out=b'ok')])
    ssh_mod._pve_node_exec(m, 'pve1', 'true')
    m.config.ssh_key = KEY.replace('AAAA', 'BBBB')
    rc, out, _ = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert len(m.connects) == 2 and (rc, out) == (0, 'ok')


def test_the_refusal_is_per_node_and_per_cluster(monkeypatch):
    _no_password_leg(monkeypatch)
    m = _Mgr(answers=['auth', _Client(out=b'ok')])
    ssh_mod._pve_node_exec(m, 'pve1', 'true')
    rc, out, _ = ssh_mod._pve_node_exec(m, 'pve2', 'true')
    assert (rc, out) == (0, 'ok')
    other = _Mgr(answers=[_Client(out=b'ok')], cid='c2')
    rc, out, _ = ssh_mod._pve_node_exec(other, 'pve1', 'true')
    assert (rc, out) == (0, 'ok')


@pytest.mark.parametrize('kind', ['unreachable', 'host_key'])
def test_no_password_follows_a_node_that_is_not_there_or_not_the_pinned_one(monkeypatch, kind):
    """A password changes nothing about a dead node, and it must not go to a host whose key
    does not match the pinned one."""
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=[kind], user='root@pam', pass_='root-pw')
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert rc == 1 and sent == []
    assert m.failures == ['pve1']
    assert "node 'pve1'" in err


def test_a_key_that_cannot_be_loaded_still_lets_the_password_through(monkeypatch):
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=['key'], user='root@pam', pass_='root-pw')
    rc, out, _ = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert len(m.connects) == 1, 'the key was not tried first'
    assert (rc, out) == (0, 'pw-ok') and sent == [('10.0.0.7', 'root', 'root-pw')]
    # no login was refused, so nothing counts against the node
    assert m.failures == []


def test_a_refused_password_after_a_refused_key_says_both(monkeypatch):
    monkeypatch.setattr(ssh_mod, '_ssh_exec', lambda *a, **k: (255, '', 'Permission denied (publickey,password).'))
    m = _Mgr(answers=['auth'], user='root@pam', pass_='wrong')
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert rc == 255
    assert 'Permission denied (publickey,password).' in err and 'stored SSH key was refused' in err
    assert m.failures == ['pve1']


# --- the polled caller ----------------------------------------------------------------------

def test_the_console_tiles_do_not_log_in_twice_per_poll_on_a_node_that_refuses_the_key(monkeypatch):
    """vnc_grab.screendump_to_png runs on every tile poll. On a node that refuses the key
    and has no password, a poll after the first one does not reach sshd at all."""
    from pegaprox.utils import vnc_grab
    sent = _no_password_leg(monkeypatch)
    m = _Mgr(answers=['auth'] * 20)
    for vmid in range(100, 110):
        with pytest.raises(IOError):
            vnc_grab.screendump_to_png(m, 'pve1', vmid)
    assert len(m.connects) == 1 and sent == []


def test_the_console_tiles_take_their_frame_over_the_key(monkeypatch):
    import base64
    import gzip
    from PIL import Image
    from pegaprox.utils import vnc_grab
    _no_password_leg(monkeypatch)
    img = Image.new('RGB', (8, 8), (200, 30, 30))
    ppm = io.BytesIO()
    img.save(ppm, format='PPM')
    frame = base64.b64encode(gzip.compress(ppm.getvalue()))
    client = _Client(out=frame)
    m = _Mgr(answers=[client])
    png = vnc_grab.screendump_to_png(m, 'pve1', 101)
    assert png.startswith(b'\x89PNG')
    assert 'qm monitor 101' in client.cmds[0][0]


# --- with the real _ssh_connect ---------------------------------------------------------------

def _real_manager(**cfg):
    from pegaprox.core.manager import PegaProxManager
    m = PegaProxManager.__new__(PegaProxManager)
    base = dict(name='lab', host='10.0.0.1', user='ops@pve!pegaprox', pass_='the-token-secret',
                ssh_user='', ssh_key=KEY, ssh_port=22, ssh_disabled=False, fallback_hosts=[])
    base.update(cfg)
    m.config = types.SimpleNamespace(**base)
    m.id = 'c-real'
    m.logger = logging.getLogger('stored-key-test')
    m._cached_node_dict = {'pve1': {'node': 'pve1', 'status': 'online'}}
    m.is_connected = False
    m.current_host = None
    m._node_lock = threading.Lock()
    m._node_failures, m._node_blocked_until = {}, {}
    m._api_post = lambda *a, **k: types.SimpleNamespace(status_code=501)
    m._get_node_ip = lambda n: '10.0.0.7'
    return m


def _fake_paramiko(monkeypatch, seen, refuse=False, out=b'ok\n'):
    """`refuse`: True for paramiko's 'Authentication failed.' on every login, or a list
    with what each login raises in turn (None: it goes through)."""
    import paramiko
    import pegaprox.core.manager as manager_mod
    from pegaprox import globals as g
    said = list(refuse) if isinstance(refuse, (list, tuple)) else None

    class _Ssh(_Client):
        def __init__(self):
            super().__init__(out=out)

        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, **kw):
            seen.append(kw)
            why = (said.pop(0) if said else None) if said is not None else \
                ('Authentication failed.' if refuse else None)
            if why:
                raise paramiko.ssh_exception.AuthenticationException(why)

    pkey = object()
    loads = types.SimpleNamespace(from_private_key=lambda f: pkey)
    fake = types.SimpleNamespace(SSHClient=_Ssh, ssh_exception=paramiko.ssh_exception,
                                 RSAKey=loads, Ed25519Key=loads, ECDSAKey=loads)
    monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: fake)
    monkeypatch.setattr('pegaprox.utils.ssh_security.apply_host_key_policy', lambda c, p: None)
    monkeypatch.setattr('pegaprox.utils.ssh_security.persist_host_keys', lambda c: None)
    monkeypatch.setattr(g, '_ssh_semaphore', threading.Semaphore(4))
    return pkey


def test_the_real_manager_offers_the_key_and_no_password(db, monkeypatch):
    """Through PegaProxManager._ssh_connect: the key, the login of this path (root, not the
    token's user), and never the token secret."""
    sent = _no_password_leg(monkeypatch)
    seen = []
    pkey = _fake_paramiko(monkeypatch, seen)
    m = _real_manager()
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'hostname', timeout=10)
    assert (rc, out) == (0, 'ok\n'), err
    assert len(seen) == 1 and seen[0]['pkey'] is pkey and 'password' not in seen[0]
    assert seen[0]['username'] == 'root' and seen[0]['hostname'] == '10.0.0.7'
    assert sent == []


def test_the_real_manager_breaker_counts_a_refused_key_on_a_token_cluster(db, monkeypatch):
    sent = _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen, refuse=True)
    m = _real_manager()
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'hostname', timeout=10)
    assert rc == 1 and sent == [] and len(seen) == 1
    assert m._node_failures == {'pve1': 1}
    assert 'the-token-secret' not in err


@pytest.mark.parametrize('why', ['Authentication failed: transport shut down or saw EOF',
                                 'Authentication timeout.'])
def test_the_real_manager_tells_a_dropped_login_from_a_refused_key(db, monkeypatch, why):
    _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen, refuse=[why, None])
    m = _real_manager()
    assert ssh_mod._pve_node_exec(m, 'pve1', 'true', timeout=5)[0] == 1
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'qm set 101 --boot order=scsi0', timeout=5)
    assert len(seen) == 2, 'one dropped login kept the key from the next command'
    assert (rc, out) == (0, 'ok\n'), err


def test_a_login_with_the_key_that_went_through_ends_the_refusal_there(db, monkeypatch):
    """The operator fixes authorized_keys and the connection check logs in with the key: the
    console tiles and node commands of that node stop skipping it. A login as another user
    proves nothing for this one's."""
    _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen, refuse=['Authentication failed.', None, None, None])
    m = _real_manager()
    assert ssh_mod._pve_node_exec(m, 'pve1', 'true', timeout=5)[0] == 1
    # a login as another user, here ops
    assert m._ssh_connect('10.0.0.7', retries=1, failure={}, login='ops') is not None
    assert ssh_mod._pve_node_exec(m, 'pve1', 'true', timeout=5)[0] == 1
    assert len(seen) == 2, 'a login as ops lifted the refusal of root'
    assert m._ssh_connect('10.0.0.7', retries=1, failure={}, login='root') is not None
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true', timeout=5)
    assert len(seen) == 4 and (rc, out) == (0, 'ok\n'), err


def test_the_key_leg_does_not_log_each_poll_at_info(db, monkeypatch, caplog):
    """A disk copy probes every 5 s, a console tile every minute: two INFO lines per call
    were some 1,400 an hour per disk."""
    _no_password_leg(monkeypatch)
    _fake_paramiko(monkeypatch, [])
    m = _real_manager()
    caplog.set_level(logging.DEBUG, logger='stored-key-test')
    assert ssh_mod._pve_node_exec(m, 'pve1', 'stat -c %s /x', timeout=5)[0] == 0
    said = [(r.levelno, r.getMessage()) for r in caplog.records if r.name == 'stored-key-test']
    connect_lines = [(lvl, msg) for lvl, msg in said if msg.startswith(('Connecting to', 'SSH connected'))]
    assert len(connect_lines) == 2, said
    assert all(lvl == logging.DEBUG for lvl, _m in connect_lines), connect_lines


class _Busy:
    """The SSH connection semaphore with every slot taken."""

    def __init__(self):
        self.waits = []

    def acquire(self, timeout=None):
        self.waits.append(timeout)
        return False

    def release(self):
        raise AssertionError('released a slot it never got')


@pytest.mark.parametrize('local', ['queue', 'no_paramiko'])
def test_nothing_that_never_left_pegaprox_counts_against_the_node(db, monkeypatch, local):
    import pegaprox.core.manager as manager_mod
    from pegaprox import globals as g
    sent = _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen)
    busy = _Busy()
    if local == 'queue':
        monkeypatch.setattr(g, '_ssh_semaphore', busy)
    else:
        monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: None)
    m = _real_manager()
    for _ in range(3):
        rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true', timeout=5)
        assert rc == 1
    assert seen == [] and sent == []
    assert m._node_failures == {} and not m._is_node_blocked('pve1')[0]
    assert ('connection slot' if local == 'queue' else 'paramiko') in err, err
    # the wait for a slot is about the call's own time, not two minutes
    assert all(w <= 10 for w in busy.waits), busy.waits
    # with a password the node command still goes, by password
    m.config.user, m.config.pass_ = 'root@pam', 'root-pw'
    rc, out, _ = ssh_mod._pve_node_exec(m, 'pve1', 'true', timeout=5)
    assert (rc, out) == (0, 'pw-ok') and sent == [('10.0.0.7', 'root', 'root-pw')]


# --- the HA transport guard -------------------------------------------------------------------

@pytest.mark.guard_refusals
def test_the_guard_says_no_before_the_key_logs_in(db, monkeypatch):
    """_ssh_exec asks before it opens a socket (#625); the key leg logged in first and was
    refused at the command, and the refusal was booked against the node."""
    from pegaprox.core import ha
    asked = []

    def refuse(action, kind=None, need=None, again=False):
        asked.append(action)
        raise ha.GuardRefused(action, 'no lease')
    monkeypatch.setattr(ha, 'guard_on', lambda: True)
    monkeypatch.setattr(ha, 'guard', refuse)
    _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen)
    m = _real_manager()
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'qm set 101 --delete args', timeout=5)
    assert asked and rc == 1 and 'no lease' in err
    assert seen == [], 'the node saw a login from an instance that may not send'
    assert m._node_failures == {}


def test_the_command_is_asked_for_once_and_its_exec_as_the_same_call(db, monkeypatch):
    """Asked before the login, and the client's own ask at the exec is 'again': a second
    plain ask would need a lease round of its own for one command."""
    from pegaprox.core import ha, ha_transport
    events = []
    monkeypatch.setattr(ha, 'guard_on', lambda: True)
    monkeypatch.setattr(ha_transport, 'guard_ssh',
                        lambda host, cmd='', again=False: events.append(('ask', host, cmd, again)))
    _no_password_leg(monkeypatch)
    _fake_paramiko(monkeypatch, events)
    m = _real_manager()
    assert ssh_mod._pve_node_exec(m, 'pve1', 'qm set 101 --delete args', timeout=5)[0] == 0
    kinds = ['login' if isinstance(e, dict) else e for e in events]
    assert kinds == [('ask', '10.0.0.7', 'qm set 101 --delete args', False), 'login',
                     ('ask', '10.0.0.7', 'qm set 101 --delete args', True)], kinds


# --- a node the cluster does not list ---------------------------------------------------------

def _resp(code, data=None):
    return types.SimpleNamespace(status_code=code, json=lambda: {'data': data or []})


def _api_get(url, *a, **k):
    """A PVE API that knows pve1 only, the node PegaProx is connected to."""
    if url.endswith('/cluster/status'):
        return _resp(200, [{'type': 'node', 'name': 'pve1', 'ip': '10.0.0.1', 'local': 1}])
    return _resp(400)


def _listing_manager(members, **cfg):
    """The real name to address lookup, and every port answers its TCP probe."""
    m = _real_manager(**cfg)
    del m._get_node_ip
    m._cached_node_dict, m._nodes_cache_time = dict(members), time.time()
    m.is_connected, m.current_host = True, '10.0.0.1'
    m._api_get = _api_get
    m.config.api_port = 8006
    return m


@pytest.fixture
def _ports_answer(monkeypatch):
    class _Sock:
        def __init__(self, *a, **k): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0
        def close(self): pass
    monkeypatch.setattr(socket, 'socket', _Sock)


@pytest.mark.parametrize('cfg', [{}, {'user': 'root@pam', 'pass_': 'cluster-root-pw'}],
                         ids=['token-and-key', 'password-and-key'])
def test_a_name_the_cluster_does_not_list_gets_neither_key_nor_password(db, monkeypatch, _ports_answer, cfg):
    """GET .../vms/<node>/qemu/<vmid>/screenshot and the ESXi import's target_node hand the
    name on as it came. _get_node_ip's DNS step turns an address literal into itself, and
    the cluster's key, or its root password after a refused key, went there."""
    sent = _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen, refuse=bool(cfg))
    m = _listing_manager({'pve1': {'node': 'pve1'}}, **cfg)
    assert m._get_node_ip(EVIL) == EVIL, 'the lookup no longer resolves it, the test proves nothing'
    ssh_mod._node_ip_cache.clear()
    rc, out, err = ssh_mod._pve_node_exec(m, EVIL, 'echo screendump /tmp/x | qm monitor 101')
    assert rc == 1 and 'not a node of this cluster' in err, err
    assert seen == [] and sent == [], (seen, sent)
    # a member still gets its command, at the address the cluster gives it
    ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert seen and seen[-1]['hostname'] == '10.0.0.1'


def test_a_node_list_that_is_not_known_yet_refuses_too(db, monkeypatch):
    sent = _no_password_leg(monkeypatch)
    seen = []
    _fake_paramiko(monkeypatch, seen)
    m = _real_manager()
    m._cached_node_dict = {}
    rc, out, err = ssh_mod._pve_node_exec(m, 'pve1', 'true')
    assert rc == 1 and 'not a node of this cluster' in err
    assert seen == [] and sent == []


def test_the_ssh_destination_sweep_sees_the_key_leg():
    """tests/test_ssh_destinations_are_cluster_members.py looks for _ssh_connect calls; a
    getattr in between hid this one from it."""
    from test_ssh_destinations_are_cluster_members import _ssh_destinations
    sites = {(p, f) for p, _l, f, _a, _n in _ssh_destinations()}
    assert ('pegaprox/utils/ssh.py', '_stored_key_exec') in sites, sorted(sites)


# --- the two routes that hand a node name on --------------------------------------------------

def test_the_screenshot_route_takes_a_node_of_the_cluster_only(api, seed, monkeypatch):
    import pegaprox.api.vms as vms
    grabbed = []
    monkeypatch.setattr(vms, 'grab_vm_frame', lambda mgr, node, *a, **k: grabbed.append(node) or b'\x89PNG')
    monkeypatch.setattr(vms, '_vm_screenshot_cache', {})
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1')).nodes = {'pve1': {'node': 'pve1'}}
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.get(f'/api/clusters/cluster_1/vms/{EVIL}/qemu/101/screenshot?fresh=1')
    assert r.status_code == 404, r.status_code
    assert grabbed == []
    r = admin.get('/api/clusters/cluster_1/vms/pve1/qemu/101/screenshot?fresh=1')
    assert r.status_code == 200 and grabbed == ['pve1']


def test_the_esxi_import_takes_a_target_node_of_the_target_cluster_only(api, seed, monkeypatch):
    from unittest.mock import MagicMock
    import pegaprox.api.vmware as vmware_api
    import pegaprox.globals as ppglobals
    started = []
    monkeypatch.setattr(vmware_api, '_run_v2p_migration', lambda task: started.append(task))
    monkeypatch.setattr(vmware_api, '_vmware_migrations', {})
    esx = MagicMock()
    esx.host, esx.linked_clusters = 'esxi1.example.com', []
    esx.get_vm.return_value = {'data': {'name': 'guest', 'nics': []}}
    monkeypatch.setitem(ppglobals.vmware_managers, 'vmw1', esx)
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1')).nodes = {'pve1': {'node': 'pve1'}}
    admin = api.as_user(seed.user('root', role='admin'))
    body = {'target_cluster': 'cluster_1', 'target_storage': 'local-lvm', 'esxi_password': 'pw'}
    for node in (EVIL, ['pve1'], 'pve9'):
        r = admin.post('/api/vmware/vmw1/vms/42/migrate', json=dict(body, target_node=node))
        assert r.status_code == 400 and 'target_node' in r.get_json()['error'], (node, r.get_data(as_text=True))
    assert started == [] and vmware_api._vmware_migrations == {}
    r = admin.post('/api/vmware/vmw1/vms/42/migrate', json=dict(body, target_node='pve1'))
    assert r.status_code == 202, r.get_data(as_text=True)
