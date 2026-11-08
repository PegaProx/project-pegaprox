"""This process (#625, stage two S0): one per config directory, and how it goes.

  * lock_config_dir: a second process on the same config directory is refused (F1);
    instances with a PEGAPROX_CONFIG_DIR of their own are not.
  * leave_process, the way out of every restart: the children die first, then it
    exits with EXIT_RESTART where systemd or the Docker image starts it again, or it
    execs itself. Never exit 0, which Restart=on-failure takes as a clean stop (F3,
    E2), and no sudo, which the unit's NoNewPrivileges rules out anyway.
  * the kept peer sessions (F9).

MK Oct 2026
"""
import ast
import inspect
import os
import subprocess
import sys
import time
import types

import pytest

from pegaprox.core import ha

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- one process per config directory -----------------------------------------------

@pytest.fixture
def lock_fds():
    fds = []
    yield fds
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def _lock_in_child(config_dir):
    """lock_config_dir in a process of its own; its answer and exit code."""
    code = ('import sys\n'
            'from pegaprox.core import ha\n'
            'try:\n'
            '    ha.lock_config_dir()\n'
            'except ha.HaError as e:\n'
            '    print(e); sys.exit(3)\n'
            'print("locked")\n')
    out = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True,
                         timeout=120, env=dict(os.environ, PEGAPROX_CONFIG_DIR=str(config_dir),
                                               PEGAPROX_NO_GEVENT='1'))
    return out.returncode, (out.stdout + out.stderr).strip()


def test_a_second_process_on_the_same_config_directory_is_refused(tmp_path, lock_fds):
    cfg = tmp_path / 'config'
    cfg.mkdir()
    fd = ha.lock_config_dir(str(cfg / '.pegaprox.lock'))
    lock_fds.append(fd)

    rc, text = _lock_in_child(cfg)

    assert rc == 3, text
    assert f'process {os.getpid()}' in text and str(cfg) in text


def test_an_instance_with_a_config_directory_of_its_own_runs(tmp_path, lock_fds):
    """The dev box runs extra instances side by side, each with PEGAPROX_CONFIG_DIR."""
    (tmp_path / 'one').mkdir()
    (tmp_path / 'two').mkdir()
    lock_fds.append(ha.lock_config_dir(str(tmp_path / 'one' / '.pegaprox.lock')))

    rc, text = _lock_in_child(tmp_path / 'two')

    assert rc == 0 and text.endswith('locked'), text


def test_the_lock_goes_with_the_process(tmp_path, lock_fds):
    cfg = tmp_path / 'config'
    cfg.mkdir()
    fd = ha.lock_config_dir(str(cfg / '.pegaprox.lock'))
    # close-on-exec: an execv restart lets go of it, and the new image takes it again
    assert os.get_inheritable(fd) is False
    os.close(fd)

    rc, text = _lock_in_child(cfg)
    assert rc == 0, text


def test_a_second_lock_in_the_same_process_is_refused_too(tmp_path, lock_fds):
    path = str(tmp_path / '.pegaprox.lock')
    lock_fds.append(ha.lock_config_dir(path))
    with pytest.raises(ha.HaError, match='one config directory takes one process'):
        ha.lock_config_dir(path)


def test_a_filesystem_without_locks_does_not_keep_pegaprox_down(tmp_path, monkeypatch, lock_fds):
    import errno
    import fcntl

    def no_locks(fd, op):
        raise OSError(errno.ENOLCK, 'No locks available')
    monkeypatch.setattr(fcntl, 'flock', no_locks)

    assert ha.lock_config_dir(str(tmp_path / '.pegaprox.lock')) is None


def _main():
    from pegaprox import app as app_mod
    return ast.parse(inspect.getsource(app_mod.main)).body[0]


def _lines(fn, name):
    return [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call)
            and (getattr(n.func, 'attr', None) or getattr(n.func, 'id', None)) == name]


def test_main_takes_the_lock_before_it_touches_the_config_directory():
    fn = _main()
    lock = _lines(fn, 'lock_config_dir')
    assert len(lock) == 1
    for later in ('ensure_db_encrypted', 'check_markers_at_boot', 'check_peer_at_boot',
                  'create_app', 'load_config', '_start_managers'):
        assert _lines(fn, later) and lock[0] < min(_lines(fn, later)), later
    # and a refusal ends the process
    handler = next(n for n in ast.walk(fn) if isinstance(n, ast.Try)
                   and any(c.lineno == lock[0] for c in ast.walk(n) if isinstance(c, ast.Call)))
    assert 'exit' in ast.unparse(handler.handlers[0])


# --- the way out ------------------------------------------------------------------------

class _Gone(BaseException):
    pass


@pytest.fixture
def way_out(monkeypatch):
    """Records what leave_process does instead of doing it."""
    seen = []

    def _exit(code):
        seen.append(('exit', code))
        raise _Gone()

    def execv(path, argv):
        seen.append(('execv', path))
        raise _Gone()
    monkeypatch.setattr(ha.os, '_exit', _exit)
    monkeypatch.setattr(ha.os, 'execv', execv)
    monkeypatch.setattr(ha, 'kill_children', lambda: seen.append(('kill',)))
    monkeypatch.delenv('INVOCATION_ID', raising=False)
    monkeypatch.delenv('PEGAPROX_SUPERVISED', raising=False)
    return seen


def _leave():
    with pytest.raises(_Gone):
        ha.leave_process()


def test_under_systemd_it_still_execs_itself(way_out, monkeypatch):
    """An exit would count against the unit's start limit (5 in 120 s in
    systemd/pegaprox.service): a few role changes in a row and the service is failed.
    The exit is only for an admin who sets PEGAPROX_SUPERVISED."""
    monkeypatch.setenv('INVOCATION_ID', 'f' * 32)
    monkeypatch.setattr(ha.os, 'getppid', lambda: 1)
    _leave()
    assert way_out == [('kill',), ('execv', sys.executable)]


def test_when_the_admin_asks_a_restart_is_an_exit_with_75(way_out, monkeypatch):
    monkeypatch.setenv('PEGAPROX_SUPERVISED', '1')
    _leave()
    assert way_out == [('kill',), ('exit', ha.EXIT_RESTART)]


def test_without_a_supervisor_it_execs_itself_once_the_children_are_gone(way_out, monkeypatch):
    _leave()
    assert way_out == [('kill',), ('execv', sys.executable)]


def test_an_inherited_invocation_id_is_no_supervisor(way_out, monkeypatch):
    """Everything a service starts inherits INVOCATION_ID; a PegaProx started from
    such a shell would exit and never come back."""
    monkeypatch.setenv('INVOCATION_ID', 'f' * 32)
    monkeypatch.setattr(ha.os, 'getppid', lambda: 4242)
    _leave()
    assert way_out == [('kill',), ('execv', sys.executable)]


def test_the_docker_image_does_not_exit_on_a_restart():
    """A compose file without a restart policy would leave the container stopped: the
    image keeps the exec, the children die before it."""
    with open(os.path.join(ROOT, 'Dockerfile'), encoding='utf-8') as fh:
        lines = [ln.strip() for ln in fh]
    assert not any(ln.startswith('ENV PEGAPROX_SUPERVISED') for ln in lines)


def test_an_exec_that_fails_never_exits_with_0(way_out, monkeypatch):
    def broken(path, argv):
        way_out.append(('execv', path))
        raise OSError('no such interpreter')
    monkeypatch.setattr(ha.os, 'execv', broken)
    _leave()
    assert way_out == [('kill',), ('execv', sys.executable), ('exit', 75)]


def test_restart_process_runs_no_systemctl_and_no_sudo(monkeypatch):
    calls, left = [], []
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: calls.append(a) or types.SimpleNamespace(
        returncode=0, stdout='active', stderr=''))
    monkeypatch.setattr(ha, 'leave_process', lambda: left.append(1))
    monkeypatch.setattr(ha, 'time', types.SimpleNamespace(sleep=lambda s: None))

    class _Now:
        def __init__(self, target, **kw):
            self.target = target

        def start(self):
            self.target()
    monkeypatch.setattr(ha, 'threading', types.SimpleNamespace(Thread=_Now))

    ha.restart_process('promoted to active')

    assert calls == [] and left == [1]


# --- the children ---------------------------------------------------------------------

def _alive(pid):
    try:
        with open(f'/proc/{pid}/stat', 'rb') as fh:
            state = fh.read().rsplit(b')', 1)[1].split()[0]
    except OSError:
        return False
    return state not in (b'Z', b'X')


@pytest.mark.skipif(not os.path.isdir('/proc'), reason='needs /proc')
def test_every_child_dies_with_its_group_before_the_process_goes(monkeypatch):
    """An execv keeps the pid, and a child the old role started (an ssh stop, an
    ipmitool power-off) ran on next to the new role."""
    alone = subprocess.Popen(['sleep', '60'])
    leader = subprocess.Popen(['sh', '-c', 'sleep 60 & echo $!; wait'], stdout=subprocess.PIPE,
                              start_new_session=True)
    grandchild = int(leader.stdout.readline())
    registered = subprocess.Popen(['sleep', '60'], start_new_session=True)
    mine = {alone.pid, leader.pid, registered.pid}
    real = ha._children
    try:
        assert {pid for pid, _ in real()} >= mine
        assert dict(real())[leader.pid] == leader.pid != os.getpgrp()
        assert dict(real())[alone.pid] == os.getpgrp()
        # nothing else of this test process is touched
        monkeypatch.setattr(ha, '_children', lambda: [c for c in real() if c[0] in mine - {registered.pid}])
        ha.register_child_group(registered.pid)

        ha.kill_children()

        for p in (alone, leader, registered):
            assert p.wait(timeout=10) == -9
        deadline = time.monotonic() + 10
        while _alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(grandchild)
    finally:
        ha.forget_child_group(registered.pid)
        for p in (alone, leader, registered):
            if p.poll() is None:
                p.kill()
                p.wait()


def test_a_forgotten_group_is_left_alone(monkeypatch):
    killed = []
    monkeypatch.setattr(ha, '_children', lambda: [])
    monkeypatch.setattr(ha.os, 'killpg', lambda pg, sig: killed.append(pg))
    ha.register_child_group(987654)
    ha.forget_child_group(987654)
    ha.register_child_group(987655)
    try:
        ha.kill_children()
    finally:
        ha.forget_child_group(987655)
    assert killed == [987655]


# --- kept peer sessions -----------------------------------------------------------------

class _Session:
    made = []

    def __init__(self, fingerprint, fail=False):
        self.fingerprint, self.fail, self.closed, self.calls = fingerprint, fail, False, 0
        _Session.made.append(self)

    def request(self, method, url, **kw):
        self.calls += 1
        if self.fail:
            import requests
            if self.fail == 'read':
                raise requests.exceptions.ReadTimeout('took it, said nothing')
            raise requests.exceptions.ConnectTimeout('down')
        return types.SimpleNamespace(status_code=200, url=url)

    def close(self):
        self.closed = True


@pytest.fixture
def sessions(monkeypatch):
    _Session.made = []
    failing = set()
    monkeypatch.setattr(ha, '_kept_sessions', {})
    monkeypatch.setattr(ha, '_new_session', lambda fp: _Session(fp, fail=fp in failing))
    return types.SimpleNamespace(made=_Session.made, failing=failing)


URL = 'https://10.0.0.5:5000'
FP = ':'.join(['AB'] * 32)


def _call(url=URL, fp=FP, **kw):
    return ha._peer_call('POST', url, fp, '/api/ha/peer/status', json_body={}, **kw)


def test_a_call_of_its_own_gets_a_session_of_its_own(sessions):
    _call()
    _call()
    assert len(sessions.made) == 2 and all(s.closed for s in sessions.made)


def test_kept_calls_to_one_member_ride_on_one_session(sessions):
    _call(keep_alive=True)
    _call(keep_alive=True)
    _call(URL + '/', keep_alive=True)

    assert len(sessions.made) == 1
    only = sessions.made[0]
    assert only.calls == 3 and not only.closed and only.fingerprint == FP


def test_a_new_pin_gets_a_new_session(sessions):
    _call(keep_alive=True)
    other = ':'.join(['CD'] * 32)
    _call(fp=other, keep_alive=True)

    first, second = sessions.made
    assert first.closed and not second.closed and second.fingerprint == other


def test_a_kept_session_stays_across_a_call_that_never_got_out(sessions):
    """Refused or timed out while connecting: nothing of the call sits in the session, and
    a member that is down must not cost a new session per call (#625 stage 2, a confirm
    round before every write)."""
    sessions.failing.add(FP)
    for _ in range(3):
        with pytest.raises(ha.PeerUnreachable):
            _call(keep_alive=True)
    only, = sessions.made
    only.fail = False
    _call(keep_alive=True)
    assert len(sessions.made) == 1 and not only.closed and only.calls == 4


def test_a_kept_session_that_failed_after_the_call_got_out_is_dropped(sessions):
    ha._kept_session(URL, FP).fail = 'read'
    with pytest.raises(ha.PeerNoAnswer):
        _call(keep_alive=True)
    _call(keep_alive=True)

    broken, fresh = sessions.made
    assert broken.closed and not fresh.closed and fresh.calls == 1


def test_the_kept_sessions_stay_bounded(sessions):
    for n in range(ha._MAX_KEPT_SESSIONS + 2):
        _call(f'https://10.0.0.{n + 1}:5000', keep_alive=True)
    assert len(ha._kept_sessions) == ha._MAX_KEPT_SESSIONS
    assert [s.closed for s in sessions.made[:2]] == [True, True]
    assert not any(s.closed for s in sessions.made[2:])


def test_the_session_is_pinned_when_there_is_a_pin():
    from pegaprox.core.pbs import _PinnedFingerprintAdapter
    pinned = ha._new_session(FP)
    plain = ha._new_session('')
    try:
        assert isinstance(pinned.get_adapter('https://10.0.0.5:5000'), _PinnedFingerprintAdapter)
        assert not isinstance(plain.get_adapter('https://10.0.0.5:5000'), _PinnedFingerprintAdapter)
    finally:
        pinned.close()
        plain.close()
