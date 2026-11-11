"""The byte relay of an incremental replication run comes back when a node does not.

_relay_pipe pipes the exporter's stdout on the source into the importer's stdin on the
target, then waited for both exit statuses with nothing to end the wait. An importer
that gives up early (an incremental `zfs recv` refusing a target changed by a failover
test boot) stops the relay, nobody reads the exporter any more, it blocks once its SSH
window is full and never exits. An importer hung on its storage after the stream never
exits either. The run thread hung for good, the job stayed claimed, and the scheduler
skipped it on every later tick without a word.

Now a relay that broke closes the exporter's channel, which ends it on the node, and
both exit statuses are waited for no longer than the relay's timeout (at most
_EXIT_WAIT); one that does not come is 124 with a note, and the run reports a failure.

Real paramiko on both ends, over socketpairs, flow control included.
"""
import socket
import threading

import paramiko
import pytest

from pegaprox.core import incremental_repl as ir

_HOST_KEY = paramiko.RSAKey.generate(2048)
MB = 1024 * 1024


class _Server(paramiko.ServerInterface):
    def __init__(self, run):
        self.run = run

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return 'none'

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_exec_request(self, channel, command):
        threading.Thread(target=self._exec, args=(channel, command.decode()), daemon=True).start()
        return True

    def _exec(self, chan, cmd):
        try:
            # the clean-up reads of the parked stderr files come back empty
            rc = 0 if cmd.startswith('cat ') else self.run(chan)
            if rc is not None:
                chan.send_exit_status(rc)
        except Exception:
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass


class _Node:
    """A node reached over SSH; `run(chan)` is what its rbd command does, its return
    value the exit status (None sends none)."""

    def __init__(self, run):
        a, b = socket.socketpair()
        self._server = paramiko.Transport(b)
        self._server.add_server_key(_HOST_KEY)
        self._server.start_server(event=threading.Event(), server=_Server(run))
        self._client = paramiko.Transport(a)
        self._client.start_client()
        self._client.auth_none('root')

    def exec_command(self, command, timeout=None):
        chan = self._client.open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        return chan.makefile_stdin('wb'), chan.makefile('r'), chan.makefile_stderr('r')

    def close(self):
        self._client.close()
        self._server.close()


def _exporter(size, ended):
    def run(chan):
        try:
            for _ in range(size // 65536):
                chan.sendall(b'x' * 65536)   # blocks while the relay reads nothing
            return 0
        finally:
            ended.set()
    return run


def _importer(rc, stop_after=None, hang=None):
    def run(chan):
        got = 0
        while stop_after is None or got < stop_after:
            data = chan.recv(65536)
            if not data:
                break
            got += len(data)
        if hang is not None:
            hang.wait()
            return None
        return rc
    return run


@pytest.fixture
def relay():
    """relay(src_run, tgt_run, timeout) runs _relay_pipe in a thread and gives back
    (still running after `join` seconds, its result)."""
    nodes, hangs = [], []

    def go(src_run, tgt_run, timeout, join):
        src, tgt = _Node(src_run), _Node(tgt_run)
        nodes.extend((src, tgt))
        out = {}
        th = threading.Thread(target=lambda: out.update(ir._relay_pipe(
            src, 'rbd --no-progress export-diff --from-snap s1 rbd/vm-100-disk-0@s2 -',
            tgt, 'rbd --no-progress import-diff - rbd/vm-100-disk-0', timeout=timeout)), daemon=True)
        th.start()
        th.join(join)
        return th.is_alive(), out

    go.hangs = hangs
    yield go
    for ev in hangs:
        ev.set()
    for n in nodes:       # frees a relay thread that is still waiting
        n.close()


def test_an_importer_that_refuses_the_stream_ends_the_run(relay):
    ended = threading.Event()
    alive, out = relay(_exporter(8 * MB, ended), _importer(1, stop_after=100 * 1024), timeout=3, join=20)
    assert not alive, '_relay_pipe still waits 20 s after the importer exited 1 (relay timeout 3 s)'
    assert out['ok'] is False and out['tgt_rc'] == 1
    assert out['error'].startswith('relay error after ')
    # the exporter on the source node is not left blocked on its window
    assert ended.wait(5)


def test_an_importer_that_never_exits_gives_the_job_back(relay):
    hang = threading.Event()
    relay.hangs.append(hang)
    alive, out = relay(_exporter(1 * MB, threading.Event()), _importer(0, hang=hang), timeout=2, join=15)
    assert not alive, '_relay_pipe still waits 15 s for an importer that never exits (relay timeout 2 s)'
    assert out['ok'] is False
    assert out['bytes'] == 1 * MB
    assert (out['src_rc'], out['tgt_rc']) == (0, 124)
    assert 'no exit status from the importer within 2s' in out['error']


def test_a_healthy_run_reports_both_exit_codes(relay):
    alive, out = relay(_exporter(8 * MB, threading.Event()), _importer(0), timeout=3, join=60)
    assert not alive
    assert out == {'ok': True, 'bytes': 8 * MB, 'src_rc': 0, 'tgt_rc': 0, 'error': ''}


def test_the_wait_is_capped_below_the_relay_timeout(relay, monkeypatch):
    """The callers keep the default relay timeout of 4 hours; the wait after the
    stream is _EXIT_WAIT at most."""
    monkeypatch.setattr(ir, '_EXIT_WAIT', 1, raising=False)
    hang = threading.Event()
    relay.hangs.append(hang)
    alive, out = relay(_exporter(1 * MB, threading.Event()), _importer(0, hang=hang), timeout=14400, join=15)
    assert not alive, '_relay_pipe still waits 15 s for an importer that never exits (wait capped at 1 s)'
    assert out['tgt_rc'] == 124 and 'no exit status from the importer within 1s' in out['error']
