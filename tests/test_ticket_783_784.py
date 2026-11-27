"""Two reports against 1.1.0, both verified in the tree before fixing.

#783 — the per-cluster logger is keyed on the DISPLAY name, which nothing forces
to be unique (the clusters table has UNIQUE only on id), while each manager's
file handler is keyed on cluster_id. __init__ ran a blanket handlers.clear(), so
the second manager of two same-named clusters stripped the first's file handler:
that cluster's log went silent and its lines landed in the sibling's file.

#784 — signal.signal installs the handler ON the gevent hub, and http_server.stop()
waits for in-flight greenlets. Waiting on the hub raises BlockingSwitchOutError,
so a systemd stop exited 1 instead of stopping cleanly. MK

Nov 2026: the SSH console server is no subprocess any more, so there is nothing of ours
left to outlive the app. The legacy console ports are listeners of the same app in the
same process now, and the shutdown stops them with the main server.
"""
import logging
import os
import signal
import socket
import subprocess
import sys
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── #783: a sibling's log handler must survive ───────────────────────────────

@pytest.fixture
def two_same_named(tmp_path, monkeypatch):
    """Two managers, different cluster ids, same display name."""
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'LOG_DIR', str(tmp_path))
    logging.getLogger('PegaProx_Production').handlers.clear()

    from unittest.mock import MagicMock
    made = []
    for cid in ('cluster_aaa', 'cluster_bbb'):
        m = mgrmod.PegaProxManager.__new__(mgrmod.PegaProxManager)
        cfg = MagicMock(name=f'cfg-{cid}')
        cfg.name = 'Production'
        # run just the logging block __init__ does
        m.logger = logging.getLogger(f"PegaProx_{cfg.name}")
        m.logger.setLevel(logging.DEBUG)
        m.logger.propagate = False
        _own = os.path.abspath(f"{mgrmod.LOG_DIR}/{cid}.log")
        for h in list(m.logger.handlers):
            base = getattr(h, 'baseFilename', None)
            if base is None or os.path.abspath(base) == _own:
                m.logger.removeHandler(h)
        fh = logging.FileHandler(f"{mgrmod.LOG_DIR}/{cid}.log")
        m.logger.addHandler(fh)
        made.append((cid, m))
    try:
        yield made
    finally:
        logging.getLogger('PegaProx_Production').handlers.clear()


def test_the_second_manager_does_not_strip_the_firsts_log(two_same_named, tmp_path):
    logger = logging.getLogger('PegaProx_Production')
    files = {os.path.basename(h.baseFilename) for h in logger.handlers
             if getattr(h, 'baseFilename', None)}

    assert files == {'cluster_aaa.log', 'cluster_bbb.log'}, files


def test_the_real_init_keeps_a_siblings_handler():
    """Structural: the blanket clear is what did the damage."""
    src = open('pegaprox/core/manager.py').read()
    i = src.index('self.logger = logging.getLogger(f"PegaProx_')
    block = src[i:i + 1400]

    assert 'self.logger.handlers.clear()' not in block, 'the blanket clear is back'
    assert 'baseFilename' in block, 'handler ownership is not decided per file'


def test_re_creating_the_same_cluster_still_dedupes(tmp_path, monkeypatch):
    """The original intent must survive: one manager, one file handler."""
    import pegaprox.core.manager as mgrmod
    monkeypatch.setattr(mgrmod, 'LOG_DIR', str(tmp_path))
    logger = logging.getLogger('PegaProx_Solo')
    logger.handlers.clear()

    for _ in range(3):
        own = os.path.abspath(f"{mgrmod.LOG_DIR}/cluster_solo.log")
        for h in list(logger.handlers):
            base = getattr(h, 'baseFilename', None)
            if base is None or os.path.abspath(base) == own:
                logger.removeHandler(h)
        logger.addHandler(logging.FileHandler(f"{mgrmod.LOG_DIR}/cluster_solo.log"))

    file_handlers = [h for h in logger.handlers if getattr(h, 'baseFilename', None)]
    assert len(file_handlers) == 1, [h.baseFilename for h in file_handlers]
    logger.handlers.clear()


# ── #784: the shutdown must not wait on the hub ──────────────────────────────

def _shutdown_handler_source(strip_comments=False):
    """The shutdown handler's body. strip_comments because a check for a call is otherwise
    satisfied by a comment that merely names it — which this file already did once."""
    src = open('pegaprox/app.py').read()
    i = src.index('def signal_handler')
    block = src[i:i + 1400]
    if strip_comments:
        block = '\n'.join(l.split('#', 1)[0] for l in block.split('\n'))
    return block


def test_the_blocking_stop_does_not_run_on_the_hub():
    """signal.signal runs the callback ON the hub and http_server.stop() blocks on
    pool.join(), which is illegal there. It has to be deferred into its own greenlet."""
    block = _shutdown_handler_source()

    assert 'spawn(' in block, 'stop() is still called straight from the hub callback'
    assert 'http_server.stop' in block
    assert 'timeout=' in block, 'stop() should be bounded so a wedged greenlet cannot hang it'


def test_the_handler_does_not_exit_the_process_itself():
    """serve_forever() returns once stop() sets the stop event. A sys.exit() here would
    race the deferred stop and is what turned a clean stop into a non-zero exit."""
    block = _shutdown_handler_source(strip_comments=True)

    assert 'sys.exit' not in block, 'the handler still exits out from under the deferred stop'


def test_each_legacy_console_listener_is_stopped_off_the_hub():
    """The listeners on port+1 and port+2 are servers of their own; serve_forever() only
    returns for the main one. Each is stopped in a greenlet of its own and bounded, as
    the main server is."""
    block = _shutdown_handler_source(strip_comments=True)

    assert 'for extra_server in legacy_servers:' in block
    assert 'spawn(lambda srv=extra_server: srv.stop(timeout=' in block


_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import socket
import sys

import gevent
from flask import Flask

import pegaprox.app as app_mod

web = Flask('shutdown-test')


@web.route('/ping')
def ping():
    return 'pong'


port = int(sys.argv[1])
app_mod._start_gevent_server(web, '127.0.0.1', port, None, None, 4)
# serve_forever() has returned; the stops of the legacy listeners run in greenlets of their own
gevent.sleep(0.5)
for p in (port, port + 1, port + 2):
    probe = socket.socket()
    probe.settimeout(2)
    try:
        probe.connect(('127.0.0.1', p))
        print(f'STILL LISTENING {p}', flush=True)
    except OSError:
        print(f'STOPPED {p}', flush=True)
    finally:
        probe.close()
print('SERVE_FOREVER RETURNED', flush=True)
'''


def _free_ports(count):
    """A first port with count-1 free ports after it."""
    for _ in range(50):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        base = s.getsockname()[1]
        s.close()
        if base + count > 65535:
            continue
        try:
            for p in range(base, base + count):
                t = socket.socket()
                t.bind(('127.0.0.1', p))
                t.close()
        except OSError:
            continue
        return base
    pytest.skip('no run of free ports')


def _listening(port):
    try:
        socket.create_connection(('127.0.0.1', port), timeout=1).close()
        return True
    except OSError:
        return False


def test_a_sigterm_stops_the_main_server_and_both_legacy_console_ports(tmp_path):
    """The real thing, as production runs it (gevent's monkey patching, the signal handler
    on the hub): a SIGTERM ends serve_forever() without a BlockingSwitchOutError, the
    process exits 0, and none of the three ports is still listening by then."""
    port = _free_ports(3)
    log_path = tmp_path / 'server.log'
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(tmp_path / 'config')}
    env.pop('PEGAPROX_LEGACY_CONSOLE_PORTS', None)
    with open(log_path, 'w') as log:
        proc = subprocess.Popen([sys.executable, '-c', _SERVER, str(port)], cwd=str(tmp_path),
                                env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        end = time.monotonic() + 60
        while not all(_listening(p) for p in (port, port + 1, port + 2)):
            if proc.poll() is not None or time.monotonic() > end:
                pytest.fail('test server did not come up:\n' + log_path.read_text())
            time.sleep(0.2)

        proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(30)
        except subprocess.TimeoutExpired:
            pytest.fail('a SIGTERM did not stop the server:\n' + log_path.read_text())
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(5)

    out = log_path.read_text()
    assert code == 0, out
    assert 'BlockingSwitchOutError' not in out and 'Traceback' not in out, out
    assert 'SERVE_FOREVER RETURNED' in out, out
    assert [line for line in out.splitlines() if line.startswith(('STOPPED', 'STILL'))] == [
        f'STOPPED {p}' for p in (port, port + 1, port + 2)], out


def test_greenlet_exit_during_handshake_is_swallowed():
    """gevent cancels connection greenlets on stop(); GreenletExit is a BaseException so
    the SSL handler below it never saw one, and it surfaced as a shutdown traceback.

    MK Sep 2026 - this read `src[i:i + 900]` and went red when the handshake timeout was
    added above the except: the clause was still there, 780 characters past the cutoff.
    Take the method, not a guess at its length."""
    from _srcutil import handler_body
    src = open('pegaprox/app.py').read()
    block = handler_body(src, 'def wrap_socket_and_handle', nested=True)

    assert 'except GreenletExit' in block
