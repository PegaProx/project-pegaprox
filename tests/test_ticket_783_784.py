"""Two reports against 1.1.0, both verified in the tree before fixing.

#783 — the per-cluster logger is keyed on the DISPLAY name, which nothing forces
to be unique (the clusters table has UNIQUE only on id), while each manager's
file handler is keyed on cluster_id. __init__ ran a blanket handlers.clear(), so
the second manager of two same-named clusters stripped the first's file handler:
that cluster's log went silent and its lines landed in the sibling's file.

#784 — signal.signal installs the handler ON the gevent hub, and http_server.stop()
waits for in-flight greenlets. Waiting on the hub raises BlockingSwitchOutError,
so a systemd stop exited 1 instead of stopping cleanly. MK
"""
import logging
import os

import pytest


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


def test_the_console_subprocess_is_terminated():
    """The SSH WebSocket server is a separate process on an endless asyncio Future —
    verified in practice: it was reparented to init and survived its parent."""
    block = _shutdown_handler_source()

    assert 'ssh_ws_proc' in block and 'terminate()' in block


def test_the_subprocess_handle_is_actually_threaded_through():
    """Guards the guard: terminate() on a handle that is always None does nothing."""
    src = open('pegaprox/app.py').read()

    assert 'ssh_ws_proc = _start_console_servers(' in src
    assert 'return ssh_proc' in src, '_start_console_servers never hands the handle back'
    vms = open('pegaprox/api/vms.py').read()
    i = vms.index('SSH WebSocket server subprocess started')
    assert 'return proc' in vms[i:i + 200], 'the starter never returns its Popen'


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
