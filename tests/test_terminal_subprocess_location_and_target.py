"""Two things the SSH-websocket subprocess got wrong about its own host.

#957 - it validates every session against PEGAPROX_URL, which was pinned to
       127.0.0.1. Bind the app to one LAN address (the "Proxy Bind Address"
       setting) and loopback is not listening, so every terminal died with
       "Auth server unreachable" and close code 1011.
#958 - on a package install the script is written somewhere writable, and the
       fallback was the shared temp dir. An executable under a predictable name
       in a world-writable directory is not where we want to be.

MK Sep 2026
"""
import os
import re
import stat
import tempfile

import pytest

import pegaprox.globals as ppg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── #957: the URL the subprocess is told to trust ────────────────────────────

def _target_for(bind, ssl_cert=None, main_port=5000):
    """Call the PRODUCT, not a copy of it.

    An earlier version of this file reimplemented the expression here, which meant
    the test passed against the broken code too - it was only ever checking its own
    arithmetic. The spawner now goes through this helper and so does the test.
    """
    import pegaprox.api.vms as vms
    return vms._ws_subprocess_base_url(main_port, ssl_cert)


@pytest.fixture(autouse=True)
def _restore_bind():
    # getattr with a default on purpose: without it this fixture makes every test
    # in the file depend on the attribute existing, and a counter-proof run against
    # the previous state then dies with AttributeError everywhere instead of showing
    # which behaviour was wrong.
    _missing = object()
    old = getattr(ppg, 'SERVER_BIND_HOST', _missing)
    yield
    if old is _missing:
        if hasattr(ppg, 'SERVER_BIND_HOST'):
            del ppg.SERVER_BIND_HOST
    else:
        ppg.SERVER_BIND_HOST = old


@pytest.mark.parametrize('bind,expected_host', [
    ('', '127.0.0.1'),                 # nothing resolved yet
    ('0.0.0.0', '127.0.0.1'),          # wildcard: loopback is listening
    ('::', '127.0.0.1'),               # dual stack: same
    ('192.168.0.234', '192.168.0.234'),  # the reported case
    ('10.1.2.3', '10.1.2.3'),
])
def test_the_subprocess_is_pointed_at_the_address_we_bound(bind, expected_host):
    ppg.SERVER_BIND_HOST = bind
    assert _target_for(bind) == f'http://{expected_host}:5000'


def test_an_ipv6_bind_is_bracketed():
    """Otherwise the port reads as part of the address and the URL is unusable."""
    ppg.SERVER_BIND_HOST = 'fd00::42'
    assert _target_for('fd00::42') == 'http://[fd00::42]:5000'


def test_the_spawner_reads_globals_through_the_module():
    """`from pegaprox.globals import *` binds a snapshot at import time, and
    main() fills SERVER_BIND_HOST in long afterwards. Reading the star-imported
    copy would always see the empty default, so the lookup has to go through the
    module. Pinned because it looks like a pointless indirection otherwise."""
    import inspect
    import pegaprox.api.vms as vms
    src = inspect.getsource(vms._ws_subprocess_base_url)
    assert 'from pegaprox import globals as _ppg' in src, (
        'reading the star-imported copy would always see the import-time default')
    assert "getattr(_ppg, 'SERVER_BIND_HOST'" in src


# ── #958: where the script lives ─────────────────────────────────────────────

def test_the_script_directory_prefers_config_over_the_shared_temp_dir():
    import inspect
    import pegaprox.api.vms as vms
    src = inspect.getsource(vms.start_ssh_websocket_server)
    m = re.search(r'for _cand in \((.*?)\):', src, re.S)
    assert m, 'the writable-directory fallback is gone'
    candidates = m.group(1)
    assert 'CONFIG_DIR' in candidates and 'gettempdir' in candidates
    assert candidates.index('CONFIG_DIR') < candidates.index('gettempdir'), (
        f'the shared temp dir must be the last resort, not the first choice: {candidates!r}')


def test_a_planted_symlink_is_refused_rather_than_written_through(tmp_path):
    """The concrete reason the location matters. Writing with O_NOFOLLOW turns a
    pre-planted symlink into an error instead of a write into whatever it aims at."""
    target = tmp_path / 'somewhere-else'
    link = tmp_path / '.ssh_ws_server.py'
    os.symlink(target, link)

    with pytest.raises(OSError):
        os.open(str(link), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)

    assert not target.exists(), 'the write went through the symlink'


def test_the_written_script_is_not_readable_by_others(tmp_path):
    p = tmp_path / '.ssh_ws_server.py'
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write('print("hi")\n')
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert not (mode & (stat.S_IRWXG | stat.S_IRWXO)), f'mode {oct(mode)} is too open'


# --- #958 second half: the file we are about to execute ----------------------
#
# O_NOFOLLOW turns a planted *symlink* into an error. It does nothing about a plain
# file somebody else created at that path first, and the tempdir fallback is exactly
# where that is possible. O_TRUNC then happily writes our script into their inode -
# still their file, still theirs to rewrite in the moment between our write and the
# exec.

def test_the_script_is_not_written_into_a_file_somebody_else_put_there():
    """A pre-planted regular file must make the open fail, not get written into."""
    import ast
    src = open(os.path.join(ROOT, 'pegaprox', 'api', 'vms.py'), encoding='utf-8').read()
    tree = ast.parse(src)

    opens = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == 'open'
             and isinstance(n.func.value, ast.Name) and n.func.value.id == 'os'
             and any('script_path' == getattr(a, 'id', None) for a in n.args)]
    assert opens, 'no os.open(script_path, ...) found - has the writer moved?'
    for call in opens:
        flags = ast.unparse(call.args[1])
        assert 'O_EXCL' in flags, (
            f"os.open(script_path) uses {flags} - without O_EXCL a file another user "
            f"pre-created at that path is written into instead of refused")


def test_a_stale_script_from_the_last_run_is_removed_before_the_open():
    """O_EXCL only works if we clear our own leftover first - otherwise every
    restart after the first one fails to start the terminal at all."""
    src = open(os.path.join(ROOT, 'pegaprox', 'api', 'vms.py'), encoding='utf-8').read()
    window = src[src.index('def start_ssh_websocket_server'):]
    window = window[:window.index('_fd = os.open(script_path')]
    assert 'os.unlink(script_path)' in window or 'os.remove(script_path)' in window, \
        'nothing unlinks the previous script, so O_EXCL would break every restart'
