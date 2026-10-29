"""#1134 - two plugin syncs into the same folder at the same time each leave whole files.

sync_plugins.py writes every file to a temp file next to it and renames that over the
old one. Both runs used the same temp name, so the second run deleted the first one's
temp file and wrote its own under that name: the first run then renamed the second
one's half-written file into place and reported the plugin installed while it held a
truncated file, and the second run's rename found nothing and failed the plugin.

The two runs are interleaved by hand at exactly that point, no timing involved: run A
has written its temp file in full, run B has written half of its own, then A renames.
"""
import os
import threading
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNC = os.path.join(ROOT, 'packaging', 'plugins', 'sync_plugins.py')
WAIT = 10


def _sync_module():
    # compiled by hand: an import would leave a __pycache__ in packaging/plugins
    mod = types.ModuleType('pp_sync_plugins_concurrent_1134')
    mod.__file__ = SYNC
    with open(SYNC, encoding='utf-8') as fh:
        exec(compile(fh.read(), SYNC, 'exec'), mod.__dict__)
    return mod


def test_two_syncs_at_once_leave_every_file_whole(tmp_path):
    source = tmp_path / 'share' / 'plugins'
    (source / 'status_page').mkdir(parents=True)
    body = bytes(range(256)) * 512          # 128 KiB, so half of it is a real cut
    (source / 'status_page' / 'plugin.py').write_bytes(body)
    target = tmp_path / 'var-lib' / 'plugins'

    mod = _sync_module()
    real_copy = mod.shutil.copyfileobj
    a_written = threading.Event()
    b_half = threading.Event()
    a_done = threading.Event()
    roles = {}

    def interleaved_copy(src, out, *args, **kwargs):
        role = roles.get(threading.get_ident())
        if role == 'a':
            real_copy(src, out, *args, **kwargs)
            out.flush()
            a_written.set()
            assert b_half.wait(WAIT), 'run B never reached its copy'
        elif role == 'b':
            data = src.read()
            out.write(data[:len(data) // 2])
            out.flush()
            b_half.set()
            assert a_done.wait(WAIT), 'run A never finished'
            out.write(data[len(data) // 2:])
        else:
            real_copy(src, out, *args, **kwargs)

    mod.shutil = types.SimpleNamespace(copyfileobj=interleaved_copy)
    failed, said = {}, {'a': [], 'b': []}
    seen_by_a = {}

    def run(role, after=None):
        roles[threading.get_ident()] = role
        try:
            failed[role] = mod.sync(str(source), str(target), say=said[role].append)
            if role == 'a':
                # what A leaves behind when it says "installed", before B goes on
                seen_by_a['plugin.py'] = (target / 'status_page' / 'plugin.py').read_bytes()
        finally:
            if after:
                after.set()

    a = threading.Thread(target=run, args=('a', a_done))
    a.start()
    assert a_written.wait(WAIT), 'run A never reached its copy'
    b = threading.Thread(target=run, args=('b',))
    b.start()
    a.join(WAIT)
    b.join(WAIT)
    assert not a.is_alive() and not b.is_alive(), 'a sync run hung'

    assert len(seen_by_a['plugin.py']) == len(body), \
        f'run A put {len(seen_by_a["plugin.py"])} of {len(body)} bytes in place: ' \
        'the other run\'s half-written temp file'
    assert (target / 'status_page' / 'plugin.py').read_bytes() == body
    assert failed == {'a': [], 'b': []}, f'a sync run failed the plugin: {said}'
    # nothing either run wrote on the side is left behind
    assert sorted(os.listdir(target / 'status_page')) == ['plugin.py']


def test_a_killed_runs_temp_file_goes_and_a_running_ones_stays(tmp_path):
    source = tmp_path / 'share' / 'plugins'
    (source / 'status_page').mkdir(parents=True)
    (source / 'status_page' / 'plugin.py').write_bytes(b'code\n')
    target = tmp_path / 'var-lib' / 'plugins'
    (target / 'status_page').mkdir(parents=True)
    # a run killed two hours ago, with this script's naming and with the older fixed name
    dead = [target / 'status_page' / '.plugin.py.0123456789ab.sync-tmp',
            target / 'status_page' / '.plugin.py.sync-tmp']
    for path in dead:
        path.write_bytes(b'half')
        old = path.stat().st_mtime - 2 * 3600
        os.utime(path, (old, old))
    # another run writing its temp file right now
    running = target / 'status_page' / '.plugin.py.ba9876543210.sync-tmp'
    running.write_bytes(b'in progress')
    # an old file the plugin wrote itself that only looks like one: no shipped file behind it
    own = target / 'status_page' / '.notes.sync-tmp'
    own.write_bytes(b'plugin data')
    old = own.stat().st_mtime - 2 * 3600
    os.utime(own, (old, old))

    assert _sync_module().sync(str(source), str(target), say=lambda msg: None) == []

    assert (target / 'status_page' / 'plugin.py').read_bytes() == b'code\n'
    assert not any(path.exists() for path in dead), 'a dead run\'s temp file stayed'
    assert running.read_bytes() == b'in progress', 'a running sync\'s temp file was touched'
    assert own.exists() and own.read_bytes() == b'plugin data', 'a file the plugin wrote was removed'
