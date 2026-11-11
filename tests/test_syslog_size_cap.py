"""The syslog receiver is unauthenticated, so something other than time has to bound it.

Anyone who can reach :1514 decides how much arrives, and retention was purely a time
window - 30 days of whatever you care to send. syslog.db lives in config/, beside the main
encrypted database and the master key, so filling that volume takes the installation down,
not just the log viewer.

No VACUUM after the delete on purpose: reclaiming the pages means copying a multi-gigabyte
file on a server that is by then short of disk, which is the worst possible moment. The
freed pages are reused, so the file stops GROWING, which is the property that matters.

Aikido ai_pentest 700489260. MK
"""
import datetime
import os

import pytest

import pegaprox.background.syslog_server as sl


@pytest.fixture
def syslog_db(tmp_path, monkeypatch):
    monkeypatch.setattr(sl, 'DB_FILE', str(tmp_path / 'syslog.db'))
    conn = sl._open_db()
    conn.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "timestamp TEXT, hostname TEXT, severity TEXT, message TEXT)")
    conn.commit()
    conn.close()
    return str(tmp_path / 'syslog.db')


def _fill(rows, size=1000, age_days=0):
    when = (datetime.datetime.now() - datetime.timedelta(days=age_days)).isoformat()
    conn = sl._open_db()
    conn.executemany(
        "INSERT INTO logs (timestamp, hostname, severity, message) VALUES (?,?,?,?)",
        [(when, 'h', 'info', 'x' * size) for _ in range(rows)])
    conn.commit()
    conn.close()


def _count():
    conn = sl._open_db()
    n = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    conn.close()
    return n


def _settings(monkeypatch, **kw):
    import pegaprox.api.helpers as helpers
    base = {'syslog_retention_days': 3650}
    base.update(kw)
    monkeypatch.setattr(helpers, 'load_server_settings', lambda: base)


def test_the_cap_drops_the_oldest_rows(syslog_db, monkeypatch):
    """Retention alone would keep all of these - they are one day old."""
    _fill(20000)
    _settings(monkeypatch, syslog_max_db_mb=8)

    before = _count()
    sl._prune_old_logs()

    assert _count() < before


def test_a_database_inside_the_cap_is_left_alone(syslog_db, monkeypatch):
    _fill(500)
    _settings(monkeypatch, syslog_max_db_mb=2048)

    sl._prune_old_logs()

    assert _count() == 500


def test_the_cap_can_be_turned_off(syslog_db, monkeypatch):
    """An operator with a dedicated volume may not want it."""
    _fill(20000)
    _settings(monkeypatch, syslog_max_db_mb=0)

    sl._prune_old_logs()

    assert _count() == 20000


def test_the_cap_does_not_empty_the_table(syslog_db, monkeypatch):
    """Dropping everything would be its own kind of outage - the log viewer goes blank.
    Below a thousand rows there is nothing worth deleting and the size is bloat, not data."""
    _fill(20000)
    _settings(monkeypatch, syslog_max_db_mb=1)

    sl._prune_old_logs()

    assert _count() >= 1000


def test_time_based_retention_still_works(syslog_db, monkeypatch):
    """The invariant: the original bound must survive this."""
    _fill(100, age_days=60)
    _fill(100, age_days=0)
    _settings(monkeypatch, syslog_retention_days=30, syslog_max_db_mb=0)

    sl._prune_old_logs()

    assert _count() == 100


# --- the schema the receiver really creates: six indexes and FTS5 ---------------
#
# The cap measured the file, which never shrinks without a VACUUM. Once the file had been
# over the cap, every hourly run deleted about 70% of the table again and the history was
# down to a few hundred rows within hours. On the bare table above a delete gives its pages
# back at once; with the FTS5 index a delete is a marker in a new segment and the space only
# comes back after a merge, so these run on what _init_db builds.

_CAP_MB = 5


def _words(n, seed):
    import random
    rnd = random.Random(seed)
    letters = 'abcdefghijklmnopqrstuvwxyz'
    return [''.join(rnd.choice(letters) for _ in range(rnd.randint(3, 10))) for _ in range(n)]


_VOCAB = _words(4000, 7)


def _lines(rows, seed):
    """Rows as the listeners queue them, with words for the FTS5 index to hold."""
    import random
    rnd = random.Random(seed)
    now = datetime.datetime.now().isoformat()
    return [(now, '192.0.2.%d' % (i % 200), 'pve%d' % (i % 200), 1, 6, 'info',
             ' '.join(rnd.choices(_VOCAB, k=20)), 'UDP') for i in range(rows)]


def _in_use():
    """The pages that hold data; the free ones in the file get reused."""
    conn = sl._open_db()
    try:
        pages, free, size = (int(conn.execute(f'PRAGMA {p}').fetchone()[0])
                             for p in ('page_count', 'freelist_count', 'page_size'))
        return (pages - free) * size
    finally:
        conn.close()


@pytest.fixture(scope='module')
def _over_the_cap(tmp_path_factory):
    """One syslog.db about four times the cap, built once and copied for each test."""
    path = str(tmp_path_factory.mktemp('syslog') / 'syslog.db')
    saved = sl.DB_FILE
    sl.DB_FILE = path
    try:
        sl._init_db()
        for k in range(24):
            sl._flush_batch(_lines(1000, k))
    finally:
        sl.DB_FILE = saved
    return path


@pytest.fixture
def full_db(_over_the_cap, tmp_path, monkeypatch):
    import shutil
    path = str(tmp_path / 'syslog.db')
    for suffix in ('', '-wal', '-shm'):
        if os.path.exists(_over_the_cap + suffix):
            shutil.copy(_over_the_cap + suffix, path + suffix)
    monkeypatch.setattr(sl, 'DB_FILE', path)
    conn = sl._open_db()
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    finally:
        conn.close()
    assert {'logs_fts', 'logs_ad', 'idx_logs_timestamp_id'} <= names
    assert _in_use() > 3 * _CAP_MB * 1024 * 1024
    _settings(monkeypatch, syslog_max_db_mb=_CAP_MB)
    return path


def test_after_a_prune_the_data_fits_in_the_cap(full_db):
    """And it keeps about what fits, rather than whatever the deletes happen to leave."""
    fits = _CAP_MB * 1024 * 1024 / (_in_use() / _count())

    sl._prune_old_logs()

    assert _in_use() <= _CAP_MB * 1024 * 1024, \
        f'{_in_use() // 1024} KB in use after the prune, the cap is {_CAP_MB} MB'
    assert _count() >= 0.7 * fits, f'{_count()} rows kept, about {int(fits)} fit in the cap'


def test_a_second_prune_with_nothing_new_deletes_nothing(full_db):
    """The file is still over the cap, and it will stay there."""
    sl._prune_old_logs()
    kept = _count()
    assert os.path.getsize(full_db) > _CAP_MB * 1024 * 1024

    sl._prune_old_logs()

    assert _count() == kept, f'the second prune dropped {kept - _count()} of {kept} rows'


def test_quiet_hours_after_a_flood_keep_the_history(full_db):
    """One flood over the cap, then ordinary traffic far below it, an hour at a time."""
    sl._prune_old_logs()
    kept = _count()

    for hour in range(6):
        sl._flush_batch(_lines(150, 100 + hour))
        sl._prune_old_logs()
        assert _count() >= 0.8 * kept, \
            f'{_count()} rows left after hour {hour}, {kept} after the flood'
        assert _in_use() <= _CAP_MB * 1024 * 1024


# --- memory: the count cap was a cap on the wrong thing ----------------------

def _row(message):
    """An entry as the UDP and TCP listeners queue it: the row _flush_batch inserts.
    (#1015) These tests fed dicts, which nothing in the receiver ever queues - the byte
    count worked on those and on nothing real, so they passed while the ceiling never
    fired."""
    return (datetime.datetime.now().isoformat(), '192.0.2.10', 'pve1', 1, 6, 'info',
            message, 'TCP')


class _QueueHarness:
    """Reload the module with a small byte ceiling, and put it back afterwards."""

    def __init__(self, monkeypatch, mb):
        import importlib
        monkeypatch.setenv('PEGAPROX_SYSLOG_QUEUE_MB', str(mb))
        importlib.reload(sl)
        self.sl = sl

    def drain(self):
        import queue as q
        batch = []
        while True:
            try:
                batch.append(self.sl._LOG_QUEUE.get_nowait())
            except q.Empty:
                break
        self.sl._release_queue_bytes(batch)
        return batch


@pytest.fixture
def small_queue(monkeypatch):
    h = _QueueHarness(monkeypatch, 1)          # 1 MB
    yield h
    import importlib
    monkeypatch.delenv('PEGAPROX_SYSLOG_QUEUE_MB', raising=False)
    importlib.reload(sl)


@pytest.mark.parametrize('raw', ['64M', 'lots', '1.5', '', ' '])
def test_a_queue_size_that_is_no_whole_number_does_not_stop_the_start(tmp_path, raw):
    """PEGAPROX_SYSLOG_QUEUE_MB went through int() at import, and api/reports.py imports
    this module, so '64M' kept PegaProx from starting. It means 64 now."""
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PEGAPROX_SYSLOG_QUEUE_MB=raw,
               PEGAPROX_CONFIG_DIR=str(tmp_path / 'config'), PEGAPROX_LOG_DIR=str(tmp_path / 'logs'))
    run = subprocess.run([sys.executable, '-c', 'import pegaprox.background.syslog_server as sl; '
                          'print(sl._QUEUE_MAX_BYTES)'],
                         cwd=root, env=env, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    assert run.stdout.split()[-1] == str(64 * 1024 * 1024)


def test_large_messages_hit_the_byte_ceiling_long_before_the_count(small_queue):
    """20000 entries x 64 KB is 1.2 GB. The count cap never came near it."""
    big = _row('x' * 60000)

    for _ in range(40):
        small_queue.sl._enqueue_log(big)

    assert small_queue.sl._LOG_QUEUE.qsize() < 40
    assert small_queue.sl._DROPPED > 0


def test_the_bytes_counted_stay_under_the_ceiling(small_queue):
    big = _row('x' * 60000)

    for _ in range(40):
        small_queue.sl._enqueue_log(big)

    assert small_queue.sl._QUEUE_BYTES <= small_queue.sl._QUEUE_MAX_BYTES


def test_draining_gives_the_budget_back(small_queue):
    """Without this the counter only ever rises and ingestion dies permanently."""
    big = _row('x' * 60000)
    for _ in range(40):
        small_queue.sl._enqueue_log(big)

    small_queue.drain()

    assert small_queue.sl._QUEUE_BYTES == 0


def test_ingestion_recovers_after_a_flood(small_queue):
    big = _row('x' * 60000)
    for _ in range(40):
        small_queue.sl._enqueue_log(big)
    small_queue.drain()

    small_queue.sl._enqueue_log(big)

    assert small_queue.sl._LOG_QUEUE.qsize() == 1


def test_text_outside_ascii_is_charged_what_it_holds(small_queue):
    """len() counts characters. An emoji is one of them and four bytes in memory, so a
    flood of them filled four times the ceiling (#1015)."""
    import sys
    big = _row('\U0001F600' * 15000)            # 60 KB on the wire and in memory

    for _ in range(40):
        small_queue.sl._enqueue_log(big)

    held = sum(sys.getsizeof(e[6]) for e in small_queue.drain())
    assert held <= small_queue.sl._QUEUE_MAX_BYTES, \
        f'{held // 1024} KB of messages queued under a {small_queue.sl._QUEUE_MAX_BYTES // 1024} KB ceiling'


def test_ordinary_text_outside_ascii_is_unaffected(small_queue):
    line = _row('Gerät eth0 läuft wieder')

    for _ in range(2000):
        small_queue.sl._enqueue_log(line)

    assert small_queue.sl._LOG_QUEUE.qsize() == 2000


def test_ordinary_traffic_is_unaffected(small_queue):
    """A real syslog line is a couple of hundred bytes; 1 MB holds thousands."""
    line = _row('kernel: something happened on eth0')

    for _ in range(2000):
        small_queue.sl._enqueue_log(line)

    assert small_queue.sl._LOG_QUEUE.qsize() == 2000


def test_the_listener_entries_are_charged_what_they_hold(small_queue):
    """The real thing: lines through the TCP listener on loopback. 100 lines of 30 KB are
    3 MB, three times the 1 MB ceiling; charged a flat 200 bytes each they were 20 KB and
    every one of them was queued (#1015)."""
    import socket
    import time
    import gevent
    sl_ = small_queue.sl
    listener = gevent.spawn(sl_._tcp_listener, '127.0.0.1', 0)
    try:
        end = time.monotonic() + 5
        while sl_._tcp_sock is None and time.monotonic() < end:
            gevent.sleep(0.01)
        port = sl_._tcp_sock.getsockname()[1]
        line = b'<14>Oct  6 10:00:00 pve1 app: ' + b'x' * 30000 + b'\n'
        c = socket.create_connection(('127.0.0.1', port), timeout=5)
        for _ in range(100):
            c.sendall(line)
        c.close()
        while sl_._LOG_QUEUE.qsize() + sl_._DROPPED < 100 and time.monotonic() < end + 5:
            gevent.sleep(0.01)

        queued = sl_._LOG_QUEUE.qsize()
        assert sl_._LOG_QUEUE.qsize() + sl_._DROPPED == 100
        assert queued < 40, f'{queued} lines of 30 KB queued under a 1 MB ceiling'
        assert sl_._QUEUE_BYTES <= sl_._QUEUE_MAX_BYTES
        assert sl_._QUEUE_BYTES >= queued * 30000
    finally:
        sl_._stop_event.set()
        try:
            sl_._tcp_sock.close()
        except Exception:
            pass
        listener.kill()
        small_queue.drain()
