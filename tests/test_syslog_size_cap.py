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


# --- memory: the count cap was a cap on the wrong thing ----------------------

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


def test_large_messages_hit_the_byte_ceiling_long_before_the_count(small_queue):
    """20000 entries x 64 KB is 1.2 GB. The count cap never came near it."""
    big = {'message': 'x' * 60000}

    for _ in range(40):
        small_queue.sl._enqueue_log(dict(big))

    assert small_queue.sl._LOG_QUEUE.qsize() < 40
    assert small_queue.sl._DROPPED > 0


def test_the_bytes_counted_stay_under_the_ceiling(small_queue):
    big = {'message': 'x' * 60000}

    for _ in range(40):
        small_queue.sl._enqueue_log(dict(big))

    assert small_queue.sl._QUEUE_BYTES <= small_queue.sl._QUEUE_MAX_BYTES


def test_draining_gives_the_budget_back(small_queue):
    """Without this the counter only ever rises and ingestion dies permanently."""
    big = {'message': 'x' * 60000}
    for _ in range(40):
        small_queue.sl._enqueue_log(dict(big))

    small_queue.drain()

    assert small_queue.sl._QUEUE_BYTES == 0


def test_ingestion_recovers_after_a_flood(small_queue):
    big = {'message': 'x' * 60000}
    for _ in range(40):
        small_queue.sl._enqueue_log(dict(big))
    small_queue.drain()

    small_queue.sl._enqueue_log(dict(big))

    assert small_queue.sl._LOG_QUEUE.qsize() == 1


def test_ordinary_traffic_is_unaffected(small_queue):
    """A real syslog line is a couple of hundred bytes; 1 MB holds thousands."""
    line = {'message': 'kernel: something happened on eth0'}

    for _ in range(2000):
        small_queue.sl._enqueue_log(dict(line))

    assert small_queue.sl._LOG_QUEUE.qsize() == 2000
