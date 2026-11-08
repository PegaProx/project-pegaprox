"""Old drift events are pruned, but nothing anyone acts on or audits.

drift_events kept every row it ever got, and a fleet-wide change at a few thousand guests
writes thousands per scan. The scanner thread now prunes, at its start and then once a day:
'resolved' and 'superseded' rows past PEGAPROX_DRIFT_EVENT_RETENTION_DAYS (default 365, held
to 90..3650, 0 prunes nothing), and per cluster whatever of them is over
PEGAPROX_DRIFT_EVENT_CAP (default 200000), the oldest first and superseded rows before
resolved ones. An open or acknowledged row, an incident an admin confirmed and a deviation
an approved change plan names stay whatever their age. Off the hub, in chunks with a pause
in between, one log line, no alert and no audit entry.
MK Oct 2026
"""
import logging
import types
from datetime import datetime, timedelta

import gevent
import pytest

from pegaprox.api import drift
from pegaprox.core import dbcrypto

NOW = datetime(2026, 10, 21, 12, 0, 0)


class _Pinned(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


@pytest.fixture
def pinned(monkeypatch):
    monkeypatch.setattr(drift, 'datetime', _Pinned)
    for name in ('PEGAPROX_DRIFT_EVENT_RETENTION_DAYS', 'PEGAPROX_DRIFT_EVENT_CAP'):
        monkeypatch.delenv(name, raising=False)
    # The scanner thread that the app of an earlier test in this process started collapses
    # and prunes at its start, on whatever database is current then. On this test's it took
    # the rows the test was about to count (2 runs in 6 with an api test right before this
    # file). Here they run for the test only, its own loop included.
    me = gevent.getcurrent()
    for name in ('_prune_events', '_collapse_repeats'):
        real = getattr(drift, name)
        monkeypatch.setattr(drift, name, lambda real=real: real() if gevent.getcurrent() is me else 0)


def _add(db, at, status='resolved', category='deviation', change_id=None, cluster='c_a', scope='local'):
    detected = (NOW - at).isoformat() if isinstance(at, timedelta) else at
    cur = db.conn.execute(
        "INSERT INTO drift_events (cluster_id, kind, scope, severity, summary, diff, detected_at, status, "
        "category, change_id) VALUES (?, 'storage', ?, 'warning', 's', '[]', ?, ?, ?, ?)",
        (cluster, scope, detected, status, category, change_id))
    db.conn.commit()
    return cur.lastrowid


def _ids(db):
    return {r[0] for r in db.conn.execute('SELECT id FROM drift_events').fetchall()}


def _days(n):
    return timedelta(days=n)


# -- what goes and what stays --------------------------------------------------------------------

def test_what_people_act_on_or_audit_stays_at_any_age(db, pinned):
    ancient = '2001-01-01T00:00:00'
    keep = [_add(db, ancient, status='open'),
            _add(db, ancient, status='acknowledged'),
            _add(db, ancient, status='resolved', category='incident'),
            _add(db, ancient, status='superseded', category='incident'),
            _add(db, ancient, status='resolved', change_id='chg-1'),
            _add(db, ancient, status='superseded', change_id='chg-2'),
            _add(db, ancient, status='open', category='policy_violation')]
    old = [_add(db, ancient, status='resolved'), _add(db, ancient, status='superseded'),
           _add(db, _days(400), status='resolved', category='policy_violation')]
    assert drift._prune_events() == len(old)
    assert _ids(db) == set(keep)


def test_the_retention_ends_exactly_at_its_day(db, pinned, monkeypatch):
    cutoff = NOW - _days(365)
    at_cutoff = _add(db, cutoff.isoformat())
    just_before = _add(db, (cutoff - timedelta(microseconds=1)).isoformat(), status='superseded')
    young = _add(db, _days(364))
    assert drift._prune_events() == 1
    assert _ids(db) == {at_cutoff, young}
    assert just_before not in _ids(db)


@pytest.mark.parametrize('raw,days', [('30', 90), ('120', 120), ('99999', 3650), ('soon', 365), ('', 365),
                                      ('-5', 90)])
def test_the_retention_is_held_to_its_range(db, pinned, monkeypatch, raw, days):
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_RETENTION_DAYS', raw)
    inside = _add(db, _days(days) - timedelta(minutes=1))
    outside = _add(db, _days(days) + timedelta(minutes=1))
    assert drift._prune_events() == 1
    assert _ids(db) == {inside} and outside not in _ids(db)


def test_zero_days_prunes_nothing(db, pinned, monkeypatch):
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_RETENTION_DAYS', '0')
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_CAP', '1')
    rows = {_add(db, '2001-01-01T00:00:00', status=s) for s in ('resolved', 'superseded') for _ in range(3)}
    assert drift._prune_events() == 0
    assert _ids(db) == rows


def test_a_cluster_no_longer_configured_follows_the_same_rules(db, pinned):
    """No shortcut for a cluster that is gone: added back, it finds its history."""
    gone_old = _add(db, _days(500), cluster='gone')
    gone_young = _add(db, _days(10), cluster='gone')
    gone_open = _add(db, _days(500), status='open', cluster='gone')
    assert drift._prune_events() == 1
    assert _ids(db) == {gone_young, gone_open} and gone_old not in _ids(db)


# -- the cap per cluster ---------------------------------------------------------------------------

def test_over_the_cap_the_oldest_superseded_go_first(db, pinned, monkeypatch):
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_CAP', '5')
    resolved = [_add(db, _days(d)) for d in (40, 30, 20, 10)]
    superseded = [_add(db, _days(d), status='superseded') for d in (35, 25, 15, 5)]
    protected = [_add(db, _days(50), status='open'), _add(db, _days(50), status='acknowledged'),
                 _add(db, _days(50), category='incident'), _add(db, _days(50), change_id='chg')]
    other = [_add(db, _days(d), cluster='c_b', status='superseded') for d in (45, 44, 43)]
    assert drift._prune_events() == 3
    # 8 prunable rows on c_a, 5 stay: the four resolved and the newest superseded one;
    # what is protected does not count and stays, and c_b is under the cap
    assert _ids(db) == set(resolved) | {superseded[-1]} | set(protected) | set(other)


def test_past_the_superseded_the_oldest_resolved_go(db, pinned, monkeypatch):
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_CAP', '3')
    resolved = [_add(db, _days(d)) for d in (40, 30, 20, 10)]
    superseded = [_add(db, _days(d), status='superseded') for d in (2, 1)]
    assert drift._prune_events() == 3
    assert _ids(db) == set(resolved[1:])
    assert not set(superseded) & _ids(db)


@pytest.mark.parametrize('raw', ['0', '-1'])
def test_a_cap_of_zero_is_no_cap(db, pinned, monkeypatch, raw):
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_CAP', raw)
    rows = {_add(db, _days(d)) for d in range(1, 30)}
    assert drift._prune_events() == 0
    assert _ids(db) == rows


def test_the_defaults_keep_a_year_and_two_hundred_thousand(db, pinned):
    assert (drift._event_retention_days(), drift._event_cap()) == (365, 200000)


# -- how it runs ----------------------------------------------------------------------------------

def _drift_time(monkeypatch, sleep, now=lambda: 0.0):
    """drift's clock and sleep as the test has them. A scanner thread that the app of an
    earlier test in this process started reads the same module: it sleeps for real and
    nothing here sees it (a sleep that returns at once would have it spin and never let
    this test go on)."""
    me = gevent.getcurrent()

    def sleep_here(seconds):
        if gevent.getcurrent() is not me:
            gevent.sleep(seconds)
            return
        sleep(seconds)
    monkeypatch.setattr(drift, 'time', types.SimpleNamespace(time=now, sleep=sleep_here))


def test_it_deletes_in_chunks_and_lets_other_writers_in_between(db, pinned, monkeypatch):
    """A chunk per transaction and a pause after each: another writer waits one chunk at
    most, and what it changed in between wins (a row acknowledged meanwhile stays)."""
    old = [_add(db, _days(400)) for _ in range(5)]
    monkeypatch.setattr(drift, '_PRUNE_CHUNK', 2)
    commits, paused = [], []
    real = dbcrypto.run_off_hub

    def off_hub(work, path, commit=False):
        out = real(work, path, commit=commit)
        commits.append(commit)
        return out
    monkeypatch.setattr(dbcrypto, 'run_off_hub', off_hub)

    def sleep(seconds):
        paused.append(seconds)
        if len(paused) == 1:
            db.conn.execute("UPDATE drift_events SET status='acknowledged', acknowledged_by='root' WHERE id=?",
                            (old[-1],))
            db.conn.commit()
    _drift_time(monkeypatch, sleep)

    assert drift._prune_events() == 4
    assert paused == [drift._PRUNE_PAUSE, drift._PRUNE_PAUSE]
    # the read, three chunks, the cap's read
    assert commits == [False, True, True, True, False]
    assert _ids(db) == {old[-1]}


class _Plans:
    """A connection that notes the query plan of every DELETE run on it."""

    def __init__(self, conn, plans):
        self._conn, self._plans = conn, plans

    def cursor(self):
        return _Plans(self._conn.cursor(), self._plans)

    def execute(self, sql, args=()):
        if sql.lstrip().upper().startswith('DELETE'):
            self._plans.append([r[3] for r in self._conn.execute('EXPLAIN QUERY PLAN ' + sql, args)])
        return self._conn.execute(sql, args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_a_chunk_finds_its_rows_by_their_ids(db, pinned, monkeypatch):
    """MK Oct 2026 - with `status IN (...)` next to the ids, SQLite took the status index and
    went through every resolved and superseded row for each chunk: 130 ms a chunk of 1000 at
    300k rows, and the writes the hub makes on its own connection waited behind it (the hub
    stood still up to 1.3 s). The ids are the primary key; the status is checked on the rows
    they find. (Past about 20 ids SQLite takes the index, whatever the size of the table.)"""
    for _ in range(15):
        _add(db, _days(400))
        _add(db, _days(400), status='superseded')
    plans, real = [], dbcrypto.run_off_hub
    monkeypatch.setattr(dbcrypto, 'run_off_hub',
                        lambda work, path, commit=False: real(lambda conn: work(_Plans(conn, plans)), path, commit))
    assert drift._prune_events() == 30
    assert plans and all(any('INTEGER PRIMARY KEY' in step for step in plan) for plan in plans), plans
    assert not [plan for plan in plans if any('idx_drift_events' in step for step in plan)], plans


def test_the_age_index_is_there_before_the_first_run(db, pinned, monkeypatch):
    """MK Oct 2026 - the first run used to make it, and building it over a few hundred
    thousand rows held the database for seconds while the hub waited to write. The schema
    pass makes it now, before anything is served, and the prune only reads and deletes."""
    def indexes():
        return {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='index' "
                                              "AND tbl_name='drift_events'").fetchall()}
    assert 'idx_drift_events_age' in indexes()
    _add(db, _days(400))
    made, real = [], dbcrypto.run_off_hub

    def noting(work, path, commit=False):
        def traced(conn):
            conn.set_trace_callback(lambda sql: made.append(sql) if 'CREATE' in sql.upper() else None)
            return work(conn)
        return real(traced, path, commit)
    monkeypatch.setattr(dbcrypto, 'run_off_hub', noting)
    assert drift._prune_events() == 1
    assert made == []


def test_one_log_line_and_nothing_when_nothing_went(db, pinned, monkeypatch, caplog):
    monkeypatch.setenv('PEGAPROX_DRIFT_EVENT_CAP', '1')
    caplog.set_level(logging.INFO)
    for d in (400, 401, 3, 2):
        _add(db, _days(d))
    assert drift._prune_events() == 3
    said = [r.getMessage() for r in caplog.records if 'drift event' in r.getMessage()]
    assert said == ['[drift] 3 resolved or superseded drift event(s) pruned: 2 older than 365 days, '
                    '1 over the 1 kept per cluster']
    caplog.clear()
    assert drift._prune_events() == 0
    assert not [r for r in caplog.records if 'drift event' in r.getMessage()]


def test_a_failure_is_logged_and_nothing_else_happens(db, pinned, monkeypatch, caplog):
    rows = {_add(db, _days(400)) for _ in range(3)}

    def broken(work, path, commit=False):
        raise RuntimeError('disk I/O error')
    monkeypatch.setattr(dbcrypto, 'run_off_hub', broken)
    caplog.set_level(logging.INFO)
    assert drift._prune_events() == 0
    said = [r for r in caplog.records if 'pruning old drift events' in r.getMessage()]
    assert len(said) == 1 and said[0].levelno == logging.WARNING and 'disk I/O error' in said[0].getMessage()
    assert _ids(db) == rows


def _loop(monkeypatch, clock, rounds):
    """The scanner thread for `rounds` rounds of its wait, the clock moved by `clock`."""
    seen = {'round': 0}

    def sleep(seconds):
        if seconds == 1:
            seen['round'] += 1
            if seen['round'] >= rounds:
                drift._scanner_running = False
    monkeypatch.setattr(drift, '_scanner_running', True)
    monkeypatch.setattr(drift, 'SCAN_INTERVAL', 1)
    monkeypatch.setattr(drift, 'cluster_managers', {})
    _drift_time(monkeypatch, sleep, now=lambda: clock(seen['round']))
    drift._scanner_loop()


def test_the_scanner_prunes_at_its_start_and_then_once_a_day(db, pinned, monkeypatch):
    runs = []
    monkeypatch.setattr(drift, '_prune_events', lambda: runs.append(1) or 0)
    # rounds 0-3 within the first day, round 4 a day later, round 5 an hour after that
    hours = [0, 6, 12, 18, 24, 25]
    _loop(monkeypatch, lambda r: 1_000_000.0 + hours[min(r, 5)] * 3600, rounds=6)
    assert len(runs) == 2


def test_the_scanner_prunes_on_a_standby_too(db, pinned, monkeypatch):
    from pegaprox.core import ha
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    old, young = _add(db, _days(400)), _add(db, _days(4))
    _loop(monkeypatch, lambda r: 0.0, rounds=1)
    assert _ids(db) == {young} and old not in _ids(db)
