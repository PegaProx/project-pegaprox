"""A schedule table that did not load must not be written back over the real one.

save_schedules() starts with an unconditional `DELETE FROM scheduled_actions` and then
re-inserts whatever snapshot it was handed. load_schedules() answered
`{'actions': [], 'last_id': 0}` for a failed read, so one DB hiccup followed by an
ordinary "create schedule" request rewrote the table to hold that single new row -
every scheduled action in the installation, across every tenant, deleted and committed
by a normal user doing a normal thing.

Aikido ai_pentest 700489000. MK
"""
import pytest

import pegaprox.api.schedules as sched


@pytest.fixture
def broken_read(db, monkeypatch):
    """Only the schedule SELECT fails; writes still work, which is the dangerous part."""
    real_conn = db.conn

    class _Cursor:
        def __init__(self, inner):
            self._inner = inner
        def execute(self, sql, *a, **kw):
            if 'SELECT' in sql.upper() and 'scheduled_actions' in sql:
                raise RuntimeError('database is locked')
            return self._inner.execute(sql, *a, **kw)
        def __getattr__(self, name):
            return getattr(self._inner, name)

    class _Conn:
        def cursor(self):
            return _Cursor(real_conn.cursor())
        def __getattr__(self, name):
            return getattr(real_conn, name)

    class _DB:
        conn = _Conn()
        def __getattr__(self, name):
            return getattr(db, name)

    monkeypatch.setattr(sched, 'get_db', lambda: _DB())
    monkeypatch.setattr(sched.os.path, 'exists', lambda p: False)   # no legacy file
    return db


def _rows(db):
    cur = db.conn.cursor()
    cur.execute('SELECT id FROM scheduled_actions')
    return sorted(r[0] for r in cur.fetchall())


def _seed_schedule(db, sid, cluster_id='cluster_1'):
    db.conn.execute(
        "INSERT INTO scheduled_actions (id, cluster_id, vmid, action, schedule_type, "
        "schedule_time, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)",
        (sid, cluster_id, 100 + sid, 'start', 'daily', '03:00'))
    db.conn.commit()


def test_a_failed_read_is_marked_unavailable(broken_read):
    assert getattr(sched.load_schedules(), 'unavailable', False) is True


def test_a_good_read_is_not_marked_unavailable(db):
    _seed_schedule(db, 1)
    snap = sched.load_schedules()
    assert getattr(snap, 'unavailable', False) is False
    assert [a['id'] for a in snap['actions']] == [1]


def test_an_install_with_no_schedules_is_not_marked_unavailable(db):
    snap = sched.load_schedules()
    assert dict(snap) == {'actions': [], 'last_id': 0}
    assert getattr(snap, 'unavailable', False) is False


def test_the_writer_refuses_a_snapshot_that_never_loaded(db, broken_read):
    """The whole point: the DELETE must not run on the strength of a failed read."""
    _seed_schedule(db, 1)
    _seed_schedule(db, 2)

    snapshot = sched.load_schedules()          # fails -> empty + unavailable
    snapshot['actions'].append({'id': 3, 'cluster_id': 'cluster_1', 'vmid': 999,
                                'action': 'start', 'schedule_type': 'daily',
                                'time': '04:00', 'enabled': True})

    assert sched.save_schedules(snapshot) is False
    assert _rows(db) == [1, 2], "the existing schedules were rewritten away"


def test_the_writer_still_rewrites_a_snapshot_that_did_load(db):
    """The behaviour we must not lose."""
    _seed_schedule(db, 1)

    snapshot = sched.load_schedules()
    snapshot['actions'].append({'id': 2, 'cluster_id': 'cluster_1', 'vmid': 200,
                                'action': 'stop', 'schedule_type': 'daily',
                                'time': '05:00', 'enabled': True})

    assert sched.save_schedules(snapshot) is True
    assert _rows(db) == [1, 2]


def test_the_writer_still_honours_a_genuine_removal(db):
    """Deleting the last schedule must really empty the table."""
    _seed_schedule(db, 1)

    snapshot = sched.load_schedules()
    snapshot['actions'] = []

    assert sched.save_schedules(snapshot) is True
    assert _rows(db) == []
