"""The scheduled-actions tick must not rewrite the table around what it ran.

check_schedules() loaded every row, executed the due ones — which blocks on the
cluster API for as long as a VM takes to start or stop — and then handed the
whole pre-tick snapshot to save_schedules(), which is DELETE followed by
re-INSERT. So a schedule an operator created during that window disappeared, and
one they deleted came back and fired again on the next tick.

Same shape as the scheduled_tasks tick, which was fixed with _touch_last_run. MK
"""
import pytest

import pegaprox.api.schedules as sched


def _seed(db, action_id, name, enabled=1, schedule_type='daily', schedule_date=None):
    db.conn.execute(
        "INSERT OR REPLACE INTO scheduled_actions (id, cluster_id, vmid, vm_type, action, "
        "schedule_type, schedule_time, schedule_days, schedule_date, enabled, name) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (action_id, 'cluster_1', 100, 'qemu', 'stop', schedule_type, '02:00', '[]',
         schedule_date, enabled, name))
    db.conn.commit()


def _rows(db):
    cur = db.conn.cursor()
    cur.execute("SELECT id, name, enabled, last_run FROM scheduled_actions ORDER BY id")
    return [dict(r) for r in cur.fetchall()]


def test_recording_a_run_leaves_the_other_rows_alone(db):
    _seed(db, 1, 'keep')
    _seed(db, 2, 'ran')

    sched._record_action_run(2, '2026-09-06 02:00')

    rows = {r['id']: r for r in _rows(db)}
    assert rows[2]['last_run'] == '2026-09-06 02:00'
    assert rows[1]['last_run'] is None
    assert sorted(rows) == [1, 2]


def test_a_schedule_deleted_mid_tick_is_not_resurrected(db):
    """The tick's snapshot still holds the deleted row; writing it back would restore it."""
    _seed(db, 1, 'doomed')
    _seed(db, 2, 'ran')
    snapshot = sched.load_schedules()
    assert len(snapshot['actions']) == 2

    # an operator deletes one while execute_scheduled_action is still blocked on the cluster
    db.conn.execute("DELETE FROM scheduled_actions WHERE id = 1")
    db.conn.commit()

    sched._record_action_run(2, '2026-09-06 02:00')

    assert [r['id'] for r in _rows(db)] == [2]


def test_a_schedule_created_mid_tick_survives(db):
    _seed(db, 1, 'ran')
    sched.load_schedules()

    _seed(db, 2, 'created during the tick')
    sched._record_action_run(1, '2026-09-06 02:00')

    assert [r['name'] for r in _rows(db)] == ['ran', 'created during the tick']


def test_a_once_schedule_is_disabled_with_its_run(db):
    _seed(db, 1, 'one-shot', schedule_type='once', schedule_date='2026-09-06')

    sched._record_action_run(1, '2026-09-06 02:00', disable=True)

    row = _rows(db)[0]
    assert row['enabled'] == 0
    assert row['last_run'] == '2026-09-06 02:00'


def test_writing_a_stale_snapshot_back_is_what_resurrects_a_delete(db):
    """Why the tick must not call save_schedules: this is the mechanism, shown directly.
    save_schedules is DELETE + re-INSERT, so it restores whatever the snapshot still holds."""
    _seed(db, 1, 'doomed')
    _seed(db, 2, 'ran')
    snapshot = sched.load_schedules()

    db.conn.execute("DELETE FROM scheduled_actions WHERE id = 1")
    db.conn.commit()
    sched.save_schedules(snapshot)

    assert [r['id'] for r in _rows(db)] == [1, 2], 'save_schedules no longer round-trips'


def test_the_tick_no_longer_writes_the_whole_table_back(db):
    """save_schedules is a DELETE + re-INSERT; the tick must not be one of its callers."""
    import inspect
    src = inspect.getsource(sched.check_schedules)

    assert 'save_schedules' not in src, 'the tick still rewrites the whole table'
    assert '_record_action_run' in src
