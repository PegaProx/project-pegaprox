"""The piles of repeated open deviations are collapsed when the drift thread starts.

Until the scan looked for an open row with the same diff, every pass wrote an unchanged
deviation again, removals included, and every installation still holds that pile. When the
scanner thread starts it keeps the oldest open deviation of each cluster, kind, scope and diff
text and supersedes the rest, on a standby too: drift_events is a table of each instance, so
nothing synced may say it is done. Whatever is no such repeat stays as it is.

The thread is run up to its first sleep, with the fake PVE and fixtures of
test_drift_more_kinds.py. MK Oct 2026
"""
import ast
import json
import logging
import os
import time
import types

import pytest

from pegaprox.api import drift
from pegaprox.core import dbcrypto, ha as ha_core

from test_drift_more_kinds import CL, pve, _events  # noqa: F401
from test_ha_api import ha_env, _standby_of_active  # noqa: F401 (ha_env is a fixture)


@pytest.fixture
def active(monkeypatch):
    monkeypatch.setattr(ha_core, 'is_active', lambda: True)


def _start(monkeypatch):
    """What start_scanner's thread does, up to the first second of its wait."""
    def sleep(seconds):
        if seconds == 1:
            drift._scanner_running = False
    monkeypatch.setattr(drift, '_scanner_running', True)
    monkeypatch.setattr(drift, 'time', types.SimpleNamespace(time=time.time, sleep=sleep))
    drift._scanner_loop()


def _old_scans(monkeypatch, times):
    """Scans the way they ran before: no open row counted as the same."""
    with monkeypatch.context() as m:
        m.setattr(drift, '_open_deviation_diffs', lambda cluster_id: set())
        for _ in range(times):
            drift._scan_cluster(CL)


def _drift_and_pile(pve, monkeypatch, times=4):
    """A changed cluster option and a removed backup job, each written `times` times."""
    drift._scan_cluster(CL, autobaseline=True)
    pve.routes['/cluster/options']['keyboard'] = 'de'
    pve.routes['/cluster/backup'] = []
    _old_scans(monkeypatch, times)


def _rows(db, cluster=None):
    q, args = 'SELECT id, cluster_id, kind, scope, category, status FROM drift_events', []
    if cluster:
        q, args = q + ' WHERE cluster_id=?', [cluster]
    return {r['id']: dict(r) for r in db.conn.execute(q + ' ORDER BY id', args).fetchall()}


def _open_ids(db):
    return [r[0] for r in db.conn.execute(
        "SELECT id FROM drift_events WHERE cluster_id=? AND status='open' ORDER BY id", (CL,)).fetchall()]


def _first_of_each(db):
    return sorted(r[0] for r in db.conn.execute(
        'SELECT MIN(id) FROM drift_events WHERE cluster_id=? GROUP BY kind, scope', (CL,)).fetchall())


def _add(db, cluster, kind, scope, diff, status='open', category='deviation'):
    """`diff` as the scan stores it, or a str taken as the stored text itself."""
    cur = db.conn.execute(
        "INSERT INTO drift_events (cluster_id, kind, scope, severity, summary, diff, detected_at, status, "
        "category) VALUES (?, ?, ?, 'warning', 's', ?, '2026-10-01T00:00:00', ?, ?)",
        (cluster, kind, scope, diff if isinstance(diff, str) else json.dumps(diff), status, category))
    db.conn.commit()
    return cur.lastrowid


def _count(db, table):
    try:
        return db.conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
    except Exception:
        return None


# -- the pile ----------------------------------------------------------------------------------

def test_the_repeats_collapse_to_the_oldest(pve, db, active, monkeypatch, caplog):
    _drift_and_pile(pve, monkeypatch)
    assert len(_open_ids(db)) == 8
    oldest = _first_of_each(db)
    sent, audit = len(pve.sent), _count(db, 'audit_log')
    pushed = []
    from pegaprox.background import alerts
    alerts._notification_handlers.append(pushed.append)
    monkeypatch.setattr(drift, '_REPEAT_CHUNK', 4, raising=False)     # two chunks
    caplog.set_level(logging.INFO)

    _start(monkeypatch)

    assert _open_ids(db) == oldest
    rows = _rows(db, CL)
    assert sorted(i for i, r in rows.items() if r['status'] == 'superseded') == \
        sorted(set(rows) - set(oldest))
    # nothing new was found: no alert, no push, no audit entry per row
    assert len(pve.sent) == sent and pushed == []
    assert _count(db, 'audit_log') == audit
    said = [r.getMessage() for r in caplog.records if 'repeated open deviation' in r.getMessage()]
    assert said == ['[drift] 6 repeated open deviation(s) superseded, the oldest of each stays open']


def test_the_scan_afterwards_finds_the_kept_rows_still_open(pve, db, active, monkeypatch):
    _drift_and_pile(pve, monkeypatch)
    _start(monkeypatch)
    sent = len(pve.sent)
    res = drift._scan_cluster(CL)
    assert res['events_count'] == 0 and res['already_open'] == 2
    assert len(_open_ids(db)) == 2 and len(pve.sent) == sent


def test_a_second_start_changes_nothing(pve, db, active, monkeypatch, caplog):
    _drift_and_pile(pve, monkeypatch)
    _start(monkeypatch)
    assert len(_open_ids(db)) == 2
    before = _rows(db)
    caplog.clear()
    caplog.set_level(logging.INFO)
    _start(monkeypatch)
    assert _rows(db) == before
    assert not [r for r in caplog.records if 'repeated open deviation' in r.getMessage()]


def test_what_is_no_repeat_stays(pve, db, active, monkeypatch):
    d1 = [{'path': 'content', 'op': 'changed', 'before': 'images', 'after': 'images,iso'}]
    d2 = [{'path': 'content', 'op': 'changed', 'before': 'images', 'after': 'backup'}]
    # older rows of the same drift that are no longer open come first
    closed = [_add(db, 'c_a', 'storage', 'local', d1, status=s)
              for s in ('acknowledged', 'resolved', 'superseded')]
    first = _add(db, 'c_a', 'storage', 'local', d1)
    repeats = [_add(db, 'c_a', 'storage', 'local', d1) for _ in range(2)]
    other_diff = _add(db, 'c_a', 'storage', 'local', d2)
    # the same JSON written another way is another text: the scan would not match it either
    other_text = _add(db, 'c_a', 'storage', 'local', json.dumps(d1, separators=(',', ':')))
    other_cluster = _add(db, 'c_b', 'storage', 'local', d1)
    other_kind = _add(db, 'c_a', 'network', 'local', d1)
    other_scope = _add(db, 'c_a', 'storage', 'local2', d1)
    policy = [_add(db, 'c_a', 'access', 'policy:access_admin_role', d1, category='policy_violation')
              for _ in range(2)]
    incidents = [_add(db, 'c_a', 'storage', 'local', d1, category='incident') for _ in range(2)]
    closed_repeats = [_add(db, 'c_a', 'storage', 'local', d1, status='acknowledged') for _ in range(2)]
    before = _rows(db)

    _start(monkeypatch)

    after = _rows(db)
    changed = {i for i in before if before[i] != after[i]}
    assert changed == set(repeats)
    assert all(after[i]['status'] == 'superseded' for i in repeats)
    for i in closed + [first, other_diff, other_text, other_cluster, other_kind, other_scope] + policy + \
            incidents + closed_repeats:
        assert after[i] == before[i], i
    assert after[first]['status'] == 'open'


def test_a_row_acknowledged_meanwhile_stays_acknowledged(pve, db, active, monkeypatch):
    """The read and the writes are apart: what an admin did in between wins."""
    _drift_and_pile(pve, monkeypatch, times=3)
    real, calls = dbcrypto.run_off_hub, []

    def off_hub(work, path, commit=False):
        out = real(work, path, commit=commit)
        calls.append(out)
        if len(calls) == 1:
            db.conn.execute("UPDATE drift_events SET status='acknowledged', acknowledged_by='root' "
                            "WHERE id=?", (out[0],))
            db.conn.commit()
        return out
    monkeypatch.setattr(dbcrypto, 'run_off_hub', off_hub)
    # the prune of old events after it goes through the same door (test_drift_event_prune.py)
    monkeypatch.setattr(drift, '_prune_events', lambda: 0)

    _start(monkeypatch)

    assert len(calls) == 2, 'one read, one chunk'
    acked = calls[0][0]
    assert _rows(db)[acked]['status'] == 'acknowledged'
    assert calls[1] == len(calls[0]) - 1
    assert len(_open_ids(db)) == 2


def test_rows_from_before_the_category_column_are_deviations(pve, db, active, monkeypatch):
    """The column came with a default, so the old rows read as deviations, never as NULL."""
    c = db.conn
    c.execute('DROP TABLE drift_events')
    c.execute("CREATE TABLE drift_events (id INTEGER PRIMARY KEY AUTOINCREMENT, cluster_id TEXT NOT NULL, "
              "kind TEXT NOT NULL, scope TEXT NOT NULL, severity TEXT DEFAULT 'info', summary TEXT DEFAULT '', "
              "diff TEXT NOT NULL, detected_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', "
              "acknowledged_at TEXT, acknowledged_by TEXT DEFAULT '')")
    for _ in range(3):
        c.execute("INSERT INTO drift_events (cluster_id, kind, scope, diff, detected_at) "
                  "VALUES (?, 'storage', 'local', '[]', '2026-05-01T00:00:00')", (CL,))
    c.commit()
    db._init_db()
    assert {r[0] for r in c.execute('SELECT category FROM drift_events').fetchall()} == {'deviation'}

    _start(monkeypatch)

    assert [(i, r['status']) for i, r in _rows(db, CL).items()] == \
        [(1, 'open'), (2, 'superseded'), (3, 'superseded')]


# -- where and when it runs ------------------------------------------------------------------

def test_a_standby_collapses_its_own_table(ha_env, pve, db, monkeypatch):  # noqa: F811
    _standby_of_active(ha_env)
    assert not ha_core.is_active()
    first = _add(db, CL, 'storage', 'local', [{'path': '*', 'op': 'removed'}])
    repeats = [_add(db, CL, 'storage', 'local', [{'path': '*', 'op': 'removed'}]) for _ in range(3)]
    synced = {t: _count(db, t) for t in ha_core.SYNC_TABLES}

    _start(monkeypatch)

    assert _open_ids(db) == [first]
    assert all(_rows(db)[i]['status'] == 'superseded' for i in repeats)
    # the scan itself is the active's business, and no synced table took a note of this
    assert pve.reads == []
    assert {t: _count(db, t) for t in ha_core.SYNC_TABLES} == synced


def test_a_failure_is_logged_and_the_scanner_goes_on(pve, db, active, monkeypatch, caplog):
    _drift_and_pile(pve, monkeypatch, times=2)
    before = _rows(db)
    pve.reads.clear()

    def broken(work, path, commit=False):
        raise RuntimeError('disk I/O error')
    monkeypatch.setattr(dbcrypto, 'run_off_hub', broken)
    caplog.set_level(logging.INFO)

    _start(monkeypatch)

    said = [r for r in caplog.records if 'repeated open deviations' in r.getMessage()]
    assert len(said) == 1 and said[0].levelno == logging.WARNING
    assert 'stopped after 0' in said[0].getMessage() and 'disk I/O error' in said[0].getMessage()
    assert _rows(db) == before
    # the thread went on to its scan
    assert pve.reads


def test_no_test_starts_the_app_on_the_default_database():
    """create_app() starts the drift thread, and the collapse writes to whatever database
    get_db() names. A test module that builds the app itself does so on config/pegaprox.db
    under the working directory, which is the developer's own instance when the suite runs
    from the checkout. conftest's _integration_app points the database at a temp dir first."""
    here = os.path.dirname(os.path.abspath(__file__))
    found = []
    for name in sorted(os.listdir(here)):
        if not (name.startswith('test_') and name.endswith('.py')):
            continue
        with open(os.path.join(here, name), encoding='utf-8') as fh:
            src = fh.read()
        if 'create_app(' not in src:
            continue
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call):
                f = node.func
                if (f.id if isinstance(f, ast.Name) else getattr(f, 'attr', None)) == 'create_app':
                    found.append(f'{name}:{node.lineno}')
    assert found == [], 'use the _integration_app fixture'
