"""The rows an older PegaProx stored are converted to parts in the background.

metrics_store.run_backfill walks the rows still in the old format (fmt 0) newest first, one row
per transaction: into parts (fmt 2), or kept as JSON (fmt 1) where a row does not fit them or
does not parse. Every reader answers the same before, during and after. It picks up where it
stopped after a restart, and a row the writer pruned while it was converted is rolled back.
After a downgrade the older PegaProx writes rows of the old format again and prunes without
knowing of parts; an upgrade after that converts those rows and sweeps the parts left behind.
MK Oct 2026
"""
import json
from datetime import datetime, timedelta

import pytest

import metrics_history_fixture as mhf
from pegaprox import constants
from pegaprox.api.helpers import load_metrics_window
from pegaprox.background import metrics, metrics_store as ms
from pegaprox.core import dbcrypto

GIB = 1024 ** 3


def _q(sql, args=()):
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        return [tuple(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def _exec(sql, args=()):
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        conn.execute(sql, args)
        conn.commit()
    finally:
        conn.close()


def _snapshot(i):
    """Three clusters as the collector writes them, a fourth with an odd guest now and then."""
    def vm(v):
        run = (i + v) % 5 != 0
        return {'t': 'lxc' if v % 6 == 0 else 'qemu', 'r': run,
                'cpu': round(((i * 7 + v) % 997) / 10, 1) if run else None,
                'mem': round(((i * 3 + v) % 900) / 10, 1) if run else None,
                'maxmem': (1 + v % 4) * GIB, 'maxcpu': 1 + v % 8, 'n': f'pve{1 + (v + i // 10) % 3}'}
    clusters = {}
    for c in range(3):
        clusters[f'cluster_{c + 1}'] = {
            'name': f'Cluster {c + 1}',
            'nodes': {f'pve{k}': {'cpu': float((i + k) % 90), 'mem_percent': 40.0, 'maxcpu': 32,
                                  'maxmem': 256 * GIB, 'temp': 40.0 + k} for k in (1, 2, 3)},
            'totals': {'vms_running': 9, 'vms_stopped': 1, 'cts_running': 0, 'cts_stopped': 0,
                       'cpu_used': 1.5 * i, 'cpu_total': 96, 'mem_used': i * GIB, 'mem_total': 768 * GIB},
            'vms': {str(v): vm(v) for v in range(100 + c * 50, 100 + c * 50 + 12 - (i % 3))},
            'storage': {'local': {'used': i, 'total': 1000, 'pct': round(i / 10, 1)}},
        }
    odd = dict(clusters['cluster_3'])
    if i % 4 == 0:
        odd['vms'] = {k: dict(v, note='x') for k, v in odd['vms'].items()}
    clusters['cluster_odd'] = odd
    return {'clusters': clusters}


ROWS = 40


@pytest.fixture
def legacy(db):
    """ROWS rows as an older PegaProx wrote them, five minutes apart, the newest a minute ago."""
    now = datetime.now()
    stamps = [(now - timedelta(minutes=1 + 5 * (ROWS - 1 - i))).isoformat() for i in range(ROWS)]
    ids = mhf.History().write_legacy([(ts, _snapshot(i)) for i, ts in enumerate(stamps)])
    return ids


def _everything():
    """What every reader of the history hands out now, the caches forgotten."""
    dbcrypto._HEAVY_CACHE.clear()
    out = {'reports full': metrics.load_metrics_history(days=1),
           'reports totals': metrics.load_metrics_history(days=7, totals_only=True),
           'newest 1000': metrics.load_metrics_history()}
    dbcrypto._HEAVY_CACHE.clear()
    now = datetime.now().timestamp()
    for cid in ('cluster_1', 'cluster_3', 'cluster_odd'):
        out[f'window {cid}'] = load_metrics_window(1, cid).dicts()
        out[f'window 30 {cid}'] = load_metrics_window(30, cid).dicts()
        out[f'nodes {cid}'] = metrics.load_node_history(cid)
        out[f'range all {cid}'] = metrics.load_metrics_range(now - 7200, now, lambda c: c)
        out[f'range guest {cid}'] = metrics.load_metrics_range(
            now - 7200, now, lambda c, cid=cid: ((c.get(cid) or {}).get('vms') or {}).get('150'),
            cluster_id=cid, parts=('vms',))
        out[f'range node {cid}'] = metrics.load_metrics_range(
            now - 7200, now, lambda c, cid=cid: ((c.get(cid) or {}).get('nodes') or {}).get('pve2'),
            cluster_id=cid, parts=('nodes',))
        out[f'range head {cid}'] = metrics.load_metrics_range(
            now - 7200, now, lambda c, cid=cid: (c.get(cid) or {}).get('totals'),
            cluster_id=cid, parts=('head',))
    return json.loads(json.dumps(out))


def _fmts():
    return dict(_q('SELECT fmt, COUNT(*) FROM metrics_history GROUP BY fmt'))


def test_every_reader_answers_the_same_before_during_and_after(legacy):
    before = _everything()
    assert before['window cluster_1'] and before['range guest cluster_1']
    counts = ms.run_backfill(pace=False, limit=7)
    assert counts == {'parts': 7, 'json': 0, 'gone': 0, 'failed': 0}
    # newest first: what the pages read is done first
    converted = [r[0] for r in _q('SELECT id FROM metrics_history WHERE fmt != 0 ORDER BY id')]
    assert converted == legacy[-7:]
    assert ms._same(_everything(), before)
    # a restart walks from the top again, passes over what is done and finishes the rest
    assert ms.run_backfill(pace=False) == {'parts': ROWS - 7, 'json': 0, 'gone': 0, 'failed': 0}
    assert _fmts() == {2: ROWS}
    assert _q("SELECT COUNT(*) FROM metrics_history WHERE data != ''") == [(0,)]
    assert ms._same(_everything(), before)
    # and a third run has nothing left to do
    assert ms.run_backfill(pace=False) == {'parts': 0, 'json': 0, 'gone': 0, 'failed': 0}


def test_a_converted_row_keeps_its_id_and_its_timestamp(legacy):
    stamps = _q('SELECT id, timestamp FROM metrics_history ORDER BY id')
    ms.run_backfill(pace=False)
    assert _q('SELECT id, timestamp FROM metrics_history ORDER BY id') == stamps


def test_the_odd_cluster_keeps_its_guests_as_json_where_they_are_odd(legacy):
    ms.run_backfill(pace=False)
    bodies = _q("SELECT h.id, substr(p.body, 1, 4) FROM metrics_part p JOIN metrics_history h ON h.id = p.snap_id "
                "WHERE p.cluster_id = 'cluster_odd' AND p.part = 3 ORDER BY h.id")
    kinds = [bytes(b)[:1] == b'{' for _sid, b in bodies]
    assert kinds == [i % 4 == 0 for i in range(ROWS)]


def test_a_row_that_does_not_parse_is_kept_as_it_is_and_read_as_before(legacy):
    _exec('INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)', (datetime.now().isoformat(), '{"clusters": '))
    _exec('INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)',
          (datetime.now().isoformat(), json.dumps({'clusters': {'cluster_1': {'name': 'x'}}, 'other': 1})))
    _exec('INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)', (datetime.now().isoformat(), '[1, 2]'))
    before = _everything()
    counts = ms.run_backfill(pace=False)
    assert counts == {'parts': ROWS, 'json': 3, 'gone': 0, 'failed': 0}
    assert _q('SELECT fmt, data FROM metrics_history WHERE fmt = 1 ORDER BY id') == [
        (1, '{"clusters": '), (1, json.dumps({'clusters': {'cluster_1': {'name': 'x'}}, 'other': 1})), (1, '[1, 2]')]
    assert ms._same(_everything(), before)
    # kept for good: nothing to do the next time
    assert ms.run_backfill(pace=False)['json'] == 0


def test_a_row_pruned_while_it_is_converted_is_rolled_back(legacy, monkeypatch):
    victim = legacy[-1]
    real = ms.plan_snapshot
    rosters = _q('SELECT COUNT(*) FROM metrics_roster')

    def pruned_meanwhile(stored, check=False, ref=None):
        plan = real(stored, check, ref)
        # the writer's prune, on its own connection, between the read and the write
        _exec('DELETE FROM metrics_history WHERE id = ?', (victim,))
        return plan
    monkeypatch.setattr(ms, 'plan_snapshot', pruned_meanwhile)
    assert ms.convert_row(victim) == 'gone'
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id = ?', (victim,)) == [(0,)]
    assert _q('SELECT COUNT(*) FROM metrics_roster') == rosters
    assert _q('SELECT COUNT(*) FROM metrics_history WHERE id = ?', (victim,)) == [(0,)]
    # the roster the rolled back conversion made is not taken for one by the next write
    monkeypatch.setattr(ms, 'plan_snapshot', real)
    assert ms.run_backfill(pace=False)['parts'] == ROWS - 1
    for sid, rid in _q('SELECT snap_id, roster FROM metrics_part WHERE part = 3 AND roster IS NOT NULL'):
        assert _q('SELECT COUNT(*) FROM metrics_roster WHERE id = ?', (rid,)) == [(1,)], sid


def test_a_row_already_gone_is_passed_over(legacy):
    _exec('DELETE FROM metrics_history WHERE id = ?', (legacy[0],))
    assert ms.convert_row(legacy[0]) == 'gone'


def test_guests_that_do_not_read_back_are_kept_as_json(legacy, monkeypatch):
    real = ms.guest_map

    def off(roster, body):
        out = real(roster, body)
        for v in out.values():
            v['maxcpu'] += 1
        return out
    before = _everything()
    monkeypatch.setattr(ms, 'guest_map', off)
    assert ms.convert_row(legacy[-1]) == 'parts'
    monkeypatch.setattr(ms, 'guest_map', real)
    assert sorted(ms._mismatches) == ['cluster_1', 'cluster_2', 'cluster_3', 'cluster_odd']
    ms._mismatches.clear()
    bodies = _q('SELECT substr(body, 1, 1) FROM metrics_part WHERE snap_id = ? AND part = 3', (legacy[-1],))
    assert {bytes(b) for (b,) in bodies} == {b'{'}
    assert ms._same(_everything(), before)


def test_after_a_downgrade_an_upgrade_converts_and_sweeps(db):
    """The new version wrote parts, an older one ran for a while (its rows in the old format,
    its prune by timestamp only), then the new one again."""
    h = mhf.History()
    now = datetime.now()
    new_rows = h.write([((now - timedelta(minutes=60 - i)).isoformat(), _snapshot(i)) for i in range(5)])
    # the older version: an INSERT that names (timestamp, data), and a prune of the two oldest
    old_rows = h.write_legacy([((now - timedelta(minutes=30 - i)).isoformat(), _snapshot(10 + i)) for i in range(3)])
    _exec('DELETE FROM metrics_history WHERE id IN (?, ?)', (new_rows[0], new_rows[1]))
    assert _q('SELECT fmt FROM metrics_history WHERE id IN (?, ?, ?) ORDER BY id', tuple(old_rows)) == [(0,), (0,), (0,)]
    before = _everything()
    assert ms.run_backfill(pace=False) == {'parts': 3, 'json': 0, 'gone': 0, 'failed': 0}
    assert ms._same(_everything(), before)
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id IN (?, ?)', (new_rows[0], new_rows[1]))[0][0] > 0
    ms._last_sweep[0] = 0.0
    metrics.save_metrics_snapshot({'timestamp': now.isoformat(), **_snapshot(99)})
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id IN (?, ?)', (new_rows[0], new_rows[1])) == [(0,)]
    used = {r[0] for r in _q('SELECT DISTINCT roster FROM metrics_part WHERE roster IS NOT NULL')}
    assert {r[0] for r in _q('SELECT id FROM metrics_roster')} == used


def test_an_older_pegaprox_reading_a_converted_row_passes_over_it(legacy):
    """What its readers do with data '': json.loads raises, and each of them skips the row."""
    ms.run_backfill(pace=False)
    for (data,) in _q('SELECT data FROM metrics_history'):
        with pytest.raises(ValueError):
            json.loads(data)


# the conversion as start_metrics_collector starts it, in a process gevent did not patch
_UNPATCHED = r'''
import json, os, sys, time
from pegaprox import constants
from pegaprox.core import dbcrypto
from pegaprox.core.db import get_db
from pegaprox.background import metrics_store as ms
get_db()
vm = {"t": "qemu", "r": True, "cpu": 1.5, "mem": 20.0, "maxmem": 1073741824, "maxcpu": 2, "n": "pve1"}
snap = {"clusters": {"c1": {"name": "Testi", "nodes": {"pve1": {"cpu": 5.0}}, "vms": {"100": vm}}}}
conn = dbcrypto.connect(constants.DATABASE_FILE)
for i in range(5):
    conn.execute("INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)",
                 (f"2026-10-21T10:0{i}:00", json.dumps(snap)))
conn.commit()
conn.close()
ms.start_backfill(delay=0)


def fmts():
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        return dict(conn.execute("SELECT fmt, COUNT(*) FROM metrics_history GROUP BY fmt").fetchall())
    finally:
        conn.close()


# the main thread busy elsewhere, as the threaded server's accept loop keeps it
end = time.monotonic() + 60
while time.monotonic() < end and fmts().get(0):
    time.sleep(0.2)
print(json.dumps(fmts()))
sys.stdout.flush()
os._exit(0)
'''


def test_the_conversion_runs_where_gevent_does_not_serve(tmp_path):
    """MK Oct 2026 - started with gevent.spawn_later, the conversion waited for a hub that
    never ran where PegaProx serves without gevent (PEGAPROX_NO_GEVENT, the threaded
    fallback): the old rows stayed old. It runs in a thread of its own now, a greenlet where
    gevent patched threading."""
    import os
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PEGAPROX_CONFIG_DIR=str(tmp_path / 'config'), PEGAPROX_LOG_DIR=str(tmp_path / 'logs'))
    run = subprocess.run([sys.executable, '-c', _UNPATCHED], cwd=root, env=env, capture_output=True, text=True,
                         timeout=180)
    assert run.returncode == 0, run.stderr[-2000:]
    assert json.loads(run.stdout.splitlines()[-1]) == {'2': 5}
