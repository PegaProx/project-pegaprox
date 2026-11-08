"""Writing metrics snapshots in parts, and what keeps that store tidy.

A snapshot row and its parts go in (and out, at the end of the retention) in one transaction;
rosters are shared while the guests stay as they are and swept an hour after nothing uses them;
parts whose row an older PegaProx pruned are swept too. Every save in a test reads back what it
wrote (in production one a day) and keeps the guests as JSON where that does not match. And the
readers hand out the rows in the order today's SQL gives them, ties included.
MK Oct 2026
"""
import json
import logging
from datetime import datetime, timedelta

import pytest

import metrics_history_fixture as mhf
from pegaprox import constants
from pegaprox.background import metrics, metrics_store as ms
from pegaprox.core import dbcrypto

GIB = 1024 ** 3


def _q(sql, args=()):
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        return [tuple(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def _vm(cpu=10.0, maxcpu=2, n='pve1', r=True):
    return {'t': 'qemu', 'r': r, 'cpu': cpu if r else None, 'mem': 20.0 if r else None,
            'maxmem': 4 * GIB, 'maxcpu': maxcpu, 'n': n}


def _cluster(name='Testi', guests=3, maxcpu=2, cpu=10.0):
    return {'name': name, 'nodes': {'pve1': {'cpu': 5.0, 'mem_percent': 40.0, 'maxcpu': 8, 'maxmem': GIB}},
            'totals': {'cpu_total': 8, 'cpu_used': 0.4, 'mem_total': GIB, 'mem_used': 1,
                       'vms_running': guests, 'cts_running': 0},
            'vms': {str(100 + i): _vm(cpu=cpu, maxcpu=maxcpu) for i in range(guests)},
            'storage': {'local': {'used': 1, 'total': 2, 'pct': 50.0}}}


def _ago(minutes):
    return (datetime.now() - timedelta(minutes=minutes)).isoformat()


def _save(ts, clusters, **extra):
    snap = {'timestamp': ts, 'clusters': clusters, **extra}
    metrics.save_metrics_snapshot(snap)
    return _q('SELECT MAX(id) FROM metrics_history')[0][0]


# --- what a save writes ------------------------------------------------------------------------

def test_a_snapshot_reads_back_as_its_json_row_did(db):
    odd = _cluster('odd')
    odd['vms']['101']['note'] = 'x'
    clusters = {'c1': _cluster(), 'c2': ['not', 'a', 'dict'], 'c3': odd, 'c4': {}}
    ts = _ago(1)
    sid = _save(ts, clusters)
    assert _q('SELECT fmt, data FROM metrics_history WHERE id = ?', (sid,)) == [(2, '')]
    kinds = _q('SELECT cluster_id, part FROM metrics_part WHERE snap_id = ? ORDER BY ord, part', (sid,))
    assert kinds == [('c1', 0), ('c1', 1), ('c1', 2), ('c1', 3), ('c1', 4), ('c2', 9),
                     ('c3', 0), ('c3', 1), ('c3', 2), ('c3', 3), ('c4', 0)]
    got = metrics.load_metrics_history(days=1)['snapshots']
    want = json.loads(json.dumps({'clusters': clusters}))
    want['timestamp'] = ts
    assert len(got) == 1 and ms._same(got[0], want)


def test_a_snapshot_with_more_than_clusters_is_kept_as_the_json_it_was(db):
    ts = _ago(1)
    sid = _save(ts, {'c1': _cluster()}, note='kept')
    data = json.dumps({'clusters': {'c1': _cluster()}, 'note': 'kept'})
    assert _q('SELECT fmt, data FROM metrics_history WHERE id = ?', (sid,)) == [(1, data)]
    assert not _q('SELECT 1 FROM metrics_part WHERE snap_id = ?', (sid,))
    got = metrics.load_metrics_history(days=1)['snapshots']
    assert list(got[0]) == ['clusters', 'note', 'timestamp'] and got[0]['note'] == 'kept'


def test_a_cluster_id_the_database_cannot_hold_keeps_the_snapshot_as_json(db):
    """A lone surrogate sat escaped in the old blob, but a part's cluster_id column cannot
    take it: the save raised, and every other cluster of that snapshot was lost with it."""
    clusters = {'c1': _cluster(), 'c\ud800': _cluster('odd')}
    ts = _ago(1)
    sid = _save(ts, clusters)
    assert sid is not None, 'the snapshot was not stored'
    assert _q('SELECT fmt, data FROM metrics_history WHERE id = ?', (sid,)) == \
        [(1, json.dumps({'clusters': clusters}))]
    got = metrics.load_metrics_history(days=1)['snapshots']
    want = json.loads(json.dumps({'clusters': clusters}))
    want['timestamp'] = ts
    assert len(got) == 1 and ms._same(got[0], want)


def test_the_row_and_its_parts_go_in_together_or_not_at_all(db, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError('disk full')
    monkeypatch.setattr(ms, '_insert_parts', broken)
    _save(_ago(1), {'c1': _cluster()})          # logged, as a failed save always was
    assert _q('SELECT COUNT(*) FROM metrics_history') == [(0,)]
    assert _q('SELECT COUNT(*) FROM metrics_part') == [(0,)]


# --- the retention -----------------------------------------------------------------------------

@pytest.mark.parametrize('days', [7, 30, 365])
def test_the_retention_takes_rows_and_their_parts_together(db, monkeypatch, days):
    monkeypatch.setenv('PEGAPROX_METRICS_RETENTION_DAYS', str(days))
    old = _save(_ago((days + 1) * 1440), {'c1': _cluster()})
    kept = _save(_ago((days - 1) * 1440), {'c1': _cluster()})
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id = ?', (old,)) == [(0,)]
    newest = _save(_ago(1), {'c1': _cluster()})
    assert [r[0] for r in _q('SELECT id FROM metrics_history ORDER BY id')] == [kept, newest]
    assert {r[0] for r in _q('SELECT DISTINCT snap_id FROM metrics_part')} == {kept, newest}


# --- rosters -----------------------------------------------------------------------------------

def _rosters():
    return _q('SELECT id, cluster_id, last_snap FROM metrics_roster ORDER BY id')


def test_snapshots_share_a_roster_until_a_guest_changes(db):
    a = _save(_ago(30), {'c1': _cluster(), 'c2': _cluster()})
    b = _save(_ago(25), {'c1': _cluster(cpu=55.5), 'c2': _cluster()})     # only figures moved
    c = _save(_ago(20), {'c1': _cluster(maxcpu=4), 'c2': _cluster()})     # resized
    rows = _rosters()
    assert [(cid, last) for _rid, cid, last in rows] == [('c1', b), ('c2', c), ('c1', c)]
    refs = dict(((sid, cid), rid) for sid, cid, rid in
                _q('SELECT snap_id, cluster_id, roster FROM metrics_part WHERE part = 3'))
    assert refs[(a, 'c1')] == refs[(b, 'c1')] != refs[(c, 'c1')]
    assert refs[(a, 'c2')] == refs[(b, 'c2')] == refs[(c, 'c2')]


def test_a_roster_is_found_again_without_the_writers_memory(db):
    _save(_ago(30), {'c1': _cluster()})
    ms.forget()
    _save(_ago(25), {'c1': _cluster()})
    assert len(_rosters()) == 1
    # and a remembered roster that went is made again, not pointed at
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    conn.execute('DELETE FROM metrics_roster')
    conn.commit()
    conn.close()
    sid = _save(_ago(20), {'c1': _cluster()})
    (rid,) = _q('SELECT roster FROM metrics_part WHERE snap_id = ? AND part = 3', (sid,))[0]
    assert _q('SELECT id FROM metrics_roster') == [(rid,)]
    assert metrics.load_metrics_history(days=1)['snapshots'][-1]['clusters']['c1']['vms']['100'] == \
        json.loads(json.dumps(_vm()))


def test_a_roster_nothing_uses_goes_at_the_hourly_sweep(db, monkeypatch):
    first = _save(_ago(3 * 1440), {'c1': _cluster(maxcpu=1)})
    later = _save(_ago(2 * 1440), {'c1': _cluster(maxcpu=2)})
    assert len(_rosters()) == 2
    monkeypatch.setenv('PEGAPROX_METRICS_RETENTION_DAYS', '7')
    # nothing is pruned: both rosters stay, and the sweep ran at the first save of this process
    _save(_ago(1440), {'c1': _cluster(maxcpu=2)})
    assert len(_rosters()) == 2
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    conn.execute('DELETE FROM metrics_part WHERE snap_id = ?', (first,))
    conn.execute('DELETE FROM metrics_history WHERE id = ?', (first,))
    conn.commit()
    conn.close()
    _save(_ago(30), {'c1': _cluster(maxcpu=2)})
    assert len(_rosters()) == 2, 'swept before the hour was up'
    ms._last_sweep[0] = 0.0                  # the hour is up
    _save(_ago(20), {'c1': _cluster(maxcpu=2)})
    rows = _rosters()
    assert len(rows) == 1 and rows[0][2] > later


def test_parts_whose_row_an_older_pegaprox_pruned_are_swept(db):
    """An older PegaProx after a downgrade prunes by timestamp and knows nothing of parts."""
    gone = _save(_ago(40), {'c1': _cluster()})
    stays = _save(_ago(30), {'c1': _cluster()})
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    conn.execute('DELETE FROM metrics_history WHERE id = ?', (gone,))
    conn.commit()
    conn.close()
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id = ?', (gone,))[0][0] > 0
    ms._last_sweep[0] = 0.0
    _save(_ago(1), {'c1': _cluster()})
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id = ?', (gone,)) == [(0,)]
    assert _q('SELECT COUNT(*) FROM metrics_part WHERE snap_id = ?', (stays,))[0][0] == 5


# --- the check at write time -------------------------------------------------------------------

def test_guests_that_do_not_read_back_as_written_are_kept_as_json(db, monkeypatch, caplog):
    real = ms.guest_map

    def off_by_one(roster, body):
        out = real(roster, body)
        first = next(iter(out))
        out[first] = dict(out[first], maxcpu=out[first]['maxcpu'] + 1)
        return out
    monkeypatch.setattr(ms, 'guest_map', off_by_one)
    with caplog.at_level(logging.ERROR):
        sid = _save(_ago(1), {'c1': _cluster()})
    monkeypatch.setattr(ms, 'guest_map', real)
    assert any('kept as JSON' in r.getMessage() for r in caplog.records)
    assert ms._mismatches == ['c1']
    ms._mismatches.clear()
    (body,) = _q('SELECT body FROM metrics_part WHERE snap_id = ? AND part = 3', (sid,))[0]
    assert bytes(body)[:1] == b'{'
    assert not _q('SELECT 1 FROM metrics_part WHERE snap_id = ? AND part = 4', (sid,))
    got = metrics.load_metrics_history(days=1)['snapshots'][0]['clusters']['c1']
    assert ms._same(got, json.loads(json.dumps(_cluster())))


def test_production_checks_one_snapshot_a_day(db, monkeypatch):
    monkeypatch.setattr(ms, '_check_every_save', False)
    ms._last_check[0] = 0.0
    checks = []
    real = ms._rebuild
    monkeypatch.setattr(ms, '_rebuild', lambda parts: checks.append(1) or real(parts))
    _save(_ago(3), {'c1': _cluster()})
    assert len(checks) == 1
    _save(_ago(2), {'c1': _cluster()})
    assert len(checks) == 1
    ms._last_check[0] -= ms._CHECK_EVERY
    _save(_ago(1), {'c1': _cluster()})
    assert len(checks) == 2


def test_saves_and_conversions_take_the_one_write_lock(db, monkeypatch):
    held = []
    real = dbcrypto.run_off_hub

    def watching(work, path, commit=False):
        held.append(ms._write_lock().locked())
        return real(work, path, commit=commit)
    monkeypatch.setattr(dbcrypto, 'run_off_hub', watching)
    _save(_ago(2), {'c1': _cluster()})
    mhf.History().write_legacy([(_ago(1), {'clusters': {'c1': _cluster()}})])
    assert ms.run_backfill(pace=False) == {'parts': 1, 'json': 0, 'gone': 0, 'failed': 0}
    assert held == [True, True]


# --- the order of the rows ---------------------------------------------------------------------

def _named(n, ts):
    return ts, {'clusters': {'c1': dict(_cluster(name=f'row{n}'))}}


def _ties(db_history):
    """Rows where some timestamps are the very same string, written oldest first."""
    base = datetime.now() - timedelta(hours=3)
    stamps = []
    for i in range(30):
        stamps.append((base + timedelta(minutes=5 * (i // 3))).isoformat())   # three rows a stamp
    return db_history.write_legacy([_named(i, ts) for i, ts in enumerate(stamps)])


def _names_today(sql, args):
    # today's statements select (timestamp, data)
    return [json.loads(r[1])['clusters']['c1']['name'] for r in _q(sql, args)]


def test_the_readers_keep_the_order_today_s_sql_gives_ties_included(db):
    """Two snapshots under one timestamp come in whatever order SQLite hands them for
    ORDER BY timestamp; the new reads are the old SQL with more columns, so the same."""
    h = mhf.History()
    _ties(h)
    cutoff = (datetime.now() - timedelta(days=1)).isoformat()
    window_today = _names_today('SELECT timestamp, data FROM metrics_history '
                                'WHERE timestamp >= ? ORDER BY timestamp ASC', (cutoff,))
    reports_today = _names_today(
        'SELECT timestamp, data FROM (SELECT id, timestamp, data FROM metrics_history WHERE timestamp >= ? '
        'ORDER BY timestamp DESC LIMIT 4000) ORDER BY timestamp ASC', (cutoff,))
    newest_today = _names_today('SELECT timestamp, data FROM metrics_history ORDER BY timestamp DESC LIMIT 1000', ())

    def reads():
        from pegaprox.api.helpers import load_metrics_window
        return ([cd['name'] for _ts, cd in load_metrics_window(1, 'c1')],
                [s['clusters']['c1']['name'] for s in metrics.load_metrics_history(days=1)['snapshots']],
                [s['clusters']['c1']['name'] for s in metrics.load_metrics_history()['snapshots']])
    dbcrypto._HEAVY_CACHE.clear()
    assert reads() == (window_today, reports_today, newest_today)
    # converted, the same order
    assert ms.run_backfill(pace=False)['parts'] == 30
    dbcrypto._HEAVY_CACHE.clear()
    assert reads() == (window_today, reports_today, newest_today)


# --- the cluster window ------------------------------------------------------------------------

def test_a_window_stops_where_the_old_filter_stopped(db):
    """The per-cluster filter had its try around the whole loop: a row whose clusters is no
    map ended the window there (rows that do not parse were skipped before that)."""
    h = mhf.History()
    ts = [_ago(50 - i) for i in range(6)]
    h.write([(ts[0], {'clusters': {'c1': _cluster('a')}})])
    h.write_legacy([(ts[1], {'clusters': {'c1': _cluster('b')}})])
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    conn.execute('INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)', (ts[2], 'not json'))
    conn.commit()
    conn.close()
    h.write([(ts[3], {'clusters': {'c1': _cluster('d'), 'c2': {}}})])
    h.write_legacy([(ts[4], {'clusters': ['no', 'map']})])
    h.write([(ts[5], {'clusters': {'c1': _cluster('f')}})])
    from pegaprox.api.helpers import load_metrics_window
    assert [cd['name'] for _t, cd in load_metrics_window(1, 'c1')] == ['a', 'b', 'd']
    assert len(load_metrics_window(1, 'c2')) == 0          # {} is no snapshot of c2


def test_a_window_reads_its_parts_where_they_are_asked_for(db, monkeypatch):
    h = mhf.History()
    h.write([(_ago(10 - i), {'clusters': {'c1': _cluster(cpu=float(i))}}) for i in range(5)])
    from pegaprox.api.helpers import load_metrics_window, run_off_hub
    window = load_metrics_window(1, 'c1')
    real = dbcrypto.run_heavy_read

    def not_from_the_pool(*a, **k):
        raise AssertionError('a read in the pool went back to the hub')
    monkeypatch.setattr(dbcrypto, 'run_heavy_read', not_from_the_pool)
    # in the pool, where the report arithmetic runs, the first .get reads every snapshot's
    # guests right there
    cpus = run_off_hub(lambda w: [cd.get('vms')['100']['cpu'] for _t, cd in w], window)
    assert cpus == [0.0, 1.0, 2.0, 3.0, 4.0]
    monkeypatch.setattr(dbcrypto, 'run_heavy_read', real)
    assert ms.need(window, 'vms') is window
    assert ms._same(window.dicts()[0][1], json.loads(json.dumps(_cluster(cpu=0.0))))


def test_a_snapshot_pruned_while_its_window_is_read_leaves_the_window(db):
    h = mhf.History()
    ids = h.write([(_ago(10 - i), {'clusters': {'c1': _cluster(cpu=float(i))}}) for i in range(4)])
    from pegaprox.api.helpers import load_metrics_window
    window = load_metrics_window(1, 'c1')
    assert len(window) == 4
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    conn.execute('DELETE FROM metrics_part WHERE snap_id = ?', (ids[0],))
    conn.execute('DELETE FROM metrics_history WHERE id = ?', (ids[0],))
    conn.commit()
    conn.close()
    ms.need(window, 'vms', 'nodes')
    assert [cd['vms']['100']['cpu'] for _t, cd in window] == [1.0, 2.0, 3.0]


def test_a_list_handed_in_passes_need_as_it_is():
    hist = [(0, {'vms': {}})]
    assert ms.need(hist, 'vms') is hist


# --- the node history --------------------------------------------------------------------------

def test_the_node_history_is_what_the_route_read_of_each_snapshot(db):
    h = mhf.History()
    c = _cluster()
    c['nodes']['pve1']['temp'] = 51.5
    h.write([(_ago(40), {'clusters': {'c1': c}})])
    h.write_legacy([(_ago(30), {'clusters': {'c1': c}})])
    h.write([(_ago(20), {'clusters': {'c1': ['odd']}})])
    h.write([(_ago(10), {'clusters': {'c2': c}})])
    got = metrics.load_node_history('c1')
    assert [nodes for _ts, nodes in got] == [{}, c['nodes'], c['nodes']]


def test_a_node_s_temperature_chart_reads_the_history_once_a_minute(api, seed, monkeypatch):
    """MK Oct 2026 - at 200 nodes every request read and parsed the 1000 node maps of the
    cluster (16 MB) for one node's temperatures, and held them all at once. The read works
    the node's points out row by row and keeps them a minute, as the whole history was kept
    before this store. The points are what the route made of each snapshot."""
    m = api.make_fake_manager(cluster_id='c1')
    m.is_connected = True
    api.set_manager('c1', m)
    h = mhf.History()
    rows = []
    for i in range(6):
        c = _cluster()
        c['nodes']['pve1']['temp'] = 40.0 + i if i != 2 else None
        rows.append((_ago(60 - 5 * i), {'clusters': {'c1': c}}))
    h.write(rows[:3])
    h.write_legacy(rows[3:4])
    h.write([(_ago(39), {'clusters': {'c1': ['odd']}})] + rows[4:])
    want = sorted(({'ts': ts, 'temp': temp} for ts, nodes in metrics.load_node_history('c1')
                   for temp in [(nodes.get('pve1') or {}).get('temp')] if temp is not None and ts),
                  key=lambda x: x['ts'])
    assert len(want) == 5
    reads, real = [], dbcrypto._heavy_read_now
    monkeypatch.setattr(dbcrypto, '_heavy_read_now', lambda *a, **k: reads.append(1) or real(*a, **k))
    c = api.as_user(seed.user('root', role='admin', tenant_id='default'))
    first = c.get('/api/clusters/c1/nodes/pve1/temperature-history').get_json()
    second = c.get('/api/clusters/c1/nodes/pve1/temperature-history').get_json()
    assert first == second == {'series': want, 'unit': '°C', 'count': 5}
    assert len(reads) == 1
