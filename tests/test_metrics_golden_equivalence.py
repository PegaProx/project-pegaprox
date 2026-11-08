"""Every route that reads the metrics history, held against a recording of what it said.

Insights, costs, power, the reports and the node and guest charts all read the 5-minute
snapshots in metrics_history. However those snapshots are stored, the routes have to
answer as before for the same stored data: the same windows and strides, the same rows,
the same rounding and the same order. So ten days of history for three clusters
(tests/metrics_golden_seed.py: churn, migrations, resized and stopped guests, a host
that went away and one that joined, rows from before #965 without a host, a cluster
with entries off the usual shape, temperatures and BMC health, storage, extra rows
from force-snapshot, a two-hour gap and the night the clocks go back) are written
through the real save_metrics_snapshot, and every route below is asked for its answer.
The golden file next to this one holds those answers as the code gave them before the
storage changed.

Every clock the code reads is pinned (datetime and time in each pegaprox module, see
metrics_golden_seed.pin_clocks), the server zone too, and each route is asked cold (the
heavy-read cache and the kept reports forgotten), then once more warm, which has to say
the same. Only the stamps of when a kept report was worked out (VOLATILE) are left out
of the comparison.

The snapshots are stored in parts now (pegaprox/background/metrics_store.py), next to the
JSON rows older versions wrote, which the new code reads as they are until its background
conversion reaches them. Each state of the database a running install can be in has to
answer as the recording says, the same file for all of them:
    new        every row through today's writer;
    legacy     every row as 1.4 and older wrote it (one JSON blob, fmt 0);
    half       the legacy rows, every other one converted by the backfill;
    downgrade  rows of an old version, converted after the upgrade, then rows an older
               version wrote again after a downgrade (its INSERT knows nothing of the
               parts), then today's writer once more, and the backfill converting the
               rows of the downgrade.

Recorded again only on purpose: PEGAPROX_REGEN_GOLDEN=1 rewrites the golden file (from
the state 'new').
MK Oct 2026
"""
import json
import os
import time as _time
from datetime import datetime as _REAL_DATETIME, timedelta, timezone

import pytest

import metrics_golden_seed as seedlib

GOLDEN = os.path.join(os.path.dirname(__file__), 'test_metrics_golden_equivalence.golden.json')
# when a kept report was worked out and whether a newer one is under way: the only parts
# of an answer that depend on when it was asked, not on what is stored
VOLATILE = ('computed_at', 'refreshing')


@pytest.fixture
def server_zone():
    before = os.environ.get('TZ')
    os.environ['TZ'] = seedlib.GOLDEN_TZ
    _time.tzset()
    try:
        yield
    finally:
        if before is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = before
        _time.tzset()


def _golden_now():
    return _REAL_DATETIME(*seedlib.GOLDEN_NOW).timestamp()


# --- the seed against the collector ----------------------------------------------------------

def test_the_seed_builds_what_the_collector_builds(server_zone, monkeypatch):
    """The snapshots of the golden history are only worth something if they are the ones
    collect_metrics_snapshot writes. At the steps that hold the odd cases (guests still
    'running' on a host that went away, a shuffled resource list, a failed guest list, a
    failed storage list, a cluster that was not connected, BMC health 'na' and 'critical',
    a resource row without a vmid) the real collector runs on the same live state, and its
    snapshot has to be the builder's to the byte: keys, key order, types and rounding."""
    import pegaprox.background.metrics as metrics
    import pegaprox.api.nodes as nodes_api
    from pegaprox.core import ha

    fleet = seedlib.golden_fleet(_golden_now())
    for _ in fleet.run():
        pass
    assert set(fleet.captured) == fleet.capture

    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(nodes_api, '_hw_consent_state', lambda: (True, {}))
    monkeypatch.setattr(nodes_api, '_redfish_consent_state', lambda: (False, {}))
    # what the in-band read of each host gave, as the model has it
    monkeypatch.setattr(metrics, '_node_hw_summary', lambda mgr, node: mgr.hw_summary(node))
    seen_kinds = set()
    for step in sorted(fleet.captured):
        live, ts, built = fleet.captured[step]
        managers = {cid: seedlib.FakeManager(cid, lv) for cid, lv in live.items()}
        monkeypatch.setattr(metrics, 'cluster_managers', managers)
        monkeypatch.setattr(metrics, 'datetime', seedlib.clocks(ts)['datetime'])
        snap = metrics.collect_metrics_snapshot()
        assert snap['timestamp'] == _REAL_DATETIME.fromtimestamp(ts).isoformat()
        assert json.dumps(snap['clusters']) == built, f'step {step}'
        for lv in live.values():
            seen_kinds.add(lv['fail'])
        seen_kinds.update('hw ' + (h['health'] if h['available'] else 'na')
                          for lv in live.values() for h in lv['hw'].values() if h is not None)
        seen_kinds.update('blank vmid' for lv in live.values() for r in lv['resources'] if r['vmid'] == '')
        seen_kinds.update('stale' for lv in live.values() for r in lv['resources']
                          if r['status'] == 'running' and 'node' in r
                          and lv['nodes'][r['node']]['status'] != 'online')
    # the steps did hold what they are there for
    assert {'vms', 'storage', 'gone', 'hw critical', 'hw na', 'blank vmid', 'stale'} <= seen_kinds


def test_the_seed_holds_the_cases_it_promises(server_zone):
    """What the golden history is for, counted on the rows themselves."""
    fleet = seedlib.golden_fleet(_golden_now())
    rows = [snap for _ts, snap in fleet.run()]
    stamps = [s['timestamp'] for s in rows]
    c1 = [s['clusters']['cluster_1'] for s in rows]
    assert 2850 <= len(rows) <= 2870
    # the repeated hour: the table order of the naive local stamps is not the write order
    assert stamps != sorted(stamps) and len(set(stamps)) == len(stamps)
    assert sum(1 for t in stamps if t.startswith('2026-10-25T02')) == 24
    # before #965 no host, after it every guest has one
    assert not any('n' in e for e in c1[0]['vms'].values())
    assert all(list(e) == list(seedlib.GUEST_KEYS) for e in c1[-1]['vms'].values())
    # guests come and go, vmids come back, hosts come and go
    assert '277' in c1[-1]['vms'] and '277' not in c1[-60]['vms']
    assert '141' in c1[0]['vms'] and '141' not in c1[-1]['vms']
    assert any('pve6' in c['nodes'] for c in c1) and 'pve6' not in c1[0]['nodes']
    assert any('pve3' not in c['nodes'] for c in c1)
    # the off-shape cluster is off-shape only now and then
    c3 = [s['clusters']['cluster_3']['vms'] for s in rows]
    assert any('note' in v['300'] for v in c3) and any('note' not in v['300'] for v in c3)
    assert any(isinstance(v['301']['cpu'], int) for v in c3)
    # one cycle without cluster_2, one with its guest list lost
    assert sum(1 for s in rows if 'cluster_2' not in s['clusters']) == 1
    assert any(not s['clusters']['cluster_2']['vms'] for s in rows if 'cluster_2' in s['clusters'])


# --- the routes ------------------------------------------------------------------------------

def _routes(now):
    """(label, method, path) of every read held against the golden file."""
    now = int(now)
    nine_d = (now - 9 * 86400 - 600, now)
    three_d = (now - 3 * 86400, now)
    # the night the clocks went back: 00:30 to 02:30 UTC holds 02:00-02:59 local twice
    dst = (int(_REAL_DATETIME(2026, 10, 25, 0, 30, tzinfo=timezone.utc).timestamp()),
           int(_REAL_DATETIME(2026, 10, 25, 2, 30, tzinfo=timezone.utc).timestamp()))
    out = [(label, 'GET', path) for label, path in
           seedlib.cluster_routes('cluster_1', 'pve1', [121, 140, 151, 107, 277], now, 'acme')]
    extra = [
        ('reports/timeline day cluster_2 cpu', '/api/reports/timeline?period=day&cluster_id=cluster_2&metric=cpu'),
        ('cluster_1 report hour', '/api/clusters/cluster_1/reports/summary?period=hour'),
        ('cluster_1 report range 2h', f'/api/clusters/cluster_1/reports/summary?from={now - 7200}&to={now}'),
        ('cluster_1 report range dst', f'/api/clusters/cluster_1/reports/summary?from={dst[0]}&to={dst[1]}'),
        ('cluster_2 report week', '/api/clusters/cluster_2/reports/summary?period=week'),
        ('cluster_3 report day', '/api/clusters/cluster_3/reports/summary?period=day'),
        ('cluster_1 temperature pve3', '/api/clusters/cluster_1/nodes/pve3/temperature-history'),
        ('cluster_1 temperature pve6', '/api/clusters/cluster_1/nodes/pve6/temperature-history'),
        ('cluster_2 temperature edge1', '/api/clusters/cluster_2/nodes/edge1/temperature-history'),
        ('cluster_3 temperature lab-a', '/api/clusters/cluster_3/nodes/lab-a/temperature-history'),
        ('cluster_1 node pve3 history 9d', f'/api/clusters/cluster_1/nodes/pve3/metrics-history?from={nine_d[0]}&to={nine_d[1]}'),
        ('cluster_1 node pve6 history 9d', f'/api/clusters/cluster_1/nodes/pve6/metrics-history?from={nine_d[0]}&to={nine_d[1]}'),
        ('cluster_1 node pve2 history dst', f'/api/clusters/cluster_1/nodes/pve2/metrics-history?from={dst[0]}&to={dst[1]}'),
        ('cluster_2 node edge1 history 3d', f'/api/clusters/cluster_2/nodes/edge1/metrics-history?from={three_d[0]}&to={three_d[1]}'),
        ('cluster_3 node lab-b history 3d', f'/api/clusters/cluster_3/nodes/lab-b/metrics-history?from={three_d[0]}&to={three_d[1]}'),
        ('cluster_1 guest 121 history dst', f'/api/clusters/cluster_1/vms/121/metrics-history?from={dst[0]}&to={dst[1]}'),
        ('cluster_2 guest 999999999 history 9d', f'/api/clusters/cluster_2/vms/999999999/metrics-history?from={nine_d[0]}&to={nine_d[1]}'),
        ('cluster_2 guest 1001 history 3d', f'/api/clusters/cluster_2/vms/1001/metrics-history?from={three_d[0]}&to={three_d[1]}'),
        ('cluster_3 guest 301 history 9d', f'/api/clusters/cluster_3/vms/301/metrics-history?from={nine_d[0]}&to={nine_d[1]}'),
        ('cluster_3 guest 302 history 3d', f'/api/clusters/cluster_3/vms/302/metrics-history?from={three_d[0]}&to={three_d[1]}'),
        ('cluster_3 right-sizing 30', '/api/clusters/cluster_3/insights/right-sizing?days=30'),
        ('cluster_2 right-sizing 7', '/api/clusters/cluster_2/insights/right-sizing?days=7'),
        ('cluster_2 forecast', '/api/clusters/cluster_2/insights/forecast'),
        ('cluster_3 forecast', '/api/clusters/cluster_3/insights/forecast?days=90&threshold_pct=95'),
        ('cluster_3 insights/history 1 step 0', '/api/clusters/cluster_3/insights/history?days=1&step=0'),
        ('cluster_2 insights/history 1 step 900', '/api/clusters/cluster_2/insights/history?days=1&step=900'),
        ('cluster_3 costs summary 30', '/api/clusters/cluster_3/costs/summary?days=30'),
        ('cluster_3 costs per-vm 30', '/api/clusters/cluster_3/costs/per-vm?days=30'),
        ('cluster_2 costs summary 7', '/api/clusters/cluster_2/costs/summary?days=7'),
        ('chargeback default', '/api/tenants/default/chargeback?days=30'),
        ('chargeback acme 7', '/api/tenants/acme/chargeback?days=7'),
        ('cluster_3 power summary 30', '/api/clusters/cluster_3/power/summary?days=30'),
        ('cluster_3 power per-vm 30', '/api/clusters/cluster_3/power/per-vm?days=30'),
        ('cluster_2 power summary 7', '/api/clusters/cluster_2/power/summary?days=7'),
        ('cluster_2 power per-vm 7', '/api/clusters/cluster_2/power/per-vm?days=7'),
    ]
    out += [(label, 'GET', path) for label, path in extra]
    # a snapshot taken on demand goes through the same save, and the reads after it see it
    out.append(('force-snapshot', 'POST', '/api/insights/force-snapshot'))
    after = [
        ('after force reports/summary hour', '/api/reports/summary?period=hour'),
        ('after force cluster_1 node pve1 history 2h', f'/api/clusters/cluster_1/nodes/pve1/metrics-history?from={now - 7200}&to={now}'),
        ('after force cluster_1 guest 121 history 2h', f'/api/clusters/cluster_1/vms/121/metrics-history?from={now - 7200}&to={now}'),
        ('after force cluster_1 temperature pve1', '/api/clusters/cluster_1/nodes/pve1/temperature-history'),
        ('after force cluster_1 right-sizing 1', '/api/clusters/cluster_1/insights/right-sizing?days=1'),
        ('after force cluster_1 insights/history 1 step 3600', '/api/clusters/cluster_1/insights/history?days=1&step=3600'),
        ('after force cluster_1 costs per-vm 1', '/api/clusters/cluster_1/costs/per-vm?days=1'),
        ('after force cluster_1 power summary 1', '/api/clusters/cluster_1/power/summary?days=1'),
    ]
    out += [(label, 'GET', path) for label, path in after]
    return out


def _cold():
    """What a route may keep between two requests, forgotten."""
    from pegaprox.core import dbcrypto
    from pegaprox.api import helpers
    dbcrypto._HEAVY_CACHE.clear()
    helpers.forget_reports()


def _record(resp):
    out = {'status': resp.status_code}
    ctype = resp.headers.get('Content-Type', '')
    if ctype.startswith('application/json'):
        body = resp.get_json()
        if isinstance(body, dict):
            for k in VOLATILE:
                body.pop(k, None)
        out['json'] = body
    else:
        out['content_type'] = ctype
        out['disposition'] = resp.headers.get('Content-Disposition')
        out['text'] = resp.get_data(as_text=True)
    return out


def _dump(answers):
    """One route per line, so a diff of the file names the route that moved. Plain ASCII
    (json's escapes): the answers carry the dashes and umlauts of today's texts verbatim."""
    lines = [f' {json.dumps(label)}: {json.dumps(rec, separators=(",", ":"))}' for label, rec in answers.items()]
    return '{\n' + ',\n'.join(lines) + '\n}\n'


def _first_difference(a, b, path='$'):
    if type(a) is not type(b):
        return f'{path}: {a!r} != {b!r}'
    if isinstance(a, dict):
        if list(a) != list(b):
            return f'{path}: keys {list(a)} != {list(b)}'
        for k in a:
            d = _first_difference(a[k], b[k], f'{path}.{k}')
            if d:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f'{path}: {len(a)} items != {len(b)}'
        for i, (x, y) in enumerate(zip(a, b)):
            d = _first_difference(x, y, f'{path}[{i}]')
            if d:
                return d
        return None
    return None if a == b or (a != a and b != b) else f'{path}: {a!r} != {b!r}'


# --- the states of the stored history ---------------------------------------------------------

STATES = ('new', 'legacy', 'half', 'downgrade')
_ALL_TWINS = {'_cost_stats_cols', '_sizing_stats_cols', '_compute_power_cols'}
TWINS_RUN = {'new': _ALL_TWINS, 'legacy': set(), 'half': _ALL_TWINS - {'_compute_power_cols'},
             'downgrade': _ALL_TWINS}


def _old_save(snapshot):
    """save_metrics_snapshot as 1.4 and older had it: the whole snapshot as one JSON blob
    (json.dumps' default separators), an INSERT that names timestamp and data only, and
    the prune by age, in one write off the hub."""
    import pegaprox.background.metrics as metrics
    from pegaprox.core.dbcrypto import run_heavy_write
    timestamp = snapshot.get('timestamp', metrics.datetime.now().isoformat())
    cutoff = (metrics.datetime.now() - timedelta(days=metrics._retention_days())).isoformat()
    data = json.dumps({k: v for k, v in snapshot.items() if k != 'timestamp'})
    run_heavy_write([("INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)", (timestamp, data)),
                     ("DELETE FROM metrics_history WHERE timestamp < ?", (cutoff,))])


def _formats():
    from pegaprox import constants
    from pegaprox.core import dbcrypto
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        return dict(conn.execute('SELECT fmt, COUNT(*) FROM metrics_history GROUP BY fmt').fetchall())
    finally:
        conn.close()


def _ids(where):
    from pegaprox import constants
    from pegaprox.core import dbcrypto
    conn = dbcrypto.connect(constants.DATABASE_FILE)
    try:
        return [r[0] for r in conn.execute(f'SELECT id FROM metrics_history WHERE {where} ORDER BY id')]
    finally:
        conn.close()


def _write(state, fleet):
    """The golden history into the test's database as `state` has it; the rows written."""
    import pegaprox.background.metrics as metrics
    from pegaprox.background import metrics_store
    if state == 'new':
        return fleet.write(metrics.save_metrics_snapshot)
    if state in ('legacy', 'half'):
        written = fleet.write(_old_save)
        assert _formats() == {0: written}
        if state == 'half':
            done = {}
            for sid in _ids('id % 2 = 0'):
                r = metrics_store.convert_row(sid)
                done[r] = done.get(r, 0) + 1
            assert set(done) == {'parts'} and _formats() == {0: written - done['parts'], 2: done['parts']}
        return written
    # a third written by an old version and converted after the upgrade, a third by an
    # older version again after a downgrade, the rest after the upgrade back
    count, seen = [0], {}

    def save(snapshot):
        i = count[0]
        count[0] += 1
        if i == 950:
            metrics_store.run_backfill(pace=False)
            seen['upgraded'] = _formats()
        if i == 1900:
            seen['downgraded'] = _formats()
        (_old_save if i < 1900 else metrics.save_metrics_snapshot)(snapshot)
    written = fleet.write(save)
    assert seen['upgraded'] == {2: 950}
    # what the older version wrote: rows of the old shape, next to the converted ones
    assert seen['downgraded'] == {0: 950, 2: 950}
    assert metrics_store.run_backfill(pace=False) == {'parts': 950, 'json': 0, 'gone': 0, 'failed': 0}
    assert _formats() == {2: written}
    return written


def _spy_twins(monkeypatch):
    """How often the history reports read guests from columns (the *_cols twins)."""
    from pegaprox.api import costs, insights, power
    calls = []
    for mod, name in ((costs, '_cost_stats_cols'), (insights, '_sizing_stats_cols'),
                      (power, '_compute_power_cols')):
        real = getattr(mod, name)
        monkeypatch.setattr(mod, name, lambda *a, _real=real, _name=name, **k: calls.append(_name) or _real(*a, **k))
    return calls


@pytest.mark.parametrize('state', STATES)
def test_every_history_route_answers_as_recorded(api, seed, server_zone, monkeypatch, state):
    if os.environ.get('PEGAPROX_REGEN_GOLDEN') == '1' and state != 'new':
        pytest.skip('the recording is made from one state')
    monkeypatch.delenv('PEGAPROX_METRICS_RETENTION_DAYS', raising=False)
    now = _golden_now()
    seedlib.pin_clocks(now, monkeypatch.setattr)

    fleet = seedlib.golden_fleet(now)
    written = _write(state, fleet)
    twins = _spy_twins(monkeypatch)
    seedlib.install(seed.db, api.set_manager, fleet, tenants={
        'default': {'name': 'Default', 'clusters': []},
        'acme': {'name': 'ACME Süd', 'clusters': ['cluster_1', 'cluster_3']},
    })
    root = api.as_user(seed.user('root', role='admin'))

    answers = {'_rows_written': {'status': 0, 'json': written}}
    for label, method, path in _routes(now):
        _cold()
        resp = root.post(path) if method == 'POST' else root.get(path)
        rec = answers[label] = _record(resp)
        assert rec['status'] in (200, 404), (label, rec)
        if method == 'GET':
            again = _record(root.get(path))
            assert again == rec, f'{label}: the warm answer differs from the cold one: ' \
                                 f'{_first_difference(rec, again)}'

    # nothing on the way read a wall clock the pin above missed (a module imported late)
    late = [(n, k) for n, m in seedlib.pegaprox_modules() for k, _v in seedlib.real_clocks_in(m)]
    assert not late, f'unpinned clocks: {late[:10]} - import those modules before the pin'

    text = _dump(answers)
    if os.environ.get('PEGAPROX_REGEN_GOLDEN') == '1':
        with open(GOLDEN, 'w', encoding='utf-8') as fh:
            fh.write(text)
        return
    with open(GOLDEN, encoding='utf-8') as fh:
        want = fh.read()
    if text != want:
        golden = json.loads(want)
        moved = [label for label in set(golden) | set(answers) if golden.get(label) != answers.get(label)]
        detail = [f'{label}: {_first_difference(golden.get(label), answers.get(label))}' for label in sorted(moved)[:8]]
        pytest.fail(f'{len(moved)} route(s) answer differently from the recording:\n  ' + '\n  '.join(detail)
                    + ('' if moved else '\n  (same values, different bytes: key order or number form)'))
    # and the column twins did answer some of them: where every row of a window has its
    # guests in columns the reports read those, a row of the old shape still in a window
    # sends it the dict way. Half converted, only the hourly windows (every 12th id, so
    # even ones) are all converted, and those reach back to the rows before #965 that
    # leave the power model nothing to read from columns.
    assert set(twins) == TWINS_RUN[state], (state, sorted(set(twins)))
