"""A time range picked on a chart, answered from the metrics PegaProx stores itself.

The RRD presets of a node or guest have a handful of points in a few hours a week back,
so the charts ask for that range at the 5-minute cadence of the snapshot table instead:
nodes/<node>/metrics-history and vms/<vmid>/metrics-history for CPU and memory, and
from/to on the cluster report summary for the dashboard charts. The read is bounded
(a stride keeps it at about what a chart draws) and never cached. The drag itself is
tested at runtime in test_chart_zoom_ui.py.
MK Oct 2026
"""
import json
import math
import sqlite3
import types
from datetime import datetime, timedelta

import pytest

from test_audit_bola_high_2026_09 import _seed_pool_membership
from test_ha_api import ha_env, _standby_of_active  # noqa: F401

CID = 'cluster_1'
CADENCE = 300
DAYS = 10
NODE = f'/api/clusters/{CID}/nodes/pve1/metrics-history'
GUEST = f'/api/clusters/{CID}/vms/100/metrics-history'
REPORT = f'/api/clusters/{CID}/reports/summary'


def _blob(i):
    nodes = {} if i % 50 == 0 else {'pve1': {'cpu': float(i % 100), 'mem_percent': 40.0 + i % 3,
                                             'maxcpu': 8, 'maxmem': 1}}
    nodes['pve2'] = {'cpu': 1.0, 'mem_percent': 1.0}
    stopped = i % 40 == 0
    return json.dumps({'clusters': {
        CID: {'name': 'Testi', 'nodes': nodes,
              'totals': {'cpu_total': 100, 'cpu_used': i % 100, 'mem_total': 1000, 'mem_used': 500,
                         'vms_running': 2, 'cts_running': 0},
              'vms': {'100': {'t': 'qemu', 'r': not stopped, 'cpu': None if stopped else float(i % 7),
                              'mem': None if stopped else 25.0, 'maxmem': 4, 'maxcpu': 2},
                      '200': {'t': 'qemu', 'r': True, 'cpu': 99.0, 'mem': 99.0, 'maxmem': 4, 'maxcpu': 2}}},
        'cluster_2': {'name': 'Other', 'nodes': {'pve1': {'cpu': 77.0, 'mem_percent': 77.0}},
                      'totals': {}, 'vms': {}},
    }})


@pytest.fixture
def history(monkeypatch):
    """Ten days of snapshots every 5 minutes in a real sqlite table, so the SQL that ships
    is the SQL under test. Row i is i cadences old."""
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE metrics_history (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                 'timestamp TEXT NOT NULL, data TEXT NOT NULL)')
    now = datetime.now().replace(microsecond=0)
    rows = DAYS * 86400 // CADENCE
    for i in range(rows, -1, -1):
        conn.execute('INSERT INTO metrics_history (timestamp, data) VALUES (?, ?)',
                     ((now - timedelta(seconds=CADENCE * i)).isoformat(), _blob(i)))
    conn.commit()
    seen = []

    def fake_run_heavy_read(sql, params=(), cache_key=None, ttl=None, transform=None):
        seen.append((sql, cache_key))
        got = conn.execute(sql, params).fetchall()
        return transform(got) if transform else got

    import pegaprox.core.dbcrypto as dbcrypto
    monkeypatch.setattr(dbcrypto, 'run_heavy_read', fake_run_heavy_read)
    yield types.SimpleNamespace(now=now.timestamp(), seen=seen)
    conn.close()


def _ago(i, h):
    return h.now - CADENCE * i


def _q(h, old, new):
    """from/to for the rows between `old` and `new` cadences ago, a little wider"""
    return f'?from={_ago(old, h) - 10:.0f}&to={_ago(new, h) + 10:.0f}'


def _mgr(api, cid=CID):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = False
    m.config.name = 'Testi'
    return api.set_manager(cid, m)


@pytest.fixture
def root(api, seed):
    _mgr(api)
    return api.as_user(seed.user('root', role='admin'))


# --- the range ----------------------------------------------------------------------------

@pytest.mark.parametrize('args,why', [
    ({}, 'both needed'), ({'from': '1'}, 'both needed'), ({'to': '1'}, 'both needed'),
    ({'from': 'x', 'to': '1'}, 'unix seconds'), ({'from': '1', 'to': 'nan'}, 'unix seconds'),
    ({'from': '1e999', 'to': '1e999'}, 'unix seconds'), ({'from': '-5', 'to': '100'}, 'unix seconds'),
    ({'from': '1000', 'to': '1000'}, 'a minute'), ({'from': '1000', 'to': '1030'}, 'a minute'),
    ({'from': '1000', 'to': '900'}, 'a minute'), ({'from': '0', 'to': str(400 * 86400)}, 'a year'),
])
def test_a_range_that_makes_no_sense_is_refused(args, why):
    from pegaprox.background.metrics import history_range
    start, end, err = history_range(args, now=2e9)
    assert start is None and end is None and why in err


def test_a_range_is_cut_to_what_is_stored(monkeypatch):
    from pegaprox.background.metrics import history_range
    monkeypatch.setenv('PEGAPROX_METRICS_RETENTION_DAYS', '30')
    now = 2e9
    start, end, err = history_range({'from': str(now - 60 * 86400), 'to': str(now + 3600)}, now=now)
    assert err is None and start == now - 30 * 86400 and end == now
    start, end, err = history_range({'from': str(now - 7200), 'to': str(now - 3600.5)}, now=now)
    assert (start, end, err) == (now - 7200, now - 3600.5, None)


# --- the read -----------------------------------------------------------------------------

def _rows(h, old, new):
    from pegaprox.background.metrics import load_metrics_range
    return load_metrics_range(_ago(old, h) - 10, _ago(new, h) + 10, lambda c: c.get(CID, {}).get('totals'))


def test_a_short_range_comes_at_full_resolution_and_oldest_first(history):
    rows = _rows(history, 300, 276)     # two hours, a day back
    assert len(rows) == 25
    stamps = [datetime.fromisoformat(ts).timestamp() for ts, _ in rows]
    assert stamps == sorted(stamps)
    assert stamps[0] == _ago(300, history) and stamps[-1] == _ago(276, history)
    assert [kept['cpu_used'] for _, kept in rows] == [i % 100 for i in range(300, 275, -1)]


def test_a_long_range_is_thinned_to_what_a_chart_draws(history):
    from pegaprox.background.metrics import _RANGE_ROWS
    rows = _rows(history, 9 * 288, 0)    # nine days: 2593 snapshots
    assert _RANGE_ROWS / 2 < len(rows) <= _RANGE_ROWS
    stamps = [datetime.fromisoformat(ts).timestamp() for ts, _ in rows]
    # spread over the whole range, and its newest row is always in it
    assert stamps[-1] == history.now and stamps[0] - _ago(9 * 288, history) < 15 * CADENCE
    steps = {round(b - a) for a, b in zip(stamps, stamps[1:])}
    assert len(steps) == 1, steps


def test_the_read_is_never_cached(history):
    _rows(history, 30, 0)
    _rows(history, 31, 1)
    assert [key for _, key in history.seen] == [None, None]


def test_a_range_without_snapshots_is_empty(history):
    from pegaprox.background.metrics import load_metrics_range
    assert load_metrics_range(history.now - 40 * 86400, history.now - 35 * 86400, lambda c: c) == []
    assert load_metrics_range(history.now, history.now - 10, lambda c: c) == []


# --- the node -----------------------------------------------------------------------------

def test_the_node_route_answers_cpu_and_memory_with_gaps(root, history):
    r = root.get(NODE + _q(history, 120, 90))
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['source'] == 'history' and d['node'] == 'pve1'
    assert d['timestamps'] == [int(_ago(i, history)) for i in range(120, 89, -1)]
    # row 100 has no pve1 (the collector skips an offline node): a gap, not a 0
    assert d['metrics']['cpu'] == [None if i % 50 == 0 else float(i % 100) for i in range(120, 89, -1)]
    assert d['metrics']['memory'][0] == 40.0 + 120 % 3
    assert set(d['metrics']) == {'cpu', 'memory'}


@pytest.mark.parametrize('query', ['', '?from=1', '?from=a&to=b', '?from=200&to=100', '?from=0&to=99999999999'])
def test_the_node_route_refuses_a_bad_range(root, history, query):
    r = root.get(NODE + query)
    assert r.status_code == 400 and r.get_json()['error'], r.data


def test_the_node_route_refuses_a_bad_node_name(root, history):
    r = root.get(f'/api/clusters/{CID}/nodes/-x;id/metrics-history' + _q(history, 10, 0))
    assert r.status_code == 400


def test_the_node_route_wants_node_view(api, seed, history):
    _mgr(api)
    c = api.as_user(seed.user('nope', role='user', permissions=[], denied=['node.view']))
    r = c.get(NODE + _q(history, 10, 0))
    assert r.status_code == 403 and r.get_json()['required'] == 'node.view', r.data


def test_another_tenant_reads_no_node_of_the_cluster(api, seed, history):
    _mgr(api)
    seed.tenant('acme', [CID])
    seed.tenant('initech', ['cluster_2'])
    c = api.as_user(seed.user('milton', role='user', tenant_id='initech'))
    r = c.get(NODE + _q(history, 10, 0))
    assert r.status_code == 403 and b'Access denied to this cluster' in r.data


def test_a_confined_admin_reads_their_tenant_only(api, seed, history):
    _mgr(api)
    _mgr(api, 'cluster_2')
    seed.tenant('acme', [CID])
    seed.tenant('globex', ['cluster_2'])
    c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                              tenant_permissions={'globex': {'role': 'user'}}))
    assert c.get(NODE + _q(history, 10, 0)).status_code == 403
    r = c.get('/api/clusters/cluster_2/nodes/pve1/metrics-history' + _q(history, 10, 0))
    assert r.status_code == 200 and set(r.get_json()['metrics']['cpu']) == {77.0}


# --- the guest ----------------------------------------------------------------------------

def test_the_guest_route_answers_its_own_guest_with_gaps(root, history):
    r = root.get(GUEST + _q(history, 90, 70))
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['vmid'] == 100 and len(d['timestamps']) == 21
    # stopped at row 80: no sample there, as the RRD series has none
    assert d['metrics']['cpu'] == [None if i % 40 == 0 else float(i % 7) for i in range(90, 69, -1)]
    assert d['metrics']['memory'] == [None if i % 40 == 0 else 25.0 for i in range(90, 69, -1)]


def test_a_pool_scoped_user_reads_the_guests_of_the_pool_only(api, seed, history):
    _mgr(api)
    seed.tenant('t_confined', [])
    seed.pool(CID, 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool1'), 200: ('qemu', 'other')})
    c = api.as_user(seed.user('pooled', role='user', tenant_id='t_confined'))
    assert c.get(GUEST + _q(history, 10, 0)).status_code == 200
    r = c.get(f'/api/clusters/{CID}/vms/200/metrics-history' + _q(history, 10, 0))
    assert r.status_code == 403, r.data


def test_the_guest_route_wants_vm_view(api, seed, history):
    _mgr(api)
    c = api.as_user(seed.user('nope', role='user', permissions=[], denied=['vm.view']))
    r = c.get(GUEST + _q(history, 10, 0))
    assert r.status_code == 403 and r.get_json()['required'] == 'vm.view', r.data


def test_another_tenant_reads_no_guest_of_the_cluster(api, seed, history):
    _mgr(api)
    seed.tenant('acme', [CID])
    seed.tenant('initech', ['cluster_2'])
    c = api.as_user(seed.user('milton', role='user', tenant_id='initech'))
    assert c.get(GUEST + _q(history, 10, 0)).status_code == 403


def test_the_guest_route_refuses_a_bad_range(root, history):
    assert root.get(GUEST + '?from=10&to=x').status_code == 400


# --- the dashboard ------------------------------------------------------------------------

def test_the_report_takes_a_range_at_full_resolution(root, history):
    week = root.get(REPORT + '?period=week').get_json()
    r = root.get(REPORT + _q(history, 4 * 288 + 24, 4 * 288))    # two hours, four days back
    assert r.status_code == 200, r.data
    d = r.get_json()
    assert d['period'] == 'range' and d['data_points'] == 25
    stamps = [datetime.fromisoformat(t).timestamp() for t in d['timestamps']]
    assert stamps[0] == _ago(4 * 288 + 24, history) and stamps[-1] == _ago(4 * 288, history)
    assert d['cpu']['samples'] == [float(i % 100) for i in range(4 * 288 + 24, 4 * 288 - 1, -1)]
    # the week has every third snapshot there
    inside = [t for t in week['timestamps'] if stamps[0] <= datetime.fromisoformat(t).timestamp() <= stamps[-1]]
    assert len(inside) < 10
    assert d['from'] <= stamps[0] and d['to'] >= stamps[-1]


def test_the_report_refuses_a_bad_range_and_keeps_its_periods(root, history):
    assert root.get(REPORT + '?from=5').status_code == 400
    assert root.get(REPORT + '?from=5&to=x').status_code == 400
    day = root.get(REPORT + '?period=day').get_json()
    assert day['period'] == 'day' and 'from' not in day and day['data_points'] >= 288


# --- a standby, and the routes themselves -------------------------------------------------

def test_a_standby_answers_from_its_own_history(ha_env, seed, history, monkeypatch):  # noqa: F811
    import pegaprox.api.ha as ha_api
    forwarded = []
    monkeypatch.setattr(ha_api, 'forward_to_active', lambda read=False: forwarded.append(read))
    api = ha_env.api
    _mgr(api)
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    assert ha_env.ha.is_standby()
    for path in (NODE, GUEST, REPORT):
        r = c.get(path + _q(history, 20, 0))
        assert r.status_code == 200, (path, r.data)
        assert r.get_json()['timestamps']
    assert forwarded == []


def test_the_routes_only_read_and_are_served_once(api):
    for rule in ('/api/clusters/<cluster_id>/nodes/<node>/metrics-history',
                 '/api/clusters/<cluster_id>/vms/<int:vmid>/metrics-history'):
        rules = [r for r in api.app.url_map.iter_rules() if r.rule == rule]
        assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']], rule
    # the guest route does not take the place of a /vms/<node>/<vm_type> read
    adapter = api.app.url_map.bind('localhost')
    assert adapter.match('/api/clusters/c1/vms/100/metrics-history', method='GET')[0] == \
        'vms.get_vm_metrics_history_api'


def test_values_that_are_no_numbers_are_gaps():
    from pegaprox.background.metrics import history_series
    now = datetime.now().replace(microsecond=0)
    rows = [(now.isoformat(), {'cpu': True, 'mem_percent': float('nan')}),
            ((now + timedelta(minutes=5)).isoformat(), None),
            ('garbage', {'cpu': 1.0}),
            ((now + timedelta(minutes=10)).isoformat(), {'cpu': 3, 'mem_percent': 'x'})]
    out = history_series(rows, {'cpu': 'cpu', 'memory': 'mem_percent'})
    assert out['timestamps'] == [int(now.timestamp()), int(now.timestamp()) + 300, int(now.timestamp()) + 600]
    assert out['metrics'] == {'cpu': [None, None, 3], 'memory': [None, None, None]}
    assert not any(isinstance(v, float) and math.isnan(v) for v in out['metrics']['memory'] if v is not None)
