# -*- coding: utf-8 -*-
""""Last Week" on the reports page has to mean a week.

The three report endpoints cut their window out of "the newest 1000 snapshot
rows". At the collector's 5-min cadence that cap is ~3.5 days, and a good deal
less on an install where snapshots land more often, so period=week returned
whatever those rows happened to span - in practice the same picture the 24h view
already showed, with nothing in the response saying anything had been cut off.

The read is now bounded by time instead of by row count, and comes back
oldest-first so the timeline charts run left to right and `current` is the
newest sample rather than the oldest one.

The rows are written the way PegaProx stores them (metrics_history_fixture), and once
more the way an older PegaProx did, which the reads take as well.
"""
import types
from datetime import datetime, timedelta

import pytest

import metrics_history_fixture as mhf


CLUSTER = 'cluster_1'
CADENCE_MIN = 5
DAYS_OF_HISTORY = 6


def _snapshot(i):
    return {'clusters': {CLUSTER: {
        'name': 'Cluster One',
        'totals': {'cpu_total': 100, 'cpu_used': 10 + (i % 5),
                   'mem_total': 1000, 'mem_used': 400,
                   'vms_running': 3, 'cts_running': 1},
    }}}


@pytest.fixture(params=['parts', 'legacy'])
def history(db, monkeypatch, request):
    """Six days of real snapshot rows in the test's own database, so the SQL we ship
    is the SQL under test. The heavy-read cache is the db fixture's to clear."""
    h = mhf.recorded(monkeypatch)
    legacy = request.param == 'legacy'
    now = datetime.now()
    rows = (DAYS_OF_HISTORY * 24 * 60) // CADENCE_MIN
    h.write([((now - timedelta(minutes=CADENCE_MIN * i)).isoformat(), _snapshot(i))
             for i in range(rows, 0, -1)], legacy=legacy)

    def add_snapshot(minutes_ago=1):
        """One more row, and its (id, timestamp). Used to land a newest row on an
        id the decimation would otherwise skip."""
        ts = (now - timedelta(minutes=minutes_ago)).isoformat()
        return h.write([(ts, _snapshot(0))], legacy=legacy)[0], ts

    yield types.SimpleNamespace(now=now, rows=rows, seen=h.seen, add_snapshot=add_snapshot)


def _span_hours(timestamps):
    stamps = [datetime.fromisoformat(t) for t in timestamps]
    return (max(stamps) - min(stamps)).total_seconds() / 3600


# --- the loader ---------------------------------------------------------------

def test_a_week_long_window_reaches_back_a_week(history):
    from pegaprox.background.metrics import load_metrics_history
    snaps = load_metrics_history(days=7)['snapshots']
    oldest = datetime.fromisoformat(snaps[0]['timestamp'])
    age_days = (history.now - oldest).total_seconds() / 86400
    assert age_days > 3.5, (
        f'week view only reaches back {age_days:.1f} days - the row cap is still in play')


def test_the_window_is_the_one_that_was_asked_for(history):
    from pegaprox.background.metrics import load_metrics_history
    snaps = load_metrics_history(days=1)['snapshots']
    oldest = datetime.fromisoformat(snaps[0]['timestamp'])
    assert oldest >= history.now - timedelta(days=1, minutes=CADENCE_MIN)


def test_windowed_snapshots_come_back_oldest_first(history):
    from pegaprox.background.metrics import load_metrics_history
    stamps = [s['timestamp'] for s in load_metrics_history(days=7)['snapshots']]
    assert stamps == sorted(stamps), 'a timeline built from these would run backwards'


def test_callers_without_a_window_keep_the_old_row_cap(history):
    """nodes.py asks for "recent" with no window and sorts the result itself."""
    from pegaprox.background.metrics import load_metrics_history
    snaps = load_metrics_history()['snapshots']
    assert len(snaps) == 1000
    assert 'LIMIT 1000' in history.seen[-1]


# --- the endpoint -------------------------------------------------------------

def _cluster(api):
    m = api.make_fake_manager(cluster_id=CLUSTER)
    m.is_connected = False          # no live section, just the history
    m.config.name = 'Cluster One'   # jsonify chokes on a MagicMock name
    return api.set_manager(CLUSTER, m)


def _summary(api, seed, period):
    admin = seed.user('root', role='admin')
    _cluster(api)
    r = api.as_user(admin).get(f'/api/clusters/{CLUSTER}/reports/summary?period={period}')
    assert r.status_code == 200
    return r.get_json()


def test_last_week_shows_more_than_last_24h(api, seed, history):
    day = _summary(api, seed, 'day')
    week = _summary(api, seed, 'week')
    assert _span_hours(day['timestamps']) <= 25
    assert _span_hours(week['timestamps']) > 24 * 5, (
        'week stops short of a week - the row cap is still deciding the window')
    assert week['data_points'] > day['data_points']


def test_an_hour_stays_an_hour(api, seed, history):
    hour = _summary(api, seed, 'hour')
    assert _span_hours(hour['timestamps']) <= 1.1


def test_the_timeline_runs_forward_and_current_is_the_newest_sample(api, seed, history):
    week = _summary(api, seed, 'week')
    assert week['timestamps'] == sorted(week['timestamps'])
    assert week['cpu']['current'] == week['cpu']['samples'][-1]
    # the answer carries the server's UTC offset (test_report_times_carry_their_offset.py)
    newest = datetime.fromisoformat(week['timestamps'][-1])
    assert (history.now.astimezone() - newest).total_seconds() < CADENCE_MIN * 60 + 60, (
        'the last point is an old one - the series is reversed or decimated past the end')


# --- what the decimation must not do -----------------------------------------

def test_the_newest_snapshot_survives_the_decimation(history):
    """A week is read at stride 3. A bare `id % 3 = 0` keeps the last row only
    when its id happens to divide, so two times out of three the newest sample is
    dropped, the chart stops short and the report's `current` is a stride behind
    the data it was read from."""
    from pegaprox.background.metrics import load_metrics_history
    newest_id, newest_ts = history.add_snapshot()
    assert newest_id % 3 != 0, 'this fixture no longer lands on a row a plain modulo drops'
    snaps = load_metrics_history(days=7)['snapshots']
    assert snaps[-1]['timestamp'] == newest_ts


def test_a_windowed_read_stays_bounded(history, monkeypatch):
    """A window is a time span, so the row count is whatever the install wrote in
    it. The cap is the backstop the old flat LIMIT used to be, and it trims the
    OLD end so the recent resolution the charts are about survives."""
    import pegaprox.background.metrics as metrics
    monkeypatch.setattr(metrics, '_WINDOW_ROW_CAP', 50)
    _, newest_ts = history.add_snapshot()
    snaps = metrics.load_metrics_history(days=7)['snapshots']
    assert len(snaps) == 50
    assert snaps[-1]['timestamp'] == newest_ts


def test_the_week_read_uses_the_shared_decimation_policy(history):
    """Second copy of the stride policy here is how the two drift apart."""
    from pegaprox.api.helpers import _history_stride
    from pegaprox.background.metrics import load_metrics_history
    snaps = load_metrics_history(days=7)['snapshots']
    in_window = min(history.rows, 7 * 24 * 60 // CADENCE_MIN)
    assert len(snaps) == pytest.approx(in_window / _history_stride(7), rel=0.05)


# --- what a cached window holds (#963 follow-up) --------------------------------

@pytest.fixture(params=['parts', 'legacy'])
def fleet_history(db, monkeypatch, request):
    """Snapshots the way the collector writes them: totals plus a node, guest and
    storage map per cluster, and one cluster that carries no name. Records what each
    read hands back, which is what run_heavy_read keeps in its cache."""
    h = mhf.recorded(monkeypatch)
    now = datetime.now()
    totals = {'cpu_total': 100, 'cpu_used': 25, 'mem_total': 1000, 'mem_used': 500,
              'vms_running': 2, 'cts_running': 1}
    snaps = []
    for i in range(3, 0, -1):
        snaps.append(((now - timedelta(minutes=CADENCE_MIN * i)).isoformat(), {'clusters': {
            CLUSTER: {'name': 'Cluster One', 'totals': totals,
                      'nodes': {'pve1': {'cpu': 25.0, 'temp': 51}},
                      'vms': {str(100 + n): {'t': 'qemu', 'r': True, 'cpu': 1.0, 'mem': 2.0,
                                             'maxmem': 1, 'maxcpu': 1} for n in range(50)},
                      'storage': {'local': {'used': 1, 'total': 2, 'pct': 50.0}}},
            'cluster_2': {'totals': totals},
        }}))
    h.write(snaps, legacy=request.param == 'legacy')
    yield h.keyed


def test_a_report_read_keeps_only_names_and_totals(api, seed, fleet_history):
    """A cached window stays in memory until the next read of it replaces it, and at
    10k guests nearly all of a parsed snapshot is the guest map. The reports read a
    cluster's name and totals, so that is all their read may keep."""
    admin = seed.user('root', role='admin')
    _cluster(api)
    for url in (f'/api/clusters/{CLUSTER}/reports/summary?period=week',
                '/api/reports/summary?period=day', '/api/reports/timeline?period=hour'):
        r = api.as_user(admin).get(url)
        assert r.status_code == 200, (url, r.get_json())
    assert fleet_history, 'no history read happened'
    for key, snaps in fleet_history:
        assert snaps, key
        for snap in snaps:
            for cid, cluster in snap['clusters'].items():
                assert set(cluster) <= {'name', 'totals'}, (key, cid, sorted(cluster))


def test_the_trimmed_read_still_answers_the_same(api, seed, fleet_history):
    admin = seed.user('root', role='admin')
    _cluster(api)
    one = api.as_user(admin).get(f'/api/clusters/{CLUSTER}/reports/summary?period=day').get_json()
    assert one['data_points'] == 3
    assert one['cpu']['current'] == 25.0 and one['memory']['current'] == 50.0
    assert one['vms_running']['current'] == 3
    every = api.as_user(admin).get('/api/reports/summary?period=day').get_json()
    assert every['clusters'][CLUSTER]['name'] == 'Cluster One'
    # a cluster without a name still falls back to its id, as before the trim
    assert every['clusters']['cluster_2']['name'] == 'cluster_2'


def test_a_full_read_and_a_trimmed_one_never_share_a_cache_entry(fleet_history):
    """The node temperature history reads the nodes map: a trimmed window served to it
    from the same cache entry would come back empty."""
    from pegaprox.background.metrics import load_metrics_history
    full = load_metrics_history(days=1)['snapshots']
    trimmed = load_metrics_history(days=1, totals_only=True)['snapshots']
    assert full[-1]['clusters'][CLUSTER]['nodes']['pve1']['temp'] == 51
    assert 'nodes' not in trimmed[-1]['clusters'][CLUSTER]
    keys = [key for key, _ in fleet_history]
    assert len(set(keys)) == 2, keys
