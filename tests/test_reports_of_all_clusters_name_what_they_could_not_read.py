"""The readers across clusters say what they could not read (api/reports.py, metrics_exporter).

GET /api/reports/top-vms walked every cluster and dropped one that was not connected, whose
guest list did not answer (an UnreadList) or whose read raised, so a ranking of two clusters
out of three passed for the whole fleet. The body stays the list it was, and the clusters it
has no rows of are named in the X-Unread-Clusters header (a JSON list of their ids).

The Prometheus exporter wrote pegaprox_cluster_vms_total and pegaprox_cluster_vms_running as
0 for a guest list that did not answer, which an alert on "running guests dropped" reads as
every guest down. That scrape has no such samples for the cluster now.

The summary across clusters gave vms_running 0 for a cluster whose every snapshot in the
window had no guest count (the collector leaves the counts out when the guest list was not
read), and the timeline put 0 % CPU and memory at a snapshot without totals. Both are null.
"""
import json
import types
from datetime import datetime, timedelta

import pytest

from pegaprox.core.manager import UnreadList
# the exporter's fakes and the autouse fixture that runs its background reads inline
from test_metrics_exporter_breadth import GUESTS as PVE_GUESTS, _Pve, _find, _fresh, _scrape  # noqa: F401

ROW = {'vmid': 100, 'type': 'qemu', 'status': 'running', 'node': 'pve1', 'name': 'web',
       'cpu': 0.5, 'mem': 1, 'maxmem': 4}


def _cluster(api, cid, name, read=None, connected=True, raises=None):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = connected
    m.config = types.SimpleNamespace(name=name)
    if raises is not None:
        m.get_vm_resources.side_effect = raises
    else:
        m.get_vm_resources.return_value = read
    return api.set_manager(cid, m)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


# --- the ranking of every cluster ------------------------------------------------------------

def test_every_cluster_read_carries_no_unread_header(api, admin):
    _cluster(api, 'cluster_1', 'one', [dict(ROW)])
    _cluster(api, 'cluster_2', 'two', [dict(ROW, vmid=200, name='db', cpu=0.9)])
    r = admin.get('/api/reports/top-vms')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [v['vmid'] for v in r.get_json()] == [200, 100]
    assert 'X-Unread-Clusters' not in r.headers


def test_a_cluster_that_was_not_read_is_named_not_dropped(api, admin):
    _cluster(api, 'cluster_1', 'one', [dict(ROW)])
    _cluster(api, 'cluster_2', 'two', UnreadList())
    _cluster(api, 'cluster_3', 'three', connected=False)
    _cluster(api, 'cluster_4', 'four', raises=RuntimeError('cluster/resources timed out'))
    # a row the ranking cannot read after one it could: none of that cluster's rows stay
    _cluster(api, 'cluster_5', 'five', [dict(ROW, vmid=500, cpu=0.99), 'garbage'])
    r = admin.get('/api/reports/top-vms?metric=cpu')
    assert r.status_code == 200, r.get_data(as_text=True)
    # the body is the list it always was, of what was read
    assert [(v['cluster_id'], v['vmid']) for v in r.get_json()] == [('cluster_1', 100)]
    assert sorted(json.loads(r.headers['X-Unread-Clusters'])) == [
        'cluster_2', 'cluster_3', 'cluster_4', 'cluster_5']


def test_a_cluster_outside_the_callers_tenant_is_never_named(api, seed):
    seed.tenant('t1', clusters=['cluster_1'])
    tina = api.as_user(seed.user('tina', role='viewer', tenant_id='t1'))
    _cluster(api, 'cluster_1', 'one', [dict(ROW)])
    _cluster(api, 'cluster_2', 'two', UnreadList())
    r = tina.get('/api/reports/top-vms')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [v['cluster_id'] for v in r.get_json()] == ['cluster_1']
    assert 'X-Unread-Clusters' not in r.headers


# --- the Prometheus exporter -----------------------------------------------------------------

class _PveUnread(_Pve):
    def get_vm_resources(self, max_age=0):
        return UnreadList()


def test_the_exporter_leaves_out_the_counts_of_a_guest_list_that_did_not_answer(api):
    api.set_manager('c1', _Pve('Testi', PVE_GUESTS))
    api.set_manager('c2', _PveUnread('Lost'))
    body = _scrape(api)
    for name in ('pegaprox_cluster_vms_total', 'pegaprox_cluster_vms_running'):
        assert _find(body, name, cluster_id='c2') == [], name
    assert _find(body, 'pegaprox_cluster_connected', cluster_id='c2')[0][1] == 1
    # the cluster that was read keeps its counts
    assert _find(body, 'pegaprox_cluster_vms_total', cluster_id='c1')[0][1] == len(PVE_GUESTS)
    assert _find(body, 'pegaprox_cluster_vms_running', cluster_id='c1')[0][1] == 2


# --- the summary and the timeline of every cluster -------------------------------------------

def _history(monkeypatch, *totals):
    import pegaprox.api.reports as rep
    now = datetime.now()
    snaps = [{'timestamp': (now - timedelta(minutes=5 * (len(totals) - i))).isoformat(),
              'clusters': {'cluster_1': {'name': 'one', 'totals': t}}} for i, t in enumerate(totals)]
    monkeypatch.setattr(rep, 'load_metrics_history', lambda days=1, totals_only=True: {'snapshots': snaps})


FULL = {'cpu_total': 8, 'cpu_used': 2, 'mem_total': 16, 'mem_used': 4, 'vms_running': 3, 'cts_running': 1}
NO_GUESTS = {'cpu_total': 8, 'cpu_used': 2, 'mem_total': 16, 'mem_used': 4}


def test_the_summary_of_all_clusters_says_null_where_no_snapshot_had_a_count(api, admin, monkeypatch):
    _cluster(api, 'cluster_1', 'one', connected=False)
    _history(monkeypatch, NO_GUESTS, NO_GUESTS)
    r = admin.get('/api/reports/summary?period=hour')
    assert r.status_code == 200, r.get_data(as_text=True)
    c = r.get_json()['clusters']['cluster_1']
    assert c['vms_running'] == {'avg': None, 'min': None, 'max': None, 'current': None}
    assert c['cpu']['current'] == 25.0


def test_the_summary_of_all_clusters_counts_a_window_with_one_count(api, admin, monkeypatch):
    _cluster(api, 'cluster_1', 'one', connected=False)
    _history(monkeypatch, NO_GUESTS, FULL)
    c = admin.get('/api/reports/summary?period=hour').get_json()['clusters']['cluster_1']
    assert c['vms_running'] == {'avg': 4, 'min': 4, 'max': 4, 'current': 4}


def test_the_timeline_says_null_where_a_snapshot_has_no_totals(api, admin, monkeypatch):
    _cluster(api, 'cluster_1', 'one', connected=False)
    _history(monkeypatch, FULL, {'cpu_total': 0, 'mem_total': 0}, {}, FULL)
    r = admin.get('/api/reports/timeline?period=hour&cluster_id=cluster_1')
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()['data']['cluster_1']
    assert d['cpu'] == [25.0, None, None, 25.0]
    assert d['memory'] == [25.0, None, None, 25.0]
    assert d['vms'] == [4, None, None, 4]
