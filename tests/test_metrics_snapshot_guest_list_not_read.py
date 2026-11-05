"""A snapshot whose guest list was not read holds no guest counts (background/metrics.py).

get_vm_resources() answers an UnreadList when cluster/resources does not answer (a timeout
at 10k guests, a node that hangs). The collector looped over that empty list and stored
"0 VMs and 0 containers running, 0 stopped" for the snapshot, so the Reports chart and
every reader of the history dipped to zero for a cluster whose guests were all running.
The snapshot keeps its CPU and memory now and leaves the guest counts out, and the readers
skip it (the summaries) or say null (the series that run along the timestamps).

The rows go through the real writer into the test's own database (metrics_history_fixture),
in parts and as an older PegaProx wrote them.
NS Nov 2026
"""
import types
from datetime import datetime, timedelta

import pytest

import metrics_history_fixture as mhf
import pegaprox.api.nodes as nodes_api
import pegaprox.background.metrics as metrics
from pegaprox.core import ha
from pegaprox.core.manager import UnreadList

CID = 'cluster_1'
COUNTS = ('vms_running', 'vms_stopped', 'cts_running', 'cts_stopped')
GUESTS = [{'type': 'qemu', 'status': 'running', 'vmid': 100, 'cpu': 0.5, 'mem': 1, 'maxmem': 2, 'maxcpu': 2, 'node': 'pve1'},
          {'type': 'qemu', 'status': 'running', 'vmid': 101, 'cpu': 0.1, 'mem': 1, 'maxmem': 4, 'maxcpu': 2, 'node': 'pve1'},
          {'type': 'lxc', 'status': 'running', 'vmid': 200, 'cpu': 0.2, 'mem': 1, 'maxmem': 2, 'maxcpu': 1, 'node': 'pve1'},
          {'type': 'qemu', 'status': 'stopped', 'vmid': 102, 'cpu': 0, 'mem': 0, 'maxmem': 2, 'maxcpu': 2, 'node': 'pve1'}]


def _manager(read):
    storage = {'data': [{'storage': 'local', 'maxdisk': 100, 'disk': 25}]}
    session = types.SimpleNamespace(get=lambda url, timeout=None: types.SimpleNamespace(
        status_code=200, json=lambda: storage))
    return types.SimpleNamespace(
        is_connected=True, config=types.SimpleNamespace(name='Lab'), cluster_type='proxmox',
        nodes={'pve1': {'status': 'online', 'cpu': 0.25, 'maxcpu': 8, 'mem': 4, 'maxmem': 16}},
        get_vm_resources=read, host='10.0.0.1', api_port=8006, _create_session=lambda: session)


def _failed():
    raise RuntimeError('cluster/resources timed out')


READS = {'read': lambda: [dict(g) for g in GUESTS], 'unread': lambda: UnreadList(), 'raised': _failed}


@pytest.fixture
def collect(monkeypatch):
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    monkeypatch.setattr(nodes_api, '_hw_consent_state', lambda: (False, {}))
    monkeypatch.setattr(nodes_api, '_redfish_consent_state', lambda: (False, {}))

    def _collect(how):
        monkeypatch.setattr(metrics, 'cluster_managers', {CID: _manager(READS[how])})
        return metrics.collect_metrics_snapshot()['clusters'][CID]
    return _collect


# --- the collector -------------------------------------------------------------------------------

def test_a_guest_list_that_was_read_is_counted(collect):
    cd = collect('read')
    assert [cd['totals'][k] for k in COUNTS] == [2, 1, 1, 0]
    assert set(cd['vms']) == {'100', '101', '102', '200'}


@pytest.mark.parametrize('how', ['unread', 'raised'])
def test_a_guest_list_that_was_not_read_stores_no_counts(collect, how):
    cd = collect(how)
    for k in COUNTS:
        assert k not in cd['totals'], (k, cd['totals'])
    assert cd['vms'] == {}
    # what was read is kept
    assert cd['totals']['cpu_total'] == 8 and cd['totals']['mem_total'] == 16
    assert cd['nodes']['pve1']['cpu'] == 25.0 and cd['storage']['local']['pct'] == 25.0


# --- what the readers make of it -----------------------------------------------------------------

@pytest.fixture(params=['parts', 'legacy'])
def stored(request, db, api, seed, collect, monkeypatch):
    """Three snapshots of the last 15 minutes, the middle one without its guest list."""
    h = mhf.recorded(monkeypatch)
    now = datetime.now()
    rows = [((now - timedelta(minutes=m)).isoformat(), {'clusters': {CID: collect(how)}})
            for m, how in ((15, 'read'), (10, 'unread'), (5, 'read'))]
    h.write(rows, legacy=request.param == 'legacy')
    m = api.make_fake_manager(cluster_id=CID)
    m.is_connected = False          # the history only
    m.config.name = 'Lab'
    api.set_manager(CID, m)
    return api.as_user(seed.user('root', role='admin'))


def test_the_cluster_summary_leaves_the_snapshot_out_of_the_guest_count(stored):
    r = stored.get(f'/api/clusters/{CID}/reports/summary?period=hour')
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d['data_points'] == 3 and len(d['cpu']['samples']) == 3
    assert d['vms_running']['samples'] == [3, 3]
    assert d['vms_running']['min'] == 3 and d['vms_running']['avg'] == 3


def test_the_summary_of_all_clusters_leaves_it_out_as_well(stored):
    r = stored.get('/api/reports/summary?period=hour')
    assert r.status_code == 200, r.get_data(as_text=True)
    vms = r.get_json()['clusters'][CID]['vms_running']
    assert vms['min'] == 3 and vms['avg'] == 3


def test_the_timeline_says_null_where_the_count_was_not_read(stored):
    r = stored.get(f'/api/reports/timeline?period=hour&cluster_id={CID}&metric=vms')
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert len(d['timestamps']) == 3
    assert d['data'][CID]['vms'] == [3, None, 3]


def test_the_long_term_history_says_null_and_its_buckets_keep_what_was_read(stored):
    raw = stored.get(f'/api/clusters/{CID}/insights/history?days=1').get_json()
    assert [(s['vms_running'], s['cts_running']) for s in raw['samples']] == [(2, 1), (None, None), (2, 1)]
    assert all(s['cpu_pct'] == 25.0 for s in raw['samples'])
    one = stored.get(f'/api/clusters/{CID}/insights/history?days=1&step=86400').get_json()
    assert [(s['vms_running'], s['cts_running']) for s in one['samples']] in ([(2, 1)], [(2, 1), (2, 1)])


def test_a_bucket_counts_what_was_read_and_says_null_where_nothing_was():
    from pegaprox.api.insights import _avg_samples
    unread = {'ts': 0, 'cpu_pct': 10, 'mem_pct': 20, 'vms_running': None, 'cts_running': None}
    read = {'ts': 300, 'cpu_pct': 30, 'mem_pct': 40, 'vms_running': 2, 'cts_running': 0}
    out = _avg_samples([unread, read, dict(unread, ts=600)], 0)
    assert (out['vms_running'], out['cts_running'], out['cpu_pct']) == (2, 0, 16.67)
    out = _avg_samples([unread, dict(unread, ts=300)], 0)
    assert out['vms_running'] is None and out['cts_running'] is None and out['cpu_pct'] == 10
