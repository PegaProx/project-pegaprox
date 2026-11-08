"""The report summaries count only the running guests a confined caller may see.

check_cluster_access lets a caller with a pool grant or a VM ACL reach the cluster, and
the report summary then counted every running VM and container on it, live and from
the history, which keeps the cluster's totals only. Such a caller learnt how many guests
outside their grant were running. Now they get their own guests, counted live, no
history samples of the count, and "scoped": true, as power and costs already do. CPU
and memory stay: /metrics gives the same caller every node's figures. The summary over
all clusters does the same for a cluster reached through a grant, and the report
timeline leaves the count series out for it.
MK Oct 2026
"""
import types
from datetime import datetime, timedelta

import pytest

import pegaprox.api.reports as rep

from test_audit_bola_high_2026_09 import _seed_pool_membership

CID = 'cluster_1'
GUESTS = [
    {'vmid': 100, 'type': 'qemu', 'status': 'running', 'node': 'pve1'},
    {'vmid': 101, 'type': 'qemu', 'status': 'stopped', 'node': 'pve1'},
    {'vmid': 200, 'type': 'qemu', 'status': 'running', 'node': 'pve1'},
    {'vmid': 201, 'type': 'lxc', 'status': 'running', 'node': 'pve1'},
]
SAMPLES = 6


@pytest.fixture
def env(api, seed, monkeypatch):
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['cluster_other'])
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.config = types.SimpleNamespace(name='c1')
    m.get_node_status.return_value = {'pve1': {'status': 'online', 'cpu_percent': 50, 'mem_percent': 40,
                                               'mem_total': 100, 'mem_used': 40}}
    m.get_vm_resources.return_value = list(GUESTS)
    api.set_manager(CID, m)
    now = datetime.now()
    snaps = [{'timestamp': (now - timedelta(minutes=5 * i)).isoformat(),
              'clusters': {CID: {'name': 'c1', 'totals': {
                  'cpu_total': 100, 'cpu_used': 25, 'mem_total': 1000, 'mem_used': 500,
                  'vms_running': 7, 'cts_running': 3}}}}
             for i in range(SAMPLES, 0, -1)]
    monkeypatch.setattr(rep, 'load_metrics_history', lambda days=1, totals_only=True: {'snapshots': snaps})
    # pool grants on pool_1, which holds guest 100 and the stopped 101: for a user of a
    # tenant without clusters, one of another tenant and one of the default tenant
    seed.tenant('t_confined', [])
    for name in ('mallory', 'gina', 'dora'):
        seed.pool(CID, 'pool_1', name, ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1'), 101: ('qemu', 'pool_1'),
                                200: ('qemu', 'other'), 201: ('lxc', 'other')})
    # a VM ACL on guest 100 for a user of another tenant
    seed.vm_acl(CID, 100, users=['portal'])
    return types.SimpleNamespace(
        pool=api.as_user(seed.user('mallory', role='viewer', tenant_id='t_confined')),
        gina=api.as_user(seed.user('gina', role='viewer', tenant_id='globex')),
        dora=api.as_user(seed.user('dora', role='viewer')),
        acl=api.as_user(seed.user('portal', role='user', tenant_id='globex')),
        ops=api.as_user(seed.user('ops', role='user', tenant_id='acme')),
        root=api.as_user(seed.user('root', role='admin')))


@pytest.mark.parametrize('who', ['pool', 'gina', 'dora', 'acl'])
def test_a_confined_caller_counts_its_own_running_guests(env, who):
    r = getattr(env, who).get(f'/api/clusters/{CID}/reports/summary?period=day')
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert (d['live']['vms_running'], d['live']['cts_running']) == (1, 0)
    assert d['vms_running']['samples'] == []
    assert d['vms_running']['current'] == d['vms_running']['max'] == 1
    assert d.get('scoped') is True
    # CPU and memory keep the cluster's history
    assert d['cpu']['samples'] == [25.0] * SAMPLES and d['memory']['current'] == 50.0


@pytest.mark.parametrize('who', ['ops', 'root'])
def test_a_cluster_wide_caller_keeps_the_whole_count(env, who):
    d = getattr(env, who).get(f'/api/clusters/{CID}/reports/summary?period=day').get_json()
    assert (d['live']['vms_running'], d['live']['cts_running']) == (2, 1)
    assert d['vms_running']['samples'] == [10] * SAMPLES
    assert 'scoped' not in d


@pytest.mark.parametrize('who', ['gina', 'dora'])
def test_the_summary_over_all_clusters_gives_a_pool_caller_its_share(env, who):
    r = getattr(env, who).get('/api/reports/summary?period=day')
    assert r.status_code == 200, r.get_data(as_text=True)
    c = r.get_json()['clusters'][CID]
    assert c['vms_running'] == {'avg': 1, 'min': 1, 'max': 1, 'current': 1}
    assert c.get('scoped') is True
    assert c['cpu']['current'] == 25.0
    # counterproof: the cluster-wide operator gets the cluster's history
    c = env.ops.get('/api/reports/summary?period=day').get_json()['clusters'][CID]
    assert c['vms_running']['current'] == 10 and 'scoped' not in c


@pytest.mark.parametrize('who', ['gina', 'dora'])
def test_the_timeline_gives_a_pool_caller_no_count_of_the_whole_cluster(env, who):
    r = getattr(env, who).get('/api/reports/timeline?period=day&metric=vms')
    assert r.status_code == 200, r.get_data(as_text=True)
    c = r.get_json()['data'][CID]
    assert c['vms'] == [] and c.get('scoped') is True
    c = getattr(env, who).get('/api/reports/timeline?period=day').get_json()['data'][CID]
    assert c['vms'] == [] and c['cpu'] == [25.0] * SAMPLES
    # counterproof: the cluster-wide operator gets the series
    c = env.ops.get('/api/reports/timeline?period=day&metric=vms').get_json()['data'][CID]
    assert c['vms'] == [10] * SAMPLES and 'scoped' not in c
