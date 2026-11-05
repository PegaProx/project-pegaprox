"""Who may read the long-term history of a cluster (GET /api/clusters/<id>/insights/history).

It asked for 'insights.view', a permission no role holds and the permission list does not
know (the route came with it in June), so everyone but an admin got a 403, while its siblings
right-sizing, forecast, rollups and top-talkers ask for cluster.view and check_cluster_access.
What it answers is the cluster's CPU and memory percentages, the running VM and container
counts of the whole cluster and each node's CPU and memory: no guest of its own. So it asks
what its siblings ask now. A caller confined to some guests of the cluster (a pool grant, a
VM ACL, reached through another tenant) gets no guest counts, as the report summaries give
it none (tests/test_report_guest_counts_are_the_callers_share.py): the history holds the
whole cluster's counts only. CPU, memory and the nodes stay, /metrics gives it those too.
NS Nov 2026
"""
import types

import pytest

import pegaprox.api.insights as insights
from test_audit_bola_high_2026_09 import _seed_pool_membership

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/insights/history?days=7'


def _history(n=4):
    return [(i * 300, {'name': 'c1', 'totals': {'cpu_total': 10, 'cpu_used': 5, 'mem_total': 100, 'mem_used': 25,
                                                 'vms_running': 7, 'cts_running': 3},
                       'nodes': {'pve1': {'cpu': 50.0, 'mem_percent': 25.0}}})
            for i in range(n)]


@pytest.fixture
def env(api, seed, monkeypatch):
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['cluster_other'])
    m = api.make_fake_manager(CID)
    m.config = types.SimpleNamespace(name='c1')
    api.set_manager(CID, m)
    monkeypatch.setattr(insights, '_load_history', lambda *a, **k: _history())
    seed.tenant('t_confined', [])
    seed.pool(CID, 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership(CID, {100: ('qemu', 'pool_1')})
    seed.vm_acl(CID, 100, users=['portal'])
    return types.SimpleNamespace(
        root=api.as_user(seed.user('root', role='admin')),
        ops=api.as_user(seed.user('ops', role='user', tenant_id='acme')),
        view=api.as_user(seed.user('vic', role='viewer', tenant_id='acme')),
        pool=api.as_user(seed.user('mallory', role='viewer', tenant_id='t_confined')),
        acl=api.as_user(seed.user('portal', role='user', tenant_id='globex')),
        stranger=api.as_user(seed.user('eve', role='viewer', tenant_id='globex')),
        no_view=api.as_user(seed.user('nina', role='user', tenant_id='acme', denied=['cluster.view'])))


@pytest.mark.parametrize('who', ['root', 'ops', 'view'])
def test_an_admin_and_a_cluster_wide_cluster_view_caller_read_it_whole(env, who):
    r = getattr(env, who).get(URL)
    assert r.status_code == 200, (who, r.status_code, r.get_data(as_text=True))
    d = r.get_json()
    assert d['sample_count'] == 4 and 'scoped' not in d
    s = d['samples'][0]
    assert (s['cpu_pct'], s['mem_pct'], s['vms_running'], s['cts_running']) == (50.0, 25.0, 7, 3)
    assert s['nodes'] == {'pve1': {'cpu': 50.0, 'mem_percent': 25.0}}


@pytest.mark.parametrize('who', ['pool', 'acl'])
@pytest.mark.parametrize('step', [0, 3600])
def test_a_confined_caller_gets_cpu_memory_and_nodes_but_no_guest_counts(env, who, step):
    r = getattr(env, who).get(URL + f'&step={step}')
    assert r.status_code == 200, (who, r.status_code, r.get_data(as_text=True))
    d = r.get_json()
    assert d.get('scoped') is True and d['samples']
    for s in d['samples']:
        assert 'vms_running' not in s and 'cts_running' not in s, s
        assert (s['cpu_pct'], s['mem_pct']) == (50.0, 25.0)
        assert s['nodes']['pve1']['mem_percent'] == 25.0


@pytest.mark.parametrize('who', ['stranger', 'no_view'])
def test_a_caller_without_the_cluster_or_without_cluster_view_is_refused(env, who):
    r = getattr(env, who).get(URL)
    assert r.status_code == 403, (who, r.status_code, r.get_data(as_text=True))
    assert 'samples' not in (r.get_json() or {})


def test_the_route_asks_what_its_siblings_ask(api):
    rules = {r.rule: r.endpoint for r in api.app.url_map.iter_rules()}
    perms = {}
    for rule in ('/api/clusters/<cluster_id>/insights/history', '/api/clusters/<cluster_id>/insights/forecast',
                 '/api/clusters/<cluster_id>/insights/right-sizing'):
        fn = api.app.view_functions[rules[rule]]
        perms[rule.rsplit('/', 1)[1]] = tuple((getattr(fn, '_pp_auth', None) or {}).get('perms') or ())
    assert perms['history'] == perms['forecast'] == perms['right-sizing'] == ('cluster.view',), perms
