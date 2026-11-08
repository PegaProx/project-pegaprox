# Full-stack E2E for the Sep-2026 private disclosure: the search endpoints enumerated every VM on a
# reachable cluster with only a cluster-level gate, so a pool-/ACL-scoped user could list (and
# tag-search) VMs outside their grant — the same BOLA class as the #773 /resources leak, but never
# wired into search.py. global_search / search_vms_by_tag / global_summary / get_vm_tags now filter
# per-VM via scope_vm_rows / user_can_access_vm. These drive REAL requests through the REAL app.
import time

import pegaprox.utils.rbac as rbac
from pegaprox.api.search import save_vm_tags


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


# 100 is in the pool user's pool; 101 and 900 are not. All names contain "api" so a single query
# matches every VM — the exact "search for api finds all VMs" the report described.
_VMS = [
    {'vmid': 100, 'name': 'api-db01',  'node': 'n1', 'type': 'qemu', 'status': 'running',
     'cpu': 0.5, 'mem': 120, 'maxmem': 200, 'maxdisk': 10, 'tags': 'web'},
    {'vmid': 101, 'name': 'api-web01', 'node': 'n1', 'type': 'qemu', 'status': 'running',
     'cpu': 0.3, 'mem': 60,  'maxmem': 200, 'maxdisk': 10, 'tags': 'web'},
    {'vmid': 900, 'name': 'api-cache', 'node': 'n2', 'type': 'lxc',  'status': 'stopped',
     'cpu': 0.0, 'mem': 0,   'maxmem': 200, 'maxdisk': 10, 'tags': ''},
]


def _fake_mgr(api, vms=_VMS):
    m = api.make_fake_manager(cluster_id='cluster_1', get_vm_resources=list(vms))
    m.is_connected = True
    m.config.name = 'Cluster One'   # real str so results JSON-serialize
    m.nodes = {}                    # no node rows to reason about here
    return m


def _pool_user(seed):
    # role='viewer' == global vm.view + vm.console (== the reporter's custom role), plus ONE direct
    # pool grant on pool_1 (which contains only VM 100). tenant OWNS the cluster.
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _ids(resp):
    # global_search returns {query, count, results:[...], tag_suggestions}. Node hits carry no vmid.
    return sorted(r.get('vmid') for r in resp.get_json()['results'] if r.get('vmid') is not None)


# ── global_search ──────────────────────────────────────────────────────────
def test_global_search_confines_pool_user(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _fake_mgr(api))
    resp = api.as_user(u).get('/api/global/search?q=api&type=all')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert _ids(resp) == [100], "pool user must only find their own pool VM in global search"


def test_global_search_admin_sees_all(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _fake_mgr(api))
    resp = api.as_user(admin).get('/api/global/search?q=api&type=all')
    assert resp.status_code == 200
    assert _ids(resp) == [100, 101, 900]


def test_global_search_plain_operator_keeps_cluster_wide(api, seed):
    # Regression: a normal role-based user with NO pool/ACL grant (tenant owns the cluster) must
    # still get cluster-wide search — the fix confines only pool-/ACL-scoped callers.
    seed.tenant('tenant_x', clusters=['cluster_1'])
    otto = seed.user('otto', role='viewer', tenant_id='tenant_x')
    api.set_manager('cluster_1', _fake_mgr(api))
    resp = api.as_user(otto).get('/api/global/search?q=api&type=all')
    assert resp.status_code == 200
    assert _ids(resp) == [100, 101, 900]


# ── tag search ─────────────────────────────────────────────────────────────
def test_tag_search_confines_pool_user(api, seed):
    u = _pool_user(seed)
    save_vm_tags({'cluster_1': {'100': [{'name': 'web'}], '101': [{'name': 'web'}]}})
    api.set_manager('cluster_1', _fake_mgr(api))
    resp = api.as_user(u).get('/api/tags/search?tag=web')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    got = sorted(int(r['vmid']) for r in resp.get_json())
    assert got == [100], "pool user must not tag-search foreign VMs"


def test_tag_search_admin_sees_all(api, seed):
    admin = seed.user('root', role='admin')
    save_vm_tags({'cluster_1': {'100': [{'name': 'web'}], '101': [{'name': 'web'}]}})
    api.set_manager('cluster_1', _fake_mgr(api))
    resp = api.as_user(admin).get('/api/tags/search?tag=web')
    assert sorted(int(r['vmid']) for r in resp.get_json()) == [100, 101]


# ── single-VM tag read ─────────────────────────────────────────────────────
def test_get_vm_tags_denies_foreign_vm(api, seed):
    u = _pool_user(seed)
    save_vm_tags({'cluster_1': {'101': [{'name': 'secret'}]}})
    api.set_manager('cluster_1', _fake_mgr(api))
    assert api.as_user(u).get('/api/clusters/cluster_1/vms/100/tags').status_code == 200  # own VM
    assert api.as_user(u).get('/api/clusters/cluster_1/vms/101/tags').status_code == 403  # foreign


# ── summary counts ─────────────────────────────────────────────────────────
def test_global_summary_counts_only_scoped_vms(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _fake_mgr(api))
    body = api.as_user(u).get('/api/global/summary').get_json()
    # only VM 100 (qemu, running) is in the pool user's grant → 1 vm, 0 containers
    assert body['vms']['total'] == 1, body['vms']
    assert body['containers']['total'] == 0, body['containers']


def test_global_summary_admin_counts_all(api, seed):
    admin = seed.user('root', role='admin')
    api.set_manager('cluster_1', _fake_mgr(api))
    body = api.as_user(admin).get('/api/global/summary').get_json()
    assert body['vms']['total'] == 2 and body['containers']['total'] == 1
