# E2E for the Round-5 fixes to my OWN earlier work:
#  (1) the confinement predicate was open-coded as "(not is_owner) or has_pool_access", which misses a
#      VM-ACL-scoped caller whose tenant DOES own the cluster (the Client Portal case). Those callers
#      were treated as plain cluster-wide operators, so the tasks/audit/pools confinements were no-ops
#      for them. Now centralised in helpers.caller_is_scoped, which also counts VM-ACL scope.
#  (2) the backup-job list reused the WRITE gate for a read, blanking the page for every non-admin.
import time

import pegaprox.utils.rbac as rbac
from pegaprox.utils.audit import log_audit


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _acl_user(seed):
    """Client-Portal shape: tenant OWNS the cluster, no pool grant, scoped by VM-ACL to VM 100."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('portal', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.vm_acl('cluster_1', 100, users=['portal'])
    rbac.invalidate_vm_acls_cache()
    return u


def _plain_operator(seed):
    seed.tenant('tenant_y', clusters=['cluster_1'])
    return seed.user('otto', role='viewer', tenant_id='tenant_y', permissions=['cluster.view'])


_TASKS = [
    {'id': 100, 'type': 'qmstart', 'node': 'n1'},
    {'id': 101, 'type': 'qmstop', 'node': 'n1'},
    {'node': 'n1', 'type': 'vzdump'},
]


def _task_mgr(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_tasks.return_value = list(_TASKS)
    return m


# ── (1) VM-ACL-scoped caller is now actually confined ─────────────────────────
def test_acl_scoped_user_confined_on_tasks(api, seed):
    u = _acl_user(seed)
    api.set_manager('cluster_1', _task_mgr(api))
    body = api.as_user(u).get('/api/clusters/cluster_1/tasks').get_json()
    assert sorted(t.get('id') for t in body) == [100], f"ACL-scoped portal user must be confined; got {body}"


def test_plain_operator_still_full_tasks(api, seed):
    otto = _plain_operator(seed)
    rbac.tenants_db = {}
    api.set_manager('cluster_1', _task_mgr(api))
    body = api.as_user(otto).get('/api/clusters/cluster_1/tasks').get_json()
    assert len(body) == 3, "plain cluster-wide operator keeps the full task log"


def test_acl_scoped_user_confined_on_audit_log(api, seed):
    u = _acl_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.config.name = 'Cluster One'
    api.set_manager('cluster_1', m)
    log_audit('op', 'vm.start', 'Started VM 100', cluster='Cluster One')
    log_audit('op', 'vm.start', 'Started VM 999', cluster='Cluster One')
    details = ' | '.join(e.get('details', '') for e in api.as_user(u).get('/api/clusters/cluster_1/audit').get_json())
    assert 'VM 100' in details and 'VM 999' not in details


# ── (2) backup-job list: regression fixed, leak still closed ──────────────────
_JOBS = [
    {'id': 'job1', 'vmid': '100', 'schedule': 'daily'},
    {'id': 'job2', 'vmid': '200', 'schedule': 'daily'},
    {'id': 'job3', 'all': '1', 'schedule': 'daily'},
]


def _jobs_mgr(api):
    import types
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m._create_session.return_value.get.return_value = types.SimpleNamespace(
        status_code=200, text='', json=lambda: {'data': _JOBS})
    return m


def test_backup_jobs_plain_operator_sees_all(api, seed):
    otto = _plain_operator(seed)
    rbac.tenants_db = {}
    api.set_manager('cluster_1', _jobs_mgr(api))
    body = api.as_user(otto).get('/api/clusters/cluster_1/datacenter/backup').get_json()
    assert sorted(j['id'] for j in body) == ['job1', 'job2', 'job3'], \
        "regression: a plain cluster-wide operator must still see the whole backup-job list"


def test_backup_jobs_scoped_user_confined(api, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x', permissions=['backup.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    api.set_manager('cluster_1', _jobs_mgr(api))
    body = api.as_user(u).get('/api/clusters/cluster_1/datacenter/backup').get_json()
    assert sorted(j['id'] for j in body) == ['job1'], "scoped caller sees only jobs targeting their VMs"
