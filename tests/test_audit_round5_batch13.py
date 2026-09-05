# E2E for Batch 13 — Round-5 read/list scoping. Two HIGHs plus the "twin route" class: alternate URLs
# that served the same per-VM data as endpoints already scoped in earlier batches, leaving those fixes
# bypassable by simply calling the other URL.
import time
import types
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                  permissions=['storage.view', 'backup.view', 'cluster.view', 'node.view',
                               'vm.snapshot', 'pbs.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── HIGH: PBS protected-vms took an unauthorized caller-supplied cluster_id ────
def test_pbs_protected_vms_foreign_cluster_denied(api, seed):
    u = _pool_user(seed)
    pm = MagicMock()
    pm.connected = True
    pm.linked_clusters = []          # unlinked PBS → check_pbs_access passes (backward compat)
    ppglobals.pbs_managers['pbs1'] = pm
    api.set_manager('cluster_2', api.make_fake_manager(cluster_id='cluster_2'))
    try:
        r = api.as_user(u).get('/api/pbs/pbs1/reports/protected-vms?cluster_id=cluster_2')
        assert r.status_code == 403, r.get_data(as_text=True)
    finally:
        ppglobals.pbs_managers.pop('pbs1', None)


# ── twin: /datastores/<s>/content (the storage.py sibling was scoped earlier) ──
_CONTENT = [
    {'volid': 'local:vm-100-disk-0', 'vmid': 100, 'size': 1, 'content': 'images'},
    {'volid': 'local:vm-200-disk-0', 'vmid': 200, 'size': 1, 'content': 'images'},
    {'volid': 'local:iso/ubuntu.iso', 'content': 'iso', 'size': 1},
]


def _mgr_http(api, payload, cluster_id='cluster_1'):
    m = api.make_fake_manager(cluster_id=cluster_id)
    m.is_connected = True
    m._create_session.return_value.get.return_value = types.SimpleNamespace(
        status_code=200, text='', json=lambda: {'data': payload})
    return m


def test_datastore_content_twin_scoped(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_http(api, _CONTENT))
    body = api.as_user(u).get('/api/clusters/cluster_1/datastores/local/content?node=n1').get_json()
    volids = sorted(r['volid'] for r in body)
    assert 'local:vm-100-disk-0' in volids
    assert 'local:vm-200-disk-0' not in volids, "twin route must not leak a foreign VM's disk"
    assert 'local:iso/ubuntu.iso' in volids, "shared ISO row (no vmid) must stay"


# ── twin: node task list + task log ───────────────────────────────────────────
_NODE_TASKS = [
    {'id': '100', 'vmid': 100, 'type': 'qmstart', 'upid': 'UPID:n1:0:0:0:qmstart:100:root@pam:'},
    {'id': '101', 'vmid': 101, 'type': 'qmstop', 'upid': 'UPID:n1:0:0:0:qmstop:101:root@pam:'},
]


def _mgr_tasks(api):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_node_tasks.return_value = list(_NODE_TASKS)
    m.get_node_task_log.return_value = ['secret log line']
    m.get_node_replication.return_value = [{'id': '100-0', 'guest': 100}, {'id': '101-0', 'guest': 101}]
    return m


def test_node_task_list_scoped(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_tasks(api))
    body = api.as_user(u).get('/api/clusters/cluster_1/nodes/n1/tasks').get_json()
    assert sorted(t['vmid'] for t in body) == [100], f"node task list must be confined; got {body}"


def test_node_task_log_foreign_denied(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_tasks(api))
    upid = 'UPID:n1:0:0:0:qmstop:101:root@pam:'      # field 6 = 101 (foreign)
    assert api.as_user(u).get(f'/api/clusters/cluster_1/nodes/n1/tasks/{upid}/log').status_code == 403


def test_node_task_log_own_allowed(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_tasks(api))
    upid = 'UPID:n1:0:0:0:qmstart:100:root@pam:'     # field 6 = 100 (in mallory's pool)
    r = api.as_user(u).get(f'/api/clusters/cluster_1/nodes/n1/tasks/{upid}/log')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_node_replication_scoped(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', _mgr_tasks(api))
    body = api.as_user(u).get('/api/clusters/cluster_1/nodes/n1/replication').get_json()
    assert sorted(j['guest'] for j in body) == [100]


# ── twin: datacenter replication ──────────────────────────────────────────────
def test_datacenter_replication_scoped(api, seed):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_replication_jobs.return_value = [{'id': '100-0', 'guest': 100}, {'id': '101-0', 'guest': 101}]
    api.set_manager('cluster_1', m)
    body = api.as_user(u).get('/api/clusters/cluster_1/datacenter/replication').get_json()
    assert sorted(j['guest'] for j in body) == [100]


# ── twin: node templates ──────────────────────────────────────────────────────
def test_node_templates_scoped(api, seed):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.cluster_type = 'proxmox'
    m.get_templates.return_value = [{'vmid': 100, 'name': 't100'}, {'vmid': 101, 'name': 't101'}]
    api.set_manager('cluster_1', m)
    body = api.as_user(u).get('/api/clusters/cluster_1/nodes/n1/templates').get_json()
    assert sorted(t['vmid'] for t in body) == [100]


# ── cloud-init deployments ────────────────────────────────────────────────────
def test_deployments_scoped(api, seed, db):
    u = _pool_user(seed)
    for did, vmid in (('d1', 100), ('d2', 200)):
        db.conn.execute(
            "INSERT INTO cloud_init_deployments (id, cluster_id, node, template_id, template_name, "
            "vmid, storage, status, progress, started_by, started_at) "
            "VALUES (?, 'cluster_1','n1','t','T',?,'local','done',100,'admin','2026-01-01')", (did, vmid))
    db.conn.commit()
    body = api.as_user(u).get('/api/clusters/cluster_1/templates/deployments').get_json()['deployments']
    assert sorted(d['vmid'] for d in body) == [100]


# ── snapshot-policy run log gated on the policy's targets ─────────────────────
def test_snapshot_runs_foreign_policy_denied(api, seed, db):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1',
                              get_vm_resources=[{'vmid': 999, 'name': 'f', 'node': 'n1', 'type': 'qemu'}])
    m.is_connected = True
    api.set_manager('cluster_1', m)
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, "
                    "schedule, created_at) VALUES ('polF','cluster_1','p','vm','999','daily','2026-01-01')")
    db.conn.commit()
    r = api.as_user(u).get('/api/clusters/cluster_1/snapshot-policies/polF/runs')
    assert r.status_code == 403, r.get_data(as_text=True)
