# E2E for the Round-3 audit findings (all "sibling has the per-object gate, this write route missed it"):
#   tag WRITES (search.update_vm_tags / remove_vm_tag), schedules.delete_schedule,
#   snapshots.update_policy (authz was conditional on body targeting fields),
#   site_recovery plan writes (delete_plan et al. skipped _authz_plan_vms).
# mallory holds the needed GLOBAL perms so the per-VM confinement is what's under test.
import time

import pegaprox.utils.rbac as rbac
from pegaprox.api.schedules import save_schedules


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _pool_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                  permissions=['vm.config', 'vm.start', 'vm.snapshot', 'site_recovery.manage'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


# ── tag writes ────────────────────────────────────────────────────────────────
def test_tag_write_foreign_vm_denied(api, seed):
    u = _pool_user(seed)
    assert api.as_user(u).post('/api/clusters/cluster_1/vms/999/tags', json={'tags': [{'name': 'x'}]}).status_code == 403
    assert api.as_user(u).delete('/api/clusters/cluster_1/vms/999/tags/x').status_code == 403


def test_tag_write_own_vm_allowed(api, seed):
    u = _pool_user(seed)
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    resp = api.as_user(u).post('/api/clusters/cluster_1/vms/100/tags', json={'tags': [{'name': 'x'}]})
    assert resp.status_code == 200, resp.get_data(as_text=True)


# ── schedules delete ────────────────────────────────────────────────────────────
def _seed_schedules():
    save_schedules({'actions': [
        {'id': 1, 'cluster_id': 'cluster_1', 'vmid': 100, 'vm_type': 'qemu', 'action': 'start',
         'schedule_type': 'daily', 'time': '02:00', 'enabled': True, 'created_by': 'admin'},
        {'id': 2, 'cluster_id': 'cluster_1', 'vmid': 999, 'vm_type': 'qemu', 'action': 'start',
         'schedule_type': 'daily', 'time': '02:00', 'enabled': True, 'created_by': 'admin'},
    ]})


def test_schedule_delete_foreign_denied(api, seed):
    u = _pool_user(seed)
    _seed_schedules()
    assert api.as_user(u).delete('/api/schedules/2').status_code == 403   # VM 999 foreign


def test_schedule_delete_own_allowed(api, seed):
    u = _pool_user(seed)
    _seed_schedules()
    assert api.as_user(u).delete('/api/schedules/1').status_code == 200   # VM 100 in pool


# ── snapshots update_policy (unconditional target authz) ─────────────────────────
def test_snapshot_policy_update_foreign_denied(api, seed, db):
    u = _pool_user(seed)
    m = api.make_fake_manager(cluster_id='cluster_1',
                              get_vm_resources=[{'vmid': 999, 'name': 'f', 'node': 'n1', 'type': 'qemu'}])
    m.is_connected = True
    api.set_manager('cluster_1', m)
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, created_at) "
                    "VALUES ('pol1','cluster_1','p','vm','999','daily','2026-01-01T00:00:00')")
    db.conn.commit()
    # a body WITHOUT targeting fields must still be authorized against the policy's (foreign) target
    resp = api.as_user(u).put('/api/clusters/cluster_1/snapshot-policies/pol1', json={'enabled': 0})
    assert resp.status_code == 403, resp.get_data(as_text=True)


# ── site_recovery plan writes ────────────────────────────────────────────────────
def _seed_plan(db):
    db.conn.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster) "
                    "VALUES ('plan1','g1','p','cluster_1','cluster_1')")
    db.conn.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type) "
                    "VALUES ('v1','plan1',999,'foreign','qemu')")
    db.conn.commit()


def test_site_recovery_delete_plan_foreign_denied(api, seed, db):
    u = _pool_user(seed)
    _seed_plan(db)
    assert api.as_user(u).delete('/api/site-recovery/plans/plan1').status_code == 403


def test_site_recovery_update_plan_foreign_denied(api, seed, db):
    u = _pool_user(seed)
    _seed_plan(db)
    assert api.as_user(u).put('/api/site-recovery/plans/plan1', json={'name': 'hijack'}).status_code == 403
