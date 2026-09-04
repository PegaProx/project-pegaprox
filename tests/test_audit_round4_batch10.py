# E2E for the Round-4 fixes:
#   - snapshots.update_policy: the Batch-8 fix made the manager lookup unconditional → a non-targeting
#     edit ({"enabled":0}) 404'd when the cluster was offline (regression, hit admins + owners). Now it
#     authorizes offline via the stored direct-VM target, never 404s, and still denies foreign targets.
#   - vms.delete_vm_backup: authorized only the URL vmid, not the source vmid embedded in the volid →
#     a scoped backup.delete holder could delete another VM's backup. Now gated on the source vmid.
import time

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
                  permissions=['vm.snapshot', 'vm.backup', 'backup.delete'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def _seed_policy(db, pid, vmid):
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, created_at) "
                    "VALUES (?, 'cluster_1','p','vm',?,'daily','2026-01-01T00:00:00')", (pid, str(vmid)))
    db.conn.commit()


# ── snapshots.update_policy offline regression + security ───────────────────────
def test_policy_edit_offline_no_404_admin(api, seed, db):
    admin = seed.user('root', role='admin')
    _seed_policy(db, 'polA', 100)
    # NO manager registered (cluster offline) — a non-targeting edit must NOT 404
    resp = api.as_user(admin).put('/api/clusters/cluster_1/snapshot-policies/polA', json={'enabled': 0})
    assert resp.status_code == 200, resp.get_data(as_text=True)


def test_policy_edit_offline_own_vm_allowed(api, seed, db):
    u = _pool_user(seed)
    _seed_policy(db, 'polOwn', 100)   # targets VM 100 (in mallory's pool)
    resp = api.as_user(u).put('/api/clusters/cluster_1/snapshot-policies/polOwn', json={'enabled': 0})
    assert resp.status_code == 200, resp.get_data(as_text=True)


def test_policy_edit_offline_foreign_vm_denied(api, seed, db):
    u = _pool_user(seed)
    _seed_policy(db, 'polFor', 999)   # targets foreign VM 999 — security must hold even offline
    resp = api.as_user(u).put('/api/clusters/cluster_1/snapshot-policies/polFor', json={'enabled': 0})
    assert resp.status_code == 403, resp.get_data(as_text=True)


# ── delete_vm_backup source-vmid IDOR ───────────────────────────────────────────
def test_delete_backup_foreign_source_denied(api, seed):
    u = _pool_user(seed)
    # path vmid=100 (mallory's own) but the volid's SOURCE is VM 200 (foreign)
    volid = 'local:backup/vzdump-qemu-200-2026_01_01-00_00_00.vma.zst'
    resp = api.as_user(u).delete(f'/api/clusters/cluster_1/vms/n1/qemu/100/backups/{volid}')
    assert resp.status_code == 403, resp.get_data(as_text=True)


def test_delete_backup_own_source_passes_gate(api, seed):
    u = _pool_user(seed)
    # source VM 100 (mallory's own) — both the path-vmid and source-vmid checks pass; whatever the
    # (absent) manager does next, it must NOT be our source/vmid 403.
    volid = 'local:backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst'
    resp = api.as_user(u).delete(f'/api/clusters/cluster_1/vms/n1/qemu/100/backups/{volid}')
    assert not (resp.status_code == 403 and 'source backup' in resp.get_data(as_text=True))
    assert not (resp.status_code == 403 and 'vm.backup' in resp.get_data(as_text=True))
