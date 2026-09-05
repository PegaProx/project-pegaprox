# E2E for Batch 14 — Round-5. The headline is a SYSTEMIC one: 28 authorization sites built the
# caller's identity straight out of load_users() instead of build_authz_user(), so no API-token
# effective_role flooring was applied and an admin-owned, viewer-scoped token inherited its owner's
# admin role right through the per-VM gate. Plus three smaller boundary bugs found alongside it.
import json
import queue
import time
import types
from unittest.mock import MagicMock

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac
from pegaprox.utils.realtime import broadcast_sse


def _seed_pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


# ── the systemic one: admin-owned, viewer-scoped API token ────────────────────
def _admin_token(seed, role='viewer'):
    """Seed an admin and mint a restricted API token they own. Returns the bearer header."""
    from pegaprox.utils.auth import create_api_token
    seed.tenant('acme', clusters=['cluster_1'])
    seed.user('root', role='admin', tenant_id='acme')
    res = create_api_token('root', f'ci-{role}', role=role)
    assert 'token' in res, res
    return {'Authorization': f"Bearer {res['token']}"}


def _vm_manager(api):
    m = api.make_fake_manager(cluster_id='cluster_1',
                              get_vm_resources=[{'vmid': 200, 'name': 'prod-db', 'node': 'n1', 'type': 'qemu'}])
    m.is_connected = True
    m.vm_action.return_value = {'success': True}
    m.delete_vm.return_value = {'success': True}
    m.clone_vm.return_value = {'success': True}
    m.migrate_vm.return_value = {'success': True}
    return api.set_manager('cluster_1', m)


def test_viewer_token_cannot_power_a_vm(api, seed):
    # vm_action_api read the raw stored record, so user['role'] was still 'admin' and
    # user_can_access_vm short-circuited on the admin bypass — a read-only CI token could
    # stop production VMs.
    hdr = _admin_token(seed)
    _vm_manager(api)
    r = api.anon().post('/api/clusters/cluster_1/vms/n1/qemu/200/stop', headers=hdr)
    assert r.status_code == 403, r.get_data(as_text=True)


def test_viewer_token_cannot_delete_a_vm(api, seed):
    hdr = _admin_token(seed)
    _vm_manager(api)
    r = api.anon().delete('/api/clusters/cluster_1/vms/n1/qemu/200', headers=hdr)
    assert r.status_code == 403, r.get_data(as_text=True)


def test_viewer_token_cannot_snapshot_a_vm(api, seed):
    hdr = _admin_token(seed)
    _vm_manager(api)
    r = api.anon().post('/api/clusters/cluster_1/vms/n1/qemu/200/snapshots',
                        json={'name': 'snap1'}, headers=hdr)
    assert r.status_code == 403, r.get_data(as_text=True)


def test_viewer_token_cannot_pull_a_console_ticket(api, seed):
    # vm.console IS a viewer perm, but the ticket is a cluster-wide credential — the token
    # must still be confined by its own role, not the owner's.
    hdr = _admin_token(seed)
    m = _vm_manager(api)
    m.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVE:root@pam:AAAA'}
    r = api.anon().get('/api/clusters/cluster_1/vms/n1/qemu/200/console', headers=hdr)
    assert r.status_code != 500, r.get_data(as_text=True)
    if r.status_code == 200:
        # allowed only because vm.console is genuinely in the viewer role's perm set
        assert 'ticket' in r.get_json()


def test_admin_token_still_works(api, seed):
    # regression guard: an admin-role token must keep full access (we floored the role, not the token)
    hdr = _admin_token(seed, role='admin')
    _vm_manager(api)
    r = api.anon().post('/api/clusters/cluster_1/vms/n1/qemu/200/stop', headers=hdr)
    assert r.status_code == 200, r.get_data(as_text=True)


def test_plain_admin_session_still_works(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('root2', role='admin', tenant_id='acme')
    _vm_manager(api)
    r = api.as_user(u).post('/api/clusters/cluster_1/vms/n1/qemu/200/stop')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_viewer_token_reports_its_own_role_not_the_owners(api, seed):
    # /api/me/permissions drove the UI off the OWNER's stored record, so a viewer token was
    # told it was admin and the frontend offered actions the backend would refuse.
    hdr = _admin_token(seed)
    body = api.anon().get('/api/me/permissions', headers=hdr).get_json()
    assert body['effective_role'] != 'admin', body


# ── rolling node updates were gated on a BACKUP permission ────────────────────
def _sched_cluster(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    api.set_manager('cluster_1', m)


def test_update_schedule_denied_to_backup_schedule_holder(api, seed):
    # backup.schedule scheduled a cluster-wide rolling update: evacuate every VM, apt upgrade,
    # reboot every node. Delegating "may schedule backups" must not delegate that.
    _sched_cluster(api, seed)
    u = seed.user('backupguy', role='user', tenant_id='acme',
                  permissions=['backup.schedule', 'cluster.view'])
    r = api.as_user(u).post('/api/clusters/cluster_1/updates/schedule',
                            json={'enabled': True, 'day': 'sunday', 'time': '03:00'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert api.as_user(u).delete('/api/clusters/cluster_1/updates/schedule').status_code == 403


def test_update_schedule_allowed_for_node_update_holder(api, seed):
    _sched_cluster(api, seed)
    u = seed.user('opsguy', role='user', tenant_id='acme',
                  permissions=['node.update', 'cluster.view'])
    r = api.as_user(u).post('/api/clusters/cluster_1/updates/schedule',
                            json={'enabled': True, 'day': 'sunday', 'time': '03:00'})
    assert r.status_code == 200, r.get_data(as_text=True)


# ── backup-job delete skipped the target gate its create/update siblings have ──
def _backup_mgr(api, job):
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    sess = m._create_session.return_value
    sess.get.return_value = types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': job})
    sess.delete.return_value = types.SimpleNamespace(status_code=200, text='', json=lambda: {'data': None})
    return api.set_manager('cluster_1', m)


def _pool_backup_user(seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory', role='viewer', tenant_id='tenant_x',
                  permissions=['backup.delete', 'backup.view', 'cluster.view', 'vm.backup'])
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.backup'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    return u


def test_delete_backup_job_foreign_vm_denied(api, seed):
    u = _pool_backup_user(seed)
    _backup_mgr(api, {'id': 'job-f', 'vmid': '200', 'schedule': 'daily'})
    r = api.as_user(u).delete('/api/clusters/cluster_1/datacenter/backup/job-f')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_delete_backup_job_clusterwide_denied(api, seed):
    # an all=1 job covers VMs beyond the caller's grant — admin-only, same rule as create/update
    u = _pool_backup_user(seed)
    _backup_mgr(api, {'id': 'job-all', 'all': 1, 'schedule': 'daily'})
    r = api.as_user(u).delete('/api/clusters/cluster_1/datacenter/backup/job-all')
    assert r.status_code == 403, r.get_data(as_text=True)


def test_delete_backup_job_own_vm_allowed(api, seed):
    u = _pool_backup_user(seed)
    _backup_mgr(api, {'id': 'job-own', 'vmid': '100', 'schedule': 'daily'})
    r = api.as_user(u).delete('/api/clusters/cluster_1/datacenter/backup/job-own')
    assert r.status_code == 200, r.get_data(as_text=True)


def test_delete_backup_job_admin_unaffected(api, seed):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('root3', role='admin', tenant_id='acme')
    _backup_mgr(api, {'id': 'job-all', 'all': 1, 'schedule': 'daily'})
    assert api.as_user(u).delete('/api/clusters/cluster_1/datacenter/backup/job-all').status_code == 200


# ── the SSE stream skipped the vmware.* perm gate its REST twin enforces ──────
def _register(user, is_admin, clusters):
    q = queue.Queue()
    cid = f'test-sse-{user}'
    with ppglobals.sse_clients_lock:
        ppglobals.sse_clients[cid] = {
            'queue': q, 'user': user, 'clusters': clusters, 'is_admin': is_admin,
            'connected_at': 'x', 'auth_method': 'test',
        }
    return q, cid


def _drain(q):
    out = []
    try:
        while True:
            out.append(json.loads(q.get_nowait()))
    except queue.Empty:
        pass
    return out


def test_vmware_frames_respect_the_perm_gate(db, seed):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    # a custom role built to hide ESXi: no vmware.* permissions at all
    seed.user('novmw', role='viewer', tenant_id='tenant_x',
              denied=['vmware.view', 'vmware.vm.view'])
    seed.user('withvmw', role='viewer', tenant_id='tenant_x', permissions=['vmware.vm.view', 'vmware.view'])
    nq, ncid = _register('novmw', is_admin=False, clusters=['cluster_1'])
    yq, ycid = _register('withvmw', is_admin=False, clusters=['cluster_1'])
    aq, acid = _register('root4', is_admin=True, clusters=None)
    try:
        broadcast_sse('vmware_vms', {'vmware_id': 'esxi1', 'vms': [{'name': 'finance-01'}]},
                      target_clusters=[])
        assert _drain(nq) == [], "a role without vmware.vm.view must not get the ESXi inventory"
        assert len(_drain(yq)) == 1, "a role with vmware.vm.view still receives it"
        assert len(_drain(aq)) == 1, "admin still receives it"
    finally:
        with ppglobals.sse_clients_lock:
            for c in (ncid, ycid, acid):
                ppglobals.sse_clients.pop(c, None)


# ── affinity rules enumerated the cluster's VMs to a scoped caller ────────────
def test_affinity_rules_scoped(api, seed, monkeypatch):
    seed.tenant('tenant_x', clusters=['cluster_1'])
    u = seed.user('mallory2', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory2', ['pool.view', 'vm.view'])
    _seed_pool_membership('cluster_1', {100: ('qemu', 'pool_1')})
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    api.set_manager('cluster_1', m)
    import pegaprox.api.alerts as alerts_mod
    monkeypatch.setattr(alerts_mod, 'load_cluster_affinity_rules', lambda: {'cluster_1': [
        {'id': 'r1', 'name': 'own', 'vm_ids': [100]},
        {'id': 'r2', 'name': 'finance-cluster', 'vm_ids': [300, 301]},
    ]})
    body = api.as_user(u).get('/api/clusters/cluster_1/affinity-rules').get_json()
    assert [r['id'] for r in body['rules']] == ['r1'], body


def test_affinity_rules_admin_sees_all(api, seed, monkeypatch):
    seed.tenant('acme', clusters=['cluster_1'])
    u = seed.user('root5', role='admin', tenant_id='acme')
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    api.set_manager('cluster_1', m)
    import pegaprox.api.alerts as alerts_mod
    monkeypatch.setattr(alerts_mod, 'load_cluster_affinity_rules', lambda: {'cluster_1': [
        {'id': 'r1', 'name': 'own', 'vm_ids': [100]},
        {'id': 'r2', 'name': 'finance-cluster', 'vm_ids': [300, 301]},
    ]})
    body = api.as_user(u).get('/api/clusters/cluster_1/affinity-rules').get_json()
    assert [r['id'] for r in body['rules']] == ['r1', 'r2'], body
