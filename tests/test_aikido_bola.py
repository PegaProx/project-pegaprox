# Regression guards for the per-VM BOLA fixes (Aikido, NS Aug 2026).
# Pattern: a user reaches the cluster via a VM-ACL grant on VM 100, then targets VM 101 (which
# they do NOT own) — the per-VM gate must 403 even though the cluster-reach check passes.

import types

import pegaprox.globals as ppglobals


def _reacher(seed, perm):
    """A non-admin whose tenant does NOT include cluster_1, so she reaches it ONLY through the
    VM-ACL fallback on VM 100 — every other VM in cluster_1 must be denied downstream."""
    seed.tenant('tenant_iso', clusters=['cluster_other'])
    seed.user('alice', role='user', tenant_id='tenant_iso', permissions=[perm])
    seed.vm_acl('cluster_1', 100, users=['alice'], inherit_role=True)
    return 'alice'


def test_cancel_task_denied_for_foreign_vm(api, seed):
    # #469089252 — a vm.stop holder scoped to VM 100 must not cancel VM 101's task.
    alice = _reacher(seed, 'vm.stop')
    api.set_manager('cluster_1', api.make_fake_manager())
    upid = 'UPID:pve1:00001:00002:00003:qmshutdown:101:root@pam:'
    r = api.as_user({'username': alice, 'role': 'user'}).delete(
        f'/api/clusters/cluster_1/nodes/pve1/tasks/{upid}')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'VM task' in r.get_data(as_text=True)


def test_backup_job_create_denied_for_foreign_vmid(api, seed):
    # #469089226 — a backup.schedule holder must not schedule a job for a VM they don't own.
    alice = _reacher(seed, 'backup.schedule')
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.as_user({'username': alice, 'role': 'user'}).post(
        '/api/clusters/cluster_1/datacenter/backup', json={'vmid': '101'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'VM 101' in r.get_data(as_text=True)


def test_backup_job_cluster_wide_denied_for_non_admin(api, seed):
    # #469089226 — all=1 / pool jobs are admin-only.
    alice = _reacher(seed, 'backup.schedule')
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.as_user({'username': alice, 'role': 'user'}).post(
        '/api/clusters/cluster_1/datacenter/backup', json={'all': '1'})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_xhm_migration_detail_denied_for_foreign_vm(api, seed):
    # #469089253 — cluster reach alone must not expose another VM's migration record.
    import pegaprox.api.xhm as xhm
    alice = _reacher(seed, 'vm.migrate')
    rec = types.SimpleNamespace(
        source_cluster='cluster_1', source_vmid=101, target_cluster='cluster_1',
        to_dict=lambda: {'id': 'm1', 'source_vmid': 101})
    xhm._xhm_migrations['m1'] = rec
    try:
        r = api.as_user({'username': alice, 'role': 'user'}).get('/api/xhm/migrations/m1')
        # hidden as if not found (matches the existing _xhm_reachable contract)
        assert r.status_code == 404, r.get_data(as_text=True)
    finally:
        xhm._xhm_migrations.pop('m1', None)


def test_backup_job_allowed_for_own_vm(api, seed):
    # positive control: alice CAN schedule a job for her own VM 100 (gate passes, PVE call is faked).
    alice = _reacher(seed, 'backup.schedule')
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.as_user({'username': alice, 'role': 'user'}).post(
        '/api/clusters/cluster_1/datacenter/backup', json={'vmid': '100'})
    # not a 403 from our gate (may be 200 or a PVE-shaped error from the fake, but authz passed)
    assert r.status_code != 403, r.get_data(as_text=True)


def test_backup_job_empty_selection_denied_for_non_admin(api, seed):
    # #469089226 (CodeAnt follow-up) — PVE treats an empty / exclude-mode selection as "every VM";
    # a non-admin must not slip past the gate by omitting vmid or using exclude/selMode.
    alice = _reacher(seed, 'backup.schedule')
    api.set_manager('cluster_1', api.make_fake_manager())
    acc = api.as_user({'username': alice, 'role': 'user'})
    for payload in ({}, {'exclude': '999'}, {'selMode': 'all'}, {'selMode': 'exclude', 'vmid': '100'}):
        r = acc.post('/api/clusters/cluster_1/datacenter/backup', json=payload)
        assert r.status_code == 403, f'{payload} -> {r.status_code}: {r.get_data(as_text=True)}'


def test_backup_job_update_all_denied_for_non_admin(api, seed):
    # #469089226 (CodeAnt follow-up) — the load→edit→save round-trip of an admin all=1 job must
    # be re-checked on PUT, so a non-admin can't retune a cluster-wide job they don't own.
    alice = _reacher(seed, 'backup.schedule')
    api.set_manager('cluster_1', api.make_fake_manager())
    r = api.as_user({'username': alice, 'role': 'user'}).put(
        '/api/clusters/cluster_1/datacenter/backup/backup-abc',
        json={'all': '1', 'starttime': '03:00'})
    assert r.status_code == 403, r.get_data(as_text=True)
