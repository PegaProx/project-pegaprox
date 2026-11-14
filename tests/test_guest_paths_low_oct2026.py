"""Guest paths: the low findings of the October round.

Each finding has one test that fails on the code before the fix for its own reason and a
legitimate use beside it that keeps working:

  * an XCP-ng pool asks its own xapi.vm.* permission on delete, clone, snapshot, disk and
    snapshot policy routes, and a config edit there is checked per guest (#1110)
  * a test failover's cleanup removes only test clones and takes them off the event (#1055)
  * a test failover clones only the guests the route authorized
  * an incremental replica carries no QEMU args but the V2P sector-size ones (#1058)
  * any volume PVE files under a guest's number is that guest's (#1066)
  * a caller confined on the replica cluster neither tears down nor runs the replica (#1068)
  * a snapshot policy written through an API token runs as that token (#1073)
  * a retargeted snapshot policy runs as whoever retargeted it (#1011)
  * the script reads are for unconfined callers, as the writes are (#1024)
  * the node update reboots only for a node.reboot holder (#1072)
  * the join fingerprint is one the cluster reports, not whatever answered a handshake (#1087)
  * the bulk migrate judges an API token as the token (#1047)
  * storage balancing names only the caller's guests
  * writing VM ACLs drops the cached copy (#1007)

NS Oct 2026
"""
import datetime
import hashlib
import json
import socket
import ssl
import threading
import time
import types

import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.rbac as rbac


def _resp(status, data=None):
    return types.SimpleNamespace(status_code=status, text='', json=lambda: {'data': data})


def _pool_membership(cluster_id, mapping):
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


def _cluster(api, cid='cluster_1', cluster_type='proxmox'):
    m = api.make_fake_manager(cluster_id=cid, cluster_type=cluster_type)
    m.is_connected = True
    m.config.name = cid
    m.host, m.api_port = '192.0.2.10', 8006
    return api.set_manager(cid, m)


def _scoped(seed, name, perms, cluster='cluster_1', pool_perms=('pool.view', 'vm.view', 'vm.config')):
    """Confined: holds a pool grant on cluster_1 that covers guest 100 only."""
    seed.tenant('tenant_x', clusters=[cluster])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=perms)
    seed.pool(cluster, 'pool_1', name, list(pool_perms))
    _pool_membership(cluster, {100: ('qemu', 'pool_1')})
    return u


def _owner(seed, name, perms, clusters=('cluster_1',), role='user', tenant='acme'):
    """Unconfined: a cluster-wide operator of the tenant that owns the cluster."""
    seed.tenant(tenant, clusters=list(clusters))
    return seed.user(name, role=role, tenant_id=tenant, permissions=perms)


def _token(owner, role):
    from pegaprox.utils.auth import create_api_token
    res = create_api_token(owner, 'ci', role=role)
    assert res.get('token'), res
    return {'Authorization': f"Bearer {res['token']}"}


# --- XCP-ng asks for xapi.vm.* (#1110) ---------------------------------------------------

def _xcp(api, cid='xcp1'):
    m = _cluster(api, cid, 'xcpng')
    m.delete_vm.return_value = {'success': True}
    m.clone_vm.return_value = {'success': True, 'vmid': 101}
    m.get_next_vmid.return_value = {'success': True, 'vmid': 101}
    m.create_snapshot.return_value = {'success': True}
    m.add_disk.return_value = {'success': True, 'message': 'added'}
    m.update_vm_config.return_value = {'success': True, 'message': 'updated'}
    m.get_vm_config.return_value = {'name': 'x'}
    m.get_vm_resources.return_value = [{'vmid': 100, 'type': 'qemu', 'node': 'h1'}]
    return m


_VM_PERMS = ['vm.view', 'vm.delete', 'vm.clone', 'vm.snapshot', 'vm.config', 'cluster.view']


def test_an_xcpng_guest_asks_its_xapi_permission_on_delete_clone_snapshot_and_disks(api, seed):
    # the shipped tenant templates carry vm.* and no xapi.* at all
    u = _owner(seed, 'tadmin', _VM_PERMS, clusters=('xcp1',), role='viewer')
    m = _xcp(api)
    c = api.as_user(u)
    for method, path, body, perm in (
            ('delete', '/api/clusters/xcp1/vms/h1/qemu/100', {}, 'xapi.vm.delete'),
            ('post', '/api/clusters/xcp1/vms/h1/qemu/100/clone', {'name': 'c'}, 'xapi.vm.clone'),
            ('post', '/api/clusters/xcp1/vms/h1/qemu/100/snapshots', {'snapname': 's1'}, 'xapi.vm.snapshot'),
            ('post', '/api/clusters/xcp1/vms/h1/qemu/100/disks', {'size': 1}, 'xapi.vm.config')):
        r = getattr(c, method)(path, json=body)
        assert r.status_code == 403, (path, r.get_data(as_text=True))
        assert perm in r.get_json()['error']
    assert not (m.delete_vm.called or m.clone_vm.called or m.create_snapshot.called
                or m.add_disk.called)


def test_the_xapi_holder_and_a_proxmox_guest_are_unchanged(api, seed):
    u = _owner(seed, 'xops', _VM_PERMS + ['xapi.vm.delete', 'xapi.vm.snapshot'],
               clusters=('xcp1',), role='viewer')
    lone = _owner(seed, 'pveops', _VM_PERMS, role='viewer', tenant='pve_only')
    m = _xcp(api)
    assert api.as_user(u).delete('/api/clusters/xcp1/vms/h1/qemu/100', json={}).status_code == 200
    assert m.delete_vm.called
    # a Proxmox guest asks for vm.* only, as before
    p = _cluster(api)
    p.create_snapshot.return_value = {'success': True}
    r = api.as_user(lone).post('/api/clusters/cluster_1/vms/n1/qemu/100/snapshots', json={'snapname': 's'})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_an_xcpng_config_edit_is_checked_per_guest(api, seed):
    # role user holds xapi.vm.config pool-wide; the VM-ACL confines this account to guest 100
    u = _owner(seed, 'portal', [], clusters=('xcp1',))
    seed.vm_acl('xcp1', 100, ['portal'])
    m = _xcp(api)
    c = api.as_user(u)
    r = c.put('/api/clusters/xcp1/vms/h1/qemu/200/config', json={'name_label': 'mine-now'})
    assert r.status_code == 403, r.get_data(as_text=True)
    assert not m.update_vm_config.called
    r = c.put('/api/clusters/xcp1/vms/h1/qemu/100/config', json={'name_label': 'mine'})
    assert r.status_code == 200, r.get_data(as_text=True)
    m.update_vm_config.assert_called_once()


def test_an_xcpng_snapshot_policy_asks_xapi_vm_snapshot(api, seed, db):
    u = _owner(seed, 'tadmin', _VM_PERMS, clusters=('xcp1',), role='viewer')
    ok = seed.user('xuser', role='user', tenant_id='acme')
    _xcp(api)
    body = {'name': 'nightly', 'target_type': 'vm', 'target_value': '100'}
    r = api.as_user(u).post('/api/clusters/xcp1/snapshot-policies', json=body)
    assert r.status_code == 403, r.get_data(as_text=True)
    assert 'xapi.vm.snapshot' in r.get_json()['error']
    assert api.as_user(ok).post('/api/clusters/xcp1/snapshot-policies', json=body).status_code == 200


# --- site recovery test failover (#1055 and the late guest) ------------------------------

def _plan(db, status='ready'):
    db.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, "
               "target_cluster, status) VALUES ('p1', 'g1', 'plan', 'src', 'tgt', ?)", (status,))


def _cleanup_target(db, monkeypatch, resources, test_vmids):
    import pegaprox.background.site_recovery as srw
    _plan(db, 'testing')
    db.execute("INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at, "
               "details) VALUES ('e1', 'p1', 'test', 'completed', '2026-10-01T00:00:00', ?)",
               (json.dumps({'test_vmids': test_vmids}),))
    tgt = types.SimpleNamespace(host='192.0.2.9', api_port=8006, deleted=[], stopped=[])
    tgt._api_get = lambda url, params=None, **kw: _resp(200, resources)
    tgt.vm_action = lambda node, vmid, vt, action, force=False: tgt.stopped.append(vmid) or {'success': True}
    tgt.delete_vm = lambda node, vmid, vt, purge=False: tgt.deleted.append(vmid) or {'success': True}
    monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
    monkeypatch.setattr(srw, '_broadcast_progress', lambda *a, **k: None)
    return srw, tgt


def _event_vmids(db):
    return json.loads(db.query_one("SELECT details FROM site_recovery_events WHERE id = 'e1'")
                      ['details'])['test_vmids']


def test_the_cleanup_leaves_a_guest_that_took_a_test_clones_vmid_since(db, monkeypatch):
    srw, tgt = _cleanup_target(db, monkeypatch,
                               [{'vmid': 90100, 'node': 'd1', 'status': 'stopped', 'name': 'billing'}],
                               [{'vmid': 90100, 'vm_type': 'qemu'}])
    srw.cleanup_test('p1')
    assert tgt.deleted == [], 'the cleanup purged a guest that is not a test clone'
    assert _event_vmids(db) == []


def test_the_cleanup_removes_its_clone_once(db, monkeypatch):
    srw, tgt = _cleanup_target(db, monkeypatch,
                               [{'vmid': 90100, 'node': 'd1', 'status': 'stopped', 'name': 'SR-TEST-web'}],
                               [{'vmid': 90100, 'vm_type': 'qemu'}])
    srw.cleanup_test('p1')
    assert tgt.deleted == [90100]
    # the event no longer names it, so a later cleanup run has nothing to purge
    assert _event_vmids(db) == []
    srw.cleanup_test('p1')
    assert tgt.deleted == [90100]


def test_a_guest_added_after_the_test_failover_was_authorized_is_not_cloned(api, seed, db, monkeypatch):
    import pegaprox.api.site_recovery as srapi
    import pegaprox.background.site_recovery as srw
    boss = seed.user('boss', role='admin')
    _cluster(api, 'src')
    tgt = _cluster(api, 'tgt')
    _plan(db)
    db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name) VALUES ('v1', 'p1', 100, 'web')")
    spawned = []
    monkeypatch.setattr(srapi, '_safe_spawn_failover',
                        lambda func, plan_id, *args: spawned.append((func, plan_id, args)))
    r = api.as_user(boss).post('/api/site-recovery/plans/p1/test', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    # a second request puts another guest in before the worker reads the plan
    db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name) VALUES ('v2', 'p1', 200, 'db')")

    tgt.get_node_status.return_value = {'d1': {}}
    tgt.get_vms.return_value = [{'vmid': 100}, {'vmid': 200}]
    tgt.clone_vm.return_value = {'success': True}
    tgt.vm_action.return_value = {'success': True}
    monkeypatch.setattr(srw, '_broadcast_progress', lambda *a, **k: None)
    monkeypatch.setattr(srw.sr_boot_shots, 'pending', lambda guests: None)
    (func, plan_id, args), = spawned
    func(plan_id, *args)
    assert [c.args[1] for c in tgt.clone_vm.call_args_list] == [100]


@pytest.mark.parametrize('route', ['test', 'failover'])
def test_a_guest_added_while_the_route_checks_the_plan_is_not_handed_on(api, seed, db, monkeypatch, route):
    # NS Oct 2026 - the per-guest checks can wait on the cluster (pool lookups), and a guest
    # added meanwhile was in the list the worker got, unchecked
    import pegaprox.api.site_recovery as srapi
    boss = seed.user('boss', role='admin')
    _cluster(api, 'src')
    _cluster(api, 'tgt')
    _plan(db)
    db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name) VALUES ('v1', 'p1', 100, 'web')")
    real = rbac.user_can_access_vm

    def _racing(user, cluster_id, vmid, *a, **kw):
        if not db.query_one("SELECT id FROM site_recovery_vms WHERE id = 'v2'"):
            db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name) "
                       "VALUES ('v2', 'p1', 200, 'db')")
        return real(user, cluster_id, vmid, *a, **kw)

    monkeypatch.setattr(rbac, 'user_can_access_vm', _racing)
    spawned = []
    monkeypatch.setattr(srapi, '_safe_spawn_failover',
                        lambda func, plan_id, *args: spawned.append(args))
    r = api.as_user(boss).post(f'/api/site-recovery/plans/p1/{route}', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    args, = spawned
    assert [int(v) for v in args[-1]] == [100], 'the worker was handed a guest nobody checked'


# --- incremental replica args (#1058) ----------------------------------------------------

class _Target:
    host, api_port = '192.0.2.2', 8006

    def __init__(self):
        self.posts = []

    def _api_post(self, url, data=None, **kw):
        self.posts.append(dict(data))
        return _resp(200, None)


_SECTOR = '-set device.scsi0.logical_block_size=512 -set device.scsi0.physical_block_size=512'


@pytest.mark.parametrize('args', [
    '-chardev socket,id=x,path=/run/x -device virtserialport,chardev=x',
    _SECTOR + ' -fw_cfg name=opt/x,file=/etc/shadow',
])
def test_a_replica_takes_no_qemu_args_of_its_own(args):
    import pegaprox.api.vms as vms
    tgt = _Target()
    vms._build_incremental_replica_vm(tgt, 't1', 100, {'name': 'web', 'args': args}, [], 'far',
                                      {'id': 'j1', 'target_bridge': 'vmbr0'})
    assert 'args' not in tgt.posts[-1]


def test_a_replica_takes_no_tpm_state_on_a_host_path():
    # NS Oct 2026 - the other root-only key in the copy list: a host device as TPM state
    import pegaprox.api.vms as vms
    tgt = _Target()
    vms._build_incremental_replica_vm(tgt, 't1', 100, {'name': 'web', 'tpmstate0': '/dev/sdb,size=4M'},
                                      [], 'far', {'id': 'j1', 'target_bridge': 'vmbr0'})
    assert 'tpmstate0' not in tgt.posts[-1]
    tgt = _Target()
    vms._build_incremental_replica_vm(tgt, 't1', 100, {'name': 'web', 'tpmstate0': 'far:vm-100-disk-1,size=4M'},
                                      [], 'far', {'id': 'j1', 'target_bridge': 'vmbr0'})
    assert tgt.posts[-1]['tpmstate0'] == 'far:vm-100-disk-1,size=4M'


def test_the_v2p_sector_size_args_still_go_along():
    import pegaprox.api.vms as vms
    tgt = _Target()
    vms._build_incremental_replica_vm(tgt, 't1', 100, {'name': 'web', 'args': _SECTOR}, [], 'far',
                                      {'id': 'j1', 'target_bridge': 'vmbr0'})
    assert tgt.posts[-1]['args'] == _SECTOR and tgt.posts[-1]['name'] == 'web'


# --- datastore volumes by number (#1066) ---------------------------------------------------

def _content_mgr(api):
    m = _cluster(api)
    m._create_session.return_value.get.return_value = _resp(200, [])
    m._create_session.return_value.delete.return_value = _resp(200, None)
    return m


@pytest.mark.parametrize('volid', [
    'local-lvm:vm-300-scratch',
    'local:300/custom.qcow2',
    'local:99/base-99-disk-0.qcow2/300/vm-300-disk-1.qcow2',
    # NS Oct 2026 - a linked clone on ZFS, LVM-thin or RBD, and a ZFS container template
    'local-zfs:base-99-disk-0/vm-300-disk-1',
    'local-zfs:basevol-300-disk-0',
])
def test_a_foreign_guests_volume_is_its_whatever_its_name(api, seed, volid):
    u = _scoped(seed, 'volmal', ['storage.delete', 'cluster.view'])
    m = _content_mgr(api)
    r = api.as_user(u).delete(f'/api/clusters/cluster_1/datastores/local/content/{volid}?node=n1')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert not m._create_session.return_value.delete.called


@pytest.mark.parametrize('volid', ['local-lvm:vm-100-scratch', 'local:snippets/vm-300-cloudinit.yml',
                                   'local-zfs:base-300-disk-0/vm-100-disk-1'])
def test_the_own_guests_volume_and_shared_content_still_go(api, seed, volid):
    u = _scoped(seed, 'volok', ['storage.delete', 'cluster.view'])
    m = _content_mgr(api)
    r = api.as_user(u).delete(f'/api/clusters/cluster_1/datastores/local/content/{volid}?node=n1')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert m._create_session.return_value.delete.called


# --- the replica cluster (#1068) -----------------------------------------------------------

def _job(db, delete_target=1):
    db.execute("INSERT INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, "
               "delete_target, created_at) VALUES ('j1', 'src', 'tgt', 100, ?, '2026-10-01')",
               (delete_target,))


def test_a_caller_confined_on_the_replica_cluster_neither_tears_it_down_nor_runs_it(api, seed, db, monkeypatch):
    import pegaprox.api.vms as vms
    import pegaprox.background.cross_cluster_replication as xcr
    # owns the source, reaches the target only through a pool grant there
    u = _owner(seed, 'repops', ['cluster.config'], clusters=('src',))
    seed.pool('tgt', 'pool_t', 'repops', ['pool.view', 'vm.view'])
    _cluster(api, 'src')
    _cluster(api, 'tgt')
    _job(db)
    torn = []
    monkeypatch.setattr(vms, '_delete_replica_target', lambda job: torn.append(job['id']) or (True, 'gone'))
    monkeypatch.setattr(xcr, 'is_job_inflight', lambda job_id: False)
    monkeypatch.setattr(xcr, '_claim_job', lambda job_id: False)
    c = api.as_user(u)
    r = c.delete('/api/cross-cluster-replications/j1')
    assert r.status_code == 403, r.get_data(as_text=True)
    assert torn == []
    r = c.post('/api/cross-cluster-replications/j1/run', json={})
    assert r.status_code == 403, r.get_data(as_text=True)
    # dropping the job and keeping the replica is still theirs to do
    assert c.delete('/api/cross-cluster-replications/j1?delete_target=0').status_code == 200
    assert torn == []


def test_an_operator_of_both_clusters_keeps_the_replica_routes(api, seed, db, monkeypatch):
    import pegaprox.api.vms as vms
    import pegaprox.background.cross_cluster_replication as xcr
    u = _owner(seed, 'bothops', ['cluster.config'], clusters=('src', 'tgt'))
    _cluster(api, 'src')
    _cluster(api, 'tgt')
    _job(db)
    torn = []
    monkeypatch.setattr(vms, '_delete_replica_target', lambda job: torn.append(job['id']) or (True, 'gone'))
    monkeypatch.setattr(xcr, 'is_job_inflight', lambda job_id: False)
    monkeypatch.setattr(xcr, '_claim_job', lambda job_id: False)
    c = api.as_user(u)
    assert c.post('/api/cross-cluster-replications/j1/run', json={}).status_code == 409
    assert c.delete('/api/cross-cluster-replications/j1').status_code == 200
    assert torn == ['j1']


# --- snapshot policies: who a scheduled run is (#1073, #1011) ------------------------------

def _vm(vmid, tags=''):
    return {'vmid': vmid, 'type': 'qemu', 'node': 'n1', 'tags': tags}


def _policy_cluster(api, resources, cid='cluster_1'):
    m = _cluster(api, cid)
    m.get_vm_resources.return_value = list(resources)
    m.create_snapshot.return_value = {'success': True}
    m.list_snapshots.return_value = []
    return m


def _snapped(m):
    return sorted(c.args[1] for c in m.create_snapshot.call_args_list)


def test_a_policy_written_through_a_token_runs_as_that_token(api, seed, db):
    import pegaprox.api.snapshots as snaps
    seed.user('boss', role='admin')
    seed.vm_acl('cluster_1', 100, ['boss'])   # the 'user' token of this admin reaches guest 100 only
    m = _policy_cluster(api, [_vm(100, 'prod')])
    r = api.anon().post('/api/clusters/cluster_1/snapshot-policies', headers=_token('boss', 'user'),
                        json={'name': 'prod', 'target_type': 'tag', 'target_value': 'prod'})
    assert r.status_code == 200, r.get_data(as_text=True)
    pid = r.get_json()['policy']['id']
    # later a guest beyond the token's reach is tagged prod
    m.get_vm_resources.return_value = [_vm(100, 'prod'), _vm(200, 'prod')]
    snaps._execute_policy(pid, force=True)
    assert _snapped(m) == [100]


def test_a_policy_written_in_a_session_runs_as_its_author(api, seed, db):
    import pegaprox.api.snapshots as snaps
    boss = seed.user('boss', role='admin')
    seed.vm_acl('cluster_1', 100, ['boss'])
    m = _policy_cluster(api, [_vm(100, 'prod')])
    r = api.as_user(boss).post('/api/clusters/cluster_1/snapshot-policies',
                               json={'name': 'prod', 'target_type': 'tag', 'target_value': 'prod'})
    pid = r.get_json()['policy']['id']
    m.get_vm_resources.return_value = [_vm(100, 'prod'), _vm(200, 'prod')]
    snaps._execute_policy(pid, force=True)
    assert _snapped(m) == [100, 200]


def _mallory(seed):
    return _scoped(seed, 'mallory', ['vm.snapshot'], pool_perms=('pool.view', 'vm.view', 'vm.snapshot'))


def _boss_policy(api, seed, target):
    boss = seed.user('boss', role='admin')
    r = api.as_user(boss).post('/api/clusters/cluster_1/snapshot-policies',
                               json={'name': 'p', 'target_type': 'vm', 'target_value': target})
    assert r.status_code == 200, r.get_data(as_text=True)
    return boss, r.get_json()['policy']['id']


def test_a_retargeted_policy_runs_as_whoever_retargeted_it(api, seed, db):
    import pegaprox.api.snapshots as snaps
    mal = _mallory(seed)
    m = _policy_cluster(api, [_vm(100)])
    _boss, pid = _boss_policy(api, seed, '100')
    # every current target is in her pool; the new one matches nothing yet
    r = api.as_user(mal).put(f'/api/clusters/cluster_1/snapshot-policies/{pid}', json={'target_value': '999'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['policy']['created_by'] == 'mallory'
    m.get_vm_resources.return_value = [_vm(100), _vm(999)]
    snaps._execute_policy(pid, force=True)
    assert _snapped(m) == [], 'guest 999 was snapshotted on the authority of the old creator'


def test_a_retarget_answers_for_the_guests_the_policy_had(api, seed, db):
    mal = _mallory(seed)
    _policy_cluster(api, [_vm(100), _vm(300)])
    _boss, pid = _boss_policy(api, seed, '300')
    r = api.as_user(mal).put(f'/api/clusters/cluster_1/snapshot-policies/{pid}', json={'target_value': '100'})
    assert r.status_code == 403, 'a confined caller took over a policy that protects a guest of someone else'


def test_policy_edits_that_do_not_retarget_keep_their_author(api, seed, db):
    mal = _mallory(seed)
    _policy_cluster(api, [_vm(100)])
    boss, pid = _boss_policy(api, seed, '100')
    r = api.as_user(mal).put(f'/api/clusters/cluster_1/snapshot-policies/{pid}', json={'enabled': False})
    assert r.status_code == 200 and r.get_json()['policy']['created_by'] == 'boss'
    r = api.as_user(boss).put(f'/api/clusters/cluster_1/snapshot-policies/{pid}',
                              json={'target_type': 'tag', 'target_value': 'prod'})
    assert r.status_code == 200 and r.get_json()['policy']['created_by'] == 'boss'


# --- script reads (#1024) ------------------------------------------------------------------

def test_a_confined_scripts_holder_does_not_read_the_clusters_scripts(api, seed):
    u = _scoped(seed, 'scriptmal', ['admin.scripts', 'cluster.view'])
    ops = _owner(seed, 'scriptops', ['admin.scripts', 'cluster.view'])
    _cluster(api)
    c = api.as_user(u)
    for path in ('/api/clusters/cluster_1/scripts', '/api/clusters/cluster_1/scripts/s1/output',
                 '/api/clusters/cluster_1/scripts/deleted'):
        r = c.get(path)
        assert r.status_code == 403, (path, r.get_data(as_text=True))
    assert api.as_user(ops).get('/api/clusters/cluster_1/scripts').status_code == 200
    assert api.as_user(ops).get('/api/clusters/cluster_1/scripts/deleted').status_code == 200


# --- node update and node.reboot (#1072) ----------------------------------------------------

def test_the_node_update_reboots_only_for_a_node_reboot_holder(api, seed):
    u = _owner(seed, 'patcher', ['node.update', 'cluster.view'])
    rebooter = seed.user('rebooter', role='user', tenant_id='acme',
                         permissions=['node.update', 'node.reboot', 'cluster.view'])
    m = _cluster(api)
    m.nodes_in_maintenance = {}
    c = api.as_user(u)
    for body in ({}, {'reboot': True, 'force': True}):
        r = c.post('/api/clusters/cluster_1/nodes/n1/update', json=body)
        assert r.status_code == 403, r.get_data(as_text=True)
        assert 'node.reboot' in r.get_json()['error']
    assert not m.start_node_update.called
    # an update without the reboot is node.update alone: on to the maintenance check
    assert c.post('/api/clusters/cluster_1/nodes/n1/update', json={'reboot': False}).status_code == 400
    assert api.as_user(rebooter).post('/api/clusters/cluster_1/nodes/n1/update', json={}).status_code == 400


# --- the join fingerprint (#1087) -----------------------------------------------------------

@pytest.fixture
def tls_peer(tmp_path):
    """A TLS listener on loopback with a certificate nobody vouches for."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'on-path.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1087)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / 'c.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'k.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp_path / 'c.pem'), str(tmp_path / 'k.pem'))
    ls = socket.socket()
    ls.bind(('127.0.0.1', 0))
    ls.listen(8)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = ls.accept()
            except OSError:
                return
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except (OSError, ssl.SSLError):
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    try:
        yield ls.getsockname()[1], ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2))
    finally:
        stop.set()
        ls.close()


def _join_cluster(api, port, state):
    """join-info carries no pve_fp; state['join'] False answers it with 500, the older
    status-and-nodes path"""
    m = _cluster(api)
    m.host, m.api_port = '127.0.0.1', port
    m.config.host = '127.0.0.1'

    def get(url, **kw):
        if url.endswith('/cluster/config/join'):
            if not state['join']:
                return _resp(500, None)
            return _resp(200, {'nodelist': [{'name': 'pve1', 'ring0_addr': '10.0.0.1'}]})
        if url.endswith('/cluster/status'):
            return _resp(200, [{'type': 'cluster', 'name': 'lab'},
                               {'type': 'node', 'name': 'pve1', 'ip': '10.0.0.1', 'online': 1}])
        if url.endswith('/cluster/config/nodes'):
            return _resp(200, [])
        if url.endswith('/nodes/pve1/certificates/info'):
            return _resp(200, [{'filename': 'pve-ssl.pem', 'fingerprint': 'AB:' * 31 + 'AB'},
                               {'filename': 'pveproxy-ssl.pem', 'fingerprint': state['fp']}])
        return _resp(404, None)
    m._create_session.return_value.get.side_effect = get
    return m


def test_the_join_fingerprint_is_one_the_cluster_reports(api, seed, tls_peer, monkeypatch):
    import pegaprox.api.vms as vms
    port, wire = tls_peer
    boss = seed.user('boss', role='admin')
    state = {'fp': 'CD:' * 31 + 'CD', 'join': False}
    _join_cluster(api, port, state)
    c = api.as_user(boss)
    r = c.get('/api/clusters/cluster_1/datacenter/join-info')
    assert r.status_code == 200
    assert r.get_json().get('fingerprint') != wire, 'the unverified handshake was offered'
    state['join'] = True
    ssh = []
    monkeypatch.setattr(vms, 'secure_ssh_client', lambda paramiko: ssh.append(1) or 1 / 0)
    r = c.post('/api/clusters/cluster_1/nodes/join', json={'node_ip': '10.0.0.5', 'password': 'pw'})
    assert ssh == [], 'the join went on to the new node with an unconfirmed fingerprint'
    assert r.status_code == 500 and 'fingerprint' in r.get_json()['error']


@pytest.mark.parametrize('join', [False, True])
def test_a_certificate_the_cluster_reports_is_the_join_fingerprint(api, seed, tls_peer, join):
    port, wire = tls_peer
    boss = seed.user('boss', role='admin')
    _join_cluster(api, port, {'fp': wire.lower(), 'join': join})
    r = api.as_user(boss).get('/api/clusters/cluster_1/datacenter/join-info')
    assert r.get_json()['fingerprint'] == wire


# --- bulk migrate as the token (#1047) ------------------------------------------------------

def test_the_bulk_migrate_judges_an_admins_token_by_the_token(api, seed, db):
    seed.user('boss', role='admin')
    seed.vm_acl('cluster_1', 100, ['boss'])
    # MK Nov 2026 - 101 on n2 is theirs too: a confined caller moves guests onto a node of theirs
    seed.vm_acl('cluster_1', 101, ['boss'])
    m = _cluster(api)
    m.get_vm_resources.return_value = [{'vmid': 100, 'node': 'n1', 'type': 'qemu'},
                                       {'vmid': 101, 'node': 'n2', 'type': 'qemu'},
                                       {'vmid': 200, 'node': 'n1', 'type': 'qemu'}]
    m.migrate_vm_manual.return_value = {'success': True, 'task': None}
    body = {'target': 'n2', 'vms': [{'node': 'n1', 'vmid': 200, 'type': 'qemu'},
                                    {'node': 'n1', 'vmid': 100, 'type': 'qemu'}]}
    r = api.anon().post('/api/clusters/cluster_1/vms/bulk-migrate', json=body,
                        headers=_token('boss', 'user'))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [c.args[1] for c in m.migrate_vm_manual.call_args_list] == [100]
    assert {x['vmid']: x['success'] for x in r.get_json()['results']} == {200: False, 100: True}


# --- storage balancing recommendations ------------------------------------------------------

def _balance_cluster(api, monkeypatch):
    import pegaprox.api.storage as storage
    m = _cluster(api)

    def get(url, **kw):
        if url.endswith('/api2/json/nodes'):
            return _resp(200, [{'node': 'n1'}])
        if url.endswith('/nodes/n1/storage'):
            return _resp(200, [{'storage': 'full', 'total': 100, 'used': 90},
                               {'storage': 'empty', 'total': 100, 'used': 10}])
        if '/cluster/resources' in url:
            return _resp(200, [{'vmid': 100, 'node': 'n1', 'type': 'qemu', 'name': 'mine'},
                               {'vmid': 200, 'node': 'n1', 'type': 'qemu', 'name': 'theirs'}])
        if url.endswith('/status/current'):
            return _resp(200, {})
        if url.endswith('/config'):
            return _resp(200, {'scsi0': 'full:vm-1-disk-0,size=8G'})
        return _resp(404, None)
    m._create_session.return_value.get.side_effect = get
    monkeypatch.setattr(storage, 'storage_clusters_config', {'cluster_1': {'clusters': [
        {'id': 'sc1', 'name': 'sc', 'storages': ['full', 'empty'], 'threshold': 20, 'enabled': True}]}})
    storage._storage_cache.invalidate('cluster_1')
    return storage


def _recommended(api, user):
    r = api.as_user(user).get('/api/clusters/cluster_1/storage-clusters/sc1/status')
    assert r.status_code == 200, r.get_data(as_text=True)
    return {x['vm_name'] for x in r.get_json()['recommendations']}


def test_storage_balancing_names_only_the_callers_guests(api, seed, monkeypatch):
    storage = _balance_cluster(api, monkeypatch)
    try:
        u = _scoped(seed, 'stormal', ['storage.view', 'cluster.view'])
        ops = _owner(seed, 'storops', ['storage.view', 'cluster.view'])
        assert _recommended(api, u) == {'mine'}
        assert _recommended(api, ops) == {'mine', 'theirs'}
    finally:
        storage._storage_cache.invalidate('cluster_1')


# --- VM ACL cache (#1007) -------------------------------------------------------------------

def test_writing_vm_acls_drops_the_cached_copy(db):
    assert '300' not in rbac.get_vm_acls().get('cluster_1', {})   # now cached for the TTL
    acls = rbac.load_vm_acls()
    acls.setdefault('cluster_1', {})['300'] = {'users': ['newowner']}
    assert rbac.save_vm_acls(acls)
    # the client portal grants the creator of a container exactly this way
    assert rbac.get_vm_acls()['cluster_1']['300']['users'] == ['newowner']
