"""Where a new guest goes is a call for the whole cluster (#1081, #1086, #1056).

The QEMU and LXC create routes, on Proxmox and XCP-ng alike, only asked whether the caller
reaches the cluster, and one pool grant or one VM-ACL entry answers that. A confined caller
whose role carries vm.create could put a guest on any node, storage and bridge there.
Template deploy, OCI deploy and the PBS restore into a new VMID already held that line; the
vzdump restore into another VMID did not, and keeps now to what its PBS twin asks.

Cross-cluster migration runs its target side on a token minted for the target cluster's own
account, so reaching that cluster through one guest was enough to place a guest anywhere on
it, at any VMID.
"""
import time

import pytest

import pegaprox.utils.rbac as rbac

CID = 'cluster_1'


def _pool_member(cluster_id, mapping):
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {'data': mapping, 'timestamp': time.time(),
                                                   'refreshing': False}


def _who(api, seed, perms):
    seed.tenant('tenant_x', [CID])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    pool = seed.user('pooluser', role='viewer', tenant_id='tenant_x', permissions=perms)
    seed.pool(CID, 'pool_1', 'pooluser', ['pool.view', 'vm.view', 'vm.backup'])
    _pool_member(CID, {'100:qemu': 'pool_1'})
    acl = seed.user('acluser', role='viewer', tenant_id='acme', permissions=perms)
    seed.vm_acl(CID, 100, ['acluser'])
    return {
        'pool': api.as_user(pool),
        'acl': api.as_user(acl),
        'owner': api.as_user(seed.user('op', role='viewer', tenant_id='ops', permissions=perms)),
        'admin': api.as_user(seed.user('root', role='admin')),
    }


def _manager(api, cluster_id=CID, cluster_type='proxmox'):
    m = api.make_fake_manager(cluster_id, cluster_type=cluster_type)
    m.is_connected = True
    m.host, m.api_port = '192.0.2.10', 8006
    m.create_vm.return_value = {'success': True, 'vmid': 900}
    m.create_container.return_value = {'success': True, 'vmid': 901}
    return api.set_manager(cluster_id, m)


# --- create --------------------------------------------------------------------------------------

CREATE = [('qemu', 'create_vm', {'vmid': 900, 'name': 'new', 'memory': 1024}),
          ('lxc', 'create_container', {'vmid': 901, 'hostname': 'new', 'ostemplate': 'local:vztmpl/d.tar.zst',
                                       'password': 'ct-root-pw'})]   # a CT without a credential is a 400


@pytest.mark.parametrize('kind,method,body', CREATE)
def test_a_confined_caller_creates_no_guest(api, seed, kind, method, body):
    who = _who(api, seed, ['vm.create', 'vm.view', 'cluster.view'])
    m = _manager(api)
    for caller in ('pool', 'acl'):
        r = who[caller].post(f'/api/clusters/{CID}/nodes/pve1/{kind}', json=body)
        assert r.status_code == 403, (caller, r.data)
        assert 'whole cluster' in r.get_json()['error']
    assert not getattr(m, method).called


@pytest.mark.parametrize('kind,method,body', CREATE)
def test_the_whole_cluster_still_creates(api, seed, kind, method, body):
    who = _who(api, seed, ['vm.create', 'vm.view', 'cluster.view'])
    m = _manager(api)
    for caller in ('owner', 'admin'):
        r = who[caller].post(f'/api/clusters/{CID}/nodes/pve1/{kind}', json=body)
        assert r.status_code == 200, (caller, r.data)
    assert getattr(m, method).call_count == 2


def test_an_xcpng_create_holds_the_same_line(api, seed):
    who = _who(api, seed, ['vm.create', 'xapi.vm.create', 'vm.view', 'cluster.view'])
    m = _manager(api, cluster_type='xcpng')
    for caller in ('pool', 'acl'):
        r = who[caller].post(f'/api/clusters/{CID}/nodes/host1/qemu',
                             json={'template_uuid': 'abc', 'name': 'new'})
        assert r.status_code == 403, (caller, r.data)
    assert not m.create_vm.called
    assert who['owner'].post(f'/api/clusters/{CID}/nodes/host1/qemu',
                             json={'template_uuid': 'abc', 'name': 'new'}).status_code == 200
    assert m.create_vm.called


# --- the vzdump restore into another VMID -------------------------------------------------------

VOLID = 'local:backup/vzdump-qemu-100-2026_10_01-00_00_00.vma.zst'


def _restore_manager(api):
    m = _manager(api)
    m.get_vm_resources.return_value = [{'vmid': 100, 'node': 'pve1', 'type': 'qemu'},
                                       {'vmid': 200, 'node': 'pve2', 'type': 'qemu'}]
    started = m._create_session.return_value.post.return_value
    started.status_code = 200
    started.json.return_value = {'data': 'UPID:pve1:restore'}
    return m


def _restore(client, node, target_vmid):
    return client.post(f'/api/clusters/{CID}/vms/{node}/qemu/100/backups/restore',
                       json={'volid': VOLID, 'target_vmid': target_vmid})


def test_a_confined_caller_restores_a_new_guest_only_where_theirs_live(api, seed):
    who = _who(api, seed, ['backup.restore', 'vm.backup', 'vm.view', 'cluster.view'])
    m = _restore_manager(api)
    post = m._create_session.return_value.post
    for caller in ('pool', 'acl'):
        r = _restore(who[caller], 'pve2', 555)
        assert r.status_code == 403 and 'node' in r.get_json()['error'], (caller, r.data)
    assert not post.called
    # where VM 100 lives the new guest may go
    assert _restore(who['pool'], 'pve1', 555).status_code == 200
    assert post.call_args[1]['data']['vmid'] == 555 and post.call_args[1]['data']['force'] == 0
    # restoring their own guest in place is no new guest
    assert _restore(who['acl'], 'pve2', 100).status_code == 200
    assert post.call_args[1]['data']['force'] == 1


def test_the_pbs_twin_asks_a_pool_caller_the_same(api, seed):
    """Its node check knew the VM-ACLs only, so a pool grant read as no restriction at all."""
    who = _who(api, seed, ['vm.backup', 'vm.view', 'cluster.view'])
    m = _restore_manager(api)
    m._api_post.return_value = m._create_session.return_value.post.return_value
    body = {'mode': 'new', 'volid': 'pbs:backup/vm/100/2026-10-01T00:00:00Z', 'target_vmid': 555}
    for caller in ('pool', 'acl'):
        r = who[caller].post(f'/api/clusters/{CID}/backup-restore', json=dict(body, target_node='pve2'))
        assert r.status_code == 403 and 'node' in r.get_json()['error'], (caller, r.data)
    assert not m._api_post.called
    r = who['pool'].post(f'/api/clusters/{CID}/backup-restore', json=dict(body, target_node='pve1'))
    assert r.status_code == 200, r.data
    assert who['owner'].post(f'/api/clusters/{CID}/backup-restore',
                             json=dict(body, target_node='pve2')).status_code == 200


def test_a_new_guest_from_a_restore_keeps_to_the_tenant_range(api, seed):
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    u = seed.user('ranged_op', role='viewer', tenant_id='ranged',
                  permissions=['backup.restore', 'vm.backup', 'vm.view', 'cluster.view'])
    admin = seed.user('root', role='admin')
    m = _restore_manager(api)
    post = m._create_session.return_value.post
    r = _restore(api.as_user(u), 'pve2', 555)
    assert r.status_code == 403 and '1000-1999' in r.get_json()['error'], r.data
    assert not post.called
    # an operator of the whole cluster places it anywhere inside the range, and admins anywhere
    assert _restore(api.as_user(u), 'pve2', 1500).status_code == 200
    assert _restore(api.as_user(admin), 'pve2', 555).status_code == 200
    assert post.call_count == 2


def test_a_restore_over_a_gone_guest_keeps_to_the_tenant_range(api, seed):
    # VM 555 is not there: "into the same VMID" makes it anew, as another VMID would
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    u = seed.user('ranged_op', role='viewer', tenant_id='ranged',
                  permissions=['backup.restore', 'vm.backup', 'vm.view', 'cluster.view'])
    m = _restore_manager(api)
    post = m._create_session.return_value.post
    gone = 'pbs:backup/vm/555/2026-10-01T00:00:00Z'
    r = api.as_user(u).post(f'/api/clusters/{CID}/vms/pve2/qemu/555/backups/restore', json={'volid': gone})
    assert r.status_code == 403 and '1000-1999' in r.get_json()['error'], r.data
    r = api.as_user(u).post(f'/api/clusters/{CID}/backup-restore', json={
        'mode': 'overwrite', 'volid': gone, 'target_node': 'pve2', 'target_vmid': 555})
    assert r.status_code == 403 and '1000-1999' in r.get_json()['error'], r.data
    assert not post.called
    # VM 100 is there: over it, it stays an overwrite
    assert _restore(api.as_user(u), 'pve1', 100).status_code == 200


# --- cross-cluster migration --------------------------------------------------------------------

def _xc(client, **extra):
    body = {'source_cluster': CID, 'target_cluster': 'cluster_2', 'vmid': 100, 'vm_type': 'qemu',
            'source_node': 'pve1', 'target_node': 'far1', 'target_storage': 'local-lvm',
            # placement only: removing the source needs vm.delete as well (#1048)
            'delete_source': False}
    body.update(extra)
    return client.post('/api/cross-cluster-migrate', json=body)


def _two_clusters(api):
    src = _manager(api, CID)
    tgt = _manager(api, 'cluster_2')
    # the token mint is the first step on the target: a refusal there shows the gate let it by
    tgt.create_api_token.return_value = {'success': False, 'error': 'stopped here'}
    return src, tgt


@pytest.mark.parametrize('reach', ['pool', 'acl'])
def test_a_caller_confined_on_the_target_places_no_guest_there(api, seed, reach):
    seed.tenant('acme', [CID])
    u = seed.user('mover', role='user', tenant_id='acme', permissions=['vm.migrate'])
    if reach == 'pool':
        seed.pool('cluster_2', 'pool_far', 'mover', ['pool.view', 'vm.view'])
        _pool_member('cluster_2', {'300:qemu': 'pool_far'})
    else:
        seed.vm_acl('cluster_2', 300, ['mover'])
    src, tgt = _two_clusters(api)
    r = _xc(api.as_user(u))
    assert r.status_code == 403 and 'target cluster' in r.get_json()['error'], r.data
    assert not tgt.create_api_token.called and not src.remote_migrate_vm.called


def test_an_operator_of_both_clusters_still_migrates(api, seed):
    seed.tenant('acme', [CID, 'cluster_2'])
    u = seed.user('mover', role='user', tenant_id='acme', permissions=['vm.migrate'])
    admin = seed.user('root', role='admin')
    src, tgt = _two_clusters(api)
    for who in (u, admin):
        r = _xc(api.as_user(who))
        assert r.status_code == 500 and 'stopped here' in r.get_json()['error'], r.data
    assert tgt.create_api_token.call_count == 2


def test_the_migrated_guest_takes_a_vmid_of_the_tenant(api, seed):
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID, 'cluster_2'],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    u = seed.user('mover', role='user', tenant_id='ranged', permissions=['vm.migrate'])
    src, tgt = _two_clusters(api)
    # it keeps its VMID unless told otherwise, and 100 is outside the range
    r = _xc(api.as_user(u))
    assert r.status_code == 403 and '1000-1999' in r.get_json()['error'], r.data
    r = _xc(api.as_user(u), target_vmid=1100)
    assert r.status_code == 500 and 'stopped here' in r.get_json()['error'], r.data
    assert tgt.create_api_token.call_count == 1
    # a list is no VMID the range can judge, and goes out as one all the same
    r = _xc(api.as_user(u), target_vmid=[100])
    assert r.status_code == 403, r.data
    assert tgt.create_api_token.call_count == 1


def test_a_replica_takes_a_vmid_of_the_tenant_too(api, seed):
    """The replication twin lands its replica on the target the same way."""
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID, 'cluster_2'],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    c = api.as_user(seed.user('repl_op', role='user', tenant_id='ranged',
                              permissions=['cluster.config']))
    admin = api.as_user(seed.user('root', role='admin'))
    _manager(api, CID)
    _manager(api, 'cluster_2')
    body = {'source_cluster': CID, 'target_cluster': 'cluster_2', 'vmid': 100}
    # unpinned, the replica keeps the source VMID, and 100 is outside the range
    for extra in ({}, {'target_vmid': 555}, {'target_vmid': '555'}):
        r = c.post('/api/cross-cluster-replications', json=dict(body, **extra))
        assert r.status_code == 403 and '1000-1999' in r.get_json()['error'], (extra, r.data)
    r = c.post('/api/cross-cluster-replications', json=dict(body, target_vmid=1500))
    assert r.status_code == 200 and r.get_json()['success'], r.data
    # a job inside one cluster takes the next free VMID: nothing to judge there
    r = c.post('/api/cross-cluster-replications',
               json={'source_cluster': CID, 'target_cluster': CID, 'vmid': 100, 'target_node': 'pve2'})
    assert r.status_code == 200, r.data
    assert admin.post('/api/cross-cluster-replications', json=body).status_code == 200



def test_an_admin_a_tenant_lowers_keeps_to_the_range_as_well(api, seed):
    """Admin globally, user inside the ranged tenant (what the directory mapping writes):
    the admin shortcut of the range check must not let them past it (#1028)."""
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID, 'cluster_2'],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    c = api.as_user(seed.user('lowered', role='admin', tenant_id='ranged',
                              tenant_permissions={'ranged': {'role': 'user',
                                                             'extra': ['cluster.config'],
                                                             'denied': []}}))
    _manager(api, CID)
    _manager(api, 'cluster_2')
    body = {'source_cluster': CID, 'target_cluster': 'cluster_2', 'vmid': 100}
    r = c.post('/api/cross-cluster-replications', json=dict(body, target_vmid=555))
    assert r.status_code == 403 and '1000-1999' in r.get_json()['error'], r.data
    r = c.post('/api/cross-cluster-replications', json=dict(body, target_vmid=1500))
    assert r.status_code == 200, r.data


# --- clone: the other way to put a new guest on a node ------------------------------------------

def _token(owner, role):
    from pegaprox.utils.auth import create_api_token
    res = create_api_token(owner, f'ci-{owner}-{role}', role=role)
    assert 'token' in res, res
    return {'Authorization': f"Bearer {res['token']}"}


def _cloners(api, seed):
    """Who may clone VM 100 (on pve1): a pool user, a VM-ACL user, an operator of the whole
    cluster and an admin. ROLE_USER carries vm.clone, so a token of theirs does too."""
    seed.tenant('tenant_x', [CID])
    seed.tenant('acme', ['cluster_2'])
    seed.tenant('ops', [CID])
    pool = seed.user('pooluser', role='user', tenant_id='tenant_x')
    seed.pool(CID, 'pool_1', 'pooluser', ['pool.view', 'vm.view', 'vm.clone'])
    _pool_member(CID, {'100:qemu': 'pool_1'})
    acl = seed.user('acluser', role='user', tenant_id='acme')
    seed.vm_acl(CID, 100, ['acluser'])
    return {
        'pool': api.as_user(pool),
        'acl': api.as_user(acl),
        # another tenant's user with no grant here at all
        'stranger': api.as_user(seed.user('stranger', role='user', tenant_id='acme')),
        'owner': api.as_user(seed.user('op', role='user', tenant_id='ops')),
        'admin': api.as_user(seed.user('root', role='admin')),
    }


def _clone_manager(api):
    m = _restore_manager(api)
    m.clone_vm.return_value = {'success': True, 'data': 'UPID:pve1:clone'}
    m.get_next_vmid.return_value = {'success': True, 'vmid': 777}
    return m


def _clone(client, headers=None, **body):
    return client.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/clone', json=body,
                       **({'headers': headers} if headers else {}))


def test_a_confined_caller_clones_only_onto_a_node_of_their_own_guests(api, seed):
    who = _cloners(api, seed)
    m = _clone_manager(api)
    for caller in ('pool', 'acl'):
        r = _clone(who[caller], newid=555, target_node='pve2')
        assert r.status_code == 403 and 'node' in r.get_json()['error'], (caller, r.data)
    r = _clone(who['stranger'], newid=555)
    assert r.status_code == 403, r.data
    assert not m.clone_vm.called
    # next to their own guest is where their clone goes
    assert _clone(who['pool'], newid=555).status_code == 200
    assert _clone(who['acl'], newid=556, target_node='pve1').status_code == 200
    for caller in ('owner', 'admin'):
        assert _clone(who[caller], newid=557, target_node='pve2').status_code == 200, caller
    assert m.clone_vm.call_count == 4


def test_a_token_clones_no_further_than_its_owner(api, seed):
    _cloners(api, seed)
    m = _clone_manager(api)
    r = _clone(api.anon(), headers=_token('pooluser', 'user'), newid=555, target_node='pve2')
    assert r.status_code == 403 and 'node' in r.get_json()['error'], r.data
    # an admin's token cut down to viewer has no vm.clone at all
    r = _clone(api.anon(), headers=_token('root', 'viewer'), newid=555, target_node='pve2')
    assert r.status_code == 403, r.data
    assert not m.clone_vm.called
    assert _clone(api.anon(), headers=_token('pooluser', 'user'), newid=555).status_code == 200
    assert _clone(api.anon(), headers=_token('root', 'admin'), newid=556,
                  target_node='pve2').status_code == 200


def test_a_clone_keeps_to_the_tenant_range(api, seed):
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    u = api.as_user(seed.user('ranged_op', role='user', tenant_id='ranged'))
    admin = api.as_user(seed.user('root', role='admin'))
    m = _clone_manager(api)
    for newid in (555, '555', [1500], {'id': 1500}):
        r = _clone(u, newid=newid, target_node='pve2')
        assert r.status_code == 403, (newid, r.data)
    assert not m.clone_vm.called
    assert _clone(u, newid='1500', target_node='pve2').status_code == 200
    assert m.clone_vm.call_args[1]['newid'] == 1500
    assert _clone(admin, newid=555, target_node='pve2').status_code == 200


# --- a VMID the range cannot read is no VMID inside it ------------------------------------------

@pytest.mark.parametrize('bad', [[555], [1500, 555], {'vmid': 555}])
def test_a_vmid_that_is_no_number_does_not_pass_the_range(api, seed, bad):
    """A string PVE cannot read as a number it refuses itself; a list it receives as one."""
    seed.db.save_tenant('ranged', {'name': 'ranged', 'clusters': [CID],
                                   'vmid_range_start': 1000, 'vmid_range_end': 1999})
    u = api.as_user(seed.user('ranged_op', role='user', tenant_id='ranged',
                              permissions=['vm.create', 'backup.restore', 'vm.backup']))
    m = _restore_manager(api)
    post = m._create_session.return_value.post
    r = _restore(u, 'pve2', bad)
    assert r.status_code == 403, r.data
    assert not post.called
    for kind, method, body in CREATE:
        r = u.post(f'/api/clusters/{CID}/nodes/pve1/{kind}', json=dict(body, vmid=bad))
        assert r.status_code == 403, (kind, r.data)
        assert not getattr(m, method).called
    # no VMID at all still lets Proxmox pick one, as before
    assert u.post(f'/api/clusters/{CID}/nodes/pve1/qemu',
                  json={'name': 'new', 'memory': 1024}).status_code == 200
