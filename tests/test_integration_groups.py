# Regression: cluster (re-)grouping / rename must require real TENANT ownership of the cluster,
# not mere additive VM-ACL/pool reach into it.
#
# CodeAnt exploitation finding (2026-07-13): assign_cluster_to_group / rename_cluster only gated
# the SOURCE cluster with check_cluster_access, whose #248/#555 ACL+pool fallbacks return True for
# a cluster the actor merely has a VM-level grant on. A non-admin with admin.groups + one foreign
# VM-ACL grant could move that cluster into their own group and gain cluster-wide tenant membership
# over it (cross-tenant hijack). Fixed with a get_user_clusters(include_pools=False) ownership gate.

CLUSTER = 'cluster_1'   # the foreign cluster the actor only has VM-ACL reach into


def _acl_reach_actor(api, seed):
    # alice: non-admin in a tenant that does NOT own cluster_1, holds admin.groups, and has a
    # single VM-ACL grant on VM 100 in cluster_1 -> check_cluster_access passes via the ACL
    # fallback, but she does not TENANT-own cluster_1.
    seed.tenant('tenant_a', clusters=['cluster_home'])
    alice = seed.user('alice', role='user', tenant_id='tenant_a', permissions=['admin.groups'])
    seed.vm_acl(CLUSTER, 100, users=['alice'], inherit_role=True)
    api.set_manager(CLUSTER, api.make_fake_manager())
    return alice


def test_acl_reach_actor_cannot_move_foreign_cluster_into_group(api, seed):
    alice = _acl_reach_actor(api, seed)
    r = api.as_user(alice).put(f'/api/clusters/{CLUSTER}/group', json={'group_id': 'g-alice'})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_acl_reach_actor_cannot_ungroup_foreign_cluster(api, seed):
    # the ungroup variant ({group_id: null}) skips the destination check entirely — the source
    # ownership gate must still deny it (integrity: can't rip a cluster out of its owner's group).
    alice = _acl_reach_actor(api, seed)
    r = api.as_user(alice).put(f'/api/clusters/{CLUSTER}/group', json={'group_id': None})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_acl_reach_actor_cannot_rename_foreign_cluster(api, seed):
    alice = _acl_reach_actor(api, seed)
    r = api.as_user(alice).put(f'/api/clusters/{CLUSTER}/rename', json={'display_name': 'pwned'})
    assert r.status_code == 403, r.get_data(as_text=True)


def test_tenant_owner_can_regroup_own_cluster(api, seed):
    # positive control: the actual tenant owner (with admin.groups) is NOT over-restricted.
    seed.tenant('tenant_b', clusters=[CLUSTER])
    bob = seed.user('bob', role='user', tenant_id='tenant_b', permissions=['admin.groups'])
    api.set_manager(CLUSTER, api.make_fake_manager())
    r = api.as_user(bob).put(f'/api/clusters/{CLUSTER}/group', json={'group_id': None})
    assert r.status_code == 200, r.get_data(as_text=True)


def test_admin_can_regroup_any_cluster(api, seed):
    root = seed.user('root', role='admin', tenant_id='default')
    api.set_manager(CLUSTER, api.make_fake_manager())
    r = api.as_user(root).put(f'/api/clusters/{CLUSTER}/group', json={'group_id': None})
    assert r.status_code == 200, r.get_data(as_text=True)
