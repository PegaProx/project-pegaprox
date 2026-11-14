"""GET /api/clusters/<id>/pool-permissions answers for the pools the caller may see.

The per-pool route GET .../pools/<pool>/permissions answers a pool- or ACL-scoped caller
for the pools it holds a grant on and refuses the others (_pool_visibility). The cluster
wide listing beside it checked cluster reach only, and check_cluster_access lets such a
caller in through its pool and VM ACL fallbacks: an admin.users holder of another tenant
with a grant on one pool read who holds what on every pool of the cluster.

It filters through the same _pool_visibility now. An operator whose tenant owns the
cluster and who holds no grant there, and a global admin, keep every pool. MK
"""
import pytest

OWNER, OTHER = 'acme', 'globex'
CLUSTER = 'cluster_1'
ALL = f'/api/clusters/{CLUSTER}/pool-permissions'


@pytest.fixture
def cluster(api, seed):
    seed.tenant(OWNER, clusters=[CLUSTER])
    seed.tenant(OTHER, clusters=['cluster_other'])
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    seed.pool(CLUSTER, 'pool_a', 'poolguy', ['pool.view'])
    seed.pool(CLUSTER, 'pool_b', 'acme_ops', ['pool.admin'])
    seed.pool(CLUSTER, 'pool_b', 'acme-admins', ['pool.admin', 'vm.delete'], subject_type='group')
    return CLUSTER


def _pools(client):
    r = client.get(ALL)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['permissions'], r.get_data(as_text=True)


def test_a_pool_scoped_caller_of_another_tenant_gets_its_own_pool_only(api, seed, cluster):
    """Reaches the cluster only through its grant on pool_a."""
    caller = api.as_user(seed.user('poolguy', role='user', tenant_id=OTHER,
                                   permissions=['admin.users', 'cluster.view']))
    # the per-pool route draws the same line
    assert caller.get(f'/api/clusters/{CLUSTER}/pools/pool_b/permissions').status_code == 403

    perms, body = _pools(caller)

    assert sorted(perms) == ['pool_a']
    assert [p['subject_id'] for p in perms['pool_a']] == ['poolguy']
    assert 'pool_b' not in body and 'acme_ops' not in body and 'acme-admins' not in body


def test_an_acl_scoped_caller_gets_no_pool(api, seed, cluster):
    """Reaches the cluster only through a VM ACL and holds no pool grant."""
    seed.vm_acl(CLUSTER, 100, users=['portal'])
    caller = api.as_user(seed.user('portal', role='user', tenant_id=OTHER,
                                   permissions=['admin.users', 'cluster.view', 'vm.view']))

    perms, body = _pools(caller)

    assert perms == {}
    assert 'acme_ops' not in body and 'poolguy' not in body


def test_an_owner_tenant_operator_with_a_pool_grant_gets_that_pool_only(api, seed, cluster):
    """Its tenant owns the cluster, and its pool grant there makes it a scoped caller, as
    on the per-pool route."""
    seed.pool(CLUSTER, 'pool_a', 'acme_pooled', ['pool.view'])
    caller = api.as_user(seed.user('acme_pooled', role='user', tenant_id=OWNER,
                                   permissions=['admin.users', 'cluster.view']))
    assert caller.get(f'/api/clusters/{CLUSTER}/pools/pool_b/permissions').status_code == 403

    perms, _body = _pools(caller)

    assert sorted(perms) == ['pool_a']


def test_an_unconfined_operator_still_gets_every_pool(api, seed, cluster):
    """The counterweight: its tenant owns the cluster and it holds no grant there."""
    caller = api.as_user(seed.user('operator', role='user', tenant_id=OWNER,
                                   permissions=['admin.users', 'cluster.view']))

    perms, _body = _pools(caller)

    assert sorted(perms) == ['pool_a', 'pool_b']
    assert sorted(p['subject_id'] for p in perms['pool_b']) == ['acme-admins', 'acme_ops']


def test_a_global_admin_still_gets_every_pool(api, seed, cluster):
    perms, _body = _pools(api.as_user(seed.user('boss', role='admin')))

    assert sorted(perms) == ['pool_a', 'pool_b']


def test_the_route_still_needs_admin_users(api, seed, cluster):
    r = api.as_user(seed.user('plain', role='user', tenant_id=OWNER)).get(ALL)

    assert r.status_code == 403 and (r.get_json() or {}).get('code') == 'MISSING_PERMISSION', r.data
