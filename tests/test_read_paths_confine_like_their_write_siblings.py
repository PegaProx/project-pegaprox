"""Five read paths that never got the gate their own write sibling has.

The September object-level work went through this blueprint route by route and
gave the WRITE paths their object gates: set_vm_acl got a per-VM check,
get_pool_details got the pool gate, the pool CRUD routes got
_authz_object_write. The matching READ paths sat next to them and kept only
check_cluster_access — which is reachability, and whose #248 (VM-ACL) and #555
(pool) fallbacks deliberately admit a confined caller and defer the real
decision downstream. For these routes downstream never came.

  * GET /api/permissions/roles returned the entire custom-roles tree to any
    authenticated caller: every tenant's roles, their full permission lists and
    the username that created each. list_all_roles() directly below it has
    filtered by tenant since the multi-tenancy work.
  * GET .../pools/<p>/permissions answered for the same object as
    get_pool_details, which got the pool gate in the H3 disclosure, and had none.
  * GET .../vm-acls and .../vm-acls/<vmid> hand back the cluster's access map —
    which accounts reach which VM — on cluster reach alone.
  * GET .../security/audit enumerates every online node, the cluster firewall
    state, pending security updates, sshd findings and fail2ban bans. Whole-
    cluster posture with no per-object notion: require_unconfined()'s own case.

Every test here has its mirror, because the failure mode of an object gate is
the over-restriction, not the hole: an unconfined operator on a cluster their
tenant owns must keep seeing everything, and a global admin must keep seeing
everything everywhere. Aikido ai_pentest 700488972 700489031 700488841 700487610. MK
"""
import pytest

import pegaprox.utils.rbac as rbac

OWNER_TENANT = 'acme'          # owns cluster_1
OTHER_TENANT = 'globex'        # owns cluster_other
CLUSTER = 'cluster_1'


@pytest.fixture
def cluster(api, seed):
    seed.tenant(OWNER_TENANT, clusters=[CLUSTER])
    seed.tenant(OTHER_TENANT, clusters=['cluster_other'])
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    return CLUSTER


@pytest.fixture
def operator(api, seed, cluster):
    """Unconfined: their tenant owns the cluster, they hold no pool or ACL grant."""
    return api.as_user(seed.user('operator', role='user', tenant_id=OWNER_TENANT,
                                 permissions=['admin.users', 'admin.audit', 'cluster.view']))


@pytest.fixture
def acl_scoped(api, seed, cluster):
    """Reaches the cluster ONLY through a VM-ACL on VM 100 (the #248 fallback)."""
    u = seed.user('portal', role='user', tenant_id=OTHER_TENANT,
                  permissions=['admin.users', 'admin.audit', 'cluster.view', 'vm.view'])
    seed.vm_acl(CLUSTER, 100, users=['portal'])
    seed.vm_acl(CLUSTER, 200, users=['someone_else'])
    return api.as_user(u)


@pytest.fixture
def pool_scoped(api, seed, cluster):
    """Reaches the cluster ONLY through a grant on pool_a (the #555 fallback)."""
    u = seed.user('poolguy', role='user', tenant_id=OTHER_TENANT,
                  permissions=['admin.users', 'cluster.view'])
    seed.pool(CLUSTER, 'pool_a', 'poolguy', ['pool.view'])
    return api.as_user(u)


# --------------------------------------------------------------------------
# GET /api/permissions/roles
# --------------------------------------------------------------------------

@pytest.fixture
def roles_in_two_tenants(api, db):
    roles = {
        'global': {'shared': {'name': 'Shared', 'permissions': ['vm.view']}},
        'tenants': {
            OWNER_TENANT: {'acme_role': {'name': 'Acme', 'permissions': ['vm.view'],
                                         'created_by': 'acme_admin'}},
            OTHER_TENANT: {'globex_role': {'name': 'Globex', 'permissions': ['admin.users'],
                                           'created_by': 'globex_admin'}},
        },
    }
    assert rbac.save_custom_roles(roles)
    rbac.invalidate_roles_cache()
    return roles


def test_role_permissions_does_not_hand_over_another_tenants_roles(api, seed,
                                                                   roles_in_two_tenants):
    caller = api.as_user(seed.user('acme_user', role='user', tenant_id=OWNER_TENANT))
    body = caller.get('/api/permissions/roles').get_json()
    tenants = body['custom'].get('tenants', {})

    assert OTHER_TENANT not in tenants, f'another tenant\'s roles came back: {tenants}'
    assert 'globex_admin' not in str(body), 'the creating username leaked with them'


def test_role_permissions_still_returns_the_callers_own_and_the_global_ones(api, seed,
                                                                           roles_in_two_tenants):
    caller = api.as_user(seed.user('acme_user', role='user', tenant_id=OWNER_TENANT))
    body = caller.get('/api/permissions/roles').get_json()

    assert 'acme_role' in body['custom']['tenants'].get(OWNER_TENANT, {})
    assert 'shared' in body['custom'].get('global', {})
    assert 'admin' in body['builtin'], 'the builtin table has to survive the filter'


def test_role_permissions_keeps_everything_for_a_global_admin(api, seed, roles_in_two_tenants):
    boss = api.as_user(seed.user('boss', role='admin'))
    tenants = boss.get('/api/permissions/roles').get_json()['custom']['tenants']
    assert OWNER_TENANT in tenants and OTHER_TENANT in tenants


# --------------------------------------------------------------------------
# GET .../pools/<pool_id>/permissions
# --------------------------------------------------------------------------

def _pool_perms(cluster_id, pool_id):
    return f'/api/clusters/{cluster_id}/pools/{pool_id}/permissions'


def test_a_pool_scoped_caller_cannot_read_another_pools_grants(pool_scoped, cluster):
    r = pool_scoped.get(_pool_perms(cluster, 'pool_b'))
    assert r.status_code == 403, f'read pool_b\'s grant list: {r.data}'


def test_a_pool_scoped_caller_still_reads_its_own_pool(pool_scoped, cluster):
    r = pool_scoped.get(_pool_perms(cluster, 'pool_a'))
    assert r.status_code == 200, r.data


def test_an_unconfined_operator_still_reads_every_pool(operator, cluster):
    r = operator.get(_pool_perms(cluster, 'pool_b'))
    assert r.status_code == 200, r.data


# --------------------------------------------------------------------------
# GET .../vm-acls  and  .../vm-acls/<vmid>
# --------------------------------------------------------------------------

def _acls(cluster_id, vmid=None):
    base = f'/api/clusters/{cluster_id}/vm-acls'
    return base if vmid is None else f'{base}/{vmid}'


def test_an_acl_scoped_caller_sees_only_its_own_row_in_the_list(acl_scoped, cluster):
    r = acl_scoped.get(_acls(cluster))
    assert r.status_code == 200, r.data
    vmids = {row['vmid'] for row in r.get_json()}

    assert vmids == {100}, f'the whole access map came back: {vmids}'


def test_an_acl_scoped_caller_cannot_read_a_foreign_vms_acl(acl_scoped, cluster):
    r = acl_scoped.get(_acls(cluster, 200))
    assert r.status_code == 403, f'read VM 200\'s ACL: {r.data}'


def test_an_acl_scoped_caller_still_reads_its_own_vms_acl(acl_scoped, cluster):
    r = acl_scoped.get(_acls(cluster, 100))
    assert r.status_code == 200, r.data
    assert 'portal' in r.get_json()['users']


def test_an_unconfined_operator_still_sees_the_whole_acl_list(operator, seed, cluster):
    seed.vm_acl(cluster, 100, users=['portal'])
    seed.vm_acl(cluster, 200, users=['someone_else'])
    r = operator.get(_acls(cluster))
    assert r.status_code == 200, r.data
    assert {row['vmid'] for row in r.get_json()} == {100, 200}


# --------------------------------------------------------------------------
# GET .../security/audit
# --------------------------------------------------------------------------

def _audit(cluster_id):
    return f'/api/clusters/{cluster_id}/security/audit'


def test_a_confined_caller_cannot_pull_the_cluster_security_audit(acl_scoped, cluster):
    r = acl_scoped.get(_audit(cluster))
    assert r.status_code == 403, f'got the whole cluster\'s posture: {r.data}'


def test_an_unconfined_operator_is_not_blocked_by_the_new_gate(operator, cluster):
    """The mirror. Whatever the fake manager does with the upstream calls, the
    answer must not be the confinement 403."""
    r = operator.get(_audit(cluster))
    assert r.status_code != 403, r.data


# --------------------------------------------------------------------------
# DELETE /api/roles/<role_id> — the holder list it refuses with
# --------------------------------------------------------------------------

@pytest.fixture
def same_name_role_in_both_tenants(api, db, seed):
    roles = {
        'global': {},
        'tenants': {
            OWNER_TENANT: {'ops': {'name': 'Ops (acme)', 'permissions': ['vm.view']}},
            OTHER_TENANT: {'ops': {'name': 'Ops (globex)', 'permissions': ['vm.view']}},
        },
    }
    assert rbac.save_custom_roles(roles)
    rbac.invalidate_roles_cache()
    # a holder of the OTHER tenant's identically-named role
    seed.user('globex_operator', role='ops', tenant_id=OTHER_TENANT)
    return roles


def test_deleting_a_tenant_role_does_not_name_another_tenants_users(api, seed,
                                                                    same_name_role_in_both_tenants):
    """The holder scan matched on the role STRING across every account, so the
    refusal listed people the caller cannot see, in a tenant they have nothing
    to do with."""
    delegate = api.as_user(seed.user('acme_roleadmin', role='user', tenant_id=OWNER_TENANT,
                                     permissions=['admin.roles']))

    r = delegate.delete('/api/roles/ops')

    assert 'globex_operator' not in r.get_data(as_text=True), \
        f'another tenant\'s username came back: {r.data}'


def test_a_delegate_can_delete_its_own_unused_role(api, seed, same_name_role_in_both_tenants):
    """The functional half: nobody in the caller's tenant holds it, so the 409
    was about accounts that were never theirs."""
    delegate = api.as_user(seed.user('acme_roleadmin', role='user', tenant_id=OWNER_TENANT,
                                     permissions=['admin.roles']))

    r = delegate.delete('/api/roles/ops')
    assert r.status_code == 200, f'blocked by a foreign tenant\'s holder: {r.data}'


def test_a_role_still_in_use_inside_the_tenant_is_still_refused(api, seed,
                                                                same_name_role_in_both_tenants):
    """The mirror — the 409 exists for a reason and has to keep firing."""
    seed.user('acme_operator', role='ops', tenant_id=OWNER_TENANT)
    delegate = api.as_user(seed.user('acme_roleadmin', role='user', tenant_id=OWNER_TENANT,
                                     permissions=['admin.roles']))

    r = delegate.delete('/api/roles/ops')
    assert r.status_code == 409, r.data
    assert 'acme_operator' in r.get_data(as_text=True)
