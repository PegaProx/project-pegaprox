"""A pool grant has to make the pool's VMs visible (#793).

The regression that got us here: 6441b70 correctly stopped a pool-scoped caller falling
through to the blanket role-level vm.view, which used to hand them the whole cluster. What
nobody noticed is that `vm.view` cannot be stored in a pool grant at all — POOL_PERMISSIONS
is the allowlist the grant endpoint validates against and has never contained it. So the
inventory gate asked for the one permission a grant is incapable of carrying, and every
preset below Admin started listing an empty pool. The only value that still worked was
pool.admin, which carries vm.delete — so the fix for an over-permissive read pushed admins
into handing out a destructive grant.

test_authz_pool.py did not catch it because its fixture seeds ['pool.view', 'vm.view']
straight into the DB, which the API would have rejected. These tests grant through the real
endpoint instead, so the permission set under test is one an admin can actually create. MK
"""
import time

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api.users import POOL_PERMISSIONS
from pegaprox.utils.rbac import user_can_access_vm


CLUSTER = 'cluster_1'
POOL = 'pool_1'


def _seed_pool_membership(cluster_id, mapping):
    """VM→pool membership is normally resolved live off the cluster manager and cached; seed
    the cache so the decision path runs without a real PVE. Same helper as test_authz_pool —
    that part of its fixture was fine, it was seeding the GRANT that hid this bug."""
    data = {f"{vmid}:{vtype}": pool for vmid, (vtype, pool) in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }

# The three quick-select presets from the Pool Permissions UI, verbatim.
OPERATOR = ['pool.view', 'vm.start', 'vm.stop', 'vm.console']
POWER_USER = OPERATOR + ['vm.config', 'vm.snapshot', 'vm.backup']
ADMIN = ['pool.admin']


@pytest.fixture
def granted(api, seed, db):
    """An admin, and a user whose ONLY route to the cluster is a pool grant made through the
    real endpoint. Returns a function that applies a permission set and hands back the user."""
    seed.tenant('tenant_owner', clusters=[CLUSTER])
    seed.tenant('tenant_other', clusters=['cluster_2'])
    admin = seed.user('root_admin', role='admin')
    member = seed.user('pooled', role='user', tenant_id='tenant_other')
    api.set_manager(CLUSTER, api.make_fake_manager(CLUSTER))
    # 100 is in the granted pool, 999 deliberately is not
    _seed_pool_membership(CLUSTER, {100: ('qemu', POOL), 999: ('qemu', 'other_pool')})

    def _apply(perms):
        r = api.as_user(admin).post(
            f'/api/clusters/{CLUSTER}/pools/{POOL}/permissions',
            json={'subject_type': 'user', 'subject_id': 'pooled', 'permissions': perms})
        return r, dict(member, username='pooled')
    return _apply


def test_vm_view_cannot_even_be_stored_in_a_grant():
    """The root of it. If this ever starts passing, the gate below can go back to asking for
    vm.view directly — until then, asking for it is asking for something unreachable."""
    assert 'vm.view' not in POOL_PERMISSIONS


@pytest.mark.parametrize('label,perms', [('operator', OPERATOR), ('power user', POWER_USER)])
def test_a_preset_below_admin_still_shows_the_pools_vms(granted, label, perms):
    """The reported symptom: pool listed, no VMs inside it."""
    resp, member = granted(perms)
    assert resp.status_code == 200, f'{label}: the grant itself was rejected — {resp.get_data(as_text=True)}'

    assert user_can_access_vm(member, CLUSTER, 100, 'vm.view') is True, \
        f'{label} grant produced an invisible pool'


def test_pool_view_on_its_own_is_enough_to_see_them(granted):
    """A read-only grant has to be expressible. Before the fix the smallest working grant was
    pool.admin, i.e. an admin who wanted to give out a look had to give out vm.delete."""
    resp, member = granted(['pool.view'])
    assert resp.status_code == 200

    assert user_can_access_vm(member, CLUSTER, 100, 'vm.view') is True


def test_visibility_does_not_leak_the_actions(granted):
    """The point of the fix is narrow: it answers 'may they SEE it', nothing else. An operator
    grant must still not delete, reconfigure or migrate."""
    resp, member = granted(OPERATOR)
    assert resp.status_code == 200

    assert user_can_access_vm(member, CLUSTER, 100, 'vm.start') is True     # in the grant
    for denied in ('vm.delete', 'vm.config', 'vm.migrate', 'vm.clone', 'vm.backup'):
        assert user_can_access_vm(member, CLUSTER, 100, denied) is False, denied


def test_a_pool_grant_still_stops_at_the_pool_boundary(granted, db):
    """The hole 6441b70 closed must stay closed: visibility covers the pool's members, not the
    rest of the cluster. VM 999 is in no pool the caller holds."""
    resp, member = granted(POWER_USER)
    assert resp.status_code == 200

    assert user_can_access_vm(member, CLUSTER, 999, 'vm.view') is False


def test_a_user_with_no_grant_at_all_sees_nothing(granted):
    """The unconfined-vs-confined fixture the earlier gates were missing."""
    _, member = granted(OPERATOR)
    stranger = dict(member, username='nobody')

    assert user_can_access_vm(stranger, CLUSTER, 100, 'vm.view') is False


def test_the_admin_preset_keeps_working(granted):
    resp, member = granted(ADMIN)
    assert resp.status_code == 200

    assert user_can_access_vm(member, CLUSTER, 100, 'vm.view') is True
    assert user_can_access_vm(member, CLUSTER, 100, 'vm.delete') is True


def test_every_preset_the_ui_offers_is_actually_grantable():
    """Structural: the UI must not offer a preset the endpoint would reject. This is the check
    that would have made the mismatch obvious from either side."""
    for label, perms in (('operator', OPERATOR), ('power user', POWER_USER), ('admin', ADMIN)):
        bad = [p for p in perms if p not in POOL_PERMISSIONS]
        assert not bad, f'{label} preset contains ungrantable {bad}'
