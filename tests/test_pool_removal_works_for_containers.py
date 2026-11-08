"""Taking a container out of a pool must work the same as taking a VM out.

_authorize_pool_assignment grew a source-pool check: a real MOVE needs a management
permission on the guest, re-adding it to the pool it is already in does not. The check
asks the pool membership cache which pool the guest is in — and it looked the guest up
under `<vmid>:<vm_type or 'qemu'>`.

remove_pool_member has no vm_type to give it. Its route is
DELETE /pools/<pool>/members/<vmid>, with no type in the path, so the lookup defaulted to
qemu. A container is keyed `<vmid>:lxc`, so every LXC read as "in no pool" — which the
check treats as a move — and a pool-scoped caller could no longer take their own container
out of their own pool. Fails closed, so it is a lost operation rather than a hole, but it
is a plain regression against what worked the day before.

VMIDs are unique per cluster, so the type is not needed to identify the guest.

Found by CodeAnt pointing at the new block; the defect was one call site away. MK
"""
import time

import pytest

import pegaprox.api.static_files as sf
import pegaprox.utils.rbac as rbac

CL = 'cluster_1'
VMID = 150


def _seed_membership(cluster_id, mapping):
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': {f'{vmid}:{vtype}': pool for vmid, (vtype, pool) in mapping.items()},
            'timestamp': time.time(), 'refreshing': False,
        }


@pytest.fixture
def pool_scoped(api, seed):
    """A caller whose ONLY reach into the cluster is a read-only pool grant."""
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t_elsewhere', [])
    seed.user('robin', role='user', tenant_id='t_elsewhere', permissions=['pool.assign'])
    seed.pool(CL, 'pool_mine', 'robin', ['pool.view', 'vm.view'])
    api.set_manager(CL, api.make_fake_manager(CL))
    return seed


def _authorize(api, vm_type):
    """Exactly how remove_pool_member calls it: no vm_type at all."""
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json={}):
        _rq.session = {'user': 'robin', 'role': 'user'}
        return sf._authorize_pool_assignment(CL, 'pool_mine', VMID, vm_type)


def test_a_container_can_be_removed_from_its_own_pool(api, pool_scoped):
    _seed_membership(CL, {VMID: ('lxc', 'pool_mine')})
    ok, err = _authorize(api, None)          # the remove route passes no type
    assert ok is True, err


def test_a_vm_can_be_removed_from_its_own_pool(api, pool_scoped):
    """The case that happened to work because the default guessed right."""
    _seed_membership(CL, {VMID: ('qemu', 'pool_mine')})
    ok, err = _authorize(api, None)
    assert ok is True, err


def test_a_container_named_with_its_type_still_resolves(api, pool_scoped):
    """The add route DOES pass a type — that path must keep working too."""
    _seed_membership(CL, {VMID: ('lxc', 'pool_mine')})
    ok, err = _authorize(api, 'lxc')
    assert ok is True, err


def test_a_guest_in_someone_elses_pool_is_still_a_move(api, pool_scoped):
    """The counterweight — the check this regression came from must still bite."""
    _seed_membership(CL, {VMID: ('lxc', 'pool_theirs')})
    ok, err = _authorize(api, None)
    assert ok is False, 'a read-only holder moved a guest out of a pool they do not manage'
    assert err[1] == 403


def test_a_guest_in_no_pool_at_all_is_still_a_move(api, pool_scoped):
    """Unresolvable current pool keeps failing closed."""
    _seed_membership(CL, {})
    ok, err = _authorize(api, None)
    assert ok is False
    assert err[1] == 403
