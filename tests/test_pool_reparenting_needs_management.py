"""Seeing a VM is not enough authority to move it between pools.

Pool membership drives user_can_access_vm, so re-pooling a guest changes who can do what
to it. _authorize_pool_assignment already required two things: the caller must already
reach the VM (so assigning cannot CONFER access — that was the #766 regression fix), and
they must manage the destination pool.

The floor for "already reaches it" was vm.view, and that left one move open. A caller who
holds a READ-ONLY grant on the pool a guest currently sits in, and a managing grant on
some other pool, passes a vm.view check on that guest — and can move it into the pool with
the wider grant, handing themselves the very rights the first check exists to withhold.

So the floor is a management permission on the VM, not visibility. That is deliberately
expressed as a per-VM permission rather than as "resolve the source pool and check it":
the membership cache cannot distinguish an empty cluster from a failed refresh, which is a
real state on clusters whose API token lacks Pool.Audit, and it would fail open there.

Aikido ai_pentest 700487364. MK
"""
import contextlib
import time

import pytest

import pegaprox.api.static_files as sf
import pegaprox.utils.rbac as rbac

CL = 'cluster_1'
VMID = 100


@contextlib.contextmanager
def _as(api, username, role='user'):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost', json={}):
        _rq.session = {'user': username, 'role': role}
        yield


@pytest.fixture
def estate(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES (?, ?, '10.0.0.1', 'root@pam', 'x')''', (CL, CL))
    seed.tenant('t', [CL])
    api.set_manager(CL, api.make_fake_manager(CL))
    return seed


def _seed_membership(cluster_id, mapping):
    """Pin which pool each guest is in — same shape get_pool_membership_cache serves."""
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': {f'{vmid}:{vtype}': pool for vmid, (vtype, pool) in mapping.items()},
            'timestamp': time.time(), 'refreshing': False,
        }


def _authorize(api, username, pool_id='pool_mine', role='user'):
    with _as(api, username, role):
        return sf._authorize_pool_assignment(CL, pool_id, VMID, 'qemu')


def test_a_read_only_grant_on_the_guest_cannot_re_pool_it(api, estate):
    """The move this closes: visible through one pool, managed through another."""
    estate.user('robin', role='user', tenant_id='t', permissions=['pool.assign'])
    # their only reach on VMID 100 is read-only
    estate.vm_acl(CL, VMID, ['robin'], permissions=['vm.view'], inherit_role=False)
    estate.pool(CL, 'pool_mine', 'robin', ['vm.view', 'vm.config'])

    ok, err = _authorize(api, 'robin')
    assert ok is False, 'a read-only holder re-pooled the guest'
    assert err[1] == 403


def test_a_managing_grant_on_the_guest_still_re_pools_it(api, estate):
    """The counterweight — #766's case must keep working."""
    estate.user('sam', role='user', tenant_id='t', permissions=['pool.assign'])
    estate.vm_acl(CL, VMID, ['sam'], permissions=['vm.view', 'vm.config'], inherit_role=False)
    estate.pool(CL, 'pool_mine', 'sam', ['vm.view', 'vm.config'])

    ok, err = _authorize(api, 'sam')
    assert ok is True, err


def test_a_caller_who_cannot_see_the_guest_is_still_refused_first(api, estate):
    """The original #766 escalation stays closed, and with its own message."""
    estate.user('mallory', role='user', tenant_id='t', permissions=['pool.assign'])
    estate.pool(CL, 'pool_mine', 'mallory', ['vm.view', 'vm.config'])

    ok, err = _authorize(api, 'mallory')
    assert ok is False
    assert err[1] == 403
    assert 'Access denied to this VM' in err[0].get_json()['error']


def test_an_admin_is_unaffected(api, estate):
    estate.user('dana', role='admin')
    ok, err = _authorize(api, 'dana', role='admin')
    assert ok is True, err


def test_a_plain_cluster_wide_operator_is_unaffected(api, estate):
    """Not pool-scoped, so they manage every pool on a cluster they own — and they
    reach the guest through their role, which carries vm.config."""
    estate.user('ops', role='user', tenant_id='t',
                permissions=['pool.assign', 'vm.view', 'vm.config'])
    ok, err = _authorize(api, 'ops')
    assert ok is True, err


# --- the move itself, with a real source pool -------------------------------------

def test_moving_out_of_a_read_only_pool_into_a_managed_one_is_refused(api, estate):
    """The precise shape the report describes: source visible, destination managed.

    rory sits in a tenant that does NOT hold the cluster, so the pool grants are their
    only reach. A tenant whose tenant DID own the cluster gets vm.config on every guest
    in it through the role fall-through, and re-pooling would confer nothing — that
    caller is a cluster-wide operator who happens to also hold pool grants."""
    estate.tenant('t_elsewhere', [])
    estate.user('rory', role='user', tenant_id='t_elsewhere', permissions=['pool.assign'])
    estate.pool(CL, 'pool_src', 'rory', ['pool.view', 'vm.view'])       # read-only
    estate.pool(CL, 'pool_dst', 'rory', ['pool.view', 'vm.view', 'vm.config'])
    _seed_membership(CL, {VMID: ('qemu', 'pool_src')})

    ok, err = _authorize(api, 'rory', pool_id='pool_dst')
    assert ok is False, 'the guest was moved into the wider pool'
    assert err[1] == 403
    assert 'moved between pools' in err[0].get_json()['error']


def test_re_adding_a_guest_to_the_pool_it_is_already_in_is_allowed(api, estate):
    """#766's own case — not a move, so it confers nothing and must keep working."""
    estate.tenant('t_elsewhere', [])
    estate.user('rory', role='user', tenant_id='t_elsewhere', permissions=['pool.assign'])
    estate.pool(CL, 'pool_src', 'rory', ['pool.view', 'vm.view'])
    _seed_membership(CL, {VMID: ('qemu', 'pool_src')})

    ok, err = _authorize(api, 'rory', pool_id='pool_src')
    assert ok is True, err


def test_a_managing_grant_on_the_source_still_moves_it(api, estate):
    """Manage both ends and the move is ordinary work."""
    estate.tenant('t_elsewhere', [])
    estate.user('rory', role='user', tenant_id='t_elsewhere', permissions=['pool.assign'])
    estate.pool(CL, 'pool_src', 'rory', ['pool.view', 'vm.view', 'vm.config'])
    estate.pool(CL, 'pool_dst', 'rory', ['pool.view', 'vm.view', 'vm.config'])
    _seed_membership(CL, {VMID: ('qemu', 'pool_src')})

    ok, err = _authorize(api, 'rory', pool_id='pool_dst')
    assert ok is True, err
