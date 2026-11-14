"""PUT /api/clusters/<id>/sort-order and POST /api/clusters/reorder move only clusters the
caller manages.

The single route asked for cluster.config and that the id is a cluster, nothing about whose
cluster it is: a tenant_admin-like delegate moved another tenant's cluster in the list
every user of that tenant sees, and an unknown id answered 404 where a foreign one
answered 200. It takes the gate of the location route beside it now,
check_cluster_access and then require_unconfined.

The bulk reorder filtered by the caller's clusters, and a pool grant on another tenant's
cluster counted as one of them. It takes the clusters the single route lets the caller
move: its tenant's own, without those it is limited on there.

Every case has its counterweight: the caller's own cluster, a global admin, and an
operator of the default tenant, who is limited to no cluster. MK
"""
import pytest

A, B = 'acme', 'globex'
CA, CA2, CB = 'cluster_a', 'cluster_a2', 'cluster_b'


@pytest.fixture
def estate(api, seed):
    seed.tenant(A, clusters=[CA, CA2])
    seed.tenant(B, clusters=[CB])
    for i, cid in enumerate((CA, CA2, CB)):
        seed.db.save_cluster(cid, {'name': cid, 'host': '10.0.0.1', 'group_id': None})
        seed.db.conn.execute('UPDATE clusters SET sort_order = ? WHERE id = ?', (i + 1, cid))
        api.set_manager(cid, api.make_fake_manager(cid))
    seed.db.conn.commit()
    return seed


def _order(seed, cid):
    return seed.db.query_one('SELECT sort_order FROM clusters WHERE id = ?', (cid,))['sort_order']


def _operator(api, seed, name='op_a', tenant=A):
    return api.as_user(seed.user(name, role='user', tenant_id=tenant,
                                 permissions=['cluster.config', 'cluster.view']))


def _refused(r):
    assert (r.get_json(silent=True) or {}).get('code') != 'MISSING_PERMISSION', r.data
    return r.status_code == 403


# --- PUT .../sort-order -------------------------------------------------------------------

def test_another_tenants_cluster_is_not_moved(api, estate):
    op = _operator(api, estate)
    # the location route beside it refuses the same caller
    assert op.put(f'/api/clusters/{CB}/location', json={'latitude': None, 'longitude': None}).status_code == 403

    r = op.put(f'/api/clusters/{CB}/sort-order', json={'sort_order': 7})

    assert _refused(r), (r.status_code, r.data)
    assert _order(estate, CB) == 3


@pytest.mark.parametrize('reach', ['pool', 'acl'])
def test_a_cluster_reached_through_a_grant_is_not_moved(api, estate, reach):
    if reach == 'pool':
        estate.pool(CB, 'pool_x', 'op_a', ['pool.view', 'vm.view'])
    else:
        estate.vm_acl(CB, 100, users=['op_a'])
    op = _operator(api, estate)

    r = op.put(f'/api/clusters/{CB}/sort-order', json={'sort_order': -50})

    assert _refused(r), (r.status_code, r.data)
    assert _order(estate, CB) == 3


def test_an_own_cluster_the_caller_is_scoped_on_is_not_moved(api, estate):
    """Its tenant owns the cluster, and a pool grant there limits it, as on the location route."""
    estate.pool(CA, 'pool_x', 'op_a', ['pool.view'])
    op = _operator(api, estate)

    r = op.put(f'/api/clusters/{CA}/sort-order', json={'sort_order': 9})

    assert _refused(r), (r.status_code, r.data)
    assert _order(estate, CA) == 1


def test_a_foreign_id_answers_like_one_that_does_not_exist(api, estate):
    op = _operator(api, estate)

    unknown = op.put('/api/clusters/ffffffff/sort-order', json={'sort_order': 1})
    foreign = op.put(f'/api/clusters/{CB}/sort-order', json={'sort_order': 1})

    assert (unknown.status_code, unknown.get_json()) == (foreign.status_code, foreign.get_json())


def test_the_callers_own_cluster_still_moves(api, estate):
    r = _operator(api, estate).put(f'/api/clusters/{CA}/sort-order', json={'sort_order': 4})

    assert r.status_code == 200, r.data
    assert _order(estate, CA) == 4


def test_a_global_admin_and_a_default_tenant_operator_still_move_any(api, estate):
    admin = api.as_user(estate.user('boss', role='admin'))
    assert admin.put(f'/api/clusters/{CB}/sort-order', json={'sort_order': 5}).status_code == 200
    assert _order(estate, CB) == 5

    op = api.as_user(estate.user('op_d', role='user', permissions=['cluster.config', 'cluster.view']))
    assert op.put(f'/api/clusters/{CB}/sort-order', json={'sort_order': 6}).status_code == 200
    assert _order(estate, CB) == 6


# --- POST /api/clusters/reorder -----------------------------------------------------------

def _reorder(client, order):
    r = client.post('/api/clusters/reorder', json={'order': order})
    return r.status_code, (r.get_json() or {}).get('order')


def test_the_bulk_reorder_leaves_out_a_cluster_reached_through_a_pool(api, estate):
    """A pool grant on another tenant's cluster put it in the list the caller may write."""
    estate.pool(CB, 'pool_x', 'op_a', ['pool.view', 'vm.view'])

    assert _reorder(_operator(api, estate), [CB, CA]) == (200, [CA])
    assert _order(estate, CB) == 3


def test_the_bulk_reorder_leaves_out_an_own_cluster_the_caller_is_scoped_on(api, estate):
    """As the single route: a pool grant on its own tenant's cluster limits the caller there."""
    estate.pool(CA, 'pool_x', 'op_a', ['pool.view'])

    assert _reorder(_operator(api, estate), [CA2, CA]) == (200, [CA2])
    assert _order(estate, CA) == 1


def test_the_bulk_reorder_still_orders_the_callers_clusters(api, estate):
    assert _reorder(_operator(api, estate), [CA2, CB, CA]) == (200, [CA2, CA])
    assert (_order(estate, CA2), _order(estate, CA), _order(estate, CB)) == (0, 1, 3)


def test_a_global_admin_and_a_default_tenant_operator_still_reorder_every_cluster(api, estate):
    admin = api.as_user(estate.user('boss', role='admin'))
    assert _reorder(admin, [CB, CA, CA2]) == (200, [CB, CA, CA2])

    op = api.as_user(estate.user('op_d', role='user', permissions=['cluster.config', 'cluster.view']))
    assert _reorder(op, [CA2, CB]) == (200, [CA2, CB])
    assert (_order(estate, CA2), _order(estate, CB)) == (0, 1)
