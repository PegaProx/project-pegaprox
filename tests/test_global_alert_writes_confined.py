"""POST, PUT and DELETE on /api/alerts refuse a caller confined in the rule's cluster, as the
per-cluster write routes do.

They checked only that the caller reaches the cluster, which a pool grant or a guest ACL does
by design. A confined alert.manage holder could so create a rule on any guest of the cluster,
and change or delete one by its id, the change answered with the whole rule.

Confined: a pool grant in its own tenant, on another tenant's cluster or from the default
tenant, a guest ACL. wide (a viewer of the owning tenant), nonode (the same without node.view),
plain (a default-tenant viewer, no grant) and the admin write as before.
"""
import time
import types

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped

CID = 'cluster_1'
CONFINED = ('carol', 'dave', 'erin', 'dflt')
UNCONFINED = ('wide', 'nonode', 'plain', 'root')


@pytest.fixture
def world(api, seed):
    seed.tenant('tenant_x', clusters=[CID])
    seed.tenant('tenant_y', clusters=['cluster_2'])
    manage = ['alert.manage']
    users = {
        'carol': seed.user('carol', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dave': seed.user('dave', role='viewer', tenant_id='tenant_y', permissions=manage),
        'erin': seed.user('erin', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dflt': seed.user('dflt', role='viewer', permissions=manage),
        'wide': seed.user('wide', role='viewer', tenant_id='tenant_x', permissions=manage),
        'nonode': seed.user('nonode', role='viewer', tenant_id='tenant_x', permissions=manage,
                            denied=['node.view']),
        'plain': seed.user('plain', role='viewer', permissions=manage),
        'root': seed.user('root', role='admin'),
    }
    for name in ('carol', 'dave', 'dflt'):
        seed.pool(CID, 'pool_a', name, ['pool.view'])
    seed.vm_acl(CID, 100, ['erin'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_a', '200:qemu': 'pool_b'},
                                            'timestamp': time.time(), 'refreshing': False}
    for cid in (CID, 'cluster_2'):
        mgr = api.make_fake_manager(cluster_id=cid)
        mgr.config = types.SimpleNamespace(name=cid, check_interval=300, host='h', enabled=True)
        api.set_manager(cid, mgr)
    clients = {name: api.as_user(u) for name, u in users.items()}
    return types.SimpleNamespace(users=users, clients=clients, api=api, seed=seed)


def _rule(world, target_type='vm', target_id='200'):
    r = world.clients['root'].post(f'/api/clusters/{CID}/alerts', json={
        'name': f'cpu {target_id}', 'metric': 'cpu', 'operator': '>', 'threshold': 90,
        'target_type': target_type, 'target_id': target_id, 'channels': []})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['alert']['id']


def _body(target_id):
    return {'name': 'mine', 'cluster_id': CID, 'target_type': 'vm', 'target_id': target_id,
            'metric': 'cpu', 'operator': '>', 'threshold': 90}


def test_the_identities_are_what_the_tests_take_them_for(world):
    u = world.users
    for name in CONFINED:
        assert caller_is_scoped(u[name], CID) is True, name
        assert rbac.user_can_access_vm(u[name], CID, 100, 'vm.view') is True, name
        assert rbac.user_can_access_vm(u[name], CID, 200, 'vm.view') is False, name
        # they reach the cluster: the refusal below is not the cluster gate's
        assert world.clients[name].get(f'/api/clusters/{CID}/alerts').status_code == 200, name
    for name in UNCONFINED:
        assert caller_is_scoped(u[name], CID) is False, name


@pytest.mark.parametrize('who', CONFINED)
@pytest.mark.parametrize('vmid', ['100', '200'])
def test_a_confined_caller_creates_no_rule(world, who, vmid):
    r = world.clients[who].post('/api/alerts', json=_body(vmid))
    assert r.status_code == 403, r.get_data(as_text=True)
    # the route stores into the old alerts table: nothing went there
    assert world.seed.db.get_all_alerts() == {}


@pytest.mark.parametrize('who', UNCONFINED)
def test_an_unconfined_caller_creates_a_rule(world, who):
    r = world.clients[who].post('/api/alerts', json=_body('200'))
    assert r.status_code == 201, r.get_data(as_text=True)
    assert r.get_json()['target_id'] == '200'


@pytest.mark.parametrize('who', ('plain', 'root'))
def test_a_rule_of_no_cluster_is_still_written_by_who_reaches_every_cluster(world, who):
    r = world.clients[who].post('/api/alerts', json=dict(_body('200'), cluster_id=''))
    assert r.status_code == 201, r.get_data(as_text=True)


@pytest.mark.parametrize('who', CONFINED)
def test_a_confined_caller_changes_no_rule_nor_reads_it_back(world, who):
    rid = _rule(world)
    r = world.clients[who].put(f'/api/alerts/{rid}', json={'threshold': 1, 'enabled': False})
    assert r.status_code == 403, r.get_data(as_text=True)
    body = r.get_json()
    assert 'target_id' not in body and 'threshold' not in body, body
    assert world.seed.db.get_all_alerts() == {}


@pytest.mark.parametrize('who', UNCONFINED)
def test_an_unconfined_caller_changes_a_rule(world, who):
    rid = _rule(world)
    r = world.clients[who].put(f'/api/alerts/{rid}', json={'threshold': 95})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['threshold'] == 95


def test_a_rule_is_not_moved_to_a_cluster_its_caller_is_confined_in(world):
    # wide reaches cluster_2 through a pool there only: confined in it, not in cluster_1
    world.seed.pool('cluster_2', 'pool_c', 'wide', ['pool.view'])
    assert caller_is_scoped(world.users['wide'], CID) is False
    assert caller_is_scoped(world.users['wide'], 'cluster_2') is True
    rid = _rule(world)
    r = world.clients['wide'].put(f'/api/alerts/{rid}', json={'cluster_id': 'cluster_2'})
    assert r.status_code == 403, r.get_data(as_text=True)
    r = world.clients['root'].put(f'/api/alerts/{rid}', json={'cluster_id': 'cluster_2'})
    assert r.status_code == 200, r.get_data(as_text=True)


@pytest.mark.parametrize('who', CONFINED)
def test_a_confined_caller_deletes_no_rule(world, who):
    rid = _rule(world)
    r = world.clients[who].delete(f'/api/alerts/{rid}')
    assert r.status_code == 403, r.get_data(as_text=True)


@pytest.mark.parametrize('who', UNCONFINED)
def test_an_unconfined_caller_deletes_a_rule(world, who):
    rid = _rule(world)
    r = world.clients[who].delete(f'/api/alerts/{rid}')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['success'] is True
