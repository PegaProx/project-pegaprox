"""The alert rule reads go by the rule active-alerts reads the incidents by (alert_scope).

GET /api/clusters/<id>/alerts, GET /api/alerts, the diagnostics and the force-check answer
listed a node's rule (the node name, the threshold) and what the loop last read for it (the
node's metric value) to a caller confined to pools or guests, and to a cluster-wide caller
without node.view, while active-alerts and the push inbox keep that node's incidents from both.

Confined: a pool grant in its own tenant, on another tenant's cluster or from the default
tenant, a guest ACL. nonode is a cluster-wide viewer with node.view denied. wide (a viewer of
the owning tenant) and the admin keep every rule.
"""
import time
import types

import pytest

import pegaprox.background.alerts as alerts
import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped
from pegaprox.utils.auth import build_authz_user

CID = 'cluster_1'
CONFINED = ('carol', 'dave', 'erin', 'dflt')


def _guest(vmid, name, cpu):
    return {'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve1', 'status': 'running',
            'cpu': cpu, 'mem': 1, 'maxmem': 2, 'disk': 1, 'maxdisk': 2}


@pytest.fixture
def world(api, seed, monkeypatch):
    seed.tenant('tenant_x', clusters=[CID])
    seed.tenant('tenant_y', clusters=['cluster_2'])
    manage = ['alert.manage']
    users = {
        'carol': seed.user('carol', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dave': seed.user('dave', role='viewer', tenant_id='tenant_y', permissions=manage),
        'erin': seed.user('erin', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dflt': seed.user('dflt', role='viewer', permissions=manage),
        'nonode': seed.user('nonode', role='viewer', tenant_id='tenant_x', permissions=manage,
                            denied=['node.view']),
        'wide': seed.user('wide', role='viewer', tenant_id='tenant_x', permissions=manage),
        'root': seed.user('root', role='admin'),
    }
    for name in ('carol', 'dave', 'dflt'):
        seed.pool(CID, 'pool_a', name, ['pool.view'])
    seed.vm_acl(CID, 100, ['erin'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_a', '200:qemu': 'pool_b'},
                                            'timestamp': time.time(), 'refreshing': False}
    mgr = api.make_fake_manager(cluster_id=CID,
                                get_vm_resources=[_guest(100, 'db-a', 0.96), _guest(200, 'web-b', 0.95)],
                                get_node_summary={'cpu': 0.99}, get_node_status={})
    mgr.config = types.SimpleNamespace(name=CID, check_interval=300, host='h', enabled=True)
    api.set_manager(CID, mgr)
    monkeypatch.setattr(alerts, '_alert_last_sent', {})
    monkeypatch.setattr(alerts, '_last_eval', {})

    clients = {name: api.as_user(u) for name, u in users.items()}
    rules = {}
    for target_type, target_id in (('vm', '100'), ('vm', '200'), ('node', 'pve1'), ('cluster', '')):
        r = clients['root'].post(f'/api/clusters/{CID}/alerts', json={
            'name': f'cpu {target_id or CID}', 'metric': 'cpu', 'operator': '>', 'threshold': 90,
            'target_type': target_type, 'target_id': target_id, 'channels': []})
        assert r.status_code == 200, r.get_data(as_text=True)
        rules[target_id or CID] = r.get_json()['alert']['id']
    # rows of the old alerts table name their node or guest in node / vmid, no target_type
    seed.db.save_alert('oldnode', {'cluster_id': CID, 'node': 'pve1', 'type': 'cpu', 'threshold': 90})
    seed.db.save_alert('oldvm', {'cluster_id': CID, 'vmid': 200, 'type': 'cpu', 'threshold': 90})
    alerts.check_and_send_alerts()
    return types.SimpleNamespace(users=users, clients=clients, rules=rules)


def _expected(world, who):
    r = world.rules
    if who in ('root', 'wide'):
        return {r['100'], r['200'], r['pve1'], r[CID]}
    if who == 'nonode':
        return {r['100'], r['200'], r[CID]}
    return {r['100'], r[CID]}


def _ids(rows):
    return {a['id'] for a in rows if a.get('cluster_id') == CID}


def test_the_identities_are_what_the_tests_take_them_for(world):
    u = world.users
    for name in CONFINED:
        assert caller_is_scoped(u[name], CID) is True, name
        assert rbac.user_can_access_vm(u[name], CID, 100, 'vm.view') is True, name
        assert rbac.user_can_access_vm(u[name], CID, 200, 'vm.view') is False, name
    for name in ('nonode', 'wide'):
        assert caller_is_scoped(u[name], CID) is False, name
    assert rbac.has_permission(build_authz_user('nonode', {}), 'node.view') is False
    assert rbac.has_permission(build_authz_user('wide', {}), 'node.view') is True
    # the node rule was read: its value is what the reads below keep from those callers
    assert alerts._last_eval[world.rules['pve1']].get('current_value') == pytest.approx(99.0)


@pytest.mark.parametrize('who', CONFINED + ('nonode', 'wide', 'root'))
def test_the_per_cluster_rule_list_names_a_nodes_rule_only_with_node_view(world, who):
    r = world.clients[who].get(f'/api/clusters/{CID}/alerts')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert {a['id'] for a in r.get_json()['alerts']} == _expected(world, who)


# dave is left out: the tenant filter of GET /api/alerts counts no pool grant
@pytest.mark.parametrize('who', ('carol', 'erin', 'dflt', 'nonode', 'wide', 'root'))
def test_the_global_rule_list_names_a_nodes_rule_only_with_node_view(world, who):
    r = world.clients[who].get('/api/alerts')
    assert r.status_code == 200, r.get_data(as_text=True)
    got = _ids(r.get_json()['alerts'])
    want = _expected(world, who)
    if who in ('root', 'wide'):
        want |= {'oldnode', 'oldvm'}
    elif who == 'nonode':
        want |= {'oldvm'}
    assert got == want


@pytest.mark.parametrize('who', CONFINED + ('nonode', 'wide', 'root'))
def test_the_diagnostics_list_no_node_rule_nor_its_value_without_node_view(world, who):
    r = world.clients[who].get('/api/alerts/diagnostics')
    assert r.status_code == 200, r.get_data(as_text=True)
    rows = {a['id']: a for a in r.get_json()['alerts']}
    node_rules = {world.rules['pve1'], 'oldnode'}
    if who in ('root', 'wide'):
        assert node_rules <= set(rows), sorted(rows)
        assert rows[world.rules['pve1']]['last_evaluation']['current_value'] == pytest.approx(99.0)
    else:
        assert node_rules.isdisjoint(rows), sorted(rows)
        assert world.rules['100'] in rows and world.rules[CID] in rows, sorted(rows)
        assert 'pve1' not in {a.get('target_id') for a in rows.values()}


@pytest.mark.parametrize('who', CONFINED + ('nonode', 'wide', 'root'))
def test_the_force_check_answer_holds_no_node_rules_value_without_node_view(world, who):
    # the admin's call runs the loop again: without the cooldown it reads the node anew
    r = world.clients[who].post('/api/alerts/force-check?reset_cooldown=1')
    assert r.status_code == 200, r.get_data(as_text=True)
    evals = r.get_json()['evaluations']
    node_rules = {world.rules['pve1'], 'oldnode'}
    if who in ('root', 'wide'):
        assert node_rules <= set(evals), sorted(evals)
        assert evals[world.rules['pve1']].get('triggered'), evals
    else:
        assert node_rules.isdisjoint(evals), sorted(evals)
        assert world.rules['100'] in evals, sorted(evals)
    if who in CONFINED:
        assert world.rules['200'] not in evals and 'oldvm' not in evals, sorted(evals)


def test_the_force_check_holds_no_value_of_a_rule_no_longer_configured(world, api, seed):
    # a default-tenant operator: no tenant filter to drop the row before the rule filter does
    plain = seed.user('plain', role='viewer', permissions=['alert.manage'])
    assert rbac.get_user_clusters(plain) is None and caller_is_scoped(plain, CID) is False
    alerts._last_eval['gone'] = {'ts': time.time(), 'alert_id': 'gone', 'current_value': 97.0}
    evals = api.as_user(plain).post('/api/alerts/force-check').get_json()['evaluations']
    assert 'gone' not in evals and world.rules['pve1'] in evals
