"""GET /api/alerts, the diagnostics and the force-check answer hand a caller confined in a
cluster the rules GET /api/clusters/<id>/alerts gives it: the vm rules of the guests it may
view, not those of the other guests (their vmid, rule name, threshold and what the loop read).

Confined: a pool grant in its own tenant or on another tenant's cluster, a guest ACL, a
default-tenant account with a pool grant. The admin and a cluster-wide viewer keep every rule.
"""
import time
import types

import pytest

import pegaprox.background.alerts as alerts
import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped

CID = 'cluster_1'
CONFINED = ('carol', 'dave', 'erin', 'dflt')


def _guest(vmid, name, cpu):
    return {'vmid': vmid, 'name': name, 'type': 'qemu', 'node': 'pve1', 'status': 'running',
            'cpu': cpu, 'mem': 1, 'maxmem': 2, 'disk': 1, 'maxdisk': 2}


@pytest.fixture
def world(api, seed, monkeypatch):
    """tenant_x owns cluster_1; VM 100 is in pool_a, VM 200 in pool_b. carol, dave, erin and
    dflt are confined to VM 100 (pool grant in tenant_x, pool grant from tenant_y, guest ACL,
    pool grant from the default tenant); wide is a viewer of tenant_x without a grant."""
    seed.tenant('tenant_x', clusters=[CID])
    seed.tenant('tenant_y', clusters=['cluster_2'])
    manage = ['alert.manage']
    users = {
        'carol': seed.user('carol', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dave': seed.user('dave', role='viewer', tenant_id='tenant_y', permissions=manage),
        'erin': seed.user('erin', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dflt': seed.user('dflt', role='viewer', permissions=manage),
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
                                get_node_summary={'cpu': 0.99})
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
    alerts.check_and_send_alerts()
    return types.SimpleNamespace(users=users, clients=clients, rules=rules)


def _global(world, name):
    r = world.clients[name].get('/api/alerts')
    assert r.status_code == 200, r.get_data(as_text=True)
    return {a['id'] for a in r.get_json()['alerts'] if a.get('cluster_id') == CID}


def _per_cluster(world, name):
    r = world.clients[name].get(f'/api/clusters/{CID}/alerts')
    assert r.status_code == 200, r.get_data(as_text=True)
    return {a['id'] for a in r.get_json()['alerts']}


# dave is left out here: the tenant filter of GET /api/alerts counts no pool grant, so a
# pool on another tenant's cluster does not bring that cluster into the list at all
@pytest.mark.parametrize('who', ['carol', 'erin', 'dflt'])
def test_the_global_rule_list_gives_a_confined_caller_what_the_per_cluster_list_does(world, who):
    user = world.users[who]
    assert caller_is_scoped(user, CID) is True
    assert rbac.user_can_access_vm(user, CID, 100, 'vm.view') is True
    assert rbac.user_can_access_vm(user, CID, 200, 'vm.view') is False
    every = set(world.rules.values())
    for name in ('root', 'wide'):
        assert _global(world, name) == every, name

    per_cluster = _per_cluster(world, who)
    assert world.rules['100'] in per_cluster and world.rules['200'] not in per_cluster, per_cluster
    assert _global(world, who) == per_cluster


@pytest.mark.parametrize('who', CONFINED)
def test_the_diagnostics_and_the_force_check_keep_a_confined_caller_to_its_guests_rules(world, who):
    c = world.clients[who]
    wide = world.clients['wide']
    diag = {a['id'] for a in wide.get('/api/alerts/diagnostics').get_json()['alerts']}
    assert {world.rules['100'], world.rules['200']} <= diag, diag
    evals = wide.post('/api/alerts/force-check').get_json()['evaluations']
    assert world.rules['200'] in evals and evals[world.rules['200']].get('triggered'), evals

    r = c.get('/api/alerts/diagnostics')
    assert r.status_code == 200, r.get_data(as_text=True)
    diag = {a['id'] for a in r.get_json()['alerts']}
    assert world.rules['100'] in diag and world.rules['200'] not in diag, diag
    r = c.post('/api/alerts/force-check')
    assert r.status_code == 200, r.get_data(as_text=True)
    evals = r.get_json()['evaluations']
    assert world.rules['100'] in evals and world.rules['200'] not in evals, sorted(evals)
