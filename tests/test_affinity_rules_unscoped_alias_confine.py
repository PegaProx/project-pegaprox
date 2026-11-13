"""GET /api/affinity-rules gives a confined caller the same rules as the cluster route.

An affinity rule names every guest it groups. The cluster route
(/api/clusters/<id>/affinity-rules, served by alerts.py) shows a pool- or VM-ACL-confined
caller only the rules whose members it may all view. The flat list only kept the rules of
the clusters the caller reaches, so the same caller read every rule there, with the other
pools' guest IDs and rule names. Both now go through helpers.affinity_rules_in_view.

The check-affinity route and the single migrate answer which rule a move breaks. Their
message lists the rule's other guests and the node they run on, so a confined caller gets
the rule name only, as the migration preflight already does.

MK Nov 2026
"""
import time

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.utils.auth import create_api_token


def _pool_members(cluster_id, mapping):
    data = {f"{vmid}:qemu": pool for vmid, pool in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {
            'data': data, 'timestamp': time.time(), 'refreshing': False,
        }


@pytest.fixture
def rules(api, seed):
    """tenant_x owns cluster_1, cluster_2 belongs to someone else. VMs 100 and 101 are in pool_1."""
    seed.tenant('tenant_x', clusters=['cluster_1'])
    seed.tenant('tenant_y', clusters=['cluster_2'])
    for cid in ('cluster_1', 'cluster_2'):
        m = api.make_fake_manager(cluster_id=cid)
        m.is_connected = True
        api.set_manager(cid, m)
    _pool_members('cluster_1', {100: 'pool_1', 101: 'pool_1', 300: 'pool_fin', 301: 'pool_fin'})
    for rid, cid, vms in (('r1', 'cluster_1', [100]),
                          ('r2', 'cluster_1', [300, 301]),
                          ('r3', 'cluster_1', [100, 300]),
                          ('r4', 'cluster_1', []),
                          ('r5', 'cluster_2', [100]),
                          ('r6', '', [100]),
                          ('r7', 'cluster_1', [100, 'abc']),
                          ('r8', 'cluster_1', [100, None])):
        seed.db.save_affinity_rule(rid, cid, {'name': f'rule-{rid}', 'type': 'separate',
                                              'vms': vms, 'enabled': True})


def _flat(client):
    r = client.get('/api/affinity-rules')
    assert r.status_code == 200, r.get_data(as_text=True)
    return sorted(x['id'] for x in r.get_json()['rules'])


def _of_cluster(client, cid='cluster_1'):
    r = client.get(f'/api/clusters/{cid}/affinity-rules')
    assert r.status_code == 200, r.get_data(as_text=True)
    return sorted(x['id'] for x in r.get_json()['rules'])


def test_the_cluster_get_is_served_by_alerts_and_the_flat_one_by_history(api):
    urls = api.app.url_map.bind('localhost')
    assert urls.match('/api/clusters/cluster_1/affinity-rules', method='GET')[0] == \
        'alerts.get_cluster_affinity_rules'
    assert urls.match('/api/affinity-rules', method='GET')[0] == 'history.get_affinity_rules'


def test_a_pool_confined_viewer_gets_only_its_own_rules_from_both_urls(api, seed, rules):
    u = seed.user('mallory2', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory2', ['pool.view', 'vm.view'])
    client = api.as_user(u)
    assert _of_cluster(client) == ['r1']
    assert _flat(client) == ['r1']


def test_a_vm_acl_confined_viewer_gets_only_its_own_rules_from_both_urls(api, seed, rules):
    # its tenant owns the cluster, the ACL entry alone makes it confined (the portal case)
    u = seed.user('pat', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.vm_acl('cluster_1', 100, ['pat'])
    client = api.as_user(u)
    assert _of_cluster(client) == ['r1']
    assert _flat(client) == ['r1']


def test_a_confined_caller_never_sees_the_rules_of_a_cluster_outside_its_tenant(api, seed, rules):
    u = seed.user('mallory2', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory2', ['pool.view', 'vm.view'])
    client = api.as_user(u)
    assert 'r5' not in _flat(client)
    assert client.get('/api/clusters/cluster_2/affinity-rules').status_code == 403


def test_an_unconfined_operator_of_the_tenant_still_gets_every_rule_of_its_cluster(api, seed, rules):
    u = seed.user('olga', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    client = api.as_user(u)
    assert _of_cluster(client) == ['r1', 'r2', 'r3', 'r4', 'r7', 'r8']
    assert _flat(client) == ['r1', 'r2', 'r3', 'r4', 'r7', 'r8']


def test_an_admin_still_gets_every_rule_of_every_cluster(api, seed, rules):
    client = api.as_user(seed.user('root', role='admin'))
    assert _of_cluster(client) == ['r1', 'r2', 'r3', 'r4', 'r7', 'r8']
    assert _of_cluster(client, 'cluster_2') == ['r5']
    assert _flat(client) == ['r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8']


def test_a_rule_with_a_member_that_is_no_vmid_stays_out_for_a_pool_confined_viewer(api, seed, rules):
    u = seed.user('mallory2', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory2', ['pool.view', 'vm.view'])
    client = api.as_user(u)
    for got in (_of_cluster(client), _flat(client)):
        assert 'r7' not in got and 'r8' not in got


def test_a_rule_with_a_member_that_is_no_vmid_is_listed_for_the_operator_and_the_admin(api, seed, rules):
    for u in (seed.user('olga', role='viewer', tenant_id='tenant_x', permissions=['cluster.view']),
              seed.user('root', role='admin')):
        client = api.as_user(u)
        for got in (_of_cluster(client), _flat(client)):
            assert 'r7' in got and 'r8' in got


def test_a_rule_without_a_cluster_is_listed_to_the_admin_only(api, seed, rules):
    # a default tenant account is no tenant's operator, it reaches every cluster
    u = seed.user('dora', role='viewer', permissions=['cluster.view'])
    assert 'r6' not in _flat(api.as_user(u))
    assert 'r6' in _flat(api.as_user(seed.user('root', role='admin')))


# --- an API token -------------------------------------------------------------------------------

def _bearer(api, owner, role='viewer'):
    res = create_api_token(owner, 'ci', role=role)
    assert res.get('token'), res
    hdr = {'Authorization': f"Bearer {res['token']}"}

    class _Client:
        def get(self, path):
            return api.anon().get(path, headers=hdr)
    return _Client()


def test_a_viewer_token_of_a_pool_confined_operator_gets_only_its_own_rules(api, seed, rules):
    seed.user('otto', role='user', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'otto', ['pool.view', 'vm.view'])
    client = _bearer(api, 'otto')
    assert _of_cluster(client) == ['r1']
    assert _flat(client) == ['r1']


def test_a_viewer_token_of_an_unconfined_operator_gets_every_rule_of_its_cluster(api, seed, rules):
    seed.user('olga', role='user', tenant_id='tenant_x')
    client = _bearer(api, 'olga')
    assert _of_cluster(client) == ['r1', 'r2', 'r3', 'r4', 'r7', 'r8']
    assert _flat(client) == ['r1', 'r2', 'r3', 'r4', 'r7', 'r8']


# --- the rule a move breaks ---------------------------------------------------------------------

@pytest.fixture
def placed(api, seed, rules):
    """100 on pve1 and 101 on pve3 are pool_1's, 300 runs on fin-node. An enforced rule
    keeps 100 with 300, so moving 100 to pve3 breaks it."""
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.get_vm_resources.return_value = [
        {'vmid': 100, 'node': 'pve1', 'type': 'qemu'}, {'vmid': 101, 'node': 'pve3', 'type': 'qemu'},
        {'vmid': 300, 'node': 'fin-node', 'type': 'qemu'}, {'vmid': 301, 'node': 'fin-node', 'type': 'qemu'}]
    api.set_manager('cluster_1', m)
    seed.db.save_affinity_rule('r9', 'cluster_1', {'name': 'keep-with-db', 'type': 'together',
                                                   'vms': [100, 300], 'enabled': True, 'enforce': True})
    return m


CHECK = '/api/clusters/cluster_1/vms/100/check-affinity/pve3'
MOVE = '/api/clusters/cluster_1/vms/pve1/qemu/100/migrate'


def test_a_confined_viewer_reads_the_rule_but_not_the_other_guests_of_it(api, seed, placed):
    u = seed.user('mallory2', role='viewer', tenant_id='tenant_x', permissions=['cluster.view'])
    seed.pool('cluster_1', 'pool_1', 'mallory2', ['pool.view', 'vm.view'])
    r = api.as_user(u).get(CHECK)
    assert r.status_code == 200, r.get_data(as_text=True)
    j = r.get_json()
    assert j['violation'] is True and j['rule'] == 'keep-with-db'
    body = r.get_data(as_text=True)
    assert '300' not in body and 'fin-node' not in body


def test_the_admin_still_reads_the_other_guests_of_the_rule_and_their_node(api, seed, placed):
    r = api.as_user(seed.user('root', role='admin')).get(CHECK)
    assert r.status_code == 200, r.get_data(as_text=True)
    j = r.get_json()
    assert j['violation'] is True and j['rule'] == 'keep-with-db'
    assert '300' in j['message'] and 'fin-node' in j['message']


def test_a_confined_operator_is_told_the_rule_but_not_its_other_guests_on_a_blocked_move(api, seed, placed):
    u = seed.user('mona', role='user', tenant_id='tenant_x')
    seed.pool('cluster_1', 'pool_1', 'mona', ['pool.view', 'vm.view', 'vm.migrate'])
    r = api.as_user(u).post(MOVE, json={'target': 'pve3'})
    assert r.status_code == 409, r.get_data(as_text=True)
    j = r.get_json()
    assert j['affinity_violation'] is True and j['rule'] == 'keep-with-db'
    assert j['error'] == "Migration blocked by affinity rule 'keep-with-db'"
    body = r.get_data(as_text=True)
    assert '300' not in body and 'fin-node' not in body
    placed.migrate_vm_manual.assert_not_called()


def test_the_admin_is_still_told_the_other_guests_on_a_blocked_move(api, seed, placed):
    r = api.as_user(seed.user('root', role='admin')).post(MOVE, json={'target': 'pve3'})
    assert r.status_code == 409, r.get_data(as_text=True)
    err = r.get_json()['error']
    assert err.startswith("Migration blocked by affinity rule 'keep-with-db': ")
    assert '300' in err and 'fin-node' in err
    placed.migrate_vm_manual.assert_not_called()
