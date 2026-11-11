"""DELETE /api/affinity-rules/<rule_id> removes the rule from the table.

The route loaded every rule, dropped the one asked for and saved the rest. That save only
writes the rules it is given, so the row stayed: the answer said success, the next GET
listed the rule again and migrations and HA moves were still checked against it. The
route the UI uses (/api/clusters/<id>/affinity-rules/<rid>, served by alerts.py) deleted
the row all along.

MK Nov 2026
"""
import pytest

from pegaprox.api.history import check_affinity_violation


@pytest.fixture
def root(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    return api.as_user(seed.user('root', role='admin'))


def _rule(seed, rid, cluster_id='cluster_1'):
    seed.db.save_affinity_rule(rid, cluster_id, {'name': 'keep apart', 'type': 'separate',
                                                'vms': [101, 102], 'enabled': True, 'enforce': True})


def _ids(seed):
    return {r['id'] for rules in seed.db.get_affinity_rules().values() for r in rules}


def test_the_flat_delete_removes_the_rule_and_it_is_no_longer_enforced(root, seed):
    _rule(seed, 'r1')
    _rule(seed, 'r2')
    on_102 = {'101': 'pve1', '102': 'pve2'}
    assert check_affinity_violation('cluster_1', 101, 'pve2', vm_nodes=on_102)['enforce'] is True

    r = root.delete('/api/affinity-rules/r1')
    assert r.status_code == 200 and r.get_json()['success'] is True
    assert _ids(seed) == {'r2'}
    assert [x['id'] for x in root.get('/api/affinity-rules').get_json()['rules']] == ['r2']

    assert root.delete('/api/affinity-rules/r2').status_code == 200
    assert check_affinity_violation('cluster_1', 101, 'pve2', vm_nodes=on_102) == {'violation': False}


def test_an_unknown_rule_is_a_404(root, seed):
    _rule(seed, 'r1')
    r = root.delete('/api/affinity-rules/nope')
    assert r.status_code == 404, r.get_data(as_text=True)
    assert _ids(seed) == {'r1'}


def test_a_delete_for_one_cluster_leaves_the_rule_of_another(seed):
    _rule(seed, 'r1', cluster_id='cluster_2')
    assert seed.db.delete_affinity_rule('r1', 'cluster_1') is False
    assert _ids(seed) == {'r1'}
    assert seed.db.delete_affinity_rule('r1', 'cluster_2') is True
    assert _ids(seed) == set()


def test_the_cluster_route_the_ui_uses_deletes_too(api, root, seed):
    _rule(seed, 'r3')
    endpoint, _ = api.app.url_map.bind('localhost').match('/api/clusters/cluster_1/affinity-rules/r3',
                                                          method='DELETE')
    assert endpoint == 'alerts.delete_cluster_affinity_rule'
    assert root.delete('/api/clusters/cluster_1/affinity-rules/r3').status_code == 200
    assert _ids(seed) == set()
