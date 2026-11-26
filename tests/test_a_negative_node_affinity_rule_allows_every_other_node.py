"""PVE 9.3 node-affinity rules can be negative (pve-ha-manager 5.2.5, `affinity negative`).

The nodes of such a rule are the ones its guests avoid: PVE turns it into a rule over every
other node of the cluster, strict allows only those, non-strict puts them first and the
avoided ones last. GET /cluster/ha/rules hands the rule as written, and every reader here
took `nodes` as the allowed or preferred set. The migration preflight blocked the move PVE
allows and passed the one ha-manager refuses, the evacuation of a maintenance or a rolling
update sent the guest to the node the rule forbids, the what-if restarted it there, and the
HA groups view listed it as a group of the nodes it keeps off.

A negative rule now reads as the other nodes of the cluster. Where those are not known it
limits nothing instead of the wrong way round. A rule without `affinity` (every PVE before
9.3) reads as before. Creating a rule takes an optional affinity and sends it only when it
is negative, since positive is PVE's default and an older PVE does not know the key.
"""
import types

import pytest

import pegaprox.core.preflight as pf
import pegaprox.core.whatif as whatif
from pegaprox.core.manager import PegaProxManager
from test_migration_preflight import CFG, CID, _codes, _fresh, _guest, _node, _Pve  # noqa: F401 (_fresh is autouse)
from test_migration_preflight import _rows as _pf_rows
from test_ticket_647_placement import _evacuate, _mgr
from test_ticket_647_placement import _vm as _evac_vm
from test_whatif import GiB, _cfg, _cluster, _run
from test_whatif import _manager as _whatif_manager
from test_whatif import _rows as _whatif_rows
from test_whatif import _vm as _whatif_vm

THREE = {'pve1', 'pve2', 'pve3'}


def _rule(name, sids, nodes, strict=True, affinity='negative'):
    r = {'rule': name, 'type': 'node-affinity', 'resources': sids, 'nodes': nodes, 'strict': 1 if strict else 0}
    if affinity is not None:
        r['affinity'] = affinity
    return r


# --- the reading itself ----------------------------------------------------------------------

def test_a_strict_negative_rule_limits_the_guest_to_the_other_nodes():
    rules = [_rule('keep-off-pve3', 'vm:100', 'pve3')]
    assert pf.ha_node_limits(rules, {}, [], THREE) == {100: {'pve1', 'pve2'}}


def test_without_the_nodes_of_the_cluster_a_negative_rule_limits_nothing():
    rules = [_rule('keep-off-pve3', 'vm:100', 'pve3')]
    assert pf.ha_node_limits(rules, {}, []) == {}
    assert pf.ha_node_limits(rules, {}, [], []) == {}
    assert pf._ha_preferences([_rule('avoid', 'vm:101', 'pve1', strict=False)], {}, []) == {}


def test_a_negative_rule_naming_every_node_is_dropped_as_pve_drops_it():
    assert pf.ha_node_limits([_rule('all', 'vm:100', 'pve1,pve2,pve3')], {}, [], THREE) == {}


def test_the_guests_of_one_rule_share_its_set_of_nodes():
    # at 200 nodes a negative rule allows 199: one set per rule, not one per guest
    rules = [_rule('keep-off-pve3', 'vm:100,vm:101,ct:102', 'pve3'), _rule('pin', 'vm:103,vm:104', 'pve1', affinity=None)]
    limits = pf.ha_node_limits(rules, {}, [], THREE)
    assert limits[100] == {'pve1', 'pve2'} and limits[100] is limits[101] is limits[102]
    assert limits[103] == {'pve1'} and limits[103] is limits[104]


def test_a_positive_rule_reads_as_before_with_or_without_the_key():
    for affinity in (None, 'positive'):
        rules = [_rule('pin', 'vm:100', 'pve1,pve3', affinity=affinity),
                 _rule('pref', 'vm:101', 'pve2:2,pve3:1', strict=False, affinity=affinity)]
        assert pf.ha_node_limits(rules, {}, [], THREE) == {100: {'pve1', 'pve3'}}
        assert pf.ha_node_limits(rules, {}, []) == {100: {'pve1', 'pve3'}}
        assert pf._ha_preferences(rules, {}, [], THREE) == {101: ({'pve2'}, 'pref')}


# --- the migration preflight -----------------------------------------------------------------

def _preflight_cluster(api, rule):
    return _Pve(api, guests=[_guest(100)], configs={100: CFG},
                ha_resources=[{'sid': 'vm:100', 'state': 'started'}], ha_rules=[rule])


def test_the_preflight_lets_the_guest_go_where_a_strict_negative_rule_allows(api):
    m = _preflight_cluster(api, _rule('keep-off-pve3', 'vm:100', 'pve3'))
    row = _pf_rows(pf.intra(CID, m, [100], 'pve2'))[100]
    assert 'ha_node_rule' not in _codes(row), row['reasons']
    assert row['verdict'] != 'blocked', row['reasons']
    pf.reset_for_tests()
    row = _pf_rows(pf.intra(CID, m, [100], 'pve3'))[100]
    assert 'ha_node_rule' in _codes(row, 'blocked') and row['overridable'] is False
    reason = next(r for r in row['reasons'] if r['code'] == 'ha_node_rule')
    assert reason['text'] == 'Proxmox HA keeps it off pve3 (strict negative node affinity)'
    assert reason['args'] == {'avoided': 'pve3'}
    # its own wording in the UI (pf_ha_node_rule_avoid), the plain one asks for {nodes}
    assert reason['variant'] == 'avoid'


def test_the_block_names_the_nodes_the_rule_keeps_the_guest_off_not_every_other_one(api):
    eight = {f'pve{i}': _node() for i in range(1, 9)}
    m = _Pve(api, guests=[_guest(100), _guest(101)], configs={100: CFG, 101: CFG}, nodes=eight,
             ha_resources=[{'sid': 'vm:100', 'state': 'started'}, {'sid': 'vm:101', 'state': 'started'}],
             ha_rules=[_rule('keep-off', 'vm:100,vm:101', 'pve8,pve7')])
    rows = _pf_rows(pf.intra(CID, m, [100, 101], 'pve8'))
    for vmid in (100, 101):
        reason = next(r for r in rows[vmid]['reasons'] if r['code'] == 'ha_node_rule')
        assert reason['text'] == 'Proxmox HA keeps it off pve7, pve8 (strict negative node affinity)', reason
        assert reason['args'] == {'avoided': 'pve7, pve8'}
    # a positive rule still says where it keeps the guest
    pf.reset_for_tests()
    m.ha_rules = [_rule('pin', 'vm:100,vm:101', 'pve1,pve2', affinity=None)]
    reason = next(r for r in _pf_rows(pf.intra(CID, m, [100], 'pve8'))[100]['reasons'] if r['code'] == 'ha_node_rule')
    assert reason['args'] == {'nodes': 'pve1, pve2'}


NOT_APPLIED = f'the negative node-affinity rules of {CID} (not applied without the node status)'


def test_without_the_node_status_the_preflight_says_the_negative_rules_were_not_applied(api):
    m = _preflight_cluster(api, _rule('keep-off-pve3', 'vm:100', 'pve3'))
    m.get_node_status = lambda: {}
    res = pf.intra(CID, m, [100], 'pve3')
    assert NOT_APPLIED in res['unread'], res['unread']
    assert 'ha_node_rule' not in _codes(_pf_rows(res)[100])
    # the node status is back within the cache time: that read was not kept, the rule applies
    del m.get_node_status
    res = pf.intra(CID, m, [100], 'pve3')
    assert 'ha_node_rule' in _codes(_pf_rows(res)[100], 'blocked'), _pf_rows(res)[100]['reasons']
    assert NOT_APPLIED not in res['unread']


def test_without_a_negative_rule_the_ha_read_is_kept_as_before(api):
    m = _preflight_cluster(api, _rule('pin', 'vm:100', 'pve1,pve2', affinity=None))
    m.get_node_status = lambda: {}
    res = pf.intra(CID, m, [100], 'pve3')
    assert NOT_APPLIED not in res['unread']
    del m.get_node_status
    row = _pf_rows(pf.intra(CID, m, [100], 'pve3'))[100]
    assert 'ha_node_rule' in _codes(row, 'blocked')
    assert m.reads.count('/cluster/ha/rules') == 1, m.reads


def test_the_preflight_warns_on_the_node_a_non_strict_negative_rule_avoids(api):
    m = _preflight_cluster(api, _rule('avoid-pve2', 'vm:100', 'pve2', strict=False))
    row = _pf_rows(pf.intra(CID, m, [100], 'pve3'))[100]
    assert 'ha_prefers' not in _codes(row), row['reasons']
    pf.reset_for_tests()
    row = _pf_rows(pf.intra(CID, m, [100], 'pve2'))[100]
    assert 'ha_prefers' in _codes(row, 'warning')
    reason = next(r for r in row['reasons'] if r['code'] == 'ha_prefers')
    assert reason['args'] == {'nodes': 'pve1, pve3', 'source': 'avoid-pve2'}


# --- the evacuation of a maintenance or a rolling update -------------------------------------

def test_the_evacuation_keeps_the_guest_off_the_node_a_negative_rule_forbids():
    # pve1 has the lowest score and is what the drain of pve5 picks when nothing limits it
    m, sent = _mgr([_evac_vm(303)], {'/cluster/ha/rules': [_rule('keep-off-pve1', 'vm:303', 'pve1')],
                                     '/cluster/ha/resources': [{'sid': 'vm:303'}]})
    task = _evacuate(m)
    assert sent[303] == 'pve4', f"303 went to {sent[303]}, its rule keeps it off pve1"
    assert task.status == 'completed'


def test_the_evacuation_finds_the_one_node_a_negative_rule_leaves():
    # only pve1 is up besides pve5; the rule keeps the guest off every node but those two
    rule = _rule('keep-off', 'vm:303', 'pve2,pve3,pve4,pve6')
    m, sent = _mgr([_evac_vm(303)], {'/cluster/ha/rules': [rule]})
    nodes = m.get_node_status()
    m.get_node_status = lambda: {n: dict(d, status='online' if n in ('pve1', 'pve5') else 'offline')
                                 for n, d in nodes.items()}
    task = _evacuate(m)
    assert sent == {303: 'pve1'}, task.failed_vms
    assert task.failed_vms == []


def test_a_negative_rule_still_costs_one_read_per_evacuation():
    guests = [_evac_vm(400 + i) for i in range(20)]
    m, sent = _mgr(guests, {'/cluster/ha/rules': [_rule('keep-off-pve1', 'vm:400', 'pve1')],
                            '/storage': [{'storage': 'local', 'type': 'dir'}]})
    _evacuate(m)
    assert sent[400] != 'pve1' and len(sent) == 20
    assert m._api_get.call_count == 3, [c.args[0] for c in m._api_get.call_args_list]


# --- the what-if -----------------------------------------------------------------------------

def _whatif_cluster(guests, rules, **kw):
    api = _cluster(guests, {g['vmid']: _cfg() for g in guests},
                   ha=[(f"vm:{g['vmid']}", 'started') for g in guests], rules=rules)
    return _whatif_manager(api, guests, **kw)


def test_a_node_failure_restarts_the_guest_on_a_node_its_negative_rule_allows():
    guests = [_whatif_vm(100, 'pve1')]
    m = _whatif_cluster(guests, [_rule('keep-off-pve2', 'vm:100', 'pve2')])
    row = _whatif_rows(_run(m, type='node_failure', nodes=['pve1']))[100]
    assert row['outcome'] == 'restarted' and row['target'] == 'pve3', row
    # pve3 failing too leaves only the node it avoids: strict keeps it down
    five = ('pve1', 'pve2', 'pve3', 'pve4', 'pve5')
    m = _whatif_cluster(guests, [_rule('keep-off', 'vm:100', 'pve2,pve4,pve5')], nodes=five)
    row = _whatif_rows(_run(m, type='node_failure', nodes=['pve1', 'pve3']))[100]
    assert row['reason'] == {'code': 'no_node_rule', 'args': {'rule': 'keep-off'}}


def test_a_node_failure_puts_a_non_strict_negative_guest_on_the_other_nodes_first():
    guests = [_whatif_vm(100, 'pve1')]
    m = _whatif_cluster(guests, [_rule('avoid-pve2', 'vm:100', 'pve2', strict=False)])
    assert _whatif_rows(_run(m, type='node_failure', nodes=['pve1']))[100]['target'] == 'pve3'
    # with every other node gone it may still go where it would rather not
    m = _whatif_cluster(guests, [_rule('avoid', 'vm:100', 'pve2,pve3,pve4', strict=False)],
                        nodes=('pve1', 'pve2', 'pve3', 'pve4', 'pve5'))
    row = _whatif_rows(_run(m, type='node_failure', nodes=['pve1', 'pve5']))[100]
    assert row['outcome'] == 'restarted' and row['target'] in ('pve2', 'pve3', 'pve4'), row


def test_the_maintenance_what_if_follows_the_negative_rule_like_the_evacuation():
    guests = [_whatif_vm(100, 'pve1')]
    m = _whatif_cluster(guests, [_rule('keep-off-pve2', 'vm:100', 'pve2')])
    row = _whatif_rows(_run(m, type='maintenance', nodes=['pve1']))[100]
    assert row['outcome'] == 'moved' and row['target'] == 'pve3', row


def test_headroom_gives_the_guests_of_one_negative_rule_one_set(monkeypatch):
    guests = [_whatif_vm(100, 'pve1'), _whatif_vm(101, 'pve1')]
    m = _whatif_cluster(guests, [_rule('keep-off-pve3', 'vm:100,vm:101', 'pve3')])
    seen = []
    real = whatif._place_all

    def spy(load, survivors, placing, allowed_of):
        seen.append((allowed_of('vm:100'), allowed_of('vm:101')))
        return real(load, survivors, placing, allowed_of)
    monkeypatch.setattr(whatif, '_place_all', spy)
    _run(m, type='headroom', depth=1)
    assert seen and all(a == {'pve1', 'pve2'} and a is b for a, b in seen), seen


# --- a negative rule that names every node ---------------------------------------------------

# PVE does not write one (check_nonempty_negative_nodes_complement), but a node that leaves the
# cluster makes one: pve4 is gone. The CRM drops such a rule, the guest is not limited at all
EVERY = _rule('keep-off-all', 'vm:100', 'pve1,pve2,pve3,pve4')


def test_a_node_failure_restarts_a_guest_whose_negative_rule_names_every_node():
    m = _whatif_cluster([_whatif_vm(100, 'pve1')], [EVERY])
    row = _whatif_rows(_run(m, type='node_failure', nodes=['pve1']))[100]
    assert row['outcome'] == 'restarted' and row['target'] in ('pve2', 'pve3'), row


def test_headroom_places_a_guest_whose_negative_rule_names_every_node():
    m = _whatif_cluster([_whatif_vm(100, 'pve1')], [EVERY])
    combos = _run(m, type='headroom', depth=1)['headroom']['combinations']
    assert next(c for c in combos if c['failed'] == ['pve1'])['unplaced'] == 0, combos


def test_the_other_readers_take_a_negative_rule_naming_every_node_as_no_rule(api):
    m = _whatif_cluster([_whatif_vm(100, 'pve1')], [EVERY])
    row = _whatif_rows(_run(m, type='maintenance', nodes=['pve1']))[100]
    assert row['outcome'] == 'moved', row
    row = _pf_rows(pf.intra(CID, _preflight_cluster(api, EVERY), [100], 'pve3'))[100]
    assert 'ha_node_rule' not in _codes(row), row['reasons']
    m, sent = _mgr([_evac_vm(303)], {'/cluster/ha/rules': [_rule('keep-off-all', 'vm:303', 'pve1,pve2,pve3,pve4,pve5,pve6')]})
    _evacuate(m)
    assert sent == {303: 'pve1'}


def test_headroom_counts_a_strict_negative_guest_against_the_nodes_it_may_use():
    # pve1 fails; the guest alone would go to pve3, the emptier one, but its rule keeps it off
    guests = [_whatif_vm(100, 'pve1', maxmem=40)]
    m = _whatif_cluster(guests, [_rule('keep-off-pve3', 'vm:100', 'pve3')])
    m.get_node_status()['pve2']['mem_used'] = 20 * GiB
    combos = _run(m, type='headroom', depth=1)['headroom']['combinations']
    pve1 = next(c for c in combos if c['failed'] == ['pve1'])
    assert pve1['over_mem'] == ['pve2'] and pve1['unplaced'] == 0, pve1


# --- the HA groups view and a new rule -------------------------------------------------------

def _rules_manager(rows):
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host='10.0.0.1', api_port=8006, name='c')
    m.current_host = None
    m.is_connected = True
    m.logger = types.SimpleNamespace(debug=lambda *a, **k: None, warning=lambda *a, **k: None)
    m._api_get = lambda url, **kw: types.SimpleNamespace(status_code=200, json=lambda: {'data': rows}, text='')
    return m


def test_the_groups_view_says_which_way_a_rule_points():
    m = _rules_manager([_rule('keep-off-pve3', 'vm:100', 'pve3'),
                        _rule('pin', 'vm:101', 'pve1', affinity=None),
                        _rule('pref', 'vm:102', 'pve2', strict=False, affinity='positive')])
    groups = {g['group']: g for g in m.get_proxmox_ha_groups()}
    assert {n: g['affinity'] for n, g in groups.items()} == {
        'keep-off-pve3': 'negative', 'pin': 'positive', 'pref': 'positive'}
    # the rest of the shape is what it was
    assert groups['keep-off-pve3']['nodes'] == 'pve3' and groups['keep-off-pve3']['restricted'] == 1


@pytest.fixture
def rule_api(api, seed):
    fake = api.make_fake_manager('cluster_1')
    fake.is_connected = True
    fake.host, fake.api_port = '10.0.0.1', 8006
    fake.config.name = 'c'
    fake.posts = []
    fake.rules_status = 200

    def post(url, data=None, **kw):
        fake.posts.append((url.split('/api2/json', 1)[1], dict(data or {})))
        status = fake.rules_status if url.endswith('/cluster/ha/rules') else 200
        return types.SimpleNamespace(status_code=status, text='')
    fake._api_post.side_effect = post
    api.set_manager('cluster_1', fake)
    return fake, api.as_user(seed.user('root', role='admin'))


GROUPS = '/api/clusters/cluster_1/proxmox-ha/groups'


def test_a_new_rule_sends_affinity_only_when_it_is_negative(rule_api):
    fake, c = rule_api
    body = {'group': 'keep-off-pve3', 'nodes': 'pve3', 'resources': 'vm:100', 'restricted': 1}
    assert c.post(GROUPS, json=dict(body, affinity='negative')).status_code == 200
    assert fake.posts[-1] == ('/cluster/ha/rules', {'rule': 'keep-off-pve3', 'type': 'node-affinity',
                                                    'nodes': 'pve3', 'resources': 'vm:100', 'strict': 1,
                                                    'affinity': 'negative'})
    for given in ({'affinity': 'positive'}, {'affinity': 'Positive '}, {}):
        assert c.post(GROUPS, json=dict(body, **given)).status_code == 200
        assert 'affinity' not in fake.posts[-1][1]


def test_a_new_rule_with_another_affinity_is_refused_before_pve_is_asked(rule_api):
    fake, c = rule_api
    for bad in ('sideways', 1, ['negative']):
        r = c.post(GROUPS, json={'group': 'g', 'nodes': 'pve3', 'resources': 'vm:100', 'affinity': bad})
        assert r.status_code == 400 and 'affinity' in r.get_json()['error'], (bad, r.data)
    assert fake.posts == []


def test_a_negative_rule_never_becomes_a_pve8_group_of_the_nodes_it_avoids(rule_api):
    fake, c = rule_api
    fake.rules_status = 501
    r = c.post(GROUPS, json={'group': 'keep-off-pve3', 'nodes': 'pve3', 'resources': 'vm:100',
                             'restricted': 1, 'affinity': 'negative'})
    assert r.status_code == 400, r.data
    assert [p[0] for p in fake.posts] == ['/cluster/ha/rules']
    # a positive one still falls back to the group as before
    r = c.post(GROUPS, json={'group': 'only-pve3', 'nodes': 'pve3', 'restricted': 1})
    assert r.status_code == 200
    assert fake.posts[-1] == ('/cluster/ha/groups', {'group': 'only-pve3', 'nodes': 'pve3', 'restricted': 1})
