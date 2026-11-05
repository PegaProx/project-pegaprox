"""The what-if verdict and what it was not able to judge (core/whatif.py verdict, _headroom).

A guest whose outcome is unknown (its configuration was not read, the HA state could not
be read) was left out of the verdict, so a run that could not judge some guests still
said "Ready - nothing in the way". It warns now and says how many. The headroom check
keeps the 200 worst failure combinations in its answer, and the verdict counted the ones
that strand guests or lose quorum in those 200 only: with more combinations than that
the line said 200 where the headroom itself said more. They are counted over all of them.

Same harness as tests/test_whatif.py and tests/test_whatif_verdict_and_preflight_risk.py.
NS Nov 2026
"""
import pytest

from pegaprox.core import whatif
from test_whatif import THR, _cluster, _manager, _rows, _run, _vm
from test_whatif_risk import _forget, _mark_passed, _pve  # noqa: F401 (_forget is a fixture)
from test_whatif_verdict_and_preflight_risk import LEVELS, lab  # noqa: F401 (lab is a fixture)


def _codes(v):
    return [r['code'] for r in v['reasons']]


# --- guests the run could not judge ------------------------------------------------------------

def test_a_guest_whose_outcome_is_unknown_keeps_the_verdict_from_ready():
    rows = [{'vmid': 100, 'name': 'a', 'outcome': 'moved'}, {'vmid': 101, 'name': 'b', 'outcome': 'unknown'}]
    v = whatif.verdict({'guests': rows, 'nodes': []})
    assert v['level'] == 'warning', v
    reason = next(r for r in v['reasons'] if r['code'] == 'guests_unknown')
    assert reason['args'] == {'count': 1} and reason['level'] == 'warning'
    assert reason['text'] == '1 guest could not be judged in this run, what becomes of it is not known'
    # the same report without the unknown guest is ready
    assert whatif.verdict({'guests': rows[:1], 'nodes': []}) == {'level': 'ready', 'reasons': []}


def test_configurations_not_read_keep_the_verdict_from_ready_where_no_guest_says_so():
    v = whatif.verdict({'guests': [], 'nodes': [], 'reads': {'configs_unread': 3}})
    assert v['level'] == 'warning' and _codes(v) == ['configs_unread'], v
    assert v['reasons'][0]['args'] == {'count': 3} and '3' in v['reasons'][0]['text']
    # where the unknown guests say it already, one line is enough
    rows = [{'vmid': 101, 'name': 'b', 'outcome': 'unknown'}]
    v = whatif.verdict({'guests': rows, 'nodes': [], 'reads': {'configs_unread': 1}})
    assert _codes(v) == ['guests_unknown']
    assert whatif.verdict({'guests': [], 'nodes': [], 'reads': {'configs_unread': 0}})['level'] == 'ready'


def test_a_blocked_run_with_unknown_guests_stays_blocked():
    rows = [{'vmid': 100, 'name': 'a', 'outcome': 'down'}, {'vmid': 101, 'name': 'b', 'outcome': 'unknown'},
            {'vmid': 102, 'name': 'c', 'outcome': 'unknown'}]
    v = whatif.verdict({'guests': rows, 'nodes': []})
    assert v['level'] == 'blocked' and _codes(v) == ['guests_down', 'guests_unknown']
    assert v['reasons'][1]['args'] == {'count': 2}
    assert v['reasons'][1]['text'] == '2 guests could not be judged in this run, what becomes of them is not known'


def test_a_maintenance_with_a_configuration_it_could_not_read_is_not_ready(lab):
    guests, pve = _pve(jobs=[])
    pve.pop('/nodes/pve1/qemu/101/config')      # the read of it fails (404)
    mgr = lab.set_manager('cluster_1', _manager(pve, guests))
    for vmid in (100, 101):
        _mark_passed(vmid)
    r = whatif.run(mgr, whatif.parse_scenario({'type': 'maintenance', 'nodes': ['pve1']}), dict(THR))
    assert _rows(r)[101]['outcome'] == 'unknown' and _rows(r)[100]['outcome'] == 'moved'
    assert r['reads']['configs_unread'] == 1
    v = r['verdict']
    assert v['level'] == 'warning', v
    assert _codes(v) == ['guests_unknown'] and v['reasons'][0]['args'] == {'count': 1}


def test_the_route_counts_the_unknown_guests_the_caller_may_see(lab, seed):
    guests, pve = _pve(jobs=[])
    pve.pop('/nodes/pve1/qemu/101/config')
    lab.set_manager('cluster_1', _manager(pve, guests))
    for vmid in (100, 101):
        _mark_passed(vmid)
    body = lab.as_user(seed.user('root', role='admin')).post(
        '/api/clusters/cluster_1/whatif', json={'type': 'maintenance', 'nodes': ['pve1']}).get_json()
    assert body['verdict']['level'] == 'warning' and _codes(body['verdict']) == ['guests_unknown']
    assert body['verdict']['level'] in LEVELS


# --- every failure combination counts ----------------------------------------------------------

def test_n_plus_2_counts_the_combinations_without_quorum_beyond_the_200_it_keeps():
    # 22 nodes up and 21 down: 43 votes, 22 needed, so any two more down lose quorum, in all
    # 231 pairs; the answer keeps 200 of them
    up = tuple(f'pve{i:02d}' for i in range(22))
    down = tuple(f'old{i:02d}' for i in range(21))
    guests = [_vm(100 + i, n, maxmem=1) for i, n in enumerate(up)]
    m = _manager(_cluster(guests, {}), guests, nodes=up + down)
    for n in down:
        m.get_node_status()[n]['status'] = 'offline'
    r = _run(m, type='headroom', depth=2)
    h = r['headroom']
    assert h['checked'] == 231 and h['failing'] == 231 and len(h['combinations']) == 200
    reason = next(x for x in r['verdict']['reasons'] if x['code'] == 'headroom_quorum')
    assert reason['args'] == {'count': 231}, reason
    assert reason['text'] == 'In 231 failure combinations the cluster loses quorum'
    # and the headroom says the same for a client that reads the counts
    assert h['no_quorum'] == 231 and h['unplaced'] == 0


def test_n_plus_1_counts_the_combinations_that_strand_guests_beyond_the_200_it_keeps():
    # 205 nodes, each with a guest an HA rule holds strictly to its own node
    nodes = tuple(f'pve{i:03d}' for i in range(205))
    guests = [_vm(1000 + i, n, maxmem=1) for i, n in enumerate(nodes)]
    rules = [{'type': 'node-affinity', 'rule': f'pin{vm["vmid"]}', 'resources': f'vm:{vm["vmid"]}',
              'nodes': vm['node'], 'strict': 1} for vm in guests]
    m = _manager(_cluster(guests, {}, rules=rules), guests, nodes=nodes)
    r = _run(m, type='headroom', depth=1)
    h = r['headroom']
    assert h['checked'] == 205 and len(h['combinations']) == 200
    assert all(c['unplaced'] for c in h['combinations'])
    reason = next(x for x in r['verdict']['reasons'] if x['code'] == 'headroom_unplaced')
    assert reason['args'] == {'count': 205}, reason
    assert h['unplaced'] == 205 and h['no_quorum'] == 0


def test_a_headroom_without_the_counts_is_counted_from_its_combinations_as_before():
    # a report an older engine made (or a client built) has the combinations only
    stuck = {'combinations': [{'unplaced': 2, 'quorate': True}, {'unplaced': 0, 'quorate': False}], 'failing': 2}
    v = whatif.verdict({'guests': [], 'nodes': [], 'headroom': stuck})
    assert [(r['code'], r['args']) for r in v['reasons']] == [('headroom_unplaced', {'count': 1}),
                                                              ('headroom_quorum', {'count': 1})]


@pytest.mark.parametrize('code', ['guests_unknown', 'configs_unread'])
def test_the_new_lines_have_a_wording_for_one(code):
    one = whatif._vreason('warning', code, count=1)['text']
    many = whatif._vreason('warning', code, count=2)['text']
    assert one.startswith('1 ') and one != many.replace('2', '1', 1), (code, one)
