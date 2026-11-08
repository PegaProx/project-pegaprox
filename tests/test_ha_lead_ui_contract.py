"""The split panel, the member settings, Make leader, Force leader and the banners against the real routes (#625).

test_ha_lead_ui.py drives the UI against a fake server and pins the bodies it sends. Here the same
bodies go to pegaprox/api/ha.py in the group harness of the lease tests, and the status and the
banner the UI renders are read from the real public_status and /api/auth/check: every key the
panel, the forms and the banners read is there, every body passes the checks of its route, and this
release answers the routes it does not offer yet with the code the UI never needs to show, because
it shows none of it.
LW
"""
import pytest

from pegaprox.core import ha_vote as hv
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW
from test_ha_force_leader import _lost_majority
from test_ha_make_leader import _formed
from test_ha_member_settings import IPMI, V2, _Pve, _banner, _clusters, _handed_to_b, _viewer
from test_ha_members import IDS, group  # noqa: F401  (the fixture)
from test_ha_ui import _read


# what the forms send, as test_ha_lead_ui.py pins it (there with the fake's password)
def SITE(site):
    return {'site': site}


def VOTE(pw, **flag):
    return dict(flag, user_password=pw)


def MAKE(pw, target):
    return {'target': target, 'confirm': 'LEADER', 'user_password': pw}


def MAKE_SELF(pw):
    return {'confirm': 'LEADER', 'user_password': pw}


def FORCE(pw, cut_out, reason):
    return {'confirm': 'FORCE LEADER', 'cut_out': list(cut_out), 'reason': reason, 'user_password': pw}


def VMID(cluster, vmid):
    return {'cluster_id': cluster, 'vmid': vmid}


# what the panel, the status line, the member cells and the lead card read
LEAD_KEYS = {'transfer', 'planned_restart', 'last_campaign', 'make_leader', 'forced', 'force_leader', 'way_out',
             'renewed_ago', 'leader_change', 'unconfirmed', 'promise', 'leader_cv', 'behind', 'change_pending', 'site',
             'may_lead', 'holds_lease', 'holder', 'lease_left', 'mode', 'epoch', 'members', 'witness', 'findings',
             'agent_vmid'}
ROW_KEYS = {'instance_id', 'kind', 'voter', 'may_lead', 'site', 'cv', 'behind', 'current', 'promised_to',
            'promised_left', 'unreached_from', 'make_leader', 'make_leader_why', 'agent_vmid'}
SPLIT_KEYS = {'voters', 'majority', 'tolerates', 'level', 'sites', 'unlabeled', 'clusters', 'findings'}
SITE_KEYS = {'site', 'voters', 'votes', 'candidates', 'members', 'witness', 'survives_loss'}
CLUSTER_KEYS = {'id', 'name', 'kind', 'nodes', 'agents', 'agent_version', 'fence', 'fence_verified', 'ready',
                'not_ready', 'two_node', 'unsafe_two_node', 'claim', 'reach_sites'}
CLAIM_KEYS = {'enabled', 'state', 'epoch', 'instance', 'residual'}
FORCE_KEYS = {'offered', 'case', 'why', 'cut_out', 'warning', 'phrase'}
FORCED_KEYS = {'epoch', 'at', 'by', 'reason', 'case', 'cut_out', 'onboot_left'}


def _status(auto, n='a'):
    with auto.at(n):
        r = auto.admin.get('/api/ha/status')
    assert r.status_code == 200, r.data
    return r.get_json()


def _put(auto, n, member, what, body):
    return auto.put(n, f'/api/ha/members/{member}/{what}', body)


def test_the_ui_tests_pin_these_bodies():
    ui = _read('tests', 'test_ha_lead_ui.py')
    for literal in ("[{'site': 'dc9'}]", "{'voter': False, 'user_password': PASSWORD}",
                    "{'may_lead': False, 'user_password': PASSWORD}",
                    "{'target': B, 'confirm': 'LEADER', 'user_password': PASSWORD}",
                    "[{'confirm': 'LEADER', 'user_password': PASSWORD}]",
                    "{'confirm': 'FORCE LEADER', 'cut_out': [B, W],",
                    "'reason': 'site A burned down', 'user_password': PASSWORD}",
                    "[{'cluster_id': 'c2', 'vmid': 205},", "{'cluster_id': 'old', 'vmid': None}]"):
        assert literal in ui, literal


def test_this_release_shows_none_of_it_and_offers_none_of_it(auto, seed, monkeypatch):
    auto.pair(seed)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    status = _status(auto)
    # the UI hides the panel and the lead card on both
    assert status['auto'] is None and status['split_safety'] is None
    r = _put(auto, 'a', IDS['b'], 'vote', VOTE(ADMIN_PW, voter=False))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    r = auto.post('a', '/api/ha/make-leader', MAKE(ADMIN_PW, IDS['b']))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    r = auto.post('b', '/api/ha/force-leader', FORCE(ADMIN_PW, [IDS['a']], 'gone'))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    # a site is a label the server takes all the same; the UI sets it with the panel
    r = _put(auto, 'a', IDS['b'], 'site', SITE('dc9'))
    assert r.status_code == 200 and r.get_json()['site'] == 'dc9'


def test_the_status_carries_every_key_the_panel_reads(auto, seed, monkeypatch):
    _formed(auto, seed)
    # clusters with node HA from here on: before the switch their findings would want a tick
    _clusters(monkeypatch, c1=_Pve(fence_agent_versions={'n1': 2, 'n2': 1}, fencing={'n3': IPMI}),
              c2=_Pve(nodes=('n1', 'n2'), two_node_mode=True, fence_agent_versions={'n1': 2, 'n2': 2}, claim_enabled=True,
                      claim_state={'state': 'ours', 'instance': IDS['a'], 'epoch': 1}))
    for n in 'ab':
        got = _status(auto, n)
        assert LEAD_KEYS <= set(got['auto']), (n, sorted(LEAD_KEYS - set(got['auto'])))
        assert FORCE_KEYS <= set(got['auto']['force_leader']), sorted(FORCE_KEYS - set(got['auto']['force_leader']))
        assert set(got['auto']['make_leader']) == {'phrase', 'self'}
        for row in got['auto']['members']:
            assert ROW_KEYS <= set(row), sorted(ROW_KEYS - set(row))
        split = got['split_safety']
        assert SPLIT_KEYS <= set(split), sorted(SPLIT_KEYS - set(split))
        assert split['level'] in ('ok', 'info', 'warn', 'block')
        for s in split['sites']:
            assert SITE_KEYS <= set(s), sorted(SITE_KEYS - set(s))
        for c in split['clusters']:
            assert CLUSTER_KEYS <= set(c), sorted(CLUSTER_KEYS - set(c))
            assert CLAIM_KEYS <= set(c['claim']), sorted(CLAIM_KEYS - set(c['claim']))
        for f in split['findings']:
            assert {'code', 'level', 'text', 'member'} <= set(f)
        assert isinstance(got['site'], str) and all(isinstance(m['site'], str) for m in got['members'])
    leader = _status(auto)['auto']
    assert leader['holds_lease'] is True and isinstance(leader['renewed_ago'], (int, float))
    assert all(r['make_leader'] is True and r['make_leader_why'] == '' for r in leader['members'])
    rows = {r['instance_id']: r for r in leader['members']}
    assert rows[IDS['b']]['promised_to'] == IDS['a'] and isinstance(rows[IDS['b']]['cv'], list)
    clusters = {c['id']: c for c in _status(auto)['split_safety']['clusters']}
    assert clusters['c1']['ready'] is False and clusters['c1']['not_ready'] == ['n2']
    assert clusters['c2']['two_node'] is True and clusters['c2']['claim']['state'] == 'ours'
    member = _status(auto, 'b')['auto']
    assert member['holder'] == IDS['a'] and member['make_leader']['self'] is True
    assert member['promise']['to'] == IDS['a'] and isinstance(member['promise']['left'], (int, float))


def test_the_agent_vm_bodies_pass_their_route_and_the_status_carries_them(auto, seed, monkeypatch):
    _formed(auto, seed)
    _clusters(monkeypatch, c1=_Pve(fence_agent_versions=V2))
    for member, vmid in ((IDS['b'], 205), (IDS['a'], 100)):
        r = _put(auto, 'a', member, 'agent-vmid', VMID('c1', vmid))
        assert r.status_code == 200 and r.get_json() == {'success': True, 'changed': True}, r.data
    status = _status(auto)
    assert {r['instance_id']: r['agent_vmid'] for r in status['auto']['members']}[IDS['b']] == {'c1': 205}
    assert status['auto']['agent_vmid'] == {'c1': 100}
    # the form has a row for each of these
    assert [(c['id'], c['kind']) for c in status['split_safety']['clusters']] == [('c1', 'proxmox')]
    r = _put(auto, 'a', IDS['b'], 'agent-vmid', VMID('c1', None))
    assert r.status_code == 200 and r.get_json()['changed'] is True
    assert {r['instance_id']: r['agent_vmid'] for r in _status(auto)['auto']['members']}[IDS['b']] == {}
    # what the input lets through and the route refuses, and the refusals the form shows
    assert _put(auto, 'a', IDS['b'], 'agent-vmid', VMID('c1', 99)).status_code == 400
    r = _put(auto, 'a', IDS['b'], 'agent-vmid', VMID('nope', 101))
    assert r.status_code == 404 and r.get_json()['error'] == 'Cluster not found'
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    r = _put(auto, 'a', IDS['b'], 'agent-vmid', VMID('c1', 101))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'


def test_the_site_bodies_pass_their_route(auto, seed):
    auto.pair(seed)
    for member, site in ((IDS['b'], 'dc9'), (IDS['a'], 'dc1')):
        r = _put(auto, 'a', member, 'site', SITE(site))
        assert r.status_code == 200 and r.get_json() == {'success': True, 'site': site, 'changed': True}, r.data
    status = _status(auto)
    assert status['site'] == 'dc1' and status['auto']['site'] == 'dc1'
    assert {r['instance_id']: r['site'] for r in status['auto']['members']}[IDS['b']] == 'dc9'
    assert 'dc9' in [s['site'] for s in status['split_safety']['sites']]
    # what the input lets through and the route refuses
    r = _put(auto, 'a', IDS['b'], 'site', SITE('x' * 65))
    assert r.status_code == 400


def test_the_vote_bodies_pass_their_route(auto, seed):
    auto.pair(seed, 'bcd')
    r = _put(auto, 'a', IDS['d'], 'vote', VOTE(ADMIN_PW, voter=False))
    assert r.status_code == 200 and r.get_json()['automatic'] is False and r.get_json()['voter'] is False, r.data
    for member in (IDS['b'], IDS['a']):
        r = _put(auto, 'a', member, 'vote', VOTE(ADMIN_PW, may_lead=False))
        assert r.status_code == 200 and r.get_json()['may_lead'] is False, r.data
    status = _status(auto)
    rows = {r['instance_id']: r for r in status['auto']['members']}
    assert rows[IDS['d']]['voter'] is False and rows[IDS['b']]['may_lead'] is False
    assert status['auto']['may_lead'] is False
    # the counterproof: without the password the same request stops at the re-auth
    r = _put(auto, 'a', IDS['c'], 'vote', {'voter': False})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'


def test_the_make_leader_body_of_the_leader_passes_its_route(auto, seed):
    _formed(auto, seed)
    r = auto.post('a', '/api/ha/make-leader', MAKE(ADMIN_PW, IDS['b']))
    assert r.status_code == 200 and r.get_json()['result'] == 'handed', r.data
    # handed: the old leader is a standby once the member won, as the UI's restart waits for
    auto.run(T.W_take + 10, until=lambda: auto.leader() == 'b')
    assert auto.state('a')['role'] == 'standby'


def test_the_make_leader_body_of_a_member_passes_its_route(auto, seed):
    _formed(auto, seed)
    r = auto.post('b', '/api/ha/make-leader', MAKE_SELF(ADMIN_PW))
    assert r.status_code == 200 and r.get_json()['result'] in ('handed', 'elected'), r.data


def test_the_force_body_passes_its_route_and_the_status_says_what_it_did(auto, seed):
    _lost_majority(auto, seed)
    auto.watch('b')
    view = _status(auto, 'b')['auto']['force_leader']
    assert view['offered'] is True and view['case'] == 'auto'
    assert all({'instance_id', 'url', 'kind'} <= set(c) for c in view['cut_out'])
    r = auto.post('b', '/api/ha/force-leader', FORCE(ADMIN_PW, [c['instance_id'] for c in view['cut_out']],
                                                     'site A burned down'))
    assert r.status_code == 200 and r.get_json()['restarting'] is True, r.data
    forced = _status(auto, 'b')['auto']['forced']
    assert FORCED_KEYS <= set(forced) and forced['reason'] == 'site A burned down'
    assert isinstance(forced['onboot_left'], dict)


@pytest.mark.parametrize('when', ['takeover', 'no_leader'])
def test_the_banner_carries_what_the_banners_read(auto, seed, when):
    viewer = _viewer(auto, seed)
    if when == 'takeover':
        _handed_to_b(auto, seed)
        auto.run(T.W_take + 10, until=lambda: 'b' in auto.holders())
        # a viewer: when, and no address; an admin the addresses as well (the banner names them then)
        got = _banner(auto, 'c', viewer)
        assert got['automatic'] is True and set(got['takeover']) == {'resume_in'}
        assert set(got['leader_changed']) == {'at'} and isinstance(got['leader_changed']['at'], str)
        got = _banner(auto, 'c', auto.admin)
        assert set(got['takeover']) == {'leader', 'resume_in'} and set(got['leader_changed']) == {'to', 'from', 'at'}
        assert isinstance(got['takeover']['leader'], str) and isinstance(got['leader_changed']['to'], str)
    else:
        _formed(auto, seed)
        left = auto.node('b').promise_until - auto.clock['b']
        auto.advance(left + 1)
        got = _banner(auto, 'b', viewer)
        assert got['automatic'] is True and got['no_leader'] is True
