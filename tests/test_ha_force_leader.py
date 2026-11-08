"""Force leader (#625 stage 2, design 7.3, owner decisions Q3 b and Q13 b, slice S7).

The way out of an automatic group that lost its majority for good: on a data member
that heard no leader for the lease and a half and whose last election found no majority
answering, an admin names every member that does not answer (each powered off or
destroyed), gives a reason, the password and the typed phrase. The member becomes the
manual active of its group at a new epoch, the members it cut out are out of the group,
its claim is marked forced and the cut-out members' VMs lose their autostart. It is
offered too on a member that holds a pending switch whose maker is gone (Q13), and it
always ends in manual mode.

MK Oct 2026 (#625)
"""
import types

import pytest

from pegaprox.core import ha_vote as hv
from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _audit
from test_ha_claim import _claim, _mgr, pve  # noqa: F401  (the fixture)
from test_ha_lease_members import _restore
from test_ha_members import IDS, _sync, group  # noqa: F401  (the fixture)
from test_ha_way_out import _switch_back_only_b_took
from test_ha_witness_group import _pair, host  # noqa: F401  (the fixture)


def _force(auto, n, names, reason='site A burned down', **extra):
    body = dict({'confirm': 'FORCE LEADER', 'user_password': ADMIN_PW, 'reason': reason,
                 'cut_out': [IDS[x] for x in names]}, **extra)
    return auto.post(n, '/api/ha/force-leader', body)


def _view(auto, n):
    with auto.at(n) as ha:
        return ha.lease_status()['force_leader']


class _Guests:
    """A cluster whose guests Force leader looks up and changes."""

    def __init__(self, vms):
        self.vms, self.changed = vms, []
        self.ha_enabled = False
        self.config = types.SimpleNamespace(name='lab')

    def get_vm_resources(self, max_age=0.0):
        return list(self.vms)

    def update_vm_config(self, node, vmid, vm_type, updates):
        self.changed.append((node, vmid, vm_type, dict(updates)))
        return {'success': True}


def _lost_majority(auto, seed, standbys='bcd', down='ac', campaign=True):
    """An automatic group of a and `standbys`; the members in `down` are gone, and b
    heard no leader for the lease and a half."""
    auto.form(seed, standbys, accept=['EVEN_VOTERS'] if len(standbys) % 2 else None)
    auto.past_the_hold()
    for n in standbys:
        assert _sync(auto.g, auto.admin, n) == 'applied'
    for n in down:
        auto.crash(n)
    auto.members = ''.join(n for n in 'a' + standbys if n not in down)
    auto.advance(T.P + T.L / 2 + 1)
    if campaign:
        r = auto.post('b', '/api/ha/make-leader', {'confirm': 'LEADER', 'user_password': ADMIN_PW})
        assert r.status_code == 409 and 'no majority' in r.get_json()['error'], r.data


# --- when it is offered ------------------------------------------------------------------------

def test_force_leader_is_offered_once_no_majority_answers(auto, seed):
    _lost_majority(auto, seed)
    # the status goes by what the watch heard last
    auto.watch('b')

    view = _view(auto, 'b')

    assert view['offered'] is True and view['case'] == 'auto', view
    assert [c['instance_id'] for c in view['cut_out']] == [IDS['a'], IDS['c']]
    assert view['phrase'] == 'FORCE LEADER' and 'powered off or destroyed' in view['warning']
    assert 'until the two can reach each other again' in view['warning']


def test_not_before_an_election_found_no_majority(auto, seed):
    _lost_majority(auto, seed, campaign=False)
    view = _view(auto, 'b')
    assert view['offered'] is False and 'No election ran from here' in view['why']
    r = _force(auto, 'b', 'ac')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_FORCE_REFUSED'
    assert auto.state('b')['role'] == 'standby'


def test_not_while_a_majority_still_has_a_leader(auto, seed):
    """b is cut off from the leader only: the leader and c are a majority."""
    auto.form(seed)
    auto.past_the_hold()
    auto.cut('a', 'b')
    auto.run(T.P + T.L / 2 + 1, members='ac')
    r = auto.post('b', '/api/ha/make-leader', {'confirm': 'LEADER', 'user_password': ADMIN_PW})
    assert r.status_code == 409

    r = _force(auto, 'b', 'a')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_FORCE_REFUSED', r.data
    assert 'The last election reached a majority' in r.get_json()['error']
    assert auto.state('b')['role'] == 'standby' and auto.leader() == 'a'
    # whatever the last election said: a member that answers and holds a promise refuses it
    node = auto.node('b')
    node.last_failed = dict(node.last_failed, reached=1)
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert view['offered'] is False and 'the group has a leader' in view['why']


def test_not_while_the_leader_restarts_by_plan(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    with auto.at('a') as ha:
        assert ha.planned_restart('update') is True
    auto.crash('a')
    auto.crash('c')
    auto.members = 'b'
    auto.advance(T.P + T.L / 2 + 1)

    view = _view(auto, 'b')

    assert view['offered'] is False and 'holds the promise' in view['why']


def test_not_in_a_manual_group_on_the_leader_or_without_the_release(auto, seed, monkeypatch):
    auto.pair(seed)
    assert _view(auto, 'b')['offered'] is False and _view(auto, 'b')['case'] is None
    assert _force(auto, 'b', 'a').status_code == 409
    auto.switch_on()
    r = _force(auto, 'a', '')
    assert r.status_code == 409 and 'follows' in r.get_json()['error']
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    r = _force(auto, 'b', 'a')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED'
    assert not _audit('ha.forced_leader')


# --- what the admin has to give -------------------------------------------------------------------

def test_every_member_that_does_not_answer_is_named_and_nothing_else(auto, seed):
    _lost_majority(auto, seed)
    r = _force(auto, 'b', 'a')
    assert r.status_code == 409 and 'Tick every member' in r.get_json()['error']
    r = _force(auto, 'b', 'acd')
    assert r.status_code == 409 and 'answer and are not cut out' in r.get_json()['error']
    for bad in ({'confirm': 'force leader'}, {'reason': ' '}, {'cut_out': 'ac'}, {'cut_out': ['x']}):
        r = _force(auto, 'b', 'ac', **bad)
        assert r.status_code == 400, (bad, r.data)
    r = _force(auto, 'b', 'ac', user_password='wrong')
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    from pegaprox.utils.auth import create_api_token
    res = create_api_token('root', 'ci', role='admin')
    with auto.at('b'):
        r = auto.g.api.anon().post('/api/ha/force-leader', json={
            'confirm': 'FORCE LEADER', 'user_password': ADMIN_PW, 'reason': 'x',
            'cut_out': [IDS['a'], IDS['c']]}, headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_REAUTH'
    assert auto.state('b')['role'] == 'standby' and not _audit('ha.forced_leader')


# --- what it does --------------------------------------------------------------------------------

def test_the_member_becomes_the_manual_active_and_the_cut_out_members_are_out(auto, seed):
    _lost_majority(auto, seed)
    before = auto.state('b')
    epoch_seen = max([before['epoch']] + [m.get('epoch_seen') or 0 for m in before['members'].values()])

    r = _force(auto, 'b', 'ac')

    assert r.status_code == 200, r.data
    out = r.get_json()
    assert out['restarting'] is True and out['cut_out'] == [IDS['a'], IDS['c']]
    st = auto.state('b')
    assert st['role'] == 'active' and 'leader' not in st and st['epoch'] == out['epoch'] > epoch_seen
    assert sorted(st['members']) == [IDS['d']] and sorted(st['tombstones']) == [IDS['a'], IDS['c']]
    lease = st['lease']
    assert lease['mode'] == 'manual' and lease['cfg']['body']['mode'] == 'manual'
    assert [v['id'] for v in lease['cfg']['body']['voters']] == [IDS['b'], IDS['d']]
    assert lease['cfg']['id'][0] == out['epoch'] and lease['settled'] == hv.cfg_digest(lease['cfg'])
    assert lease['cfg']['prev'] == hv.cfg_digest(before['lease']['cfg'])
    assert st['forced']['reason'] == 'site A burned down' and st['forced']['cut_out'] == out['cut_out']
    assert ('b', 'forced to lead') in auto.g.restarts
    rows = _audit('ha.forced_leader')
    assert len(rows) == 1 and rows[0]['user'] == 'root' and 'site A burned down' in rows[0]['details']
    with auto.at('b') as ha:
        assert ha.mode() == 'manual' and ha.is_active() and not ha.lease_in_force()
        assert ha.claim_forced() is True
        status = ha.lease_status()
    assert status['forced']['epoch'] == out['epoch'] and status['way_out'] == ''
    # automatic failover comes back only through the switch
    r = auto.put('b', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
    assert r.status_code == 409


def test_the_member_that_still_answered_follows_the_forced_leader(auto, seed):
    _lost_majority(auto, seed)
    assert _force(auto, 'b', 'ac').status_code == 200
    auto.restart('b')
    # d heard no leader since: it campaigns, b answers with its manual config
    auto.run(T.P + T.L, members='d', until=lambda: auto.mode('d') == 'manual')
    assert auto.mode('d') == 'manual'
    auto.watch('d')
    assert auto.state('d')['source'] == IDS['b']


def test_a_cut_out_member_that_comes_back_hears_it_is_out(auto, seed):
    _lost_majority(auto, seed)
    assert _force(auto, 'b', 'ac').status_code == 200
    auto.restart('b')

    auto.back('a')

    st = auto.state('a')
    assert st['removed'] and st['removed']['by'] == IDS['b'] and st['role'] == 'standby'
    assert 'lease' not in st
    with auto.at('a') as ha:
        assert not ha.is_active()
    assert any('removed from the group' in row['details'] for row in _audit('ha.removed'))


def test_the_claim_of_the_forced_leader_says_so(auto, seed, pve):  # noqa: F811
    _lost_majority(auto, seed)
    assert _force(auto, 'b', 'ac').status_code == 200
    m = _mgr(pve, claim_enabled=True)
    with auto.at('b'):
        result = m._ha_claim_ensure()
    epoch = auto.state('b')['epoch']
    assert result['state'] == 'ours' and result['epoch'] == epoch
    line = _claim(pve).split()
    assert line[0] == str(epoch) and line[1] == IDS['b'] and line[4] == '1'


def test_autostart_goes_off_on_the_vms_of_the_cut_out_members(auto, seed):
    import pegaprox.globals as ppglobals
    guests = _Guests([{'vmid': 105, 'node': 'pve1', 'type': 'qemu'},
                      {'vmid': 106, 'node': 'pve2', 'type': 'qemu'}])
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    # the cluster is known while the VMs are named, and while the pass runs
    auto.g.api.set_manager('c1', guests)
    r = auto.put('a', f"/api/ha/members/{IDS['a']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 105})
    assert r.status_code == 200 and r.get_json()['changed'] is True
    r = auto.put('a', f"/api/ha/members/{IDS['d']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 106})
    assert r.status_code == 200
    ppglobals.cluster_managers.pop('c1')
    auto.past_the_hold()
    for n in 'bcd':
        assert _sync(auto.g, auto.admin, n) == 'applied'
    assert auto.state('b')['members'][IDS['a']]['agent_vmid'] == {'c1': 105}
    for n in 'ac':
        auto.crash(n)
    auto.members = 'bd'
    auto.advance(T.P + T.L / 2 + 1)
    assert auto.post('b', '/api/ha/make-leader', {'confirm': 'LEADER',
                                                   'user_password': ADMIN_PW}).status_code == 409
    assert _force(auto, 'b', 'ac').status_code == 200
    assert auto.state('b')['forced']['onboot'] == {'c1': [105]}
    auto.g.api.set_manager('c1', guests)

    with auto.at('b') as ha:
        assert ha.forced_onboot_pass() == ['c1/105']
        assert ha.forced_onboot_pass() == []
    # only the VM of the member it cut out, never the one of d
    assert guests.changed == [('pve1', 105, 'qemu', {'onboot': 0})]
    assert auto.state('b')['forced']['onboot'] == {}
    assert any('c1/105' in row['details'] for row in _audit('ha.forced_onboot'))


def test_a_cluster_that_does_not_answer_is_tried_again_and_then_said(auto, seed):
    _lost_majority(auto, seed)
    assert _force(auto, 'b', 'ac').status_code == 200
    with auto.at('b') as ha:
        st = ha._load()
        with ha._lock:
            ha._commit_locked(dict(st, forced=dict(st['forced'], onboot={'c9': [120]})))
        for _ in range(ha.ONBOOT_TRIES - 1):
            assert ha.forced_onboot_pass() == []
        assert auto.state('b')['forced']['onboot'] == {'c9': [120]}
        ha.forced_onboot_pass()
    assert auto.state('b')['forced']['onboot'] == {}
    assert any('do it by hand' in row['details'] for row in _audit('ha.forced_onboot'))


# --- a pending switch whose maker is gone (Q13 b) -----------------------------------------------

def _pending_without_its_maker(auto, seed):
    auto.pair(seed, 'bc')
    r = auto.switch_on(settle=False)
    assert r.status_code == 200, r.data
    auto.cut('a', 'c')
    auto.step('a')
    assert auto.mode('b') == 'auto_pending' and auto.mode('c') == 'manual'
    auto.crash('a')
    auto.heal()
    auto.members = 'bc'


def test_a_pending_switch_whose_maker_is_gone_stays_until_force_leader(auto, seed):
    _pending_without_its_maker(auto, seed)
    # no timeout takes it back to manual mode by itself, and nobody promotes it by hand
    auto.run(hv.SWITCH_TIMEOUT + 60, dt=5.0)
    assert auto.mode('b') == 'auto_pending'
    r = auto.post('b', '/api/ha/promote', {'confirm': 'PROMOTE', 'user_password': ADMIN_PW, 'force': True})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'

    view = _view(auto, 'b')
    assert view['offered'] is True and view['case'] == 'pending', view
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert [c['instance_id'] for c in view['cut_out']] == [IDS['a']]

    r = _force(auto, 'b', 'a', reason='the old leader was decommissioned')

    assert r.status_code == 200, r.data
    st = auto.state('b')
    assert st['role'] == 'active' and st['lease']['mode'] == 'manual'
    assert sorted(st['members']) == [IDS['c']] and list(st['tombstones']) == [IDS['a']]


def test_not_while_the_maker_of_the_switch_answers(auto, seed):
    _pending_without_its_maker(auto, seed)
    auto.back('a')
    auto.advance(T.P + T.L / 2 + 1)
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert view['offered'] is False and 'started the switch, answers' in view['why']


# --- 'unknown' and 'pending' never force past a group that answers ------------------------------
#
# Found by the attack on S7: in these two cases no election from here has to have failed, so
# the members that answer decide. One that fails over automatically, holds another switch, or
# is an active means the group has somebody to follow.

def _restored_before_the_switch(auto, seed, standbys, accept=None, witness=None):
    """b's state is put back from a copy made before the group went automatic."""
    auto.pair(seed, standbys)
    backup = auto.file('b')
    if witness is not None:
        _pair(auto, witness)
        for n in standbys:
            assert _sync(auto.g, auto.admin, n) == 'applied'
    assert auto.switch_on(accept=accept).status_code == 200
    auto.past_the_hold()
    for n in standbys:
        _sync(auto.g, auto.admin, n)
    auto.run(2 * T.R)
    assert auto.leader() == 'a'
    _restore(auto, 'b', backup)
    with auto.at('b') as ha:
        assert ha.way_out_refusal() == ha.RESTORED_ERROR
        # the process has been up for a while
        ha._rt().born -= 300


def test_unknown_is_refused_while_the_members_that_answer_fail_over_automatically(auto, seed):
    """The other three are an automatic group between two leaders: every promise ran out,
    nobody campaigned yet, and all of them answer b. Forced, b would act next to the
    leader they elect a moment later."""
    _restored_before_the_switch(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.advance(T.L + T.P)
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert view['offered'] is False and view['case'] == 'unknown', view
    assert 'follow it' in view['why']

    r = _force(auto, 'b', '')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_FORCE_REFUSED', r.data
    assert auto.state('b')['role'] == 'standby' and not _audit('ha.forced_leader')


def test_unknown_is_refused_while_the_rest_of_the_group_answers_split_among_itself(auto, host, seed):  # noqa: F811
    """a is powered off and the admin ticks only a, truthfully. c, d and the witness are
    split from each other for a while, each still answers b: once the split heals they
    elect their own leader, so b is not forced past them."""
    _restored_before_the_switch(auto, seed, 'bcd', witness=host)
    auto.crash('a')
    auto.members = 'bcd'
    auto.cut('c', 'd')
    auto.cut('c', 'w')
    auto.cut('d', 'w')
    auto.run(90, members='cd')
    assert auto.active() == []

    r = _force(auto, 'b', 'a', reason='site of a burned down')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_FORCE_REFUSED', r.data
    assert 'follow it' in r.get_json()['error']
    auto.heal()
    auto.run(240, members='cd', until=lambda: auto.active() != [])
    acting = auto.active()
    assert len(acting) == 1 and acting != ['b'], acting


def test_unknown_is_refused_while_a_manual_active_answers(auto, seed):
    """b holds a switch back to manual mode only it took; later the admin switches
    automatic failover off properly on the leader while b is cut off, and the cut heals.
    b's manual config is still not known as the group's (case unknown), and the group's
    manual active answers it."""
    auto.form(seed, 'bc')
    _switch_back_only_b_took(auto, 'c')
    lead = auto.leader()
    other = 'c' if lead == 'a' else 'a'
    auto.cut(lead, 'b')
    auto.cut(other, 'b')
    for _ in range(12):
        r = auto.put(lead, '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW})
        if r.status_code == 200:
            break
        auto.run(10, members=lead + other)
    assert r.status_code == 200, r.data
    auto.run(30, members=lead + other)
    auto.heal()
    auto.run(10, members=lead + other)
    auto.watch(lead, other)
    with auto.at('b') as ha:
        ha._rt().born -= 300
        assert ha.way_out_check()
    assert lead in auto.active() and auto.mode(lead) == 'manual'

    r = _force(auto, 'b', '', reason='b cannot be promoted')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_FORCE_REFUSED', r.data
    assert 'answers as an active instance' in r.get_json()['error']
    assert auto.state('b')['role'] == 'standby' and auto.active() == [lead]


@pytest.mark.parametrize('role, mode, by, offered', [
    ('standby', 'manual', None, True),
    ('active', 'manual', None, False),
    ('standby', 'auto', None, False),
    ('standby', 'auto_pending', 'maker', True),
    ('standby', 'auto_pending', 'other', False),
    ('standby', 'auto_pending', None, False),
])
def test_a_pending_member_goes_by_every_answer(auto, seed, monkeypatch, role, mode, by, offered):
    """b holds the switch a started, a is gone. What c answers decides: a member that
    holds the same switch, or none, leaves Force leader offered; an active, a member that
    fails over automatically or one holding another switch does not."""
    _pending_without_its_maker(auto, seed)
    auto.advance(T.P + T.L / 2 + 1)
    seen = {'mode': mode, 'pending_by': {'maker': IDS['a'], 'other': 'f' * 32, None: None}[by],
            'holds': False, 'holder': None, 'cfg_id': None}
    rec = dict(auto.state('b')['members'][IDS['c']], instance_id=IDS['c'])
    monkeypatch.setattr(auto.ha, '_group_says',
                        lambda timeout=5: [(rec, (role, 3, None, False, (None, None), seen), None)])
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert view['offered'] is offered, view
    if offered:
        assert [c['instance_id'] for c in view['cut_out']] == [IDS['a']]


# --- what Force leader leaves behind ---------------------------------------------------------------

def test_the_vm_of_a_member_stays_with_it_once_it_leads(auto, seed):
    """A member keeps the VM the leader named for it: once it leads, its own entry of the
    list it hands out carries it, and a Force leader later still switches its autostart
    off."""
    import pegaprox.globals as ppglobals
    guests = _Guests([{'vmid': 105, 'node': 'pve1', 'type': 'qemu'},
                      {'vmid': 106, 'node': 'pve2', 'type': 'qemu'}])
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.g.api.set_manager('c1', guests)
    assert auto.put('a', f"/api/ha/members/{IDS['a']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 105}).status_code == 200
    assert auto.put('a', f"/api/ha/members/{IDS['b']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 106}).status_code == 200
    ppglobals.cluster_managers.pop('c1')
    auto.past_the_hold()
    for n in 'bcd':
        assert _sync(auto.g, auto.admin, n) == 'applied'
    assert auto.state('b')['agent_vmid'] == {'c1': 106}

    r = auto.post('a', '/api/ha/make-leader', {'target': IDS['b'], 'confirm': 'LEADER',
                                               'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(T.W_take + 10, until=lambda: auto.leader() == 'b')
    assert auto.leader() == 'b'
    auto.run(2 * T.R)
    for n in 'acd':
        _sync(auto.g, auto.admin, n)
    with auto.at('b') as ha:
        assert ha.lease_status()['agent_vmid'] == {'c1': 106}
    assert auto.state('c')['members'][IDS['b']]['agent_vmid'] == {'c1': 106}
    assert auto.state('a')['agent_vmid'] == {'c1': 105}

    # b's site burns, a with it: c forces
    auto.crash('b')
    auto.crash('a')
    auto.members = 'cd'
    auto.advance(T.P + T.L / 2 + 1)
    assert auto.post('c', '/api/ha/make-leader', {'confirm': 'LEADER',
                                                   'user_password': ADMIN_PW}).status_code == 409
    r = auto.post('c', '/api/ha/force-leader', {'confirm': 'FORCE LEADER', 'user_password': ADMIN_PW,
                                                'reason': 'site of b burned', 'cut_out': [IDS['a'], IDS['b']]})
    assert r.status_code == 200, r.data
    assert sorted(auto.state('c')['forced']['onboot']['c1']) == [105, 106]


def test_a_member_forced_without_a_voter_config_is_not_left_as_put_back(auto, seed):
    """b's state was put back from before the switch and holds no voter config; a and c
    are gone for good. Once forced, its note of the group is the forced state's, not the
    automatic group it left: no 'put back from a copy', and it can be unpaired."""
    auto.pair(seed, 'bc')
    backup = auto.file('b')
    assert 'lease' not in backup
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    for n in 'bc':
        assert _sync(auto.g, auto.admin, n) == 'applied'
    auto.run(2 * T.R)
    _restore(auto, 'b', backup)
    with auto.at('b') as ha:
        ha._rt().born -= 300
    auto.crash('a')
    auto.crash('c')
    auto.members = 'b'

    r = _force(auto, 'b', 'ac', reason='both gone')

    assert r.status_code == 200, r.data
    auto.restart('b')
    with auto.at('b') as ha:
        assert ha.way_out_refusal() == '' and ha.lease_status()['way_out'] == ''
    r = auto.post('b', '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert auto.file('b')['role'] == 'standalone'


def test_force_leader_goes_out_on_both_alert_paths_and_the_event_stream(auto, seed, monkeypatch):
    """A break-glass: besides the critical log line and the audit row, the plugin hook
    (globals._notification_handlers), the webhook channels (send_to_channels) and an SSE
    ha_status event with severity critical. A source that calls only the first reaches no
    webhook (#815)."""
    import pegaprox.globals as ppglobals
    import pegaprox.utils.realtime as realtime
    import pegaprox.utils.webhooks as webhooks
    hooked, sent, pushed = [], [], []
    monkeypatch.setattr(ppglobals, '_notification_handlers',
                        list(ppglobals._notification_handlers) + [hooked.append])
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, channel_ids=None: sent.append(alert))
    monkeypatch.setattr(realtime, 'broadcast_sse',
                        lambda kind, data, cluster_id=None, target_clusters=None: pushed.append((kind, data)))
    _lost_majority(auto, seed)

    r = _force(auto, 'b', 'ac', reason='site A burned down')

    assert r.status_code == 200, r.data
    epoch = r.get_json()['epoch']
    assert len(hooked) == 1 and sent == hooked
    alert = hooked[0]
    assert alert['severity'] == 'critical' and alert['metric'] == 'ha_forced_leader'
    assert f'epoch {epoch}' in alert['message'] and 'manual mode' in alert['message']
    # the reason is the admin's own words: in the audit row, not in every inbox
    assert 'site A burned down' not in alert['message']
    assert [k for k, _d in pushed] == ['ha_status']
    assert pushed[0][1]['severity'] == 'critical' and pushed[0][1]['event'] == 'ha.forced_leader'


def test_the_forced_leader_holds_the_schedules_of_the_minute_it_took_over_in(auto, seed, monkeypatch):
    """Lab E8: a task of that minute ran on the old leader during the cut and again on
    the forced one, at its first pass after the restart. The minute it took over in is
    held, plus the skew, as after a takeover (5.7); a later one runs, and nothing is held
    once the epoch moved on. A manual active without Force leader holds nothing
    (test_ha_confirm_sites)."""
    from datetime import datetime
    _lost_majority(auto, seed)
    assert _force(auto, 'b', 'ac').status_code == 200
    auto.restart('b')
    took = datetime.fromisoformat(auto.state('b')['forced']['at']).timestamp()
    wall = {'t': took + 0.5}
    monkeypatch.setattr(auto.ha, '_wall', lambda: wall['t'])

    with auto.at('b') as ha:
        assert ha.is_active() and ha.mode() == 'manual'
        assert ha.schedule_held() is True
        # a minute the first pass would catch up, the one it took over in
        assert ha.schedule_held(ha.schedule_at(took)) is True
        later = took - took % 60 + 120
        assert ha.schedule_held(ha.schedule_at(later)) is False
        wall['t'] = later + 0.5
        assert ha.schedule_held() is False
        # the epoch moved on (a promotion, the switch): no longer the forced one
        st = ha._load()
        wall['t'] = took + 0.5
        assert ha._forced_hold(dict(st, epoch=st['epoch'] + 1)) is False


def test_a_refused_force_leader_alerts_nobody(auto, seed, monkeypatch):
    import pegaprox.utils.webhooks as webhooks
    sent = []
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, channel_ids=None: sent.append(alert))
    _lost_majority(auto, seed, campaign=False)
    assert _force(auto, 'b', 'ac').status_code == 409
    assert sent == []


def test_a_member_rolled_back_whole_is_the_documented_limit(auto, host, seed):  # noqa: F811
    """Known limit, written down for the operator (way_out_refusal, the HA guide): a member
    restored as a whole - a VM snapshot rolled back - brings its state file back with the
    note next to it, from the same moment, so it cannot be told from a live member that
    never knew the switch. Never roll a member back while its group runs: unpair it and
    pair it again."""
    import os
    auto.pair(seed, 'b')
    backup = auto.file('b')
    note = auto.g.files['b'] + '.group'
    assert not os.path.exists(note)
    _pair(auto, host)
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.switch_on().status_code == 200
    auto.past_the_hold()
    assert os.path.exists(note)
    # the whole directory as it was: the note did not exist yet
    os.unlink(note)
    _restore(auto, 'b', backup)
    with auto.at('b') as ha:
        assert ha.way_out_refusal() == ''
        doc = ha.way_out_refusal.__doc__
    assert 'snapshot' in doc and 'unpair it and pair it again' in doc


def _clock_far_off(auto, monkeypatch, who='b', off=300):
    """`who` signs five minutes ahead and reads the others' calls as five minutes old:
    every member refuses its calls (401 HA_CLOCK), as for one restored from an old VM
    snapshot with the clock of that moment."""
    from pegaprox.core import ha_wire
    import time
    ha = auto.ha
    real = ha._signed_headers

    def signed(private, sender, receiver, method, path, body):
        if sender != IDS[who]:
            return real(private, sender, receiver, method, path, body)
        stream = ha._lease_stream if path in (ha.VOTE_PATH, ha.RENEW_PATH) else ha._call_stream
        return ha_wire.signed_headers(private, sender, receiver, method, path, body, time.time() + off,
                                      ha._stream_nonce(stream, receiver))
    monkeypatch.setattr(ha, '_signed_headers', signed)
    check = ha._signature_check

    def checked(headers, method, path, body, sender, public_key, receiver):
        said = check(headers, method, path, body, sender, public_key, receiver)
        return 'skewed' if said == 'ok' and receiver == IDS[who] else said
    monkeypatch.setattr(ha, '_signature_check', checked)


def test_an_unknown_member_whose_calls_are_refused_is_not_forced_past_the_leader(auto, seed, monkeypatch):
    """b, put back from before the switch, hears every member refuse its calls: they are
    there, and one of them leads. Nothing they said is known, so they are neither cut out
    nor waved through: Force leader is refused until the clocks agree."""
    _restored_before_the_switch(auto, seed, 'bcd', accept=['EVEN_VOTERS'])
    assert auto.leader() == 'a'
    _clock_far_off(auto, monkeypatch)
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert view['offered'] is False and 'refuses the calls of this instance' in view['why']

    r = _force(auto, 'b', '')

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_FORCE_REFUSED', r.data
    assert auto.file('b')['role'] == 'standby'


def test_a_pending_member_whose_calls_are_refused_is_not_forced_past_the_maker(auto, seed, monkeypatch):
    """The maker of the switch is back and answers, but refuses b's calls: b cannot tell
    it from a member that is gone, and Force leader is refused."""
    _pending_without_its_maker(auto, seed)
    auto.back('a')
    auto.members = 'abc'
    auto.advance(T.P + T.L / 2 + 1)
    with auto.at('b') as ha:
        ha._rt().switch_heard = None
    _clock_far_off(auto, monkeypatch)
    with auto.at('b') as ha:
        view = ha.force_leader_view(probe=True)
    assert view['offered'] is False and 'refuses the calls of this instance' in view['why']

    r = _force(auto, 'b', '', reason='the maker is gone')

    assert r.status_code == 409, r.data
