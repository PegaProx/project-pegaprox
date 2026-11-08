"""Removal, leaving and pairing in an automatic group (#625 stage 2, design 7.4, F7 and
F14, slice S7).

Only the lease holder removes a member, once a majority confirmed the lease again
(ha.confirm_step), and the member leaves the voter config first, one change at a time;
never below three votes, never the leader itself. A member that unpairs asks the leader
to take it out first; without a leader that is refused. Pairing a member or the witness
goes under the same confirm.

MK Oct 2026 (#625)
"""


from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, URLS, group  # noqa: F401  (the fixture)

REMOVE = {'confirm': 'REMOVE', 'user_password': ADMIN_PW}
UNPAIR = {'confirm': 'UNPAIR', 'user_password': ADMIN_PW}


def _voters(auto, n='a'):
    return [rec['id'] for rec in auto.file(n)['lease']['cfg']['body']['voters']]


def _four(auto, seed):
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    auto.watch('a')


def test_the_leader_removes_a_member_out_of_the_voter_config_first(auto, seed):
    _four(auto, seed)

    r = auto.post('a', f"/api/ha/members/{IDS['d']}/remove", REMOVE)

    assert r.status_code == 200, r.data
    a = auto.file('a')
    assert IDS['d'] not in a['members'] and IDS['d'] in a['tombstones']
    assert IDS['d'] not in _voters(auto)
    auto.run(2 * T.R, dt=1.0)
    # the change reaches a majority of the voters before it, and the group goes on
    assert auto.leader() == 'a' and IDS['d'] not in _voters(auto, 'b')
    assert any('removed https://standby-d.example:5000' in row['details'] for row in _audit('ha.member_removed'))


def test_a_removal_that_leaves_too_few_votes_is_refused(auto, seed):
    auto.form(seed, 'bc')
    auto.past_the_hold()
    auto.watch('a')

    r = auto.post('a', f"/api/ha/members/{IDS['c']}/remove", REMOVE)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert 'fewer than 3 votes' in r.get_json()['error']
    assert IDS['c'] in auto.file('a')['members'] and IDS['c'] in _voters(auto)
    assert not _audit('ha.member_removed')


def test_a_removal_needs_the_lease_and_is_made_on_the_leader(auto, seed):
    _four(auto, seed)
    r = auto.post('b', f"/api/ha/members/{IDS['d']}/remove", REMOVE)
    assert r.status_code == 409 and 'Only the active instance' in r.get_json()['error']
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    r = auto.post('a', f"/api/ha/members/{IDS['d']}/remove", REMOVE)
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE', r.data
    assert IDS['d'] in auto.file('a')['members'] and IDS['d'] in _voters(auto)


def test_a_removal_waits_for_the_change_before_it(auto, seed, monkeypatch):
    """One change of the voter config at a time: while the one before has no majority,
    the removal is refused, and nothing of it is made later."""
    _four(auto, seed)
    node = auto.node('a')
    monkeypatch.setattr(node, '_is_committed', lambda: False)
    with auto.rt('a').lock:
        node._committed = None

    r = auto.post('a', f"/api/ha/members/{IDS['d']}/remove", REMOVE)

    assert r.status_code == 409 and 'did not go through in time' in r.get_json()['error'], r.data
    assert IDS['d'] in auto.file('a')['members'] and IDS['d'] in _voters(auto)
    assert auto.node('a')._changes == []


def test_a_member_leaves_through_the_leader(auto, seed):
    _four(auto, seed)

    r = auto.post('d', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 200, r.data
    assert r.get_json()['left_through'] == IDS['a'] and r.get_json()['restarting'] is True
    assert auto.file('d')['role'] == 'standalone'
    a = auto.file('a')
    assert IDS['d'] not in a['members'] and IDS['d'] not in _voters(auto)
    # kept out with a tombstone; the leader is not told the unpairing a second time
    assert a['tombstones'][IDS['d']]['by'] == IDS['a'] and not _audit('ha.removed')
    assert _audit('ha.member_left')
    assert any('taken out of the voter config by the leader' in row['details'] for row in _audit('ha.unpaired'))


def test_without_a_leader_nobody_leaves(auto, seed):
    _four(auto, seed)
    auto.crash('a')
    auto.members = 'bcd'

    r = auto.post('d', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert 'no leader answers' in r.get_json()['error']
    assert auto.file('d')['role'] == 'standby' and auto.file('d')['members']


def test_the_leader_and_a_vote_the_group_needs_do_not_leave(auto, seed):
    auto.form(seed, 'bc')
    auto.past_the_hold()
    r = auto.post('a', '/api/ha/unpair', UNPAIR)
    assert r.status_code == 409 and 'make another member leader first' in r.get_json()['error']
    # said here, before the leader is asked or the password checked
    auto.g.calls.clear()
    r = auto.post('c', '/api/ha/unpair', {'confirm': 'UNPAIR'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE'
    assert not [c for c in auto.g.calls if c[3] == '/api/ha/peer/leave']


def test_the_leave_route_takes_a_member_out_on_the_leader_only(auto, seed):
    _four(auto, seed)
    with auto.at('d') as ha:
        resp = ha.call_member(ha.member(IDS['b']), 'POST', ha.LEAVE_PATH, json_body={})
    assert resp.status_code == 409 and resp.json()['follow']['instance_id'] == IDS['a']
    assert IDS['d'] in auto.file('a')['members']


def test_pairing_in_an_automatic_group_is_confirmed_first(auto, seed, monkeypatch):
    auto.form(seed, 'bc')
    auto.past_the_hold()
    asked = []
    real = auto.ha.confirm_step

    def confirm_step(what, need=auto.ha.NEED_STEP):
        asked.append(what)
        return real(what, need)
    monkeypatch.setattr(auto.ha, 'confirm_step', confirm_step)
    r = auto.post('a', '/api/ha/pairing-code', {'url': URLS['a'], 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert asked == ['a pairing code']


def test_a_member_whose_leave_answer_got_lost_hears_it_is_out_and_leaves(auto, seed):
    """The leader took d out of the voter config and the member list, and its answer did
    not reach d. The leader keeps a tombstone, as for a removal: d's next try hears 410,
    and d lets go of the group and leaves."""
    _four(auto, seed)
    # the answers of a to d are lost, d's calls get there
    auto.cuts.add(('a', 'd'))

    r = auto.post('d', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    a = auto.file('a')
    assert IDS['d'] not in a['members'] and IDS['d'] not in _voters(auto)
    assert a['tombstones'][IDS['d']]['by'] == IDS['a']
    assert auto.file('d')['role'] == 'standby' and auto.file('d')['members']
    auto.heal()

    r = auto.post('d', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 200, r.data
    assert auto.file('d')['role'] == 'standalone'
    # the group goes on without it
    auto.members = 'abc'
    auto.run(2 * T.R)
    assert auto.leader() == 'a'


def test_a_401_from_the_leader_is_no_word_that_the_member_left(auto, seed):
    """A leader that took the member out without a tombstone answers 401 under its own
    id. So does an instance that left the group since and is on its own: that answer
    says nothing about the group, and the member stays until the leader says 410."""
    _four(auto, seed)
    with auto.at('a') as ha:
        ha._remove_voter(IDS['d'])
        ha.forget_peer(IDS['d'])

    r = auto.post('d', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 409, r.data
    assert auto.file('d')['role'] == 'standby' and auto.file('d')['members']


def test_a_member_does_not_leave_on_the_word_of_a_former_leader(auto, seed):
    """Four data members, d cut off. The lead goes to c and a leaves the group through
    it: b, c and d are three votes now, and c would let none of them go. d reaches only
    a again, standalone by now, which answers its leave with 401 under its own id: d
    stays in the group, which still counts its vote."""
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    auto.watch('a')
    auto.isolate('d')
    r = auto.post('a', '/api/ha/make-leader', {'target': IDS['c'], 'confirm': 'LEADER',
                                               'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(T.W_take + 10, members='abc', until=lambda: auto.leader() == 'c')
    assert auto.leader() == 'c'
    auto.run(2 * T.R, members='abc')
    r = auto.post('a', '/api/ha/unpair', UNPAIR)
    assert r.status_code == 200 and auto.file('a')['role'] == 'standalone', r.data
    auto.members = 'bcd'
    auto.run(2 * T.R, members='bc')
    auto.heal()
    for n in 'bc':
        auto.cut('d', n)
    auto.advance(T.L + T.P)

    r = auto.post('d', '/api/ha/unpair', UNPAIR)

    assert r.status_code == 409, r.data
    assert auto.file('d')['role'] == 'standby'
    assert IDS['d'] in [rec['id'] for rec in auto.file('c')['lease']['cfg']['body']['voters']]
