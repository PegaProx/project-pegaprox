"""The state file of a leader goes back: a backup put back, a VM snapshot reverted (#625
stage 2).

A term lasts until the next election, so last night's copy of the leader holds an older
voter config of the very epoch it leads, or the manual state from before the group was
switched off and on again. Only the leader of a term makes configs of it: a member that
names one the leader does not hold says the leader's state went back, and it leaves -
whatever it would make from there has an id its members passed already, and a commit is
counted by digest, not by id. A copy restored to its manual state comes up as a manual
active; the first vote request of a member brings it the group's chain, and with it the
word that the group elects: it is a standby from that write on.

MK Oct 2026 (#625)
"""
import json

from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, _post, _promote, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture

ON = {'mode': 'auto', 'lease_s': 20, 'user_password': ADMIN_PW}
OFF = {'mode': 'manual', 'user_password': ADMIN_PW}
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5


def _restore(auto, n, before):
    """The state file of n as it was at `before`, and a new process on it."""
    with open(auto.g.files[n], 'w', encoding='utf-8') as fh:
        json.dump(before, fh)
    auto.ha._rts.pop(IDS[n], None)
    auto.ha.reset_for_tests()
    with auto.at(n) as ha:
        said = ha.check_peer_at_boot()
        ha.lease_start()
    return said


def _kinds(auto):
    out = {}
    for n in auto.members:
        with auto.at(n) as ha:
            if ha.is_active():
                out[n] = 'lease' if ha.lease_in_force() else 'hand'
    return out


def test_a_leader_whose_state_file_went_back_in_its_term_comes_up_as_a_standby(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    backup = auto.file('a')
    assert backup['role'] == 'leader' and backup['lease']['cfg']['id'] == [1, 3]
    # the voter config moves on inside the term: another lease length
    assert auto.put('a', '/api/ha/mode', dict(ON, lease_s=30)).get_json()['changed'] is True
    auto.run(4 * T.R, dt=1.0)
    assert {tuple(auto.file(n)['lease']['cfg']['id']) for n in 'abc'} == {(1, 4)}

    assert _restore(auto, 'a', backup) == 'no majority - standby'
    a = auto.file('a')
    assert a['role'] == 'standby' and a['lease']['cfg']['id'] == [1, 3]
    assert [e['details'] for e in _audit('ha.lease_lost')][-1] == (
        'came up as a standby: a member holds voter config [1, 4], newer than the [1, 3] held here')
    # nobody acted on the old config, and switching off there is a standby's business
    assert _kinds(auto) == {}
    r = auto.put('a', '/api/ha/mode', OFF)
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'

    # the two that hold the newer config elect, and a takes their chain
    auto.run(2 * BOUND, dt=1.0, until=lambda: _kinds(auto) != {})
    winner = auto.leader()
    assert winner in ('b', 'c') and _kinds(auto) == {winner: 'lease'}
    auto.run(3 * T.R, dt=1.0)
    assert auto.file('a')['lease']['cfg'] == auto.file(winner)['lease']['cfg']


def test_an_active_restored_to_its_manual_state_is_a_standby_once_a_vote_request_brings_the_chain(auto, seed):
    """The group was switched off and on again, and the leader's copy from the manual time
    is put back: a manual active, acting by hand. The members elect; the first real vote
    request carries the chain, and a is a standby in that write, and restarts as one."""
    auto.form(seed)
    auto.past_the_hold()
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.run(3 * T.R, dt=1.0)
    backup = auto.file('a')
    assert backup['role'] == 'active' and backup['lease']['mode'] == 'manual'
    auto.watch()
    assert auto.put('a', '/api/ha/mode', ON).status_code == 200
    auto.run(4 * T.R, dt=1.0, until=lambda: all(auto.mode(n) == 'auto' for n in 'abc'))
    auto.step('a')
    assert auto.leader() == 'a'
    auto.past_the_hold()

    assert _restore(auto, 'a', backup) == 'ok'
    assert _kinds(auto) == {'a': 'hand'}

    auto.run(3 * BOUND, dt=1.0, until=lambda: auto.leader() in ('b', 'c'))
    winner = auto.leader()
    assert winner in ('b', 'c') and _kinds(auto) == {winner: 'lease'}
    a = auto.file('a')
    assert a['role'] == 'standby' and a['lease']['mode'] == 'auto'
    assert [why for n, why in auto.g.restarts if n == 'a'][-1].startswith(
        'automatic failover: member ')
    assert [e for e in _audit('ha.stepped_down') if 'active by hand, is a standby now' in e['details']]
    # it follows the leader from its next renewal on, and is not stuck: no route needed
    auto.run(3 * T.R, dt=1.0)
    assert auto.file('a')['source'] == IDS[winner]
    assert auto.file('a')['lease']['cfg'] == auto.file(winner)['lease']['cfg']
    with auto.at('a') as ha:
        assert ha.is_standby() and ha.no_lease() is None
