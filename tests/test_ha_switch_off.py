"""The switch back to manual mode is the group's mode only once a majority holds it (#625
stage 2, design 4.13).

The leader writes the manual voter config and sends it with its next round; until a
majority of the voters holds it, the leader's lease is in force and the group fails over
automatically. So everything says automatic until then: the mode route, the status a
member answers, mode() on the leader. A leader that loses its lease before that drops
the config as it leaves - kept, it would be an instance promoted by hand next to the
leader its members elect. A member that took the config from such a leader does not know
whether a majority took it too; it is promoted by hand only once it knows, and never
while a member answers as the holder of a lease. What a failed write costs here: the
role write at the end of the switch is tried again, a config that was not written is
answered 500, and a voter that cannot write its state says so.

MK Oct 2026 (#625)
"""
import errno
import os
import stat

from pegaprox.core import ha_vote as hv
from test_ha_api import ADMIN_PW, _audit
from test_ha_members import IDS, _post, _promote, _sync, group  # noqa: F401
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture

OFF = {'mode': 'manual', 'user_password': ADMIN_PW}
PROMOTE = {'confirm': 'PROMOTE', 'user_password': ADMIN_PW}
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5


def _kinds(auto):
    """{name: 'lease' or 'hand'} of every instance that may act right now."""
    out = {}
    for n in auto.members:
        with auto.at(n) as ha:
            if ha.is_active():
                out[n] = 'lease' if ha.lease_in_force() else 'hand'
    return out


class _DirSync:
    """os.fsync of a directory fails with EIO on the instances in `only`, `times` times
    (None: always), while `armed`."""

    def __init__(self, monkeypatch, auto, only, times=None):
        self.real, self.failed = os.fsync, []
        self.auto, self.only, self.times, self.armed = auto, only, times, True
        monkeypatch.setattr(os, 'fsync', self)

    def __call__(self, fd):
        if self.armed and stat.S_ISDIR(os.fstat(fd).st_mode) and self.auto.g.name() in self.only:
            if self.times is None or len(self.failed) < self.times:
                self.failed.append(self.auto.g.name())
                raise OSError(errno.EIO, os.strerror(errno.EIO))
        return self.real(fd)


# --- until a majority holds it, the group is automatic ---------------------------------------

def test_the_mode_route_says_automatic_until_a_majority_holds_the_switch_back(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    auto.isolate('a')

    r = auto.put('a', '/api/ha/mode', OFF)
    assert r.status_code == 200 and r.get_json() == {'success': True, 'mode': 'auto', 'result': 'off'}
    with auto.at('a') as ha:
        assert ha.mode() == 'auto' and ha.lease_in_force() and ha.peer_lease_status()['mode'] == 'auto'
    # asked again while it waits: it is on its way, nothing more
    r = auto.put('a', '/api/ha/mode', OFF)
    assert r.status_code == 409 and 'majority' in r.get_json()['error']
    r = auto.put('a', '/api/ha/mode', {'mode': 'auto', 'lease_s': 30, 'user_password': ADMIN_PW})
    assert r.status_code == 409 and auto.node('a').view.lease_s == 20


def test_a_leader_that_loses_its_lease_before_the_switch_back_went_through_drops_it(auto, seed):
    """The leader is cut off when the admin switches automatic failover off on it. Its
    lease runs out, and it comes back as a standby of an automatic group: not promoted by
    hand, whether a member answers it or not, while the two it left elect a leader."""
    auto.form(seed)
    auto.past_the_hold()
    auto.isolate('a')
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.run(T.L + 3, dt=1.0)
    assert ('a', 'automatic failover: lease ran out') in auto.g.restarts

    a = auto.file('a')
    assert a['role'] == 'standby' and a['lease']['mode'] == 'auto' and a['lease']['cfg']['id'] == [1, 3]
    assert [e['details'] for e in _audit('ha.auto_off_dropped')] == [
        'automatic failover was not switched off: no majority of the members took the change before '
        'this instance lost the lead, and the group goes on failing over automatically']
    assert _audit('ha.auto_off') == []
    for body in (PROMOTE, dict(PROMOTE, force=True)):
        with auto.at('a'):
            r = _post(auto.admin, '/api/ha/promote', body)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data

    # the two it left elect, and only their leader acts, for as long as the cut lasts
    auto.run(2 * BOUND, dt=1.0, until=lambda: _kinds(auto) != {})
    winner = auto.leader()
    assert winner in ('b', 'c') and _kinds(auto) == {winner: 'lease'}
    auto.run(120, dt=1.0)
    assert _kinds(auto) == {winner: 'lease'}
    # after the heal a takes the new leader's chain
    auto.heal()
    auto.run(3 * T.R, dt=1.0)
    assert auto.file('a')['lease']['cfg'] == auto.file(winner)['lease']['cfg']


def test_a_member_that_holds_a_switch_back_nobody_committed_is_not_promoted(auto, seed):
    """The leader's switch back reached b, and b's answer did not come back; c heard
    nothing of it. The leader loses its lease and drops the config, b keeps it. a and c
    say automatic with an older config: b cannot tell them from members that missed a
    switch back, and is not promoted by hand next to the leader those two may elect."""
    auto.form(seed)
    auto.past_the_hold()
    auto.isolate('c')
    auto.cut('b', 'a', both=False)
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.step('a')
    assert auto.mode('b') == 'manual' and 'settled' not in auto.file('b')['lease']
    auto.run(T.L + 3, dt=1.0)
    assert auto.file('a')['lease']['mode'] == auto.file('c')['lease']['mode'] == 'auto'
    auto.heal()

    # with force: the sync first fails, b follows a standby now
    with auto.at('b'):
        r = _post(auto.admin, '/api/ha/promote', dict(PROMOTE, force=True))
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert 'says this group fails over automatically' in r.get_json()['error']
    assert auto.file('b')['role'] == 'standby'


def test_a_member_that_holds_the_lease_always_counts_against_a_promotion(auto, seed, monkeypatch):
    """Whatever config id it names: a member that missed a switch back holds no lease."""
    auto.form(seed)
    auto.past_the_hold()
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    assert _sync(auto.g, auto.admin, 'b') in ('applied', 'unchanged')
    b = auto.file('b')['lease']
    assert b['settled'] == hv.cfg_digest(b['cfg'])
    older = {'mark': auto.ha.LEASE_MARK, 'mode': 'auto', 'cfg_id': (1, 3), 'holds': False}

    def asked(holds):
        def ask(rec, signer, timeout):
            return ('active' if holds and rec['instance_id'] == IDS['c'] else 'standby', 1, 2, False,
                    (None, None), dict(older, holds=holds and rec['instance_id'] == IDS['c']))
        return ask
    with auto.at('b') as ha:
        monkeypatch.setattr(ha, '_ask', asked(False))
        assert ha._members_say_auto() is None
        monkeypatch.setattr(ha, '_ask', asked(True))
        assert ha._members_say_auto()['instance_id'] == IDS['c']


def test_a_leader_that_is_switching_off_says_automatic_and_nobody_is_promoted_next_to_it(auto, seed):
    """Four votes, c down, d misses the round: the switch back reached b only, two of four.
    The lease is in force on a, a says so in its status, and b is not promoted."""
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    auto.crash('c')
    auto.members = 'abd'
    auto.run(2 * T.R, dt=1.0)
    auto.cut('a', 'd')
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.step('a')
    assert auto.file('a')['role'] == 'leader' and auto.mode('b') == 'manual'
    with auto.at('a') as ha:
        said = ha.peer_lease_status()
        assert said['mode'] == 'auto' and said['lease']['holds'] is True

    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_MODE', r.data
    assert _kinds(auto) == {'a': 'lease'}


def test_the_promotion_says_when_the_old_active_refused_to_step_down(auto, seed, monkeypatch):
    """The audit line names what the old active answered: an automatic leader leaves by
    its lease, not on the word of a member promoted next to it. (Here the members are
    not asked first, as when none of them answers.)"""
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()
    auto.crash('c')
    auto.members = 'abd'
    auto.cut('a', 'd')
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    auto.step('a')
    monkeypatch.setattr(auto.ha, '_members_say_auto', lambda timeout=5: None)
    # b holds a switch back nobody confirmed, which S7 refuses a plain promotion for
    # (tests/test_ha_way_out.py); this is about what the audit line says
    monkeypatch.setattr(auto.ha, 'way_out_check', lambda: '')
    r = _promote(auto.g, auto.admin, 'b')
    assert r.status_code == 200, r.data
    assert auto.file('a')['role'] == 'leader'
    assert _audit('ha.promoted')[-1]['details'].startswith(
        'promoted to active with epoch 2, old active refused to step down')


# --- what a failed write costs ---------------------------------------------------------------

def test_a_switch_back_whose_role_write_fails_is_written_with_the_next_answer(auto, seed, monkeypatch):
    """One EIO on the write that makes the leader a manual active: the commit stands (a
    majority holds the config), and the next round's answers write the role."""
    auto.form(seed)
    auto.past_the_hold()
    assert auto.put('a', '/api/ha/mode', OFF).status_code == 200
    sync = _DirSync(monkeypatch, auto, 'a', times=1)
    auto.run(3 * T.R, dt=1.0)
    assert sync.failed == ['a']
    a = auto.file('a')
    assert a['role'] == 'active' and a['lease']['mode'] == 'manual'
    assert len(_audit('ha.auto_off')) == 1
    auto.run(2 * T.L, dt=1.0)
    assert auto.active() == ['a'] and ('a', 'automatic failover: lease ran out') not in auto.g.restarts


def test_a_switch_back_that_was_not_written_is_answered_500_and_changes_nothing(auto, seed, monkeypatch):
    auto.form(seed)
    auto.past_the_hold()
    sync = _DirSync(monkeypatch, auto, 'a')
    r = auto.put('a', '/api/ha/mode', OFF)
    assert r.status_code == 500 and 'could not be written' in r.get_json()['error'], r.data
    assert sync.failed and auto.node('a').view.mode == 'auto' and auto.node('a').view.id == (1, 3)
    assert not [e for e in _audit('ha.mode_changed') if 'switched off' in e['details']]
    assert auto.file('a')['lease']['mode'] == 'auto'


def test_a_change_whose_write_failed_is_tried_again(auto, seed, monkeypatch):
    auto.form(seed)
    auto.past_the_hold()
    sync = _DirSync(monkeypatch, auto, 'a')
    r = auto.put('a', '/api/ha/mode', {'mode': 'auto', 'lease_s': 45, 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['changed'] is True
    auto.run(2 * T.R, dt=1.0)
    assert sync.failed and auto.node('a').view.lease_s == 20 and len(auto.node('a')._changes) == 1
    sync.armed = False
    auto.run(2 * T.R, dt=1.0)
    assert auto.node('a').view.lease_s == 45 and auto.node('a')._changes == []


def test_a_voter_that_cannot_write_its_state_says_so_on_itself_and_to_its_members(auto, seed, monkeypatch):
    """EIO on every directory sync of b: it never votes, and its own findings and those of
    every member that asks it name why, until a write succeeds again."""
    auto.form(seed)
    auto.past_the_hold()
    sync = _DirSync(monkeypatch, auto, 'b')
    auto.crash('a')
    auto.members = 'bc'
    auto.run(2 * BOUND, dt=1.0)
    assert sync.failed and auto.active() == []
    auto.watch('b', 'c')
    with auto.at('b') as ha:
        mine = [f for f in ha.auto_findings() if f['code'] == 'STATE_NOT_WRITTEN']
        assert len(mine) == 1 and mine[0]['member'] is None and 'Input/output error' in mine[0]['text']
        assert ha.peer_lease_status()['write_failed'] is True
    with auto.at('c') as ha:
        assert [f['member'] for f in ha.auto_findings() if f['code'] == 'STATE_NOT_WRITTEN'] == [IDS['b']]
    # the disk is back: the next write clears it, and the group elects
    sync.armed = False
    auto.run(2 * BOUND, dt=1.0, until=lambda: auto.active() != [])
    assert len(auto.active()) == 1
    with auto.at('b') as ha:
        assert 'write_failed' not in ha.peer_lease_status()
        assert not [f for f in ha.auto_findings() if f['code'] == 'STATE_NOT_WRITTEN']
