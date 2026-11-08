"""Automatic failover in a group (#625 stage 2): the lease of ha_vote.py, run by
pegaprox/core/ha.py through the real routes.

Three to five instances in one process (tests/_ha_lease_harness.py): each has its own
state file, lease clock and node, and every vote and renewal is a signed peer call
through the Flask app. The clocks are turned by hand, so a lease of twenty seconds
costs no time here.

MK Oct 2026 (#625)
"""
import pytest

from test_ha_api import _audit
from test_ha_members import IDS, group  # noqa: F401 - the fixture
from _ha_lease_harness import T, auto  # noqa: F401 - the fixture

# I6 of the design: after the leader is lost, one acting leader within this long
BOUND = T.P + T.L / 4 + T.T_vote + T.W_take + 5


# --- the switch leaves a leader with a lease ----------------------------------------------

def test_a_switched_group_has_one_leader_with_a_lease(auto, seed):
    auto.form(seed)

    assert auto.holders() == ['a'] and auto.active() == ['a']
    a = auto.file('a')
    # on disk the leader says so, and an older release reads that as no role it knows
    assert a['role'] == 'leader' and a['lease']['mode'] == 'auto'
    assert a['lease']['led']['epoch'] == a['epoch'] == 1 and a['lease']['voted_for'] == IDS['a']
    with auto.at('a') as ha:
        assert ha.role() == 'active' and not ha.is_standby() and ha.acting_process()
    for n in 'bc':
        st = auto.file(n)
        assert st['role'] == 'standby' and st['lease']['mode'] == 'auto'
        assert st['lease']['voted_for'] == IDS['a'] and st['source'] == IDS['a']
        with auto.at(n) as ha:
            assert ha.is_standby() and not ha.is_active() and not ha.holds_lease()
            assert not ha.acting_process()
        # the same voter config everywhere, signed by the instance that switched
        assert st['lease']['cfg'] == a['lease']['cfg'] and st['lease']['cfg']['by'] == IDS['a']


def test_a_state_file_without_the_lease_block_reads_as_before(auto, seed):
    """A group that never switched has no lease block, no 'leader' and no node: the
    predicates are the role, as they were."""
    auto.pair(seed)
    for n in 'abc':
        st = auto.file(n)
        assert 'lease' not in st and 'witness' not in st and 'leader' not in st
        with auto.at(n) as ha:
            assert ha.mode() == 'manual' and not ha.lease_in_force()
            assert ha.is_active() == ha.holds_lease() == ha.acting_process() == (n == 'a')
            assert ha.lease_step() is None and ha._rts.get(IDS[n]) is None or not auto.rt(n).node


def test_the_role_on_disk_is_leader_and_an_unreadable_lease_block_keeps_it_passive(auto, seed):
    auto.form(seed)
    st = auto.file('a')
    assert st['role'] == 'leader' and 'leader' not in st
    with auto.at('a') as ha:
        assert ha._load()['role'] == 'active' and ha._load()['leader'] is True

    # the votes and the voter config cannot be read: it must neither vote nor lead
    st['lease']['cfg'] = {'id': 'x'}
    auto.g.write('a', st)
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        assert ha.role() == 'standby' and not ha.is_active() and not ha.holds_lease()
        assert 'lease state' in ha._load()['broken']
        with pytest.raises(ha.HaError):
            ha._update(interval=45)

    # a release before automatic failover reads 'leader' as a role it does not know
    st = auto.file('b')
    st.pop('lease')
    st['role'] = 'leader'
    auto.g.write('b', st)
    with auto.at('b') as ha:
        assert ha.role() == 'standby' and not ha.is_active()


# --- renewals ---------------------------------------------------------------------------

def test_the_leader_renews_and_a_renewal_costs_a_voter_no_write(auto, seed):
    auto.form(seed)
    gens = {n: auto.file(n)['lease']['gen'] for n in 'abc'}
    before = auto.node('a').lease_until
    auto.g.calls.clear()

    auto.run(60, dt=1.0)

    assert auto.leader() == 'a' and auto.node('a').lease_until > before + 50
    renewals = [c for c in auto.g.calls if c[3] == '/api/ha/peer/renew']
    # every R = 4 s, to both members
    assert 26 <= len(renewals) <= 34 and {c[1] for c in renewals} == {'b', 'c'}
    assert not [c for c in auto.g.calls if c[3] == '/api/ha/peer/vote']
    # nothing was written for them: the promise is memory, the hold after a start covers it
    assert {n: auto.file(n)['lease']['gen'] for n in 'abc'} == gens
    for n in 'bc':
        node = auto.node(n)
        assert node.promise_to == IDS['a'] and node.promise_until > auto.clock[n]
        assert node.leader_seen == IDS['a']


def test_a_renewal_carries_the_leaders_cv_and_a_member_behind_it_pulls(auto, seed, db):
    auto.form(seed)
    with auto.at('a') as ha:
        ha.cv_tick(force=True)
        held = ha.cv_entry()
    auto.pulls.clear()

    auto.advance(T.R)
    auto.step('a')

    for n in 'bc':
        assert auto.state(n)['members'][IDS['a']]['cv_seen'] == held
    # c and b hold what the leader holds: nothing to pull
    assert auto.pulls == []

    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name) VALUES ('c1', 100, 'prod')")
    db.conn.commit()
    with auto.at('a') as ha:
        assert ha.cv_tick() == 'stepped'
        newer = ha.cv_entry()
    assert newer[1] == held[1] + 1
    auto.advance(T.R)
    auto.step('a')
    # the note about the change never went out here (no timer runs): the renewal made up for it
    assert sorted(auto.pulls) == ['b', 'c']
    assert auto.state('b')['members'][IDS['a']]['cv_seen'] == newer
    # and the leader's node counts by the cv it holds
    assert auto.node('a').cv == tuple(newer[:2])


# --- the leader is lost -----------------------------------------------------------------

def test_a_lost_leader_is_replaced_within_the_bound(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    assert auto.leader() == 'a'

    auto.crash('a')
    auto.members = 'bc'
    took = auto.run(BOUND + 10, until=lambda: auto.leader() in ('b', 'c'))

    winner = auto.leader()
    other = 'c' if winner == 'b' else 'b'
    assert winner in ('b', 'c') and took <= BOUND, took
    # never before the takeover wait after its vote round: the old lease is surely over
    assert took >= T.W_take
    st = auto.file(winner)
    assert st['role'] == 'leader' and st['epoch'] == 2 and st['lease']['led']['epoch'] == 2
    assert st['lease']['voted_for'] == IDS[winner] and st['source'] is None
    # it restarted to come up as the leader, and the boot check found its majority
    assert (winner, 'automatic failover: won the election') in auto.g.restarts
    assert (winner, 'lease held') in auto.boots and auto.killed == []
    # the other one voted for it, wrote that down, and pulls from it now
    theirs = auto.file(other)
    assert theirs['role'] == 'standby' and theirs['epoch'] == 2
    assert theirs['lease']['voted_for'] == IDS[winner] and theirs['source'] == IDS[winner]
    said = [r['details'] for r in _audit('ha.elected')]
    assert len(said) == 1 and 'epoch 2' in said[0]


def test_a_new_leader_holds_the_lease_first_and_acts_only_after_the_takeover_wait(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(BOUND, until=lambda: auto.holders() != [])

    winner = auto.holders()[0]
    with auto.at(winner) as ha:
        # the process that came up to lead, with a valid lease, and still not acting
        assert ha.holds_lease() and ha.acting_process() and not ha.is_active()
        wait = ha.no_lease()
        assert wait['retry_after'] >= 1 and 'taking over' in wait['error']
        left = auto.node(winner).acting_from - auto.clock[winner]
    assert 0 < left <= T.W_take

    auto.run(left - 1, dt=0.5)
    assert auto.active() == []
    auto.run(2, dt=0.5)
    assert auto.active() == [winner]
    with auto.at(winner) as ha:
        assert ha.no_lease() is None


def test_the_old_leader_comes_back_as_a_standby_of_the_new_one(auto, seed):
    auto.form(seed)
    auto.past_the_hold()
    auto.crash('a')
    auto.members = 'bc'
    auto.run(BOUND + 10, until=lambda: auto.leader() in ('b', 'c'))
    winner = auto.leader()

    # its state file still says leader, at the epoch it won
    assert auto.file('a')['role'] == 'leader' and auto.file('a')['epoch'] == 1
    said = auto.back('a')
    auto.members = 'abc'

    # the boot round met the higher epoch: a standby without a restart, nothing acted
    assert said == 'no majority - standby'
    assert auto.file('a')['role'] == 'standby' and not [r for r in auto.g.restarts if r[0] == 'a']
    with auto.at('a') as ha:
        assert ha.is_standby() and not ha.is_active() and not ha.acting_process()
    auto.run(2 * T.R, dt=1.0)
    st = auto.file('a')
    assert st['epoch'] == 2 and st['source'] == IDS[winner] and st['lease']['voted_for'] == IDS[winner]
    assert auto.active() == [winner]


# --- partitions -------------------------------------------------------------------------

def test_a_leader_cut_off_from_the_majority_stops_and_the_majority_elects(auto, seed):
    auto.form(seed)
    auto.past_the_hold()

    auto.isolate('a')
    # its lease runs out by itself: nobody tells it
    passed = auto.run(T.per_round + T.R + 1, dt=0.5, until=lambda: 'a' not in auto.active())
    assert passed <= T.per_round + T.R + 1 and auto.active() == []
    st = auto.file('a')
    assert st['role'] == 'standby' and st['lease']['led']['epoch'] == 1
    assert ('a', 'automatic failover: lease ran out') in auto.g.restarts
    # what it started while it led is killed at once, not a restart later
    assert auto.killed == ['a']
    lost = [r['details'] for r in _audit('ha.lease_lost')]
    # and it says whom it could not reach at the end
    assert lost and 'lost the lease' in lost[0] and 'still heard: nobody' in lost[0]
    assert 'not heard any more: https://standby.example:5000, https://standby-c.example:5000' in lost[0]

    took = auto.run(BOUND, until=lambda: auto.leader() in ('b', 'c'))
    winner = auto.leader()
    assert winner in ('b', 'c') and took <= BOUND
    # the minority side never acted next to it
    with auto.at('a') as ha:
        assert not ha.is_active() and not ha.holds_lease()

    auto.heal()
    auto.run(2 * T.R, dt=1.0)
    assert auto.active() == [winner]
    assert auto.file('a')['source'] == IDS[winner] and auto.file('a')['epoch'] == 2


def test_a_member_in_the_minority_never_raises_the_epoch(auto, seed):
    auto.form(seed)
    auto.past_the_hold()

    auto.isolate('c')
    auto.g.calls.clear()
    auto.run(3 * BOUND, dt=1.0)

    # it asked (pre-votes) and nobody answered: no vote of its own, no new epoch
    asked = [c for c in auto.g.calls if c[0] == 'c' and c[3] == '/api/ha/peer/vote']
    assert asked and auto.file('c')['epoch'] == 1 and auto.file('c')['lease']['voted_for'] == IDS['a']
    assert auto.leader() == 'a' and auto.file('a')['epoch'] == 1
    with auto.at('c') as ha:
        assert not ha.is_active() and not ha.holds_lease()

    auto.heal()
    auto.run(3 * T.R, dt=1.0)
    # nothing was disturbed: the same leader, the same epoch, no restart anywhere
    assert auto.leader() == 'a' and {auto.file(n)['epoch'] for n in 'abc'} == {1}
    assert auto.g.restarts == [r for r in auto.g.restarts if 'automatic failover' not in str(r[1])]


def test_a_two_two_split_leaves_no_leader_on_either_side(auto, seed):
    auto.form(seed, 'bcd', accept=['EVEN_VOTERS'])
    auto.past_the_hold()

    for x in 'ab':
        for y in 'cd':
            auto.cut(x, y)
    auto.run(3 * BOUND, dt=1.0)

    # four votes need three: neither half has them
    assert auto.active() == [] and auto.holders() == []
    for n in 'abcd':
        with auto.at(n) as ha:
            assert not ha.is_active()

    auto.heal()
    took = auto.run(BOUND + T.lost_lease_backoff, dt=1.0, until=lambda: auto.leader() is not None)
    assert auto.leader() is not None and took <= BOUND + T.lost_lease_backoff


def test_a_frozen_leader_steps_down_on_the_higher_epoch_when_it_thaws(auto, seed):
    """A paused VM: its clock stood still, so its lease looks valid to it. The first
    renewal it sends meets the epoch the others moved to, and it leaves."""
    auto.form(seed)
    auto.past_the_hold()

    auto.pause('a', freeze=True)
    auto.members = 'bc'
    auto.run(BOUND + 10, until=lambda: auto.leader() in ('b', 'c'))
    winner = auto.leader()
    assert winner in ('b', 'c')

    auto.resume('a')
    auto.members = 'abc'
    with auto.at('a') as ha:
        # by its own clock nothing happened: the gate would still open ...
        assert ha.holds_lease() and ha.is_active()
    # ... until its next renewal is due, R at the latest
    auto.run(T.R, dt=0.5, members='a', until=lambda: auto.file('a')['role'] == 'standby')

    # the answer to it closes the gate: standby, restart, nothing more from it
    st = auto.file('a')
    assert st['role'] == 'standby' and st['lease']['led']['epoch'] == 1
    assert [r for r in auto.g.restarts if r[0] == 'a'] == [('a', 'automatic failover: epoch 2 seen')]
    auto.run(2 * T.R, dt=1.0)
    assert auto.active() == [winner] and auto.file('a')['source'] == IDS[winner]


def test_a_leader_that_sees_a_higher_epoch_in_a_status_answer_leaves(auto, seed):
    auto.form(seed)
    st = auto.file('b')
    st['epoch'] = 4
    auto.g.write('b', st)
    with auto.at('b') as ha:
        ha._rts.pop(IDS['b'], None)

    with auto.at('a') as ha:
        assert ha.watch_once() == 'stepped down'

    assert auto.file('a')['role'] == 'standby'
    assert ('a', 'automatic failover: member bbbbbbbb is at epoch 4') in auto.g.restarts


# --- a voter that came back from an older state ---------------------------------------------

def test_a_voter_that_went_back_is_quarantined_and_an_admin_takes_it_back(auto, seed):
    from test_ha_api import ADMIN_PW
    auto.form(seed)
    auto.run(2 * T.R, dt=1.0)
    old = auto.file('b')

    # two changes of the voter config: every member writes them down (gen goes up)
    for lease_s in (30, 25):
        r = auto.put('a', '/api/ha/mode', {'mode': 'auto', 'lease_s': lease_s,
                                           'user_password': ADMIN_PW})
        assert r.status_code == 200 and r.get_json()['changed'] is True, r.data
        auto.run(4 * T.R, dt=1.0)
    assert auto.file('b')['lease']['gen'] > old['lease']['gen']
    assert auto.file('b')['lease']['cfg']['body']['lease_s'] == 25

    # b comes back from the earlier state
    auto.g.write('b', old)
    with auto.at('b') as ha:
        ha._rts.pop(IDS['b'], None)
    auto.run(6 * T.R, dt=1.0)

    body = auto.file('a')['lease']['cfg']['body']
    assert body['quarantined'] == [IDS['b']]
    assert _audit('ha.member_quarantined')
    node = auto.node('a')
    # it still counts in the majority to reach, its acks do not count
    assert node.view.n == 3 and IDS['b'] not in node.view.counting
    with auto.at('a') as ha:
        findings = {f['code']: f for f in ha.auto_findings()}
    assert findings['QUARANTINED']['member'] == IDS['b']

    r = auto.post('a', f"/api/ha/members/{IDS['c']}/readmit", {'user_password': ADMIN_PW})
    assert r.status_code == 409 and 'not quarantined' in r.get_json()['error']
    r = auto.post('a', f"/api/ha/members/{IDS['b']}/readmit", {'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    auto.run(6 * T.R, dt=1.0)

    assert auto.file('a')['lease']['cfg']['body']['quarantined'] == []
    assert IDS['b'] in auto.node('a').view.counting
    # and it stays in: what the leader held against it went with the change
    auto.run(10 * T.R, dt=1.0)
    assert auto.file('a')['lease']['cfg']['body']['quarantined'] == []
    assert _audit('ha.member_readmitted') and auto.leader() == 'a'


# --- boot (4.9) -------------------------------------------------------------------------

def test_a_leader_boots_with_its_majority_and_acts_at_once_when_the_wait_is_over(auto, seed):
    auto.form(seed)
    auto.run(T.R, dt=1.0)

    said = auto.restart('a')

    assert said == 'lease held'
    with auto.at('a') as ha:
        assert ha.acting_process() and ha.holds_lease() and ha.is_active()
    rt = auto.rt('a')
    assert rt.acting and not rt.boot_check


def test_a_leader_boots_without_a_majority_as_a_standby_and_nothing_restarts(auto, seed):
    auto.form(seed)
    auto.crash('b')
    auto.crash('c')
    before = auto.clock['a']

    said = auto.restart('a')

    assert said == 'no majority - standby'
    # it asked for fifteen seconds, a round a second
    assert T.boot_wait <= auto.clock['a'] - before <= T.boot_wait + 3
    st = auto.file('a')
    assert st['role'] == 'standby' and st['lease']['led']['epoch'] == 1
    assert not [r for r in auto.g.restarts if r[0] == 'a']
    with auto.at('a') as ha:
        assert ha.is_standby() and not ha.acting_process() and not ha.is_active()
    assert any('came up as a standby' in r['details'] for r in _audit('ha.lease_lost'))


def test_a_standby_boots_into_the_hold_after_a_start(auto, seed):
    auto.form(seed)
    auto.past_the_hold()

    assert auto.restart('b') == 'automatic group, standby'

    node = auto.node('b')
    assert node is not None and node.hold_until == pytest.approx(auto.clock['b'] + T.hold_after_start)
    # it grants nobody but the holder it wrote down, however the request looks
    with auto.at('b') as ha:
        ans = ha.lease_request(IDS['c'], 'vote', {
            'epoch': 2, 'candidate': IDS['c'], 'pre': False, 'why': 'timer',
            'cv': list(auto.node('c').cv), 'cfg_id': list(node.view.id), 'lease_s': 20})
    assert ans['granted'] is False and ans['reason'] == 'HOLD_AFTER_START'
    assert auto.file('b')['epoch'] == 1 and auto.file('b')['lease']['voted_for'] == IDS['a']
    # and takes the renewals of that holder at once
    auto.advance(T.R)
    auto.step('a')
    assert node.promise_to == IDS['a'] and auto.leader() == 'a'


def test_a_whole_group_starting_cold_keeps_its_leader(auto, seed):
    auto.form(seed)
    for n in 'abc':
        with auto.at(n) as ha:
            ha._rts.pop(IDS[n], None)

    # the standbys first, then the leader: its boot round finds them
    assert auto.restart('b') == auto.restart('c') == 'automatic group, standby'
    assert auto.restart('a') == 'lease held'

    assert auto.leader() == 'a' and {auto.file(n)['epoch'] for n in 'abc'} == {1}


def test_a_boot_that_outlasts_the_lease_gets_a_round_of_its_own_and_no_restart(auto, seed):
    """B2: fifteen to thirty seconds of start-up are longer than the lease of the boot
    round. The lease loop starts with a round of its own; the process stays the acting
    one meanwhile, so what was started for the leader does not end."""
    auto.form(seed)
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        assert ha.check_peer_at_boot() == 'lease held'
        # create_app, the managers ...: nothing ticks, the lease of the boot round runs out
        auto.advance(T.per_round + 5)
        assert ha.acting_process() and not ha.holds_lease() and not ha.is_active()
        assert ha.lease_start() is True
        assert ha.acting_process() and not ha.is_active()
    auto.deliver('a')

    with auto.at('a') as ha:
        assert ha.acting_process() and ha.holds_lease() and ha.is_active()
    assert not [r for r in auto.g.restarts if r[0] == 'a']
    assert auto.rt('a').armed is True


def test_a_leader_that_loses_the_lease_while_starting_restarts_as_a_standby(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        assert ha.check_peer_at_boot() == 'lease held'
        auto.advance(T.per_round + 5)
        auto.crash('b')
        auto.crash('c')
        assert ha.lease_start() is True
    auto.auto_restart = False
    auto.members = 'a'
    auto.run(T.boot_wait + 3, dt=1.0)

    assert auto.file('a')['role'] == 'standby'
    assert ('a', 'automatic failover: lost the lease while starting') in auto.g.restarts
    with auto.at('a') as ha:
        assert not ha.acting_process() and not ha.is_active()


def test_a_manual_group_boots_by_the_old_check(auto, seed):
    from test_ha_api import ADMIN_PW
    auto.pair(seed)
    auto.g.calls.clear()
    with auto.at('a') as ha:
        assert ha.check_peer_at_boot() == 'ok'
    # the members were asked for role and epoch, nobody for a vote or a renewal
    assert {c[3] for c in auto.g.calls} == {'/api/ha/peer/status'}

    # and so does a group that was automatic once: its lease state is there, not in force
    auto.switch_on()
    assert auto.put('a', '/api/ha/mode', {'mode': 'manual', 'user_password': ADMIN_PW}).status_code == 200
    auto.run(2 * T.R, dt=1.0)
    assert auto.mode('a') == 'manual' and 'lease' in auto.file('a')
    auto.g.calls.clear()
    with auto.at('a') as ha:
        ha._rts.pop(IDS['a'], None)
        assert ha.check_peer_at_boot() == 'ok'
        assert ha.is_active() and ha.acting_process()
    assert {c[3] for c in auto.g.calls} == {'/api/ha/peer/status'}


# --- pairing into an automatic group ------------------------------------------------------

def test_a_member_that_joins_an_automatic_group_is_in_the_voter_config_without_a_vote(auto, seed):
    from test_ha_members import _pair, _sync
    auto.form(seed)

    r = _pair(auto.g, auto.admin, 'd')
    assert r.status_code == 200, r.data
    assert _sync(auto.g, auto.admin, 'd') == 'applied'
    auto.members = 'abcd'
    auto.run(4 * T.R, dt=1.0)

    body = auto.file('a')['lease']['cfg']['body']
    rec = next(v for v in body['voters'] if v['id'] == IDS['d'])
    with auto.at('d') as ha:
        assert rec['voter'] is False and rec['public_key'] == ha.own_public_key()
    # three votes still, and d holds the config: it took it from the leader it follows
    assert auto.node('a').view.n == 3 and auto.file('d')['lease']['cfg'] == auto.file('a')['lease']['cfg']
    assert auto.file('d')['lease']['mode'] == 'auto' and auto.node('d').promise_to == IDS['a']
    assert auto.leader() == 'a'


# --- the lease state next to everything else in the state file ---------------------------------

def test_the_lease_state_survives_every_other_write_of_the_state_file(auto, seed):
    from test_ha_members import _sync
    auto.form(seed)
    lease = {n: auto.file(n)['lease'] for n in 'ab'}

    with auto.at('a') as ha:
        ha._update(interval=45)
        ha._note_members({IDS['b']: {'last_error': 'x'}})
        ha.set_member_serve(IDS['b'], True)
    st = auto.file('a')
    # still the leader on disk, and what it voted and holds is where it was
    assert st['role'] == 'leader' and st['lease'] == lease['a'] and st['interval'] == 45
    with auto.at('a') as ha:
        ha.reset_for_tests()
        assert ha._load()['leader'] is True and ha._load()['lease'] == lease['a']

    # a sync on a member: the member list, the config version, the sync status
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    st = auto.file('b')
    assert st['lease'] == lease['b'] and st['serve_assigned'] is True and st['role'] == 'standby'


def test_a_sync_does_not_move_the_term_of_an_automatic_member(auto, seed):
    """In a manual group a standby takes the epoch of the active it pulls from. In an
    automatic one the epoch is the term: it moves with a vote or a renewal, which write
    down who it went to, and never without."""
    auto.pair(seed)
    snap = {'instance_id': IDS['a'], 'epoch': 5}
    with auto.at('c') as ha:
        ha._adopt_group(snap)
        assert ha.epoch() == 5
    auto.g.write('c', dict(auto.file('c'), epoch=1))

    auto.switch_on()
    with auto.at('b') as ha:
        before = ha._load()['lease']
        ha._adopt_group(snap)
        assert ha.epoch() == 1 and ha._load()['lease'] is before
        assert not auto.rt('b').stale


def test_an_instance_that_was_removed_has_no_vote_left(auto, seed):
    auto.form(seed)
    with auto.at('c') as ha:
        assert ha._mark_removed(IDS['a'], 1) == 'standby'
        st = ha._load()
        assert 'lease' not in st and st['removed'] and ha.mode() == 'manual'
        assert ha._lease_node() is None and auto.rt('c').node is None
        ans = ha.lease_request(IDS['b'], 'vote', {'epoch': 2, 'candidate': IDS['b']})
        assert ans['granted'] is False and ans['reason'] == 'MODE_MANUAL'
        assert not ha.is_active() and ha.is_standby()


def test_the_time_zone_is_set_on_a_leader_that_holds_its_lease(auto, seed):
    auto.form(seed)
    r = auto.put('a', '/api/ha/timezone', {'timezone': 'Europe/Vienna'})
    assert r.status_code == 200 and auto.file('a')['timezone'] == 'Europe/Vienna'

    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    r = auto.put('a', '/api/ha/timezone', {'timezone': 'Europe/Berlin'})
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    assert auto.file('a')['timezone'] == 'Europe/Vienna'
