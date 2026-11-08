"""Confirm rounds without spacing (#625 stage 2): rounds overlap, and still no write goes
out before a majority answered a round that started after it was decided.

One leader node (tests/test_ha_vote.py Box), its calls answered by hand in any order.
The rules pinned here: a caller that no round out can serve starts one at once, up to
CONFIRM_IN_FLIGHT out; past that, callers share the next one, which starts as one comes
back. A round serves exactly the callers decided before it started, whatever order the
answers come in and whatever the clock read. A round that fails fails only the callers
no other round out can serve. A clock step and a step down void what is out. Confirm
rounds never start faster than CONFIRM_RATE_MAX, and a voter that owes CONFIRM_PER_VOTER
answers is passed by them but not by the renewal every R.

MK Oct 2026 (#625)
"""
import pytest

from pegaprox.core import ha_vote as hv
from test_ha_vote import Box, T, _leader, _ok, genesis


def _ready():
    box = _leader()
    box.answer_all('renew', _ok)
    assert box.node.is_active()
    box.sent.clear()
    return box


def _tags(box):
    return sorted({s[3] for s in box.sent if s[1] == 'renew'})


def _answer(box, tag, fn=_ok, only=None):
    """Answer the calls of round `tag` (of `only` alone, when given)."""
    calls = [s for s in box.sent if s[1] == 'renew' and s[3] == tag and (only is None or s[0] == only)]
    box.sent = [s for s in box.sent if s not in calls]
    for to, _k, b, t in calls:
        box.node.on_answer(to, t, fn(to, b))
    return len(calls)


def _ask(box, seen, key, need=5):
    box.node.confirm(need, lambda ok: seen.setdefault(key, ok))


def test_a_writer_back_to_back_gets_a_round_of_its_own_at_once_each_time():
    """No spacing: the next write's round leaves the moment it is asked for, and comes
    back with the first voter's answer (a majority of three is the leader and one)."""
    box = _ready()
    seen = {}
    for i in range(20):
        # as fast as the bound lets rounds start
        box.now += 1.01 / hv.CONFIRM_RATE_MAX
        before = set(_tags(box))
        _ask(box, seen, i)
        new = set(_tags(box)) - before
        assert len(new) == 1, f'write {i}: {len(new)} rounds started'
        _answer(box, new.pop(), only='b')
        assert seen.get(i) is True
    assert len(seen) == 20


def test_rounds_overlap_up_to_the_cap_and_callers_queue_for_the_next():
    box = _ready()
    seen, rounds = {}, []
    for i in range(hv.CONFIRM_IN_FLIGHT):
        box.now += 0.002
        before = set(_tags(box))
        _ask(box, seen, i)
        new = set(_tags(box)) - before
        assert len(new) == 1
        rounds.append(new.pop())
    # as many out as may be: two more callers start nothing and wait together
    box.now += 0.002
    before = set(_tags(box))
    _ask(box, seen, 'e')
    _ask(box, seen, 'f')
    assert set(_tags(box)) == before and seen == {}
    assert box.node.next_wake() > box.now - 1e-9
    # the first round back serves the first caller only, and the next round leaves now
    _answer(box, rounds[0], only='b')
    assert seen == {0: True}
    after = set(_tags(box)) - before
    assert len(after) == 1, 'the queued callers got no round as one came back'
    shared = after.pop()
    _answer(box, shared, only='b')
    # it started after e and f, and after 1 to 3: it serves all of them
    assert seen == {0: True, 1: True, 2: True, 3: True, 'e': True, 'f': True}
    # the rounds still out come back late and change nothing
    for tag in rounds[1:]:
        _answer(box, tag)
    assert len(seen) == 6


def test_answers_out_of_order_serve_only_whom_their_round_started_after():
    box = _ready()
    seen = {}
    box.now += 0.001
    _ask(box, seen, 1)
    r1 = _tags(box)[-1]
    box.now += 0.001
    _ask(box, seen, 2)
    r2 = _tags(box)[-1]
    assert r2 > r1
    # the later round comes back first: it started after both callers
    _answer(box, r2, only='b')
    assert seen == {1: True, 2: True}
    _answer(box, r1)
    assert seen == {1: True, 2: True}

    box = _ready()
    seen = {}
    box.now += 0.001
    _ask(box, seen, 1)
    r1 = _tags(box)[-1]
    box.now += 0.001
    _ask(box, seen, 2)
    r2 = _tags(box)[-1]
    # the earlier round first: the second caller came after it started
    _answer(box, r1, only='c')
    assert seen == {1: True}
    _answer(box, r2, only='c')
    assert seen == {1: True, 2: True}


def test_a_round_never_serves_a_call_made_after_it_started_on_a_held_clock():
    """A paused VM whose clock was held reads the same time before and after: the round
    that left before the pause has the start time of a call made after it. It serves
    only what was asked before it left."""
    box = _ready()
    seen = {}
    box.now += 0.01
    _ask(box, seen, 'before')
    r1 = _tags(box)[-1]
    # no tick, no time: the clock stood still
    _ask(box, seen, 'after')
    r2 = _tags(box)[-1]
    assert r2 != r1, 'the call after the round left got no round of its own'
    _answer(box, r1, only='b')
    assert seen == {'before': True}
    _answer(box, r2, only='b')
    assert seen == {'before': True, 'after': True}


def test_a_failed_round_fails_only_the_callers_no_other_round_can_serve():
    box = _ready()
    seen = {}
    box.now += 0.001
    _ask(box, seen, 1)
    r1 = _tags(box)[-1]
    box.now += 0.001
    _ask(box, seen, 2)
    r2 = _tags(box)[-1]
    # every voter answers r1 and none of them acks: no majority, the round is done
    _answer(box, r1, fn=lambda to, b: None)
    assert seen == {}, 'r2 can still serve caller 1'
    _answer(box, r2, only='b')
    assert seen == {1: True, 2: True}
    # with nothing else out a failed round fails its caller
    box.now += 0.001
    _ask(box, seen, 3)
    _answer(box, _tags(box)[-1], fn=lambda to, b: None)
    assert seen[3] is False


def test_a_clock_step_while_rounds_are_out_lets_none_of_them_serve():
    box = _ready()
    seen = {}
    box.now += 0.001
    _ask(box, seen, 1)
    r1 = _tags(box)[-1]
    # the wall clock steps against the lease clock; no tick sees it before the answer
    box.wall_offset += 3600
    _answer(box, r1, only='b')
    assert 'clock_jump' in box.names()
    assert seen == {}, 'a round from before the step served a caller'
    newer = [t for t in _tags(box) if t > r1]
    assert newer, 'no round after the step'
    _answer(box, newer[-1], only='b')
    assert seen == {1: True}


def test_a_step_down_while_rounds_are_out_fails_every_caller():
    box = _ready()
    seen = {}
    box.now += 0.001
    _ask(box, seen, 1)
    r1 = _tags(box)[-1]
    box.now += 0.001
    _ask(box, seen, 2)
    r2 = _tags(box)[-1]
    _answer(box, r1, fn=lambda to, b: dict(_ok(to, b), ok=False, epoch=2), only='b')
    assert seen == {1: False, 2: False} and box.restarts
    _answer(box, r2)
    assert seen == {1: False, 2: False}


def test_confirm_rounds_never_start_faster_than_the_bound():
    """Callers every 0.1 ms, each answered at once: over a second of lease clock no more
    rounds than CONFIRM_RATE_MAX plus the first burst and the renewals, and every caller
    gets its answer."""
    box = _ready()
    start = box.now
    seen = {}
    n = 10000
    for i in range(n):
        box.now = start + i * 0.0001
        _ask(box, seen, i, need=0)
        box.node.tick()
        box.answer_all('renew', lambda to, b: _ok(to, b) if to == 'b' else None)
    box.now += 0.01
    box.node.tick()
    box.answer_all('renew', _ok)
    rounds = box.node._tag
    renewals = int(1.0 / T.R) + 2
    assert rounds <= hv.CONFIRM_RATE_MAX + hv.CONFIRM_IN_FLIGHT + renewals + 1, rounds
    assert rounds >= 0.8 * hv.CONFIRM_RATE_MAX, f'the bound throttles below itself: {rounds}'
    assert len(seen) == n and all(seen.values())


def test_a_voter_that_does_not_answer_is_passed_by_confirm_rounds_not_by_renewals():
    box = _ready()
    seen = {}
    for i in range(60):
        # one confirm as often as CONFIRM_RATE_MAX lets a round start
        box.now += 1.01 / hv.CONFIRM_RATE_MAX
        _ask(box, seen, i)
        for tag in _tags(box):
            _answer(box, tag, only='b')
    assert len(seen) == 60 and all(seen.values())
    to_c = [s for s in box.sent if s[0] == 'c' and s[1] == 'renew']
    assert len(to_c) == hv.CONFIRM_PER_VOTER, len(to_c)
    # the renewal every R goes to c all the same
    box.sent = [s for s in box.sent if s[0] != 'c']
    box.later(T.R)
    assert any(s[0] == 'c' for s in box.sent if s[1] == 'renew')
    # once the calls it owes time out, the confirm rounds ask it again
    box.later(T.renew_timeout + 0.1)
    box.sent.clear()
    box.now += 0.001
    _ask(box, seen, 'again')
    assert {s[0] for s in box.sent if s[1] == 'renew'} == {'b', 'c'}


def test_no_confirm_round_starts_while_too_few_voters_can_be_asked():
    box = _ready()
    node = box.node
    # b and c each owe CONFIRM_PER_VOTER answers of rounds that reached a majority
    owed = []
    for _ in range(hv.CONFIRM_PER_VOTER):
        r = node._new_round('renew', box.now, box.now + T.renew_timeout, 1, {'b', 'c'})
        r.majority = True
        owed.append(r)
    box.sent.clear()
    seen = {}
    box.now += 0.001
    _ask(box, seen, 1)
    assert _tags(box) == [] and seen == {}, 'a round with only the leader to count started'
    for r in owed:
        node._finish(r, box.now)
    box.now += 0.001
    node.tick()
    tags = _tags(box)
    assert tags
    _answer(box, tags[-1], only='b')
    assert seen == {1: True}


def test_in_manual_mode_a_confirm_asks_nobody():
    box = Box('a', genesis(mode=hv.MODE_MANUAL), role=hv.ROLE_ACTIVE)
    box.sent.clear()
    seen = []
    for _ in range(100):
        box.node.confirm(5, seen.append)
    assert seen == [True] * 100 and box.sent == []


@pytest.mark.parametrize('rate', [100, 2000])
def test_a_group_under_a_stream_of_confirms_keeps_its_leader_and_answers_in_a_round_trip(rate):
    """The simulator with its invariants (I1-I8 after every event): three data voters,
    0.5 ms each way, confirms as a Poisson stream. Latency is about one round trip, not a
    spacing; rounds stay under the bound; nobody else is elected."""
    import _ha_vote_sim as hs
    sim = hs.Sim(11, delay=(0.0005, 0.0005), jitter=0.0001, writes=0.0, steps=0.0)
    for i in 'abc':
        sim.add(i)
    sim.start('a', rates=None)
    assert sim.wait_for(lambda: sim.leader() == 'a', 90)
    a = sim.members['a']
    t0, dur = sim.now, 5.0
    lat, failed, renews = [], [0], set()
    real = sim._transmit

    def transmit(src, to, kind, body, tag):
        if src.iid == 'a' and kind == 'renew':
            renews.add(tag)
        return real(src, to, kind, body, tag)
    sim._transmit = transmit

    def answer(ok, asked):
        if ok:
            lat.append(sim.now - asked)
        else:
            failed[0] += 1

    def ask():
        if a.up and a.node is not None and a.node.is_active():
            asked = sim.now
            a.node.confirm(5, lambda ok, asked=asked: answer(ok, asked))
            sim._after(a)
        if sim.now < t0 + dur:
            sim.after(sim.rng.expovariate(rate), ask)
    sim.after(0.001, ask)
    sim.run(t0 + dur + 1)
    lat.sort()
    assert failed[0] == 0 and len(lat) > 0.8 * rate * dur
    assert lat[len(lat) // 2] < 0.004, f'median {lat[len(lat) // 2] * 1e3:.2f} ms'
    assert len(renews) / dur <= hv.CONFIRM_RATE_MAX + hv.CONFIRM_IN_FLIGHT + 1
    assert not [e for e in sim.elections if e[0] > t0] and sim.leader() == 'a'
