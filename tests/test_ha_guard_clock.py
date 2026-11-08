"""A token from before a pause that held the lease clock (#625 stage 2, design 4.2 and 5.3;
found by the round-three attack on slice S4).

confirm_lease() leaves a token for one call, and ha._token_fits takes it while
ha_clock() <= until - need and rt.jumps is what it was. A pause that holds the lease
clock (a frozen VM, SIGSTOP) moves only the wall clock, and rt.jumps moves only once the
node looks at its clock: a tick of the loop, an answer, a confirm. guard() took the token
without that look, so the step's call went out right after the pause, while another
member led. guard() now has the node look first (ha._clock_look), for a call asked the
first time and for one that goes out again (again=True): the token is void and the call
asks for a round of its own, which the newer leader's epoch refuses.

MK Oct 2026 (#625)
"""
import time

import pytest

from pegaprox.core import ha_transport as hx
from test_ha_members import IDS, group  # noqa: F401
from _ha_lease_harness import auto  # noqa: F401

START = 'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/101/status/start'

pytestmark = pytest.mark.guard_refusals


def _other_leader(auto):
    for n in 'bc':
        with auto.at(n) as ha:
            if ha.is_active():
                return n
    return None


def _paused_while_another_took_over(auto, seed):
    """a confirms, then freezes with its lease clock held until b or c leads; the wall
    clock of a moved on by the pause."""
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        tok, jumps = ha._guard_tls.token, ha._rts[IDS['a']].jumps
    auto.pause('a', freeze=True)
    auto.run(240, dt=1.0, members='bc', until=lambda: _other_leader(auto) is not None)
    other = _other_leader(auto)
    assert other is not None
    auto.resume('a')
    auto.skew['a'] = auto.skew.get('a', 0.0) + 240
    return tok, jumps, other


@pytest.mark.parametrize('ctx', ['background step', 'request'])
def test_a_token_from_before_a_held_pause_does_not_send_after_it(auto, seed, ctx):
    tok, jumps, other = _paused_while_another_took_over(auto, seed)
    with auto.at('a') as ha:
        assert ha.is_active(), 'held clock: a still sees its lease'
        # the runtime of a as it was: the round finds the newer epoch, and a starts over
        rt = ha._rts[IDS['a']]
        with pytest.raises(ha.GuardRefused) as e:
            if ctx == 'request':
                with auto.g.api.app.test_request_context('/', method='POST'):
                    hx.guard_http('POST', START)
            else:
                hx.guard_http('POST', START)
        assert e.value.why == ha.GUARD_UNCONFIRMED
        assert rt.jumps > jumps
        assert ha._guard_tls.token is not tok
    with auto.at(other) as ha:
        assert ha.is_active()


def test_the_same_call_sent_again_after_the_pause_is_refused(auto, seed):
    """The call went out on the token before the pause; once more after it (a new login,
    the connection now up): again=True takes the token only after the clock look."""
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        hx.guard_http('POST', START)
        hx.guard_http('POST', START, again=True)
    auto.pause('a', freeze=True)
    auto.run(240, dt=1.0, members='bc', until=lambda: _other_leader(auto) is not None)
    auto.resume('a')
    auto.skew['a'] = auto.skew.get('a', 0.0) + 240
    with auto.at('a') as ha:
        with pytest.raises(ha.GuardRefused):
            hx.guard_http('POST', START, again=True)


def test_without_a_step_of_the_clock_the_token_serves_as_before(auto, seed):
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        sent = len(auto.rt('a').outbox)
        # a small step (NTP slewing, under ha_vote.CLOCK_JUMP) voids nothing
        auto.skew['a'] = auto.skew.get('a', 0.0) + 1.0
        hx.guard_http('POST', START)
        hx.guard_http('POST', START, again=True)
        assert len(auto.rt('a').outbox) == sent, 'no round of its own'


def test_a_step_of_the_wall_clock_alone_voids_the_token_at_the_next_call(auto, seed):
    """Not only a pause: an NTP step past CLOCK_JUMP between the confirm and the call."""
    auto.form(seed)
    with auto.at('a') as ha:
        assert ha.confirm_lease()
        jumps = ha._rts[IDS['a']].jumps
        auto.skew['a'] = auto.skew.get('a', 0.0) + 30
        # a request asks for a round of its own; the group is there, so it gets one
        with auto.g.api.app.test_request_context('/', method='POST'):
            hx.guard_http('POST', START)
        assert ha._rts[IDS['a']].jumps == jumps + 1


def test_what_the_clock_look_costs_a_call(auto, seed, monkeypatch):
    """guard() on a token that fits, in automatic mode: with and without the look."""
    auto.form(seed)
    n = 3000

    def per_call():
        with auto.at('a') as ha:
            assert ha.confirm_lease()
            hx.guard_http('POST', START)
            t = time.perf_counter()
            for _ in range(n):
                ha.guard('POST /x', again=True)
            return (time.perf_counter() - t) / n
    with_look = min(per_call() for _ in range(3))
    monkeypatch.setattr(auto.ha, '_clock_look', lambda rt: None)
    without = min(per_call() for _ in range(3))
    added = with_look - without
    print(f'\nguard() on a token that fits: {with_look * 1e6:.2f} us with the clock look, '
          f'{without * 1e6:.2f} us without: {added * 1e6:.2f} us more per call')
    assert added < 50e-6
