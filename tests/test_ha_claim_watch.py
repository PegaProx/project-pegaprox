"""The claim watch and the VM each member runs as (#625 stage 2, design 4.10, 6.3 and 7.5,
owner decision Q4 b with Q9: the claim is optional per cluster and off by default; slice
S7).

On every look at the group the active of a manual group, and the leader of an automatic
one, looks at the claim of each cluster with node HA and the claim switched on: ours
goes on where it is lower or missing, and a claim of a member (or of a newer copy of
this instance) at a higher epoch means this instance is the stale one, and it steps
down. A promoted active writes its claim at its new epoch when its monitor starts
(S6). With the claim off nothing is read or written.

The clusters are the manager of tests/test_ha_claim.py, its SSH a shell on a directory
that stands in for /etc/pve.

MK Oct 2026 (#625)
"""
import threading
import time
import types

import pytest

from _ha_lease_harness import T, auto  # noqa: F401  (the fixture)
from test_ha_api import ADMIN_PW, _audit
from test_ha_claim import _claim, _mgr, _plant, pve  # noqa: F401  (the fixture)
from test_ha_members import IDS, _built, _sync, group  # noqa: F401  (the fixture)


def _cluster(auto, pve, on=True):  # noqa: F811
    m = _mgr(pve, claim_enabled=on)
    m.ha_enabled = True
    auto.g.api.set_manager('c1', m)
    return m


def _watch(auto, n, force=True):
    with auto.at(n) as ha:
        return ha.claim_watch(force=force)


def test_the_active_steps_down_for_a_member_that_claims_the_cluster_at_a_higher_epoch(auto, seed, pve):  # noqa: F811
    auto.pair(seed)
    _cluster(auto, pve)
    _plant(pve, f"5 {IDS['b']} - 0 0\n")

    assert _watch(auto, 'a') == 'stepped down'

    a = auto.file('a')
    assert a['role'] == 'standby' and a['source'] == IDS['b'] and a['epoch'] == 5
    assert ('a', 'stepped down to standby') in auto.g.restarts
    assert any('claim watch' in row['details'] for row in _audit('ha.stepped_down'))
    # nothing of ours went over the newer claim
    assert _claim(pve).startswith(f"5 {IDS['b']}")


def test_a_lower_claim_or_none_becomes_ours(auto, seed, pve):  # noqa: F811
    auto.pair(seed)
    m = _cluster(auto, pve)
    assert _watch(auto, 'a') == 'ok'
    assert _claim(pve).startswith(f"1 {IDS['a']} ")
    _plant(pve, f"0 {IDS['b']} - 0 0\n")
    assert _watch(auto, 'a') == 'ok'
    assert _claim(pve).startswith(f"1 {IDS['a']} ") and auto.file('a')['role'] == 'active'
    # and at most once per pass
    sent = len(m.sent)
    assert _watch(auto, 'a', force=False) == 'cached' and len(m.sent) == sent


def test_a_newer_copy_of_this_instance_sends_it_aside(auto, seed, pve):  # noqa: F811
    auto.pair(seed)
    _cluster(auto, pve)
    _plant(pve, f"7 {IDS['a']} - 0 0\n")

    assert _watch(auto, 'a') == 'stepped aside'

    a = auto.file('a')
    assert a['role'] == 'standby' and a['source'] is None and a['epoch'] == 7


def test_an_instance_the_group_does_not_know_is_refused_there_and_not_followed(auto, seed, pve):  # noqa: F811
    auto.pair(seed)
    m = _cluster(auto, pve)
    _plant(pve, f"9 {'f' * 32} - 0 0\n")

    assert _watch(auto, 'a') == 'ok'

    assert auto.file('a')['role'] == 'active'
    assert m.ha_config['claim_state']['state'] == 'higher'
    # looked at again later, not on every pass
    sent = len(m.sent)
    assert _watch(auto, 'a') == 'none' and len(m.sent) == sent


def test_with_the_claim_off_nothing_is_read_or_written(auto, seed, pve):  # noqa: F811
    auto.pair(seed)
    m = _cluster(auto, pve, on=False)
    _plant(pve, f"5 {IDS['b']} - 0 0\n")
    assert _watch(auto, 'a') == 'none'
    assert m.sent == [] and auto.file('a')['role'] == 'active'


def test_a_standby_and_an_instance_of_its_own_watch_nothing(auto, seed, pve):  # noqa: F811
    m = _cluster(auto, pve)
    assert _watch(auto, 'e') == 'idle'
    auto.pair(seed)
    assert _watch(auto, 'b') == 'idle'
    assert m.sent == []


def test_the_leader_of_an_automatic_group_steps_down_for_a_newer_claim(auto, seed, pve):  # noqa: F811
    auto.form(seed)
    auto.past_the_hold()
    _cluster(auto, pve)
    assert _watch(auto, 'a') == 'ok' and auto.leader() == 'a'
    _plant(pve, f"9 {IDS['c']} - 0 0\n")

    assert _watch(auto, 'a') == 'stepped down'

    assert auto.file('a')['role'] == 'standby'
    with auto.at('a') as ha:
        assert not ha.is_active()


def test_the_loop_runs_the_watch_with_every_look(monkeypatch):
    """_loop starts the claim watch (on a greenlet of its own) and calls forced_onboot_pass
    after the watch and the housekeeping; it never waits for a claim write itself."""
    import ast
    import inspect
    from pegaprox.core import ha
    src = inspect.getsource(ha._loop)
    names = [ast.unparse(c.func) for c in ast.walk(ast.parse(src.strip())) if isinstance(c, ast.Call)]
    assert names.index('claim_watch_soon') > names.index('watch_once')
    assert 'claim_watch' not in names and 'forced_onboot_pass' in names


# --- the VM each member runs as ----------------------------------------------------------------

def test_the_leader_names_the_vm_of_each_member_and_the_members_learn_it(auto, seed, pve):  # noqa: F811
    auto.pair(seed)
    _cluster(auto, pve, on=False)
    r = auto.put('a', f"/api/ha/members/{IDS['b']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 104})
    assert r.status_code == 200 and r.get_json()['changed'] is True
    r = auto.put('a', f"/api/ha/members/{IDS['b']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 104})
    assert r.get_json()['changed'] is False
    r = auto.put('a', f"/api/ha/members/{IDS['a']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 100})
    assert r.status_code == 200
    assert auto.file('a')['members'][IDS['b']]['agent_vmid'] == {'c1': 104}
    assert auto.file('a')['agent_vmid'] == {'c1': 100}
    assert any('runs as VM 104 on cluster c1' in row['details'] for row in _audit('ha.member_agent_vmid'))
    assert _sync(auto.g, auto.admin, 'b') == 'applied'
    assert auto.file('b')['members'][IDS['a']]['agent_vmid'] == {'c1': 100}
    # null forgets it
    r = auto.put('a', f"/api/ha/members/{IDS['b']}/agent-vmid", {'cluster_id': 'c1', 'vmid': None})
    assert r.status_code == 200 and r.get_json()['changed'] is True
    assert 'agent_vmid' not in auto.file('a')['members'][IDS['b']] or \
        auto.file('a')['members'][IDS['b']]['agent_vmid'] == {}


@pytest.mark.parametrize('body, code', [({'cluster_id': 'c1', 'vmid': 'x'}, 400),
                                        ({'cluster_id': 'c1', 'vmid': 99}, 400),
                                        ({'cluster_id': 'c1', 'vmid': True}, 400),
                                        ({'vmid': 101}, 400),
                                        ({'cluster_id': 'nope', 'vmid': 101}, 404)])
def test_the_vm_route_refuses_what_names_no_vm(auto, seed, pve, body, code):  # noqa: F811
    auto.pair(seed)
    _cluster(auto, pve, on=False)
    r = auto.put('a', f"/api/ha/members/{IDS['b']}/agent-vmid", body)
    assert r.status_code == code, r.data
    assert 'agent_vmid' not in auto.file('a')['members'][IDS['b']]


def test_the_vm_is_named_on_the_leader_only(auto, seed, pve):  # noqa: F811
    auto.form(seed)
    _cluster(auto, pve, on=False)
    r = auto.put('b', f"/api/ha/members/{IDS['c']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 101})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = auto.put('a', f"/api/ha/members/{'f' * 32}/agent-vmid", {'cluster_id': 'c1', 'vmid': 101})
    assert r.status_code == 409
    auto.isolate('a')
    auto.auto_restart = False
    auto.advance(T.per_round + 0.5)
    r = auto.put('a', f"/api/ha/members/{IDS['c']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 101})
    assert r.status_code == 503 and r.get_json()['code'] == 'HA_NO_LEASE'
    with auto.at('a') as ha:
        rows = ha.lease_status()['members']
    assert all(row['agent_vmid'] == {} for row in rows)
    assert ADMIN_PW


# --- a cluster whose nodes do not answer (S7 attack) ----------------------------------------
#
# The claim is written over SSH, 30 s per node. The watch ran between two looks at the group
# and waited for every batch of clusters, so one dead cluster held the HA loop up on every
# pass. Now the loop starts it on its own greenlet, it asks CLAIM_WATCH_NODES nodes per
# cluster, never a second time while a write still runs, and a result that came late or
# not at all is looked at again after CLAIM_RETRY.

class _SlowClaim:
    """A cluster with node HA and the claim on, whose nodes do not answer until `go` is
    set."""

    def __init__(self):
        self.ha_enabled = True
        self.config = types.SimpleNamespace(name='site-b')
        self.calls, self.limits = 0, []
        self.go = threading.Event()

    def _ha_claim_enabled(self):
        return True

    def _ha_claim_ensure(self, takeover=False, limit=None):
        self.calls += 1
        self.limits.append(limit)
        self.go.wait(20)
        return {'state': 'unreachable'}


def _dead_cluster(group, seed, monkeypatch):  # noqa: F811
    from test_ha_members import _REAL_FAN_OUT
    _built(group, seed, 'b')
    # the real fan-out with its timeout (the harness runs calls one after the other)
    monkeypatch.setattr(group.ha, '_fan_out', _REAL_FAN_OUT)
    slow = _SlowClaim()
    group.api.set_manager('c-dead', slow)
    return slow


def test_the_loop_hands_the_claim_watch_to_a_greenlet_and_waits_for_nothing(group, seed, monkeypatch):  # noqa: F811
    slow = _dead_cluster(group, seed, monkeypatch)
    started = []
    monkeypatch.setattr(group.ha, '_lease_spawn',
                        lambda fn, name: started.append(threading.Thread(target=fn, name=name, daemon=True)) or
                        started[-1].start())
    try:
        with group.at('a') as ha:
            t0 = time.monotonic()
            assert ha.claim_watch_soon() is True
            took = time.monotonic() - t0
            for _ in range(100):
                if slow.calls:
                    break
                time.sleep(0.05)
            # a second start while one runs starts nothing, and a pass asks no cluster whose
            # write still runs
            assert ha.claim_watch_soon() is False
            assert ha.claim_watch(force=True) == 'none'
            assert slow.calls == 1 and slow.limits == [ha.CLAIM_WATCH_NODES]
            slow.go.set()
            started[0].join(10)
            assert not started[0].is_alive()
            # the cluster answered nothing usable: not asked again on the next pass
            ha._rt().claims['at'] -= ha.CLAIM_WATCH + 1
            assert ha.claim_watch() == 'none' and slow.calls == 1
            assert ha.claim_watch_soon() is True
            started[1].join(10)
            assert slow.calls == 1
    finally:
        slow.go.set()
    assert took < 1.0 and [t.name for t in started] == ['ha-claim-watch', 'ha-claim-watch']


def test_a_late_claim_write_is_not_waited_out_nor_started_again(group, seed, monkeypatch):  # noqa: F811
    slow = _dead_cluster(group, seed, monkeypatch)
    monkeypatch.setattr(group.ha, 'CLAIM_WATCH_WAIT', 0.3)
    try:
        with group.at('a') as ha:
            t0 = time.monotonic()
            assert ha.claim_watch(force=True) == 'ok'
            assert time.monotonic() - t0 < 5
            # still running: the next pass leaves it alone
            assert ha.claim_watch(force=True) == 'none' and slow.calls == 1
            slow.go.set()
            for _ in range(100):
                if not ha._rt().claims['jobs']:
                    break
                time.sleep(0.05)
            assert not ha._rt().claims['jobs']
            # it came late: looked at again after CLAIM_RETRY, not on the next pass
            assert ha.claim_watch(force=True) == 'none' and slow.calls == 1
            cid = 'c-dead'
            what, until = ha._rt().claims['seen'][cid]
            assert 0 < until - time.monotonic() <= ha.CLAIM_RETRY
            ha._rt().claims['seen'][cid] = (what, time.monotonic() - 1)
            assert ha.claim_watch(force=True) == 'ok' and slow.calls == 2
    finally:
        slow.go.set()


def test_the_vm_route_is_refused_while_automatic_failover_is_not_shipped(auto, seed, pve, monkeypatch):  # noqa: F811
    """It only serves Force leader, which is refused then as well: a manual group stays as
    it is, its etag included."""
    from pegaprox.core import ha_vote as hv
    auto.pair(seed, 'b')
    _cluster(auto, pve, on=False)
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', False)
    before = auto.file('a')

    r = auto.put('a', f"/api/ha/members/{IDS['b']}/agent-vmid", {'cluster_id': 'c1', 'vmid': 105})

    assert r.status_code == 409 and r.get_json()['code'] == 'HA_AUTO_NOT_SHIPPED', r.data
    assert auto.file('a') == before and not _audit('ha.member_agent_vmid')
