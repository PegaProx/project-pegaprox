"""The lease protocol of automatic failover (#625 stage 2) in the simulator, seed by seed.

Each scenario S-1 to S-25 of the design (section 11.1), and seven more (a lease cut to
15 s, a cold start at a long lease, a crash in the hand-over, a long lease trimmed off
the chain or left behind with a branch while a promise from it runs, a reboot onto a
fast clock), runs over PEGAPROX_HA_SIM_SEEDS seeds (500 unless set; 10000 for the long
run), and so does a run with random faults.
After every event the simulator checks I1-I8 (tests/_ha_vote_sim.py); a scenario adds
what it expects on top. A failure names the scenario and the seed, with the tail of the
log; PEGAPROX_HA_SIM_SEED=<n> replays that one seed.

    PEGAPROX_HA_SIM_SEEDS=10000 python -m pytest tests/test_ha_vote_sim.py

MK Oct 2026 (#625)
"""
import math
import os
import random
import re

import pytest

from pegaprox.core import ha_vote as hv

import _ha_vote_sim as hs
from _ha_vote_sim import Violation

SEEDS = int(os.environ.get('PEGAPROX_HA_SIM_SEEDS', '500'))
ONLY = os.environ.get('PEGAPROX_HA_SIM_SEED')

T = hv.Timings()
# one lease on a leader clock running 10% slow, plus the round that carried it
LEASE_REAL = T.per_round / 0.9 + T.renew_timeout
# I6 as the design states it, and with what a heal can add on top: members that restart
# at the heal refuse every candidate for P + D, and a vote round that misses an answer
# costs one back-off of up to L. Both in true time, on clocks that may run 10% slow
I6_TIGHT = hs.bound_i6(T) / 0.9
I6 = (hs.bound_i6(T) + T.hold_after_start + T.L) / 0.9


def _seeds(n=None):
    if ONLY is not None:
        return [int(ONLY)]
    return range(SEEDS if n is None else n)


def _each(scenario, n=None):
    """Run scenario(seed) over the seeds; returns what each run returned."""
    out = []
    for seed in _seeds(n):
        try:
            out.append(scenario(seed))
        except Violation as e:
            raise AssertionError(f'{scenario.__name__}, seed {seed}:\n{e}') from None
        except AssertionError as e:
            raise AssertionError(f'{scenario.__name__}, seed {seed}: {e}') from None
    return out


def group(seed, data='abc', witness='', leader='a', rates=True, start=True, **kw):
    sim = hs.Sim(seed, **kw)
    for i in data:
        sim.add(i)
    for i in witness:
        sim.add(i, kind=hv.KIND_WITNESS)
    if start:
        r = {i: sim.rng.uniform(0.9, 1.1) for i in sim.order} if rates else None
        sim.start(leader, rates=r)
    return sim


def settle(sim, who='a', limit=30):
    assert sim.wait_for(lambda: sim.leader() == who, limit), f'{who} never acted'


def elections_after(sim, t):
    return [e for e in sim.elections if e[0] > t]


def acts(sim, who, after):
    return [e for e in sim.effects if e[1] == who and e[0] > after]


def leader_within(sim, limit, among=None):
    """One member (of `among`) acts within `limit` seconds; returns it."""
    ok = sim.wait_for(lambda: sim.leader() is not None and (among is None or sim.leader() in among),
                      limit)
    assert ok, f'no leader {"among " + among if among else ""} within {limit:.0f} s'
    return sim.leader()


# --- S-1 to S-12 ---

def s1_leader_crash(seed):
    """S-1: 3 data, the leader crashes (for good or for a while): a new leader, I1-I3,
    within I6 as the design states it unless a round was lost on the way (both members
    left campaign within the same few ms and split the vote: about 1 in 10000 seeds)."""
    sim = group(seed)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 40))
    t = sim.now
    lost = sim.counts.get('lost', 0)
    if seed % 2:
        sim.stop('a')
    else:
        sim.crash('a')
    sim.mark_heal()
    sim.run(t + I6 + 5)
    took = sim.time_to_leader()
    bound = I6_TIGHT if sim.counts.get('lost', 0) == lost else I6
    assert took is not None and took <= bound, f'took {took}'
    if seed % 2:
        assert sim.leader() in ('b', 'c')
        assert len(elections_after(sim, t)) == 1
    sim.run(sim.now + 60)
    assert sim.leader() is not None
    return took


def s2_two_two_wan_cut(seed):
    """S-2: 2+2 over a WAN, cut, no witness: no leader on either side, nothing acts."""
    sim = group(seed, 'abcd', delay=(0.02, 0.08))
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 30))
    t = sim.now
    sim.partition('ab', 'cd')
    sim.run(t + 240)
    assert not elections_after(sim, t)
    assert not [e for e in sim.effects if e[0] > t + T.renew_timeout]
    assert all(not m.node.holds_lease() for m in sim.members.values() if m.node)
    sim.heal_all()
    sim.mark_heal()
    leader_within(sim, I6)


def s3_witness_third_site(seed):
    """S-3: 2+2 + witness at a third site, site 1 cut off: site 2 leads, the floor rule
    keeps the stale member of site 2 out."""
    sim = group(seed, 'abcd', 'w', delay=(0.02, 0.08), writes=0.8)
    sim.members['d'].no_pull = bool(seed % 2)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(20, 60))
    sim.partition('ab', 'cdw')
    floor = max(sim.floors.values())
    sim.mark_heal()
    who = leader_within(sim, I6, 'cd')
    assert sim.node(who).cv >= floor
    if seed % 2:
        # d pulled nothing: it is either not the winner or it caught up first
        assert who == 'c' or sim.counts.get('catchup')
    sim.run(sim.now + 30)


def s4_three_one(seed):
    """S-4: 3+1, the single member at site 1 leads: the three elect, its confirms fail."""
    sim = group(seed, 'abcd', delay=(0.02, 0.08), steps=1.0)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 30))
    t = sim.now
    failed = sim.counts.get('confirm failed', 0)
    sim.partition('a', 'bcd')
    sim.mark_heal()
    leader_within(sim, I6, 'bcd')
    assert not acts(sim, 'a', t + T.renew_timeout)
    assert sim.counts.get('confirm failed', 0) > failed


def s5_one_way_cut(seed):
    """S-5: the leader is cut in one direction only: it loses the lease, one leader after."""
    sim = group(seed)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 30))
    t = sim.now
    for o in 'bc':
        if seed % 2:
            sim.cut('a', o, both=False)
        else:
            sim.cut(o, 'a', both=False)
    sim.run(t + LEASE_REAL + 1)
    assert sim.node('a') is None or not sim.node('a').holds_lease()
    sim.mark_heal()
    who = leader_within(sim, I6, 'bc')
    sim.run(sim.now + 60)
    assert sim.leader() == who


def s6_witness_then_voter(seed):
    """S-6: 2 data + witness. The witness goes down: the lease holds. A data voter goes
    down as well: the lease is gone and nobody leads."""
    sim = group(seed, 'ab', 'w')
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 30))
    t = sim.now
    sim.stop('w')
    sim.run(t + 90)
    assert sim.leader() == 'a' and not elections_after(sim, t)
    t2 = sim.now
    sim.stop('b')
    sim.run(t2 + LEASE_REAL + T.R)
    assert sim.holder() is None
    sim.run(t2 + 120)
    assert sim.holder() is None and not elections_after(sim, t)


def s7_flapping(seed):
    """S-7: the leader's links flap (5 s, L/2, L, 2L) for 30 min: at most one leader
    change per 2L, I1-I3 throughout."""
    period = (5.0, T.L / 2, T.L, 2 * T.L)[seed % 4]
    sim = group(seed, writes=0.2, steps=0.2)
    settle(sim)
    start = sim.now
    duration = 1800.0

    def down():
        if sim.now > start + duration:
            return
        who = sim.holder() or sim.leader() or 'a'
        sim.isolate(who)
        sim.after(period / 2, up)

    def up():
        sim.heal_all()
        sim.after(period / 2, down)

    sim.after(1.0, down)
    sim.run(start + duration)
    changes = len(elections_after(sim, start))
    assert changes <= duration / (2 * T.L) + 2, f'{changes} leader changes at a period of {period} s'
    sim.heal_all()
    sim.mark_heal()
    leader_within(sim, I6)
    return changes


def s8_clock_rates(seed):
    """S-8: every lease clock 10% off and slewing; in half the seeds the leader runs 10%
    slow and every voter 10% fast whenever it is cut off. Half the seeds take the winner
    in-process (S10) so that it holds its lease from the vote round on, which no restart
    hides. Failovers right at the boundary: I1 holds."""
    worst = seed % 2 == 0
    sim = group(seed, 'abcd', rates=False, start=False, restart_on_win=seed % 4 >= 2)
    rates = {i: (0.9 if i == 'a' else 1.1) if worst else sim.rng.uniform(0.9, 1.1) for i in sim.order}
    sim.start('a', rates=rates)
    settle(sim)
    start = sim.now

    def slew():
        if not worst:
            sim.set_rate(sim.rng.choice(sim.order), sim.rng.uniform(0.9, 1.1))
        sim.after(sim.rng.uniform(5, 30), slew)

    def cut():
        who = sim.holder() or 'a'
        if worst:
            for i in sim.order:
                sim.set_rate(i, 0.9 if i == who else 1.1)
        sim.isolate(who)
        sim.after(sim.rng.uniform(15, 45), sim.heal_all)
        sim.after(sim.rng.uniform(60, 120), cut)

    sim.after(1.0, slew)
    sim.after(sim.rng.uniform(1, 10), cut)
    sim.run(start + 300)
    assert elections_after(sim, start)


def s9_frozen_leader(seed):
    """S-9: the leader's VM is paused with its clock for 3L, then resumed: it steps down
    on the first refused renewal, renews above no epoch it won, and takes no step."""
    sim = group(seed, writes=0.6, steps=1.0)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 30))
    sim.pause('a', freeze_clock=True)
    sim.run(sim.now + 3 * T.L)
    t = sim.now
    sim.resume('a')
    sim.run(t + 30)
    assert not acts(sim, 'a', t)
    assert elections_after(sim, 0)
    assert sim.node('a') is None or sim.node('a').st['role'] == hv.ROLE_STANDBY
    assert sim.counts.get('step_down', 0) + sim.counts.get('lease_lost', 0) >= 1


def s10_wall_jump(seed):
    """S-10: the leader's wall clock steps by an hour: the others refuse its calls
    (HA_CLOCK), its lease runs out, a member takes over; the clock step forces a round."""
    sim = group(seed, steps=1.0)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 30))
    t = sim.now
    sim.wall_step('a', 3600 if seed % 2 else -3600)
    sim.run(t + 5)
    assert sim.counts.get('clock_jump')
    sim.mark_heal()
    leader_within(sim, I6, 'bc')
    assert sim.counts.get('refused HA_CLOCK')
    assert not acts(sim, 'a', t + LEASE_REAL)


def s11_voter_restart(seed):
    """S-11: a voter restarts (process, container on the same boot, or host) inside its
    promise while a member that is cut off from the leader campaigns at once: the hold
    after start refuses it, and the leader keeps its lease."""
    sim = group(seed)
    settle(sim)
    sim.cut('a', 'c')
    sim.run(sim.now + T.P + T.L)
    t = sim.now
    kind = seed % 3
    if kind == 2:
        sim.reboot_host('b', downtime=(1.0, 4.0))
    else:
        sim.crash('b', downtime=(0.5, 3.0))
    # c asks the moment b is back, before the leader's next renewal reaches b
    sim.set_delay('a', 'b', 1.5, 0.0)
    sim.wait_for(lambda: sim.node('b') is not None, 10, step=0.05)
    n = sim.node('c')
    if n is not None and n._campaign is None:
        n.campaign_now()
        sim._after(sim.members['c'])
    sim.run(sim.now + 60)
    assert not elections_after(sim, t)
    assert sim.leader() == 'a'


def s12_rollback(seed):
    """S-12: a voter comes back from an old state: the leader sees its generation go
    back, quarantines it by a config change, and its votes do not count."""
    sim = group(seed, 'abcd', 'w', writes=0.8)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(40, 80))
    sim.rollback('b', back=sim.rng.randint(12, 40))
    assert sim.wait_for(lambda: any(
        'b' in (hv.CfgView(c).cfg['body'].get('quarantined') or ())
        for c in sim.committed_cfgs()), 60), 'b was not quarantined'
    t = sim.now
    sim.stop('a')
    who = leader_within(sim, I6, 'cd')
    for when, iid, epoch, why in elections_after(sim, t):
        assert 'b' not in sim.counted[(iid, epoch)]
    # the admin re-admits it on the new leader
    n = sim.node(who)
    n.change_cfg(lambda body: dict(body, quarantined=[q for q in body['quarantined'] if q != 'b']))
    sim.run(sim.now + 30)
    assert 'b' in sim.node(who).view.counting


# --- S-13 to S-25 ---

def s13_transfer(seed):
    """S-13: Make leader: to a member that can catch up it moves at the next epoch; to a
    stale one it is refused and the leader goes on."""
    sim = group(seed, 'abc', writes=0.8)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(10, 40))
    t = sim.now
    if seed % 2:
        sim.members['c'].no_pull = True
        sim.run(sim.now + 10)
        assert sim.node('a').transfer_to('c') == ''
        sim.run(sim.now + hv.TRANSFER_CATCHUP + 2)
        assert sim.counts.get('transfer_refused')
        assert sim.leader() == 'a' and not elections_after(sim, t)
        return
    assert sim.node('a').transfer_to('b') == ''
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: sim.leader() == 'b', T.W_take + 30), 'b never acted'
    ups = elections_after(sim, t)
    assert [(e[1], e[2], e[3]) for e in ups] == [('b', 2, 'transfer')]


def s14_break_glass(seed):
    """S-14: break-glass on a member cut off from a majority that is alive: two act only
    until the old leader's claim check, the cluster refuses its SSH steps at once, and the
    tombstones settle it after the heal. Models the recommended Q3 (b) and Q9 (a); the
    module has no break-glass of its own yet."""
    sim = group(seed, steps=1.0)
    sim.enable_claims()
    settle(sim)
    sim.partition('ab', 'c')
    # no renewal for P + L/2, and its own campaign failed for want of a majority
    sim.run(sim.now + T.P + T.L / 2 + T.L)
    c = sim.members['c']
    t = sim.now
    epoch = max(sim.node('c').epoch, sim.node('c').epoch_seen) + 1
    sim.stop('c')
    st = dict(c.store.state)
    body = dict(st['cfg']['body'], mode=hv.MODE_MANUAL,
                voters=[r for r in st['cfg']['body']['voters'] if r['id'] == 'c'])
    cfg = hv.make_cfg(st['cfg'], epoch, 'c', body, c.sign)
    st.update(role=hv.ROLE_ACTIVE, epoch=epoch, cfg=cfg, cfg_chain=st['cfg_chain'] + [st['cfg']])
    c.store.state = st
    sim.allow_dual_actors = True
    sim.boot('c')
    sim.force_claim('c', epoch)
    sim.run(t + sim.claim_watch + 1)
    assert sim.node('a') is None or not sim.node('a').is_active()
    sim.allow_dual_actors = False
    assert not [e for e in sim.effects if e[1] == 'a' and e[3] == 'ssh' and e[0] > t]
    assert sim.leader() == 'c'
    # the heal: a and b hear 410 from c and go passive for good
    sim.heal_all()
    sim.stop('a')
    sim.stop('b')
    sim.run(sim.now + 60)
    assert sim.leader() == 'c'


def s15_change_in_partition(seed):
    """S-15: a voter is removed while the group is split. Committed on the majority side
    it holds; cut off before it committed, the other side elects under the old config and
    the uncommitted one is left behind. One leader, majorities overlap (I8)."""
    sim = group(seed, 'abcd', 'w')
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    t = sim.now
    drop_d = lambda body: dict(body, voters=[r for r in body['voters'] if r['id'] != 'd'])
    if seed % 2:
        sim.partition('abc', 'dw')
        sim.node('a').change_cfg(drop_d)
        sim._after(sim.members['a'])
        sim.run(t + 30)
        assert 'd' not in sim.node('a').view.voters
        assert sim.leader() == 'a'
        sim.heal_all()
        sim.run(sim.now + 60)
        assert sim.leader() == 'a' and not elections_after(sim, t)
        assert sim.node('d').view.id == sim.node('a').view.id
        return
    split = []

    def on_cfg(m, name, info):
        if name == 'cfg' and info.get('why') == 'change' and not split:
            split.append(sim.now)
            sim.partition('ab', 'cdw')
    sim.on_event_hook = on_cfg
    sim.node('a').change_cfg(drop_d)
    sim._after(sim.members['a'])
    sim.run(t + 5)
    assert split
    sim.mark_heal()
    who = leader_within(sim, I6, 'cd')
    sim.heal_all()
    sim.run(sim.now + 60)
    assert sim.leader() == who
    assert len({sim.node(i).view.id for i in 'abcd' if sim.node(i)}) == 1


def s16_real_vote_fails(seed):
    """S-16: a member's pre-vote passes and its real vote fails (it is cut off right
    then): the old leader stepped down once, and there is one leader after."""
    sim = group(seed)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    t = sim.now
    sim.isolate('a')
    cut = []

    def on_vote(m, name, info):
        if name == 'vote' and not cut:
            cut.append(m.iid)
            sim.isolate(m.iid)
    sim.on_event_hook = on_vote
    sim.run(t + T.P + T.L)
    assert cut, 'nobody got to a real vote'
    sim.on_event_hook = None
    loser = cut[0]
    sim.heal('a', [i for i in 'bc' if i != loser][0])
    sim.mark_heal()
    who = leader_within(sim, I6, ''.join(i for i in 'abc' if i != loser))
    sim.heal_all()
    sim.run(sim.now + 60)
    assert sim.leader() == who
    assert sim.down_count('a', since=t) == 1
    assert [e[1] for e in elections_after(sim, t)] == [who]


def s17_late_campaign(seed):
    """S-17: a transfer fails, the old leader wins again, then the target's late
    campaign call and a replayed release_to come in: the target does not win."""
    sim = group(seed, 'abc', start=False)
    sim.members['c'].may_lead = False
    sim.start('a', rates={i: sim.rng.uniform(0.9, 1.1) for i in sim.order})
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    t = sim.now
    kept = {}

    def on_stop(m, name, info):
        if name == 'acting_stop' and m.iid == 'a' and not kept:
            kept['epoch'] = m.node.led_epoch
            sim.isolate('b')
    sim.on_event_hook = on_stop
    assert sim.node('a').transfer_to('b') == ''
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: sim.leader() == 'a' and sim.node('a').led_epoch > kept.get('epoch', 99),
                        3 * T.L + I6), 'a did not win again'
    sim.on_event_hook = None
    sim.heal_all()
    E = kept['epoch']
    sim.inject('a', 'b', 'campaign', {'epoch': E})
    sim.inject('a', 'c', 'renew', {'epoch': E, 'leader': 'a', 'lease_s': 20, 'cv': (E, 0),
                                   'release_to': {'to': 'b', 'epoch': E + 1}})
    sim.inject('a', 'b', 'renew', {'epoch': E, 'leader': 'a', 'lease_s': 20, 'cv': (E, 0),
                                   'release_to': {'to': 'b', 'epoch': E + 1}})
    sim.run(sim.now + 90)
    assert sim.leader() == 'a'
    assert 'b' not in [e[1] for e in elections_after(sim, t)]


def s18_uncommitted_witness(seed):
    """S-18: the leader adds a witness, only the witness hears of it, the leader dies;
    the new leader removes the old one, which then comes back: no two leaders, and the
    config ids order the configs (the uncommitted one is never committed)."""
    sim = group(seed, 'abcd', 'w', start=False)
    sim.start('a', exclude='w', rates={i: sim.rng.uniform(0.9, 1.1) for i in sim.order})
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    w = sim.members['w']
    rec = {'id': 'w', 'public_key': w.public_key, 'site': ''}
    made = []

    def on_cfg(m, name, info):
        if name == 'cfg' and info.get('why') == 'change' and m.iid == 'a' and not made:
            made.append(hv.pair(info['cfg']['id']))
            for o in 'bcd':
                sim.cut('a', o)
    sim.on_event_hook = on_cfg
    sim.node('a').change_cfg(lambda body: dict(body, witness=rec))
    sim._after(sim.members['a'])
    sim.run(sim.now + 1)
    assert made
    sim.stop('a')
    sim.on_event_hook = None
    who = leader_within(sim, I6, 'bcd')
    sim.run(sim.now + 10)
    sim.node(who).change_cfg(lambda body: dict(body, voters=[r for r in body['voters'] if r['id'] != 'a']))
    sim.run(sim.now + 20)
    assert 'a' not in sim.node(who).view.voters
    sim.heal_all()
    sim.boot('a')
    sim.run(sim.now + 120)
    assert sim.leader() == who
    assert made[0] not in sim.committed
    assert 'a' not in sim.node('a').view.voters


def s19_witness_chain(seed):
    """S-19: the witness misses two config changes that make a new data voter; the new
    voter's vote request carries the chain, the witness checks it and its vote counts.
    Real Ed25519 signatures."""
    sim = hs.Sim(seed, crypto='ed25519')
    sim.add('a')
    sim.add('b', may_lead=False)
    sim.add('c', voter=False)
    sim.add('w', kind=hv.KIND_WITNESS)
    sim.start('a', rates={i: sim.rng.uniform(0.9, 1.1) for i in sim.order})
    settle(sim)
    sim.cut('a', 'w')
    sim.node('a').change_cfg(lambda body: dict(body, voters=[dict(r, voter=True) if r['id'] == 'c' else r
                                                            for r in body['voters']]))
    sim._after(sim.members['a'])
    sim.run(sim.now + 10)
    sim.node('a').change_cfg(lambda body: dict(body, voters=[dict(r, site='x') if r['id'] == 'c' else r
                                                            for r in body['voters']]))
    sim._after(sim.members['a'])
    sim.run(sim.now + 10)
    assert sim.node('a').view.id[1] == 3 and sim.node('w').view.id[1] == 1
    t = sim.now
    sim.stop('a')
    sim.mark_heal()
    leader_within(sim, I6, 'c')
    epoch = elections_after(sim, t)[0][2]
    assert 'w' in sim.counted[('c', epoch)]
    assert sim.node('w').view.id[1] >= 3


def s20_four_and_witness(seed):
    """S-20: 4 data + witness: five votes, a majority of three; any two may go."""
    sim = group(seed, 'abcd', 'w')
    settle(sim)
    for i in sim.order:
        v = sim.node(i).view
        assert (v.n, v.m, len(v.data), v.witness) == (5, 3, 4, 'w')
    sim.run(sim.now + sim.rng.uniform(5, 20))
    two = sim.rng.sample('abcd', 2)
    if 'a' not in two:
        two[0] = 'a'
    for i in two:
        sim.stop(i)
    sim.mark_heal()
    who = leader_within(sim, I6, ''.join(i for i in 'abcd' if i not in two))
    sim.run(sim.now + 30)
    v = sim.node(who).view
    assert (v.n, v.m, len(v.data), v.witness) == (5, 3, 4, 'w')


def _delays(sim, table):
    for (x, y), d in table.items():
        sim.set_delay(x, y, d, 0.0)


def _campaign_together(sim):
    # a is gone; once its last renewals have landed, hold the timers until both
    # candidates' promises ran out, then start both
    sim.run(sim.now + 1)
    for i in 'bcd':
        sim.node(i).election_at = math.inf
    sim.run(sim.now + T.P / 0.9 + 1)
    t = sim.now
    for i in 'bc':
        assert sim.node(i).campaign_now() == ''
        sim._after(sim.members[i])
    return t


def s21_split_election(seed):
    """S-21: two members campaign at once and one wins the term with the other one's vote
    for itself on record: the loser takes the winner's renewals at that term (D4)."""
    sim = group(seed, 'abcd', 'w', writes=0.0)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    sim.stop('a')
    # both pre-votes pass before either real vote lands; b's real vote reaches d and w
    # first, c has voted for itself in the same term by then
    fast, slow = 0.010, 0.020
    _delays(sim, {('b', 'c'): fast, ('c', 'b'): fast, ('b', 'd'): fast, ('d', 'b'): fast,
                  ('b', 'w'): fast, ('w', 'b'): fast, ('c', 'd'): slow, ('d', 'c'): slow,
                  ('c', 'w'): slow, ('w', 'c'): slow})
    t = _campaign_together(sim)
    sim.mark_heal()
    leader_within(sim, I6)
    ups = elections_after(sim, t)
    assert ups[0][1] == 'b'
    E = ups[0][2]
    sim.run(sim.now + 10)
    c = sim.node('c')
    assert c.epoch == E and c.st['voted_for'] == 'b' and c.promise_to == 'b'
    assert len(elections_after(sim, t)) == 1


def s22_stale_candidate(seed):
    """S-22: the only timer candidate is stale and the fresh voter may not lead: the
    candidate catches up from it and wins; every write is held or captured."""
    sim = group(seed, 'abc', start=False, writes=0.9)
    sim.members['c'].may_lead = False
    sim.start('a', rates={i: sim.rng.uniform(0.9, 1.1) for i in sim.order})
    settle(sim)
    sim.members['b'].no_pull = True
    sim.run(sim.now + sim.rng.uniform(20, 60))
    sim.stop('a')
    sim.mark_heal()
    sim.members['b'].no_pull = False
    leader_within(sim, I6 + T.L, 'b')
    assert sim.counts.get('catchup')
    assert sim.node('b').cv >= sim.node('c').cv
    sim.boot('a')
    sim.run(sim.now + 60)
    assert sim.lost_writes() == []


def s23_reordered_rounds(seed):
    """S-23: rounds overlap and their answers cross and come late: nobody is quarantined."""
    sim = group(seed, 'abcd', 'w', steps=0.8, late=0.3, jitter=0.05)
    settle(sim)
    sim.run(sim.now + 200)
    assert not sim.counts.get('suspect')
    assert all(not (sim.node(i).view.cfg['body'].get('quarantined')) for i in sim.order)


def s24_mode_switch(seed):
    """S-24: switching automatic mode on with a member cut off, a manual promote while it
    is pending, switching on for real, and off again with a member cut off: never two act."""
    sim = group(seed, 'abc', start=False)
    sim.start('a', mode=hv.MODE_MANUAL, rates={i: sim.rng.uniform(0.9, 1.1) for i in sim.order})
    sim.run(5)
    assert sim.leader() == 'a'
    sim.partition('ab', 'c')
    assert sim.node('a').switch_on() == ''
    sim._after(sim.members['a'])
    sim.run(sim.now + 30)
    assert sim.node('b').view.mode == hv.MODE_PENDING
    assert sim.node('b').promote_manual(9) == 'HA_AUTO_MODE'
    sim.run(sim.now + hv.SWITCH_TIMEOUT / 0.9 + 5)
    assert sim.counts.get('switch_cancelled') and sim.node('a').view.mode == hv.MODE_MANUAL
    sim.run(sim.now + 30)
    assert sim.node('b').view.mode == hv.MODE_MANUAL
    sim.heal_all()
    assert sim.wait_for(lambda: sim.node('a').switch is None, 30)
    assert sim.node('a').switch_on() == ''
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: sim.node('a').view.mode == hv.MODE_AUTO and sim.leader() == 'a', 60)
    sim.run(sim.now + 30)
    assert all(sim.node(i).view.mode == hv.MODE_AUTO for i in 'abc')
    assert sim.node('b').manual_promote_refusal() == 'HA_AUTO_MODE'
    sim.partition('ab', 'c')
    assert sim.node('a').switch_off() == ''
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: sim.node('a').st['role'] == hv.ROLE_ACTIVE, 30)
    sim.run(sim.now + T.P + 2 * T.L)
    sim.heal_all()
    sim.run(sim.now + 60)
    assert sim.leader() == 'a'
    assert all(sim.node(i).view.mode == hv.MODE_MANUAL for i in 'abc')


def s25_split_no_block(seed):
    """S-25: a split vote between two candidates: each voter promised P, not the 80 s
    of a won election, so the next round finds a leader long before that."""
    sim = group(seed, 'abcd', 'w', writes=0.0)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    sim.stop('a')
    # b's votes reach d first, c's reach w first: two votes each
    fast, slow = 0.005, 0.05
    _delays(sim, {('b', 'c'): fast, ('c', 'b'): fast, ('b', 'd'): fast, ('d', 'b'): fast,
                  ('c', 'w'): fast, ('w', 'c'): fast, ('b', 'w'): slow, ('c', 'd'): slow})
    t = _campaign_together(sim)
    sim.run(t + 3)
    assert not elections_after(sim, t), 'the vote did not split'
    assert sim.wait_for(lambda: elections_after(sim, t), T.P + T.L + T.T_vote + 2), 'blocked'
    assert elections_after(sim, t)[0][0] - t < T.won_hold


# --- a lease cut short, a cold start at a long lease, a crash in the hand-over ---

def _lease_shrink(seed, old):
    """The admin shortens the lease from `old` to 15 s, then a voter restarts while the
    leader is cut off from it and the third member asks for its vote at once. The voter
    holds everyone but the leader off for as long as the longest lease it may have
    promised (1.1 old + D, not 1.1 x 15 + D), and the leader's lease shrank with the
    config: no two hold a lease, no two act, and the next leader acts within the old
    length's timings."""
    sim = group(seed, lease_s=old)
    settle(sim)
    t_old = hv.Timings(old)
    # c is cut off from a until its own promise to a ran out
    sim.cut('a', 'c')
    sim.run(sim.now + t_old.P / 0.9 + 5)
    a = sim.node('a')
    a.change_cfg(lambda body: dict(body, lease_s=hv.LEASE_MIN))
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: a.view.lease_s == hv.LEASE_MIN and a._is_committed(), 10, step=0.1)
    t = sim.now
    sim.cut('a', 'b')
    sim.crash('b', downtime=(1.0, 3.0))
    assert sim.wait_for(lambda: sim.node('b') is not None, 10, step=0.05)
    b_up = sim.members['b'].booted_at
    n = sim.node('c')
    if n._campaign is None:
        n.campaign_now()
        sim._after(sim.members['c'])
    t_new = hv.Timings(hv.LEASE_MIN)
    limit = (t_old.hold_after_start + t_new.L + t_old.T_vote + t_old.W_take) / 0.9 + 10
    leader_within(sim, b_up - sim.now + limit, 'bc')
    # every vote needs b, and b's clock may run 10% fast
    assert elections_after(sim, t)[0][0] >= b_up + t_old.hold_after_start / 1.1
    sim.run(sim.now + 30)


def lease_shrink_60(seed):
    _lease_shrink(seed, 60)


def lease_shrink_120(seed):
    _lease_shrink(seed, 120)


def cold_start_long_lease(seed):
    """The whole group starts cold at a long lease (75 or 120 s), the voters 1-3 s after
    the leader: its boot round goes out again every second, so it acts within boot_wait
    instead of booting as a standby and waiting minutes for an election."""
    L = (75, 120)[seed % 2]
    sim = group(seed, lease_s=L, start=False)
    rates = {i: sim.rng.uniform(0.9, 1.1) for i in sim.order}
    sim.start('a', rates=rates, boot_at={i: sim.rng.uniform(1.0, 3.0) for i in 'bc'})
    leader_within(sim, T.boot_wait, 'a')
    assert not sim.counts.get('boot_standby') and not sim.elections
    sim.run(sim.now + 2 * L)
    assert sim.leader() == 'a'


def transfer_crash_in_wait(seed):
    """Make leader: a hands its term to b and crashes in the wait phase, b's process
    stalls before its campaign goes out, and a is back in a second or two. The hand-over
    was on disk before release_to went out, so a comes back as a standby and never renews
    in the term it gave away; b wins on the allowances and nobody holds a lease next to
    it. Half the seeds take the winner in-process (S10)."""
    sim = group(seed, 'abcd', 'w', restart_on_win=seed % 2 == 0)
    settle(sim)
    sim.run(sim.now + sim.rng.uniform(5, 20))
    t = sim.now

    def on_release(m, name, info):
        if m.iid == 'a' and name == 'round' and info.get('kind') == 'release':
            sim.after(0.05, sim.pause, 'b')
    sim.on_event_hook = on_release
    assert sim.node('a').transfer_to('b') == ''
    sim._after(sim.members['a'])

    def waiting():
        n = sim.node('a')
        return n is not None and n.transfer is not None and n.transfer['phase'] == 'wait'
    assert sim.wait_for(waiting, hv.TRANSFER_CATCHUP + 5, step=0.01), 'a never handed over'
    sim.on_event_hook = None
    sim.crash('a', downtime=(1.0, 2.0))
    # b's vote request never reaches a
    sim.cut('b', 'a', both=False)
    assert sim.wait_for(lambda: sim.node('a') is not None, 5, step=0.05)
    sim.run(sim.now + sim.rng.uniform(0.5, 3.0))
    a = sim.node('a')
    assert a.st['role'] == hv.ROLE_STANDBY and not a.holds_lease()
    sim.resume('b')
    leader_within(sim, T.W_take / 0.9 + 10, 'b')
    assert [(e[1], e[2], e[3]) for e in elections_after(sim, t)] == [('b', 2, 'transfer')]
    sim.heal_all()
    sim.run(sim.now + 60)
    assert sim.leader() == 'b'


def _changes(sim, leader, k):
    """k config changes on `leader`, each committed before the next goes out."""
    n = sim.node(leader)
    for j in range(k):
        site = f'x{j}'

        def change(body, site=site):
            return dict(body, voters=[dict(r, site=site) if r['id'] == leader else r
                                      for r in body['voters']])
        n.change_cfg(change)
        sim._after(sim.members[leader])
        assert sim.wait_for(lambda: n._is_committed() and n.view.records[leader]['site'] == site,
                            5, step=0.02), f'change {j} never committed'


RESTARTS = ('crash', 'reboot', 'reboot, renewal, crash')


def _restart_in_promise(sim, who, leader, asker, how):
    """`who` restarts cut off from `leader`: its process crashes, its host reboots, or its
    host reboots, it takes one more renewal (a short promise) and then crashes. `asker`
    asks for its vote the moment it is back. Returns the first restart's time and the true
    time the promise it made before runs to; its clock keeps its rate."""
    m = sim.members[who]
    left = m.node.lease_promise_until - m.node.clock()
    assert left > hv.Timings(hv.LEASE_MIN).hold_after_start, 'no long promise left'
    t = sim.now
    sim.cut(leader, who)
    if how == 'crash':
        sim.crash(who, downtime=(0.5, 3.0))
    else:
        sim.reboot_host(who, downtime=(0.5, 3.0))
    assert sim.wait_for(lambda: sim.node(who) is not None, 5, step=0.05)
    if how == 'reboot, renewal, crash':
        sim.heal(leader, who)
        assert sim.wait_for(lambda: sim.node(who).promise_to == leader, 10, step=0.05)
        sim.cut(leader, who)
        sim.crash(who, downtime=(0.5, 3.0))
        assert sim.wait_for(lambda: sim.node(who) is not None, 5, step=0.05)
    n = sim.node(asker)
    if n._campaign is None:
        n.campaign_now()
        sim._after(sim.members[asker])
    return t, t + left / m.clock.rate


def _held_off(sim, t, end):
    """Nobody wins before `end`, and a new leader acts after it within an election, the
    restart of the winner and W_take at 15 s."""
    t15 = hv.Timings(hv.LEASE_MIN)
    limit = end - sim.now + (t15.L + t15.T_vote + 25 + t15.W_take) / 0.9 + 10
    assert sim.wait_for(lambda: elections_after(sim, t) and sim.leader() is not None, limit), \
        f'no new leader within {limit:.0f} s'
    assert elections_after(sim, t)[0][0] >= end


def lease_trimmed_off(seed):
    """The lease goes from 120 s down to 15 s and 16 more changes push the 120 s config out
    of every chain (CFG_KEEP) while b's promise from a 120 s round runs on. b restarts cut
    off from the leader (a crash, a host reboot, or a reboot, one more renewal and a
    crash: the record has to outlive the short promise of the new boot), and c asks for
    its vote the moment b is back. No config on disk covers that promise any more: b wrote
    it down with the change that took the cover away, and holds c off until it ends."""
    sim = group(seed, lease_s=hv.LEASE_MAX, steps=1.0)
    settle(sim)
    # c's own promise to a runs out; it takes the 15 s config, then is cut off again
    sim.cut('a', 'c')
    sim.run(sim.now + hv.Timings(hv.LEASE_MAX).P / 0.9 + 5)
    a = sim.node('a')
    a.change_cfg(lambda body: dict(body, lease_s=hv.LEASE_MIN))
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: a.view.lease_s == hv.LEASE_MIN and a._is_committed(), 10, step=0.05)
    sim.heal('a', 'c')
    assert sim.wait_for(lambda: sim.node('c').view.lease_s == hv.LEASE_MIN, 5, step=0.02)
    sim.cut('a', 'c')
    _changes(sim, 'a', hv.CFG_KEEP)
    assert hv.longest_lease(sim.node('b').chain) == hv.LEASE_MIN
    sim.run(sim.now + hv.Timings(hv.LEASE_MIN).hold_after_start)
    t, end = _restart_in_promise(sim, 'b', 'a', 'c', RESTARTS[seed % 3])
    _held_off(sim, t, end)


def branch_dropped(seed):
    """a grows the lease from 15 s to 120 s while cut off: the change reaches nobody and
    stays on a's disk. b and c elect one of them; a, back as a standby, takes the winner's
    renewals and promises 1.1 x 120 s by the config it holds, until the winner's own config
    of its term leaves that one behind. Then a restarts cut off from the winner (as in
    lease_trimmed_off), and the third member asks at once: a holds it off until the
    promise ends."""
    sim = group(seed, lease_s=hv.LEASE_MIN, steps=1.0)
    sim.members['a'].downtime = (0.5, 2.0)
    settle(sim)
    sim.run(sim.now + 5)
    sim.partition(['a'], ['b', 'c'])
    a = sim.node('a')
    a.change_cfg(lambda body: dict(body, lease_s=hv.LEASE_MAX))
    sim._after(sim.members['a'])
    sim.run(sim.now + 1)
    assert a.view.lease_s == hv.LEASE_MAX and not a._is_committed()
    assert sim.wait_for(lambda: max(sim.winners) > 1, 200, step=0.2), 'no election'
    term = max(sim.winners)
    new = sim.winners[term]
    third = 'c' if new == 'b' else 'b'
    assert sim.wait_for(lambda: sim.node('a') is not None, 10, step=0.1)
    sim.heal_all()
    assert sim.wait_for(lambda: sim.node('a').view.id[0] == term, 120, step=0.2), 'a never took the new term'
    assert hv.longest_lease(sim.node('a').chain) == hv.LEASE_MIN
    # the third member's promise to the winner runs out, the winner leads on with a
    sim.cut(new, third)
    sim.run(sim.now + hv.Timings(hv.LEASE_MIN).P / 0.9 + 2)
    t, end = _restart_in_promise(sim, 'a', new, third, RESTARTS[seed % 3])
    _held_off(sim, t, end)


def reboot_on_a_fast_clock(seed):
    """b's lease clock runs 10% slow until its host reboots right after a renewal, and 10%
    fast after; the leader, 10% slow as well, is cut off from b, and c asks every half
    second from the moment b is back. b holds c off for 1.1 L + D on the fast clock, which
    is L + D / 1.1 of true time from its start: past every lease that rests on its promise
    (I1) and past what the promise is sure to cover (I4). The rest of the promise read at
    the slow rate would still run then; the simulator once took that for I4."""
    L = (60, 90, 120)[seed % 3]
    sim = hs.Sim(seed, lease_s=L, steps=1.0)
    sim.add('a')
    sim.add('b', may_lead=False)
    sim.add('c')
    sim.start('a', rates={'a': 0.9, 'b': 0.9, 'c': 1.0})
    settle(sim)
    sim.cut('a', 'c')
    sim.run(sim.now + hv.Timings(L).P / 0.9 + 5)
    b = sim.members['b']
    seen = {}

    def on_event(m, name, info):
        if m is b and name == 'promise' and 'left' not in seen:
            seen['left'] = info['until'] - m.node.clock()
            sim.after(0.001, reboot)
        elif m is b and name == 'granted' and 'grant' not in seen:
            seen['grant'] = sim.now

    def reboot():
        seen['t'] = sim.now
        sim.cut('a', 'b')
        sim.reboot_host('b', downtime=(0.5, 2.0))
        sim.set_rate('b', 1.1)

    def ask():
        n = sim.node('c')
        if 'grant' not in seen and n is not None and n._campaign is None and not n.is_active():
            n.campaign_now()
            sim._after(sim.members['c'])
        if 'grant' not in seen:
            sim.after(0.5, ask)
    sim.on_event_hook = on_event
    assert sim.wait_for(lambda: sim.node('b') is None, hv.Timings(L).R + 1, step=0.01)
    assert sim.wait_for(lambda: sim.node('b') is not None, 5, step=0.05)
    hold_end = b.booted_at + sim.node('b').t.hold_after_start / 1.1
    ask()
    leader_within(sim, (hv.Timings(L).hold_after_start + hv.Timings(L).W_take) / 0.9 + 60, 'c')
    assert hold_end <= seen['grant'] < seen['t'] + seen['left'] / 0.9


# --- clocks off the majority of the members (Q15) ---

def skewed_member_loses_the_race(seed):
    """Lab C2: b's wall clock is 30 s off every other one. The leader goes away (for good
    or for a while): a member with a right clock wins every time, within I6 as S-1 has
    it. Returns whether b voted for the winner (it keeps voting)."""
    sim = group(seed, 'abcd', 'w')
    settle(sim)
    # up for longer than the step: a process estimates its start by the wall clock as it
    # reads now, and refuses calls signed before that (ha._process_started)
    sim.run(sim.now + 60)
    sim.wall_step('b', 30 if seed % 2 else -30)
    sim.run(sim.now + hs.WATCH_EVERY + 1)
    assert sim.skewed('b') and not any(sim.skewed(i) for i in 'acd')
    sim.run(sim.now + sim.rng.uniform(0, 20))
    t = sim.now
    lost = sim.counts.get('lost', 0)
    if seed % 4 < 2:
        sim.stop('a')
    else:
        sim.crash('a')
    sim.mark_heal()
    sim.run(t + I6 + 5)
    took = sim.time_to_leader()
    bound = I6_TIGHT if sim.counts.get('lost', 0) == lost else I6
    assert took is not None and took <= bound, f'took {took}'
    ups = elections_after(sim, t)
    assert all(who != 'b' for _t, who, _e, _why in ups), f'b won: {ups}'
    if not ups:
        # a came back and renewed before anybody's timer ran out
        assert seed % 4 >= 2 and sim.leader() == 'a'
        return False
    _t, who, e, _why = ups[0]
    return any(v == 'b' for v, *_rest in sim.grants.get((who, e), ()))


def all_clocks_apart(seed):
    """Every wall clock 12 s off the next one, the witness's too: every data member is off
    the majority of what it measures and puts its campaign off. One is elected all the
    same, at most one lease later than I6 allows. Returns how long it took."""
    sim = group(seed, 'abcd', 'w')
    settle(sim)
    sim.run(sim.now + 60)
    order = list('abcdw')
    sim.rng.shuffle(order)
    sim.set_walls({iid: 12.0 * k for k, iid in enumerate(order)})
    sim.run(sim.now + hs.WATCH_EVERY + 1)
    assert all(sim.skewed(i) for i in 'abcd')
    sim.run(sim.now + sim.rng.uniform(0, 20))
    t = sim.now
    lost = sim.counts.get('lost', 0)
    sim.stop('a')
    sim.mark_heal()
    sim.run(t + I6 + T.L / 0.9 + 5)
    took = sim.time_to_leader()
    bound = (I6_TIGHT if sim.counts.get('lost', 0) == lost else I6) + T.L / 0.9
    assert took is not None and took <= bound, f'took {took}'
    assert sim.counts.get('campaign_deferred')
    return took


def only_member_off_loses_twice(seed):
    """b is the last data member that can lead, 30 s off a and the witness, and the first
    two campaigns it runs fail (the witness misses them). It waits its lease once, not
    once per try: a leader within I6 plus one lease, as any group whose clocks drifted
    apart. Returns how often b put its campaign off."""
    sim = group(seed, 'ab', 'w')
    settle(sim)
    sim.run(sim.now + 60)
    sim.wall_step('b', 30 if seed % 2 else -30)
    sim.run(sim.now + hs.WATCH_EVERY + 1)
    assert sim.skewed('b') and not sim.skewed('a')
    sim.run(sim.now + sim.rng.uniform(0, 20))
    tries = []

    def on_prevote(m, name, info):
        if m.iid == 'b' and name == 'prevote':
            tries.append(sim.now)
            if len(tries) <= 2:
                sim.cut('b', 'w')
                sim.after(T.T_vote + 0.5, sim.heal, 'b', 'w')
    sim.on_event_hook = on_prevote
    t = sim.now
    before = sim.counts.get('campaign_deferred', 0)
    sim.stop('a')
    sim.mark_heal()
    sim.run(t + I6 + T.L / 0.9 + 5)
    took = sim.time_to_leader()
    assert took is not None and took <= I6 + T.L / 0.9, f'took {took}'
    assert sim.leader() == 'b' and len(tries) == 3
    return sim.counts.get('campaign_deferred', 0) - before


def fuzz(seed, walls=False):
    """Random faults for 400 s on a random layout - partitions, directed and dropping
    cuts, crashes, SIGSTOP pauses, slews, host reboots, transfers, planned restarts,
    changes of the lease length anywhere in 15-120 s, a disk that fails the next few
    writes, and early campaigns - then a heal: I1-I8 throughout, a leader within I6 by
    the longest lease in play, no write lost. Half the seeds start at a random lease.
    With `walls` the wall clocks step as well, a few seconds or past the signature
    window, and the heal leaves them apart (within the window): the members off the
    majority put their campaigns off (Q15), and the leader may come one lease later,
    plus the time a member that restarts at the heal refuses calls signed before its
    start by the clocks behind its own.
    Returns whether the leader came later than I6 as the design states it."""
    layouts = (('abc', ''), ('abcd', ''), ('abc', 'w'), ('ab', 'w'), ('abcd', 'w'))
    lease_s = hv.LEASE_DEFAULT if seed % 2 else random.Random(seed).randint(hv.LEASE_MIN, hv.LEASE_MAX)
    sim = hs.Sim(seed, lease_s=lease_s, late=0.01)
    longest = [lease_s]
    rng = sim.rng
    data, wit = layouts[seed % len(layouts)]
    for i in data:
        sim.add(i, may_lead=(i in 'ab') or rng.random() < 0.7,
                voter=(i in 'abc') or rng.random() < 0.7 or not wit)
    for i in wit:
        sim.add(i, kind=hv.KIND_WITNESS)
    sim.start('a', rates={i: rng.uniform(0.9, 1.1) for i in sim.order})
    ids = list(sim.order)
    end = 430.0

    def fault():
        if sim.now > end:
            return
        if walls and rng.random() < 0.2:
            # a step a member's watch sees as skew, or one past the signature window
            far = rng.random() < 0.3
            step = rng.uniform(130, 300) if far else rng.uniform(6, 40)
            sim.wall_step(rng.choice(ids), step if rng.random() < 0.5 else -step)
            sim.after(rng.uniform(3, 25), fault)
            return
        r = rng.random()
        x = rng.choice(ids)
        if r < 0.15:
            g = rng.sample(ids, rng.randint(1, len(ids) - 1))
            sim.partition(g, [i for i in ids if i not in g])
            sim.after(rng.uniform(5, 60), sim.heal_all)
        elif r < 0.3:
            y = rng.choice([i for i in ids if i != x])
            sim.cut(x, y, both=rng.random() < 0.5, how=rng.choice(('blackhole', 'drop')))
            sim.after(rng.uniform(5, 60), sim.heal, x, y)
        elif r < 0.4:
            sim.isolate(x)
            sim.after(rng.uniform(5, 60), sim.heal_all)
        elif r < 0.55:
            sim.crash(x)
        elif r < 0.65:
            sim.pause(x)
            sim.after(rng.uniform(1, 40), sim.resume, x)
        elif r < 0.75:
            sim.set_rate(x, rng.uniform(0.9, 1.1))
        elif r < 0.8:
            sim.reboot_host(x)
        elif r < 0.88:
            ld = sim.leader()
            cands = [i for i in ids if i != ld and sim.members[i].kind == hv.KIND_DATA]
            if ld is not None and cands:
                sim.node(ld).transfer_to(rng.choice(cands))
                sim._after(sim.members[ld])
        elif r < 0.91:
            ld = sim.leader()
            if ld is not None:
                sim.node(ld).planned_restart()
                sim._after(sim.members[ld])
        elif r < 0.94:
            # another lease length, through the voter config
            ld = sim.leader()
            if ld is not None:
                L = rng.randint(hv.LEASE_MIN, hv.LEASE_MAX)
                longest.append(L)
                sim.node(ld).change_cfg(lambda body, L=L: dict(body, lease_s=L))
                sim._after(sim.members[ld])
        elif r < 0.97:
            # a full disk: the next writes of x fail
            sim.members[x].store.fail = rng.randint(1, 3)
        else:
            n = sim.node(x)
            if n is not None and not sim.members[x].paused:
                n.campaign_now()
                sim._after(sim.members[x])
        sim.after(rng.uniform(3, 25), fault)

    sim.at(30, fault)
    sim.run(end)
    sim.heal_all()
    spread = 0.0
    if walls:
        # apart but inside the window: every clock 6-12 s off the next in half the seeds
        # (each member off the majority), within +-15 s of each other in the rest
        order = list(ids)
        rng.shuffle(order)
        if seed % 4 < 2:
            gap = rng.uniform(6, 12)
            offsets = {iid: gap * k for k, iid in enumerate(order)}
        else:
            offsets = {iid: rng.uniform(-15, 15) for iid in order}
        sim.set_walls(offsets)
        spread = max(offsets.values()) - min(offsets.values())
    for i in ids:
        sim.members[i].store.fail = 0
        sim.resume(i)
        if not sim.members[i].up:
            sim.boot(i)
    sim.mark_heal()
    # holds after start and W_take follow the longest lease a chain may still hold
    t = hv.Timings(max(longest))
    bound = (hs.bound_i6(t) + t.hold_after_start + t.L) / 0.9
    if walls:
        # one lease of deferral (Q15), and a member that restarted at the heal is deaf to
        # the clocks behind its own for up to the spread
        bound += (t.L + spread) / 0.9
    sim.run(end + bound + 20)
    took = sim.time_to_leader()
    assert took is not None and took <= bound, f'no leader {took} s after the heal'
    assert sim.lost_writes() == []
    return took > hs.bound_i6(t) / 0.9


SCENARIOS = [
    s1_leader_crash, s2_two_two_wan_cut, s3_witness_third_site, s4_three_one, s5_one_way_cut,
    s6_witness_then_voter, s7_flapping, s8_clock_rates, s9_frozen_leader, s10_wall_jump,
    s11_voter_restart, s12_rollback, s13_transfer, s14_break_glass, s15_change_in_partition,
    s16_real_vote_fails, s17_late_campaign, s18_uncommitted_witness, s19_witness_chain,
    s20_four_and_witness, s21_split_election, s22_stale_candidate, s23_reordered_rounds,
    s24_mode_switch, s25_split_no_block,
    lease_shrink_60, lease_shrink_120, cold_start_long_lease, transfer_crash_in_wait,
    lease_trimmed_off, branch_dropped, reboot_on_a_fast_clock,
]


@pytest.fixture
def auto_shipped(monkeypatch):
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)


@pytest.mark.parametrize('scenario', [s for s in SCENARIOS if s is not s24_mode_switch],
                         ids=lambda s: s.__name__)
def test_scenario(scenario):
    _each(scenario)


def test_s24_mode_switch(auto_shipped):
    _each(s24_mode_switch)


# --- counterproofs: each check sees what it is there for ---

def forgotten_promise(seed, keep_w_take=True):
    """A voter restarts and forgets its promise at once (the hold after start taken out),
    and votes for a member cut off from the leader whose lease rests on that promise.
    The leader never hears that it lost the term and acts until its lease runs out."""
    sim = group(seed, keep_w_take=keep_w_take, restart_on_win=False, collect=True, steps=1.0)
    settle(sim)
    sim.cut('a', 'c')
    sim.run(sim.now + T.P + T.L)
    sim.members['b'].hold_disabled = True
    sim.set_delay('a', 'b', 1.5, 0.0)
    sim.crash('b', downtime=(0.2, 0.5))
    sim.wait_for(lambda: sim.node('b') is not None, 5, step=0.02)
    sim.cut('b', 'a', both=False)
    n = sim.node('c')
    if n._campaign is None:
        n.campaign_now()
        sim._after(sim.members['c'])
    sim.run(sim.now + 60)
    return sim.broken()


def test_w_take_keeps_acting_apart_when_a_voter_forgot_its_promise():
    """4.14 point 3: two leases at once (I1), a vote against a running promise (I4), and
    still the two acting intervals stay apart (I3)."""
    hits = set()
    for seed in _seeds(50):
        broken = forgotten_promise(seed)
        assert 'I3' not in broken, seed
        hits |= broken
    assert {'I1', 'I4'} <= hits


def test_the_short_takeover_wait_rests_on_every_promise():
    """What Q2's other choice costs: with W_take = D + G a forgotten promise lets two act."""
    hits = set()
    for seed in _seeds(50):
        hits |= forgotten_promise(seed, keep_w_take=False)
    assert 'I3' in hits


def test_a_promise_lost_over_a_reboot_is_caught(monkeypatch):
    """I4 across a host reboot still bites at the rate a promise is sure to run: a voter
    that drops its record at the reboot, or that does not write it down again on the new
    boot's clock and loses it with the next crash, grants c (or votes for itself) inside
    the promise."""
    orig = hv.Node.__init__

    def drop_at_reboot(self, me, kind, *, store, boot_id='', **kw):
        rec = store.load().get('promised')
        if rec and rec.get('boot_id') != boot_id:
            store.state = dict(store.state, promised=None)
        orig(self, me, kind, store=store, boot_id=boot_id, **kw)
    monkeypatch.setattr(hv.Node, '__init__', drop_at_reboot)
    assert 'I4' in _first_violation(lease_trimmed_off, range(1, 30, 3))

    def not_carried(self, *a, **kw):
        orig(self, *a, **kw)
        self._promised_until = -math.inf
    monkeypatch.setattr(hv.Node, '__init__', not_carried)
    assert 'I4' in _first_violation(lease_trimmed_off, range(2, 30, 3))


def _first_violation(scenario, seeds):
    for seed in seeds:
        try:
            scenario(seed)
        except Violation as e:
            return str(e)
        except AssertionError:
            pass
    return ''


def test_a_lease_without_its_margin_is_caught(monkeypatch):
    orig = hv.Timings.__init__

    def no_margin(self, lease_s=hv.LEASE_DEFAULT, keep_w_take=True):
        orig(self, lease_s, keep_w_take)
        self.per_round = self.P
    monkeypatch.setattr(hv.Timings, '__init__', no_margin)
    assert 'I1' in _first_violation(s8_clock_rates, range(0, 200, 2))


def late_answers(seed):
    """The leader's clock runs 10% slow, its answers take 1.9 s, then it is cut off."""
    sim = group(seed, rates=False, start=False, steps=1.0)
    sim.start('a', rates={'a': 0.9, 'b': 1.0, 'c': 1.0})
    settle(sim)
    for o in 'bc':
        sim.set_delay(o, 'a', 1.9, 0.0)
    sim.run(sim.now + 10)
    sim.isolate('a')
    sim.run(sim.now + 40)


def test_a_lease_counted_from_the_answer_is_caught(monkeypatch):
    assert _first_violation(late_answers, range(20)) == ''
    orig = hv.Node._majority

    def from_receipt(self, r, now):
        orig(self, r, now)
        if r.kind in ('renew', 'boot'):
            self.lease_until = max(self.lease_until, now + self._per_round(r.lease_s))
    monkeypatch.setattr(hv.Node, '_majority', from_receipt)
    assert 'I7' in _first_violation(late_answers, range(20))


def lease_from_an_older_round(seed):
    """The leader holds its lease from a 120 s round, shortens the lease to 100 s (with less
    left than a 100 s round gives, nothing to cut) and commits one more change through
    answers that each come in a round without a majority. Two configs on, the lease still
    rests on the 120 s round, which neither the view nor the config before it names."""
    sim = group(seed, 'abcd', 'w', lease_s=120, rates=False, start=False, steps=0.0, writes=0.0)
    sim.start('a', rates={i: 1.0 for i in sim.order}, skew=0.0)
    settle(sim)
    a, ma = sim.node('a'), sim.members['a']
    # a voter not up yet at a's boot round is passed by confirm rounds until a renewal
    # reaches it (ha_vote Node._unreached): one every R, and then all are asked
    sim.run(sim.now + hv.Timings(120).R + 1)
    assert not a._unreached

    def only(x):
        for o in 'bcdw':
            (sim.heal if o == x else sim.cut)('a', o)

    def round_now():
        a.confirm(0, lambda ok: None)
        sim._after(ma)
        sim.run(sim.now + 0.5)
    only('b')
    t0 = ma.lease_t0
    sim.run(sim.now + 25)
    a.change_cfg(lambda body: dict(body, lease_s=100))
    sim._after(ma)
    sim.run(sim.now + 0.5)
    round_now()
    only('c')
    round_now()
    assert a.view.lease_s == 100 and a._is_committed()
    a.change_cfg(lambda body: dict(body, voters=[dict(r, site='x') if r['id'] == 'a' else r
                                                 for r in body['voters']]))
    sim._after(ma)
    sim.run(sim.now + 0.5)
    round_now()
    only('b')
    round_now()
    assert a._is_committed() and a.view.id == (1, 3) and ma.lease_t0 == t0
    sim.run(t0 + hv.Timings(100).per_round / 0.9 + 2)
    assert a.holds_lease()
    sim.run(t0 + hv.Timings(120).per_round + 1)
    assert not a.holds_lease()


def test_i7_counts_each_round_by_the_lease_it_asked_for(monkeypatch):
    for seed in _seeds(20):
        lease_from_an_older_round(seed)
    # a round counted by the longest lease in the chain instead of the one it asked for
    orig = hv.Node._majority

    def by_longest(self, r, now):
        orig(self, r, now)
        if r.kind in ('renew', 'boot') and r.majority:
            self.lease_until = max(self.lease_until,
                                   r.t0 + self._per_round(hv.longest_lease(self._chain)))
    monkeypatch.setattr(hv.Node, '_majority', by_longest)
    assert 'I7' in _first_violation(lease_shrink_120, range(10))


def test_a_re_term_is_caught(monkeypatch):
    """The draft's re-term (A1): a leader that sees a higher epoch takes it on instead of
    stepping down, and renews at an epoch nobody elected it for."""
    orig = hv.Node._step_down

    def re_term(self, now, why):
        seen = re.search(r'epoch (\d+)', why)
        if seen and self.st['role'] == hv.ROLE_LEADER:
            e = int(seen.group(1))
            self.st = dict(self.st, epoch=e, voted_for=self.me, led=dict(self.st['led'], epoch=e))
            return
        return orig(self, now, why)
    monkeypatch.setattr(hv.Node, '_step_down', re_term)
    assert 'I2' in _first_violation(s9_frozen_leader, range(20))


def test_a_vote_for_a_stale_candidate_is_caught(monkeypatch):
    orig = hv.Node._vote_rules

    def lax(self, *a):
        why = orig(self, *a)
        return '' if why in ('STALE', 'BELOW_FLOOR') else why
    monkeypatch.setattr(hv.Node, '_vote_rules', lax)
    assert 'I5' in _first_violation(s22_stale_candidate, range(20))


def test_a_change_of_two_voters_at_once_is_refused_and_caught(monkeypatch):
    def swap(body):
        voters = [r for r in body['voters'] if r['id'] != 'd']
        return dict(body, voters=voters, witness=None) if body.get('witness') else None

    def run(seed):
        sim = group(seed, 'abcd', 'w')
        settle(sim)
        sim.node('a').change_cfg(swap)
        sim._after(sim.members['a'])
        sim.run(sim.now + 20)
        return sim
    sim = run(0)
    assert sim.counts.get('change_refused') and sim.node('a').view.n == 5
    # without the guard the change goes through and the simulator sees it
    monkeypatch.setattr(hv, 'majorities_intersect', lambda a, b: True)
    assert 'I8' in _first_violation(run, range(5))


def d4_binding(seed):
    """c voted for b in the term a won, then took a's renewals (D4); a leads with c and d
    while b and the witness are cut off from it. c restarts and b asks for its vote the
    moment c is back. a's lease rests on the promise c forgot."""
    sim = group(seed, 'abcd', 'w', restart_on_win=False, collect=True, writes=0.0, start=False)
    sim.start('a', rates={i: sim.rng.uniform(0.95, 1.05) for i in sim.order})
    c = sim.members['c']
    c.store.state = dict(c.store.state, voted_for='b')
    for o in 'bw':
        sim.cut('a', o)
    settle(sim)
    sim.run(sim.now + T.hold_after_start + 2)
    sim.set_delay('a', 'c', 1.5, 0.0)
    sim.crash('c', downtime=(0.2, 0.4))
    sim.wait_for(lambda: sim.node('c') is not None, 5, step=0.02)
    n = sim.node('b')
    if n._campaign is None:
        n.campaign_now()
        sim._after(sim.members['b'])
    sim.run(sim.now + 40)
    return sim.broken()


def test_a_voter_binds_to_the_winner_of_its_term(monkeypatch):
    """The voter keeps its vote of record on the winner once it takes its renewals; with
    the loser left on record (the design's D4 wording) the hold after start lets the loser
    through and two hold a lease."""
    for seed in _seeds(30):
        assert not d4_binding(seed), seed
    orig = hv.Node._save

    def keep_the_loser(self, chain=None, promised=-math.inf, **changes):
        if chain is None and set(changes) == {'voted_for'}:
            return True
        return orig(self, chain=chain, promised=promised, **changes)
    monkeypatch.setattr(hv.Node, '_save', keep_the_loser)
    hits = set()
    for seed in _seeds(30):
        hits |= d4_binding(seed)
    assert 'I1' in hits and 'I3' not in hits


def test_random_faults():
    late = _each(fuzz)
    # I6 as the design states it holds in nearly every run; what goes past it is a heal
    # that restarted members or a vote that lost an answer (see I6 above)
    assert sum(late) <= max(2, len(late) // 50)


# --- clocks off the majority (Q15) ---

def fuzz_walls(seed):
    return fuzz(seed, walls=True)


def test_a_member_off_the_majority_loses_the_race_and_keeps_voting():
    voted = _each(skewed_member_loses_the_race)
    # whenever its vote was asked in time, it gave it
    assert any(voted)


def test_a_group_whose_clocks_all_drifted_apart_still_elects():
    _each(all_clocks_apart)


def test_random_faults_with_wall_clocks_apart():
    """I1-I8 with clocks that step, some past the signature window, and a leader after
    the heal with the clocks still apart."""
    _each(fuzz_walls)


def _on_time(self, now):
    # Node._maybe_campaign without Q15: the timer alone decides
    if not self._timer_candidate():
        return
    if self._promise_live(now):
        self.election_at = self.promise_until + self.rng.uniform(0, self.t.L / 4)
        return
    self._prevote(now, 'timer')


def _first_failure(scenario, seeds):
    """The first assertion or violation of `scenario` over `seeds`, '' for none."""
    for seed in seeds:
        try:
            scenario(seed)
        except AssertionError as e:
            return f'seed {seed}: {e}'
    return ''


def test_without_the_deferral_a_member_off_the_majority_wins(monkeypatch):
    assert _first_failure(skewed_member_loses_the_race, range(20)) == ''
    monkeypatch.setattr(hv.Node, '_maybe_campaign', _on_time)
    assert 'b won' in _first_failure(skewed_member_loses_the_race, range(40))


def test_a_deferral_without_end_elects_nobody(monkeypatch):
    """The deferral counts once per timer. One that holds for as long as the clock is off
    leaves a group whose clocks all drifted apart without a leader."""
    def every_time(self, now):
        if self._timer_candidate() and not self._promise_live(now) and self.skewed():
            self.election_at = now + self.t.L
            return
        _on_time(self, now)
    monkeypatch.setattr(hv.Node, '_maybe_campaign', every_time)
    assert 'took None' in _first_failure(all_clocks_apart, range(5))


def test_a_member_off_the_majority_waits_its_lease_once_not_once_per_try():
    """A lost try of its own brings no second wait (I6 plus one lease, not one per round)."""
    assert set(_each(only_member_off_loses_twice)) == {1}


def test_a_wait_per_lost_try_leaves_the_group_without_a_leader_too_long(monkeypatch):
    """Counterproof: a back-off that brings a deferral of its own adds a lease to every
    round the member loses, and the leader comes later than I6 plus one lease."""
    arm = hv.Node._arm_timer

    def every_try(self, now, backoff=None):
        arm(self, now, backoff)
        self.deferred_at = None
    monkeypatch.setattr(hv.Node, '_arm_timer', every_try)
    assert 'took' in _first_failure(only_member_off_loses_twice, range(20))


def _isolated_after_shrink(seed):
    sim = group(seed, lease_s=120, steps=1.0)
    settle(sim)
    a = sim.node('a')
    a.change_cfg(lambda body: dict(body, lease_s=15))
    sim._after(sim.members['a'])
    assert sim.wait_for(lambda: a.view.lease_s == 15 and a._is_committed(), 10, step=0.05)
    sim.run(sim.now + 200)
    sim.isolate('a')
    sim.run(sim.now + 150)


def test_i7_goes_by_the_lease_the_round_sent(monkeypatch):
    """A leader that counts a round by the longest lease in its chain and says so in its
    own event: I7 takes the lease from the round as it went out, not from the node, so
    it is caught as I7 and not only once a second leader shows up (I1)."""
    for seed in _seeds(5):
        _isolated_after_shrink(seed)
    orig = hv.Node._majority

    def by_longest_and_says_so(self, r, now):
        orig(self, r, now)
        if r.kind in ('renew', 'boot') and r.majority:
            L = hv.longest_lease(self._chain)
            self.lease_until = max(self.lease_until, r.t0 + self._per_round(L))
            self._event('lease', tag=r.tag, t0=r.t0, until=self.lease_until,
                        acks=frozenset(r.acks), lease_s=L)
    monkeypatch.setattr(hv.Node, '_majority', by_longest_and_says_so)
    assert 'I7' in _first_violation(_isolated_after_shrink, range(10))
