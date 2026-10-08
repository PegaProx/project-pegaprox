"""The vote and lease rules of automatic failover (#625 stage 2), one instance at a time.

pegaprox/core/ha_vote.py has no I/O of its own: a Node here gets a clock the test turns
by hand, a dict for a state file and a list for what it sends. The simulator in
test_ha_vote_sim.py runs whole groups; these pin each rule on its own, with a case
next to it that the rule exists for.

MK Oct 2026 (#625)
"""
import base64
import hashlib
import math
import random
import time

import pytest

from pegaprox.core import ha_vote as hv


def _keys(iid):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'k' + iid.encode()).digest())
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode(), hv.ed25519_signer(base64.b64encode(raw).decode())


KEYS = {i: _keys(i) for i in 'abcdefw'}
T = hv.Timings()


def body(data='abc', witness='', mode=hv.MODE_AUTO, lease_s=20, **flags):
    voters = []
    for i in data:
        rec = {'id': i, 'public_key': KEYS[i][0], 'voter': True, 'may_lead': True, 'site': ''}
        rec.update(flags.get(i, {}))
        voters.append(rec)
    w = {'id': witness, 'public_key': KEYS[witness][0], 'site': ''} if witness else None
    return {'mode': mode, 'lease_s': lease_s, 'voters': voters, 'witness': w, 'quarantined': []}


def genesis(by='a', epoch=1, **kw):
    return hv.make_cfg(None, epoch, by, body(**kw), KEYS[by][1])


class Store:
    def __init__(self, st):
        self.state = st
        self.saves = []
        self.fail = False

    def load(self):
        return self.state

    def save(self, st):
        if self.fail:
            raise OSError('disk full')
        self.state = st
        self.saves.append(st)


class Box:
    """One node: a clock the test turns, a dict store, a list of what it sent."""

    def __init__(self, me, cfg, *, role=hv.ROLE_STANDBY, kind=hv.KIND_DATA, epoch=1,
                 voted_for='a', cv=(1, 5), led=None, chain=(), floor=hv.ZERO, start=1000.0,
                 boot_id='boot-1', state=None, **kw):
        self.now = start
        self.wall_offset = 5e6
        self.sent = []
        self.events = []
        self.restarts = []
        st = hv.new_state(cfg, role=role, epoch=epoch, kind=kind, cv=cv)
        st.update(voted_for=voted_for, led=led, cfg_chain=list(chain), floor_cv=floor)
        # state: a state file written before, for a restart
        self.store = Store(st if state is None else state)
        self.node = hv.Node(me, kind, store=self.store, clock=lambda: self.now,
                            wall=lambda: self.now + self.wall_offset, send=self._send, hooks=self,
                            rng=random.Random(7), sign=KEYS[me][1], verify=hv.ed25519_verify,
                            boot_id=boot_id, **kw)

    def _send(self, to, kind, body, tag):
        self.sent.append((to, kind, body, tag))

    def restart(self, why):
        self.restarts.append(why)

    def event(self, name, info):
        self.events.append((name, info))

    def snapshot(self):
        return {'data': 'x'}

    def apply_snapshot(self, frm, ans):
        return hv.pair(ans.get('cv'))

    def names(self):
        return [n for n, _ in self.events]

    def later(self, dt):
        self.now += dt
        self.node.tick()

    def vote(self, cand, epoch, pre=False, cv=(1, 5), cfg_id=None, why='timer', chain=None):
        req = {'epoch': epoch, 'candidate': cand, 'pre': pre, 'why': why, 'cv': cv,
               'cfg_id': cfg_id or self.node.view.id}
        if chain is not None:
            req['chain'] = chain
        return self.node.on_request(cand, 'vote', req)

    def renew(self, leader, epoch, **extra):
        req = {'epoch': epoch, 'leader': leader, 'lease_s': 20, 'cv': (epoch, 9), 'floor_cv': (1, 0)}
        req.update(extra)
        return self.node.on_request(leader, 'renew', req)

    def answer_all(self, kind, fn):
        """Answer every call of `kind` sent so far with fn(to, body)."""
        calls = [s for s in self.sent if s[1] == kind]
        self.sent = [s for s in self.sent if s[1] != kind]
        for to, _, b, tag in calls:
            self.node.on_answer(to, tag, fn(to, b))


def settled(box, dt=T.hold_after_start + 1):
    """Past the hold after start, the way a node is that has run for a while."""
    box.now += dt
    return box


# --- timings and counts ---

def test_timings_at_the_recommended_lease():
    t = hv.Timings(20)
    assert (t.R, t.renew_timeout, t.P, t.D, t.per_round) == (4, 2, pytest.approx(22), 2, 16)
    assert t.W_take == pytest.approx(31.2)
    assert t.hold_after_start == pytest.approx(24)
    assert (t.won_hold, t.lost_lease_backoff) == (80, 40)
    assert hv.LEASE_DEFAULT == 20
    # the owner may still drop W_take to D + G (Q2)
    assert hv.Timings(20, keep_w_take=False).W_take == pytest.approx(7)


@pytest.mark.parametrize('L', range(hv.LEASE_MIN, hv.LEASE_MAX + 1))
def test_a_lease_ends_inside_every_promise(L):
    t = hv.Timings(L)
    # leader 10% slow against a voter 10% fast: the lease ends 1.11 D before the promise
    lease_end = t.per_round / 0.9
    promise_end = t.P / 1.1
    assert promise_end - lease_end == pytest.approx(t.D / 0.9)
    assert t.D >= 2 and t.per_round > t.need
    # a voter that restarts holds others off for longer than the promise it forgot
    assert t.hold_after_start / 1.1 > lease_end


def test_majority_and_counts():
    assert [hv.majority(n) for n in (3, 4, 5)] == [2, 3, 3]
    v = hv.CfgView(genesis(data='abcd', witness='w'))
    assert (v.n, v.m, len(v.data), v.witness) == (5, 3, 4, 'w')
    b = body('abcd', 'w', d={'voter': False})
    b['quarantined'] = ['c']
    v = hv.CfgView(hv.make_cfg(None, 1, 'a', b, KEYS['a'][1]))
    # a non-voter does not count in n; a quarantined voter does, its answers do not
    assert (v.n, v.m) == (4, 3)
    assert v.counting == frozenset('abw')


def test_body_limits():
    assert hv.body_error(body('abcd', 'w')) == ''
    assert hv.body_error(body('abcde')) == 'voters'
    assert hv.body_error(body('ab')) == 'too few voters'
    assert hv.body_error(body('ab', mode=hv.MODE_MANUAL)) == ''
    assert hv.body_error(body('ab', 'w')) == ''
    b = body('abc')
    b['witness'] = {'id': 'a', 'public_key': KEYS['a'][0]}
    assert hv.body_error(b) == 'witness'
    assert hv.body_error(dict(body(), quarantined=['z'])) == 'quarantined'
    assert hv.body_error(body(lease_s=14)) == 'lease_s'
    assert hv.body_error(body(lease_s=121)) == 'lease_s'


def test_automatic_mode_cannot_be_switched_on_yet():
    assert hv.AUTO_MODE_SHIPPED is False
    box = Box('a', genesis(mode=hv.MODE_MANUAL), role=hv.ROLE_ACTIVE, voted_for=None)
    assert box.node.switch_on() == 'NOT_SHIPPED'
    assert box.node.view.mode == hv.MODE_MANUAL and not box.store.saves


def test_switch_on_once_shipped(monkeypatch):
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    box = Box('a', genesis(mode=hv.MODE_MANUAL), role=hv.ROLE_ACTIVE, voted_for=None)
    assert box.node.switch_on() == ''
    assert box.node.view.mode == hv.MODE_PENDING
    # pending is not automatic: the active still acts by its role, and promotes are refused
    assert box.node.is_active() and box.node.manual_promote_refusal() == 'HA_AUTO_MODE'


def test_the_lease_clock_is_boottime():
    if not hasattr(time, 'CLOCK_BOOTTIME'):
        pytest.skip('no CLOCK_BOOTTIME here')
    before = time.clock_gettime(time.CLOCK_BOOTTIME)
    now = hv.ha_clock()
    assert before <= now <= time.clock_gettime(time.CLOCK_BOOTTIME)
    # it counts from the boot, not from 1970
    assert now < time.time() / 2


# --- the config chain (4.12) ---

def _chain3():
    g = genesis()
    c2 = hv.make_cfg(g, 1, 'a', body('abcd'), KEYS['a'][1])
    c3 = hv.make_cfg(c2, 2, 'b', body('abcd', b={'site': 'x'}), KEYS['b'][1])
    return g, c2, c3


def test_a_chain_is_taken_link_by_link():
    g, c2, c3 = _chain3()
    assert [hv.pair(c['id']) for c in (g, c2, c3)] == [(1, 1), (1, 2), (2, 3)]
    assert hv.newer_chain([g], [g, c2, c3], hv.ed25519_verify) == [g, c2, c3]
    assert hv.newer_chain([g, c2, c3], [g, c2], hv.ed25519_verify) is None


def test_a_changed_or_wrongly_signed_link_is_refused():
    g, c2, c3 = _chain3()
    bad = dict(c3, body=dict(c3['body'], lease_s=30))
    with pytest.raises(hv.CfgRefused) as e:
        hv.newer_chain([g, c2], [bad], hv.ed25519_verify)
    assert e.value.code == 'BAD_CFG'
    # d joined in c2 and is a voter of c2: it may sign c3; e is nobody there
    by_e = hv.make_cfg(c2, 2, 'e', c3['body'], KEYS['e'][1])
    with pytest.raises(hv.CfgRefused):
        hv.newer_chain([g, c2], [by_e], hv.ed25519_verify)
    # a member that only votes in the config it adds cannot sign itself in (D2)
    adds_e = hv.make_cfg(g, 1, 'e', body('abce'), KEYS['e'][1])
    with pytest.raises(hv.CfgRefused):
        hv.newer_chain([g], [adds_e], hv.ed25519_verify)
    non_voter = hv.make_cfg(None, 1, 'a', body('abcd', d={'voter': False}), KEYS['a'][1])
    by_d = hv.make_cfg(non_voter, 1, 'd', non_voter['body'], KEYS['d'][1])
    with pytest.raises(hv.CfgRefused):
        hv.newer_chain([non_voter], [by_d], hv.ed25519_verify)
    assert hv.newer_chain([non_voter], [hv.make_cfg(non_voter, 1, 'a', non_voter['body'],
                                                    KEYS['a'][1])], hv.ed25519_verify)


def _resigned(cfg, by, **change):
    out = dict(cfg, **change)
    out['sig'] = KEYS[by][1](bytes.fromhex(hv.cfg_digest(out)))
    return out


def test_a_link_must_carry_the_digest_of_the_one_before():
    g, c2, c3 = _chain3()
    # signed by a voter of c2 and the right version, but hung off another config
    elsewhere = _resigned(c3, 'b', prev=hv.cfg_digest(g))
    with pytest.raises(hv.CfgRefused) as e:
        hv.newer_chain([g], [c2, elsewhere], hv.ed25519_verify)
    assert e.value.code == 'BAD_CFG'


def test_a_link_counts_the_version_on_by_one():
    g, c2, c3 = _chain3()
    skip = _resigned(c2, 'a', id=[1, 3])
    with pytest.raises(hv.CfgRefused):
        hv.newer_chain([g], [skip], hv.ed25519_verify)
    # an epoch going back never reads as newer: the id orders by epoch first
    back = _resigned(c3, 'b', id=[0, 3])
    assert hv.newer_chain([g, c2], [back], hv.ed25519_verify) is None


def test_an_uncommitted_config_is_left_behind_by_the_next_leader():
    g = genesis()
    mine = hv.make_cfg(g, 1, 'a', body('abc', 'w'), KEYS['a'][1])
    theirs = hv.make_cfg(g, 2, 'b', g['body'], KEYS['b'][1])
    # same version, a later epoch: (2, 2) > (1, 2), and it hangs off the genesis we hold
    assert hv.newer_chain([g, mine], [g, theirs], hv.ed25519_verify) == [g, theirs]
    # the other way round nothing changes
    assert hv.newer_chain([g, theirs], [g, mine], hv.ed25519_verify) is None


def test_a_gap_means_pairing_again():
    g, c2, c3 = _chain3()
    with pytest.raises(hv.CfgRefused) as e:
        hv.newer_chain([g], [c3], hv.ed25519_verify)
    assert e.value.code == 'CFG_GAP'
    chain = [g]
    for i in range(hv.CFG_KEEP + 5):
        chain.append(hv.make_cfg(chain[-1], 1, 'a', g['body'], KEYS['a'][1]))
    kept = hv.newer_chain([g], chain, hv.ed25519_verify)
    assert len(kept) == hv.CFG_KEEP + 1 and kept[-1] is chain[-1]


def test_majorities_of_two_configs_in_a_row_overlap():
    g = genesis()
    add = hv.make_cfg(g, 1, 'a', body('abc', 'w'), KEYS['a'][1])
    drop = hv.make_cfg(add, 1, 'a', body('ab', 'w'), KEYS['a'][1])
    swap = hv.make_cfg(g, 1, 'a', body('abd'), KEYS['a'][1])
    assert hv.majorities_intersect(g, add) and hv.majorities_intersect(add, drop)
    assert not hv.majorities_intersect(g, swap)


# --- floor and catch-up (4.6, 4.11) ---

def test_the_floor_is_what_a_majority_holds():
    assert hv.floor_of([(1, 9), (1, 4), (1, 7)], 2) == (1, 7)
    assert hv.floor_of([(1, 9)], 2) is None


def test_a_stale_candidate_pulls_from_the_freshest_named_voter():
    stale = {'reason': 'STALE', 'cv': (1, 7), 'fresher': {'id': 'b', 'cv': (1, 7)}}
    fresher = {'reason': 'STALE', 'cv': (1, 9), 'fresher': {'id': 'c', 'cv': (1, 9)}}
    promised = {'reason': 'PROMISED', 'cv': (1, 20)}
    assert hv.catchup_source([('b', stale), ('c', fresher)], (1, 5)) == 'c'
    # a refusal that is not about freshness names nobody
    assert hv.catchup_source([('d', promised)], (1, 5)) is None
    # the witness names nobody: the data voter ahead of us with the highest cv
    floor = {'reason': 'BELOW_FLOOR', 'cv': None}
    assert hv.catchup_source([('w', floor), ('d', promised), ('b', {'reason': 'TERM', 'cv': (1, 6)})],
                             (1, 5)) == 'd'
    assert hv.catchup_source([('w', floor)], (1, 5)) is None


# --- the voter (4.4) ---

def test_a_vote_is_on_disk_before_the_answer():
    box = settled(Box('c', genesis(data='abcd')))
    ans = box.vote('b', 2)
    assert ans['granted']
    assert box.store.state['epoch'] == 2 and box.store.state['voted_for'] == 'b'
    assert box.node.promise_to == 'b' and box.node.promise_until == pytest.approx(box.now + T.P)
    # a second candidate in the same term gets nothing
    assert box.vote('d', 2)['reason'] == 'TERM'


def test_a_vote_that_cannot_be_written_is_no_vote():
    box = settled(Box('c', genesis()))
    box.store.fail = True
    ans = box.vote('b', 2)
    assert not ans['granted'] and ans['reason'] == 'WRITE_FAILED'
    assert box.node.promise_to is None and box.node.epoch == 1


def test_a_pre_vote_changes_nothing():
    box = settled(Box('c', genesis(data='abcd')))
    assert box.vote('b', 2, pre=True)['granted']
    assert not box.store.saves and box.node.promise_to is None
    # and a member that is only cut off never raises the term with it
    assert box.vote('d', 2)['granted']


def test_manual_and_pending_members_do_not_vote():
    for mode in (hv.MODE_MANUAL, hv.MODE_PENDING):
        box = settled(Box('c', genesis(mode=mode)))
        assert box.vote('b', 2)['reason'] == 'MODE_MANUAL'


def test_only_a_voter_of_my_config_is_a_candidate():
    b = body('abcd', d={'may_lead': False})
    b['quarantined'] = ['b']
    box = settled(Box('c', hv.make_cfg(None, 1, 'a', b, KEYS['a'][1])))
    assert box.vote('b', 2)['reason'] == 'NOT_CANDIDATE'
    assert box.vote('e', 2)['reason'] == 'NOT_CANDIDATE'
    # may_lead only stops a pre-vote on the timer; Make leader and catch-up retries pass
    assert box.vote('d', 2, pre=True)['reason'] == 'NOT_CANDIDATE'
    assert box.vote('d', 2, pre=True, why='make_leader')['granted']
    assert box.vote('d', 2, pre=True, why='catchup')['granted']


def test_a_live_promise_keeps_others_out():
    box = settled(Box('c', genesis()))
    assert box.renew('a', 1)['ok']
    assert box.vote('b', 2)['reason'] == 'PROMISED'
    box.now += T.P - 0.1
    assert box.vote('b', 2)['reason'] == 'PROMISED'
    box.now += 0.2
    assert box.vote('b', 2)['granted']


def test_the_allowance_is_for_one_candidate_in_one_term():
    box = settled(Box('c', genesis(data='abcd')))
    assert box.renew('a', 1, release_to={'to': 'b', 'epoch': 2})['ok']
    assert box.vote('d', 2)['reason'] == 'PROMISED'
    assert box.vote('b', 3)['reason'] == 'PROMISED'
    assert box.vote('b', 2)['granted']


def test_a_late_release_does_nothing_in_a_later_term():
    box = settled(Box('c', genesis(data='abcd'), epoch=3, voted_for='a'))
    # a release_to sent at 1 for term 2 arrives while the group is at 3 (A2)
    assert box.renew('a', 1, release_to={'to': 'b', 'epoch': 2})['reason'] == 'OLD_EPOCH'
    assert box.node.allow is None
    # one for the wrong term is not taken either
    assert box.renew('a', 3, release_to={'to': 'b', 'epoch': 5})['ok']
    assert box.node.allow is None
    # and a renewal at another epoch drops one that was
    box.renew('a', 3, release_to={'to': 'b', 'epoch': 4})
    assert box.node.allow[:2] == ('b', 4)
    box.renew('d', 4)
    assert box.node.allow is None


def test_the_allowance_runs_out_after_P():
    box = settled(Box('c', genesis()))
    box.renew('a', 1, release_to={'to': 'b', 'epoch': 2})
    box.now += T.P + 0.1
    box.renew('a', 1)
    assert box.vote('b', 2)['reason'] == 'PROMISED'


def test_the_hold_after_start():
    box = Box('c', genesis(), voted_for='a')
    # a restart forgets every promise; whatever it promised went to its voted_for
    assert box.vote('b', 2)['reason'] == 'HOLD_AFTER_START'
    assert box.vote('a', 2)['granted']
    box2 = Box('c', genesis(), voted_for='a')
    box2.now += T.hold_after_start + 0.01
    assert box2.vote('b', 2)['granted']


def _shrunk(old=60, new=15):
    """A chain whose lease went down from `old` to `new`."""
    g = genesis(lease_s=old)
    return g, hv.make_cfg(g, 1, 'a', body(lease_s=new), KEYS['a'][1])


def test_the_hold_after_start_covers_the_longest_lease_held():
    # the promise this voter forgot may come from a round under the 60 s config, and the
    # leader's lease from that round may still run
    g, c2 = _shrunk()
    box = Box('c', c2, chain=[g], voted_for='a')
    box.now += hv.Timings(15).hold_after_start + 1
    assert box.vote('b', 2)['reason'] == 'HOLD_AFTER_START'
    box.now = box.node.started + hv.Timings(60).hold_after_start + 0.01
    assert box.vote('b', 2)['granted']


def test_the_hold_after_start_never_shrinks_in_a_process():
    # this voter holds a 60 s config that the leader of term 1 never committed; the
    # leader of term 2 went another way at 20 s, and taking its chain drops the 60 s one
    g = genesis(lease_s=20)
    mine = hv.make_cfg(g, 1, 'a', body(lease_s=60), KEYS['a'][1])
    theirs = hv.make_cfg(g, 2, 'b', body(lease_s=20), KEYS['b'][1])
    box = Box('c', mine, chain=[g], voted_for='a')
    assert box.vote('b', 3, cfg_id=(2, 2), chain=[g, theirs])['reason'] == 'HOLD_AFTER_START'
    assert box.node.chain == [g, theirs]
    box.now = box.node.started + hv.Timings(20).hold_after_start + 5
    assert box.vote('b', 3, cfg_id=(2, 2))['reason'] == 'HOLD_AFTER_START'
    box.now = box.node.started + hv.Timings(60).hold_after_start + 0.01
    assert box.vote('b', 3, cfg_id=(2, 2))['granted']


def _past(g, n=hv.CFG_KEEP + 1, lease_s=15):
    """n configs after `g` at lease_s, one site change each; 17 push `g` out of every chain."""
    out, prev = [], g
    for k in range(n):
        prev = hv.make_cfg(prev, 1, 'a', body(lease_s=lease_s, a={'site': f's{k}'}), KEYS['a'][1])
        out.append(prev)
    return out


def _trimmed_promise():
    """c promised a for 1.1 x 120 s under the 120 s config, then took the change to 15 s and
    16 more: the 120 s config leaves the chain while that promise runs."""
    g = genesis(lease_s=120)
    box = settled(Box('c', g), hv.Timings(120).hold_after_start + 1)
    box.renew('a', 1, lease_s=120)
    end = box.now + 1.1 * 120
    box.now += 10
    assert box.renew('a', 1, lease_s=15, chain=_past(g))['ok']
    assert hv.longest_lease(box.node.chain) == 15
    return box, end


def test_a_promise_no_config_on_disk_covers_goes_on_disk():
    box, end = _trimmed_promise()
    rec = box.store.state['promised']
    assert rec['boot_id'] == 'boot-1' and rec['until'] == pytest.approx(end)
    assert rec['len'] == pytest.approx(end - box.now)
    # a restart on the same boot holds everyone else off until that promise ends, not for
    # the 18.5 s the 15 s configs on disk would say
    again = Box('c', genesis(), state=box.store.state, start=box.now + 1)
    assert again.vote('b', 2)['reason'] == 'HOLD_AFTER_START'
    again.now = end - 0.1
    assert again.vote('b', 2)['reason'] == 'HOLD_AFTER_START'
    again.now = end + 0.01
    assert again.vote('b', 2)['granted']
    # after a reboot the old lease clock means nothing: the full length from the start
    other = Box('c', genesis(), state=box.store.state, start=3.0, boot_id='boot-2')
    other.now = 3.0 + rec['len'] - 0.1
    assert other.vote('b', 2)['reason'] == 'HOLD_AFTER_START'
    other.now = 3.0 + rec['len'] + 0.01
    assert other.vote('b', 2)['granted']


def test_a_promise_a_dropped_branch_covered_goes_on_disk():
    # c holds a's 120 s config of term 1 that never reached a majority and promises b, the
    # leader of term 2, 1.1 x 120 s by it. b's own config of term 2 leaves it behind
    g = genesis(lease_s=20)
    mine = hv.make_cfg(g, 1, 'a', body(lease_s=120), KEYS['a'][1])
    theirs = hv.make_cfg(g, 2, 'b', body(lease_s=20), KEYS['b'][1])
    box = settled(Box('c', mine, chain=[g]), hv.Timings(120).hold_after_start + 1)
    assert box.renew('b', 2)['ok']
    end = box.now + 1.1 * 120
    box.now += 5
    assert box.renew('b', 2, chain=[theirs])['ok'] and box.node.chain == [g, theirs]
    assert box.store.state['promised']['until'] == pytest.approx(end)
    again = Box('c', genesis(), state=box.store.state, start=box.now + 1)
    again.now = end - 0.1
    assert again.vote('a', 3, cfg_id=(2, 2))['reason'] == 'HOLD_AFTER_START'
    again.now = end + 0.01
    assert again.vote('a', 3, cfg_id=(2, 2))['granted']


def test_a_longer_promise_than_the_configs_cover_goes_with_the_vote():
    box = settled(Box('c', genesis(lease_s=15)))
    req = {'epoch': 2, 'candidate': 'b', 'pre': False, 'why': 'timer', 'cv': (1, 5),
           'cfg_id': (1, 1), 'lease_s': 120}
    box.store.fail = True
    assert box.node.on_request('b', 'vote', req)['reason'] == 'WRITE_FAILED'
    box.store.fail = False
    assert box.node.on_request('b', 'vote', req)['granted']
    # one write: the vote and the promise it makes
    st = box.store.saves[-1]
    assert st['voted_for'] == 'b' and st['promised']['until'] == pytest.approx(box.now + 1.1 * 120)


def test_renewals_write_nothing_while_the_configs_cover_the_promise():
    box = settled(Box('c', genesis(lease_s=120)), hv.Timings(120).hold_after_start + 1)
    for _ in range(30):
        assert box.renew('a', 1, lease_s=120)['ok']
        box.now += hv.Timings(120).R
    assert box.store.saves == [] and box.store.state['promised'] is None


def test_a_record_nothing_needs_goes_with_the_next_renewal():
    box, end = _trimmed_promise()
    box.now += 30
    # still needed: no renewal writes it again
    n = len(box.store.saves)
    box.renew('a', 1, lease_s=15)
    assert len(box.store.saves) == n
    # the configs on disk cover what is left of it: the next renewal drops it, and a write
    # that fails for it costs no renewal
    box.now = end - hv.Timings(15).hold_after_start + 0.5
    box.store.fail = True
    assert box.renew('a', 1, lease_s=15)['ok'] and box.store.state['promised'] is not None
    box.store.fail = False
    assert box.renew('a', 1, lease_s=15)['ok'] and box.store.state['promised'] is None


def test_a_record_from_another_boot_is_kept_in_this_boots_terms():
    st = hv.new_state(genesis(), role=hv.ROLE_STANDBY, epoch=1, cv=(1, 5))
    st.update(voted_for='a', promised={'boot_id': 'boot-1', 'until': 5000.0, 'len': 100.0})
    box = Box('c', genesis(), state=st, start=10.0, boot_id='boot-2')
    assert box.node.hold_until == pytest.approx(110.0)
    # the first renewal writes it down on this boot's clock, or it is no renewal; a second
    # restart on the same boot still holds until then, not for the 24 s its configs say
    box.now = 12.0
    box.store.fail = True
    assert box.renew('a', 1)['reason'] == 'WRITE_FAILED'
    box.store.fail = False
    assert box.renew('a', 1)['ok']
    assert box.store.state['promised'] == {'boot_id': 'boot-2', 'until': 110.0, 'len': 98.0}
    again = Box('c', genesis(), state=box.store.state, start=30.0, boot_id='boot-2')
    again.now = 109.9
    assert again.vote('b', 2)['reason'] == 'HOLD_AFTER_START'
    again.now = 110.01
    assert again.vote('b', 2)['granted']
    # a value on the old clock below the new clock's start says nothing either, and a host
    # without a boot id never knows it is on the same boot
    st.update(promised={'boot_id': 'boot-1', 'until': 50.0, 'len': 100.0})
    assert Box('c', genesis(), state=st, start=200.0, boot_id='boot-2').node.hold_until == 300.0
    st.update(promised={'boot_id': '', 'until': 50.0, 'len': 100.0})
    assert Box('c', genesis(), state=st, start=200.0, boot_id='').node.hold_until == 300.0


def test_a_broken_record_holds_no_longer_than_a_promise_can_run():
    for rec in ({'boot_id': 'boot-1', 'until': 'x', 'len': 5}, {'until': math.nan, 'len': 5}, 'x'):
        st = dict(hv.new_state(genesis(), role=hv.ROLE_STANDBY, cv=(1, 5)), promised=rec)
        box = Box('c', genesis(), state=st)
        assert box.node.hold_until == pytest.approx(box.now + T.hold_after_start)
    st = dict(hv.new_state(genesis(), role=hv.ROLE_STANDBY, cv=(1, 5)),
              promised={'boot_id': 'boot-0', 'until': 1e12, 'len': 1e12})
    box = Box('c', genesis(), state=st)
    assert box.node.hold_until == pytest.approx(box.now + hv.Timings(hv.LEASE_MAX).hold_after_start)


def test_my_own_vote_waits_for_the_longest_hold():
    g, c2 = _shrunk()
    box = Box('b', c2, chain=[g], voted_for='a')
    long_hold = box.node.started + hv.Timings(60).hold_after_start
    assert box.node.election_at >= long_hold
    box.now += hv.Timings(15).hold_after_start + 1
    assert box.node._self_ok(2, box.now) is False
    box.now = long_hold + 0.01
    assert box.node._self_ok(2, box.now) is True


def test_the_hold_after_start_gives_way_to_the_allowance():
    box = Box('c', genesis(data='abcd'), voted_for='a')
    box.now += 1
    box.renew('a', 1, release_to={'to': 'b', 'epoch': 2})
    assert box.vote('d', 2)['reason'] == 'PROMISED'
    assert box.vote('b', 2)['granted']


def test_a_candidate_must_be_as_fresh_as_the_voter():
    box = settled(Box('c', genesis(), cv=(1, 9)))
    ans = box.vote('b', 2, cv=(1, 8))
    assert ans['reason'] == 'STALE' and ans['fresher'] == {'id': 'c', 'cv': (1, 9)}
    assert box.vote('b', 2, cv=(1, 9), pre=True)['granted']
    w = settled(Box('w', genesis(witness='w'), kind=hv.KIND_WITNESS, role=hv.ROLE_WITNESS,
                    floor=(1, 6)))
    assert w.vote('b', 2, cv=(1, 5))['reason'] == 'BELOW_FLOOR'
    assert w.vote('b', 2, cv=(1, 6))['granted']


def test_a_candidate_with_an_older_config_is_refused_and_handed_the_newer_one():
    g = genesis()
    c2 = hv.make_cfg(g, 1, 'a', body('abcd'), KEYS['a'][1])
    box = settled(Box('c', c2, chain=[g]))
    ans = box.vote('b', 2, cfg_id=(1, 1))
    assert ans['reason'] == 'OLD_CFG' and [hv.pair(c['id']) for c in ans['chain']] == [(1, 2)]


def test_a_voter_learns_a_new_voter_from_the_candidates_chain():
    g = genesis(witness='w')
    c2 = hv.make_cfg(g, 1, 'a', body('abcd', 'w'), KEYS['a'][1])
    w = settled(Box('w', g, kind=hv.KIND_WITNESS, role=hv.ROLE_WITNESS))
    assert w.vote('d', 2, cfg_id=(1, 2))['reason'] == 'NOT_CANDIDATE'
    ans = w.vote('d', 2, cfg_id=(1, 2), chain=[g, c2])
    assert ans['granted'] and w.node.view.id == (1, 2)


def test_a_leader_refuses_votes_and_steps_down_on_a_real_one_above_its_epoch():
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', lambda to, b: {'ok': True, 'epoch': 1, 'cfg_id': (1, 1), 'gen': 1})
    assert box.node.holds_lease()
    assert box.vote('b', 2, pre=True)['reason'] == 'LEADER'
    assert not box.restarts
    assert box.vote('b', 2)['reason'] == 'LEADER'
    assert box.restarts and box.store.state['role'] == hv.ROLE_STANDBY
    assert not box.node.is_active()


# --- renewals (4.4) ---

def test_renewals_below_my_epoch_are_refused():
    box = settled(Box('c', genesis(), epoch=3))
    ans = box.renew('a', 2)
    assert not ans['ok'] and ans['epoch'] == 3 and box.node.promise_to is None


def test_a_higher_epoch_is_on_disk_before_the_answer():
    box = settled(Box('c', genesis(data='abcd'), epoch=1))
    assert box.renew('b', 4)['ok']
    assert (box.store.state['epoch'], box.store.state['voted_for']) == (4, 'b')
    box.store.fail = True
    assert box.renew('d', 5)['reason'] == 'WRITE_FAILED'
    assert box.node.promise_to == 'b'


def test_a_losing_candidate_takes_the_winners_renewals_and_binds_to_it():
    # c ran in term 2 and voted for itself; b won term 2 (D4)
    box = settled(Box('c', genesis(), epoch=2, voted_for='c'))
    assert box.renew('b', 2)['ok']
    assert box.node.promise_to == 'b'
    # and its vote of record in term 2 is b now: after a restart, the hold lets
    # nobody through but b, so a lease that rests on this member's forgotten promise
    # cannot be undercut by c, the loser
    assert box.store.state['voted_for'] == 'b'
    again = Box('c', box.store.state['cfg'], epoch=2, voted_for=box.store.state['voted_for'])
    assert again.vote('c', 3)['reason'] == 'HOLD_AFTER_START'
    assert again.node._self_ok(3, again.now) is False


def test_a_voter_that_granted_a_loser_binds_to_the_winner():
    box = settled(Box('d', genesis(data='abcd'), epoch=2, voted_for='c'))
    assert box.renew('b', 2)['ok'] and box.store.state['voted_for'] == 'b'
    again = Box('d', box.store.state['cfg'], epoch=2, voted_for='b')
    assert again.vote('c', 3)['reason'] == 'HOLD_AFTER_START'


def test_the_hold_of_a_won_election_ends_with_the_next_renewal():
    box = settled(Box('c', genesis()))
    box.renew('b', 2, hold_s=T.won_hold)
    assert box.node.promise_until == pytest.approx(box.now + T.won_hold)
    box.now += 10
    box.renew('b', 2)
    assert box.node.promise_until == pytest.approx(box.now + 1.1 * 20)
    assert box.node.lease_promise_until == pytest.approx(box.now + 1.1 * 20)
    # never past HOLD_MAX
    box.renew('b', 2, hold_s=10_000)
    assert box.node.promise_until == pytest.approx(box.now + hv.HOLD_MAX)


def test_a_promise_follows_the_longer_lease():
    box = settled(Box('c', genesis(lease_s=30)))
    box.renew('a', 1)
    assert box.node.promise_until == pytest.approx(box.now + 1.1 * 30)


def test_manual_members_refuse_renewals_and_take_the_config():
    g = genesis()
    off = hv.make_cfg(g, 1, 'a', body(mode=hv.MODE_MANUAL), KEYS['a'][1])
    box = settled(Box('c', g))
    ans = box.renew('a', 1, chain=[g, off])
    assert ans['reason'] == 'MODE_MANUAL' and ans['cfg_id'] == (1, 2)
    assert box.node.view.mode == hv.MODE_MANUAL and box.node.promise_to is None


def test_a_pending_member_acks_only_the_member_that_asked():
    g = genesis(mode=hv.MODE_MANUAL)
    pending = hv.make_cfg(g, 1, 'a', body(mode=hv.MODE_PENDING), KEYS['a'][1])
    box = settled(Box('c', g, voted_for=None))
    ans = box.renew('a', 1, chain=[g, pending], switch=True)
    # the ack names the config it is for, by digest
    assert ans['ok'] and ans['cfg_digest'] == hv.cfg_digest(pending)
    assert box.node.view.mode == hv.MODE_PENDING and box.node.promise_to is None
    assert box.renew('b', 1, switch=True)['reason'] == 'MODE_MANUAL'
    assert box.vote('b', 2)['reason'] == 'MODE_MANUAL'
    assert box.node.promote_manual(5) == 'HA_AUTO_MODE'


def test_a_switch_round_is_no_renewal_to_a_member_in_automatic_mode():
    """Whoever sends it is not switching the group this member is in. Taken for a
    renewal, it would hand the sender this voter's term, its vote and its promise."""
    box = settled(Box('c', genesis()))
    assert box.renew('a', 1)['ok']
    held, saves = dict(box.store.state), len(box.store.saves)

    for epoch in (1, 5):
        ans = box.renew('b', epoch, switch=True)
        assert ans['ok'] is False and ans['reason'] == 'MODE_AUTO'
        assert ans['cfg_digest'] == hv.cfg_digest(box.node.view.cfg)
    assert box.store.state == held and len(box.store.saves) == saves
    assert box.node.promise_to == 'a' and box.node.leader_seen == 'a'


def test_a_renewal_comes_from_a_data_voter_of_the_config_held():
    """Only a data voter can have won a term: a member without a vote, the witness and
    an instance the config does not name renew nothing, at any epoch."""
    b = body('abcd', 'w', d={'voter': False})
    box = settled(Box('c', hv.make_cfg(None, 1, 'a', b, KEYS['a'][1])))
    for frm in 'dwe':
        ans = box.renew(frm, 2)
        assert ans['ok'] is False and ans['reason'] == 'NOT_VOTER', frm
    assert box.store.state['epoch'] == 1 and box.node.promise_to is None and not box.store.saves
    assert box.renew('b', 2)['ok']


def test_a_voter_renews_one_leader_per_term():
    box = settled(Box('c', genesis()))
    assert box.renew('a', 1)['ok']
    ans = box.renew('b', 1)
    assert ans['ok'] is False and ans['reason'] == 'PROMISED' and ans['holder'] == 'a'
    assert box.store.state['voted_for'] == 'a' and box.node.promise_to == 'a'
    # a higher term is another term, and written down as ever
    assert box.renew('b', 2)['ok'] and box.store.state['voted_for'] == 'b'
    # and a promise that came with a vote is no renewal: the winner of a split election
    # renews with the voter of the loser (D4)
    other = settled(Box('c', genesis(), voted_for=None, epoch=1))
    other.now += T.P
    assert other.vote('b', 2)['granted'] and other.renew('a', 2)['ok']


def test_the_witness_takes_the_floor():
    w = settled(Box('w', genesis(witness='w'), kind=hv.KIND_WITNESS, role=hv.ROLE_WITNESS))
    w.renew('a', 1, floor_cv=(1, 7))
    assert w.store.state['floor_cv'] == (1, 7)
    w.renew('a', 1, floor_cv=(1, 3))
    assert w.store.state['floor_cv'] == (1, 7)


def test_a_catch_up_is_served_only_without_a_leader():
    box = settled(Box('c', genesis()))
    box.renew('a', 1)
    assert box.node.on_request('b', 'snapshot', {'catchup': True})['reason'] == 'PROMISED'
    box.now += T.P + 1
    assert box.node.on_request('b', 'snapshot', {'catchup': True})['ok']
    assert box.node.on_request('e', 'snapshot', {'catchup': True})['reason'] == 'NOT_VOTER'


# --- the leader (4.5-4.9) ---

def _leader(**kw):
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    return Box('a', genesis(), role=hv.ROLE_LEADER, led=led, **kw)


def _ok(to, b):
    return {'ok': True, 'epoch': b['epoch'], 'cfg_id': (1, 1), 'gen': 1, 'cv': (1, 5)}


def _holds(box, **extra):
    """An answer from a member that holds the config the leader holds now: id and digest."""
    view = box.node.view
    return lambda to, b: dict(_ok(to, b), cfg_id=view.id, cfg_digest=hv.cfg_digest(view.cfg), **extra)


def test_a_leader_that_hears_another_data_voter_renew_in_its_term_leaves():
    """One leader per term. Two of them refusing each other as equals would both keep
    their lease for good."""
    box = _leader()
    box.answer_all('renew', _ok)
    assert box.node.is_active()
    ans = box.renew('b', 1)
    assert ans['reason'] == 'GONE' and box.restarts == ['renewal at epoch 1']
    assert box.store.state['role'] == hv.ROLE_STANDBY and not box.node.is_active()


def test_a_leader_keeps_its_term_against_a_switch_round_and_a_member_without_a_vote():
    b = body('abcd', d={'voter': False})
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', hv.make_cfg(None, 1, 'a', b, KEYS['a'][1]), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', _ok)
    ans = box.renew('b', 1, switch=True)
    assert ans['reason'] == 'MODE_AUTO' and ans['cfg_digest'] == hv.cfg_digest(box.node.view.cfg)
    assert box.renew('d', 1)['reason'] == 'NOT_VOTER'
    assert box.renew('b', 0)['reason'] == 'OLD_EPOCH'
    assert box.node.is_active() and not box.restarts
    assert box.store.state['role'] == hv.ROLE_LEADER


def _switching(monkeypatch):
    monkeypatch.setattr(hv, 'AUTO_MODE_SHIPPED', True)
    box = Box('a', genesis(mode=hv.MODE_MANUAL), role=hv.ROLE_ACTIVE, voted_for=None)
    assert box.node.switch_on() == ''
    box.later(0)
    return box, hv.cfg_digest(box.node.view.cfg)


def test_the_switch_counts_a_member_only_on_its_ack_of_the_pending_config(monkeypatch):
    """Not on a refusal, whatever config id stands in it, and not on an ack of another
    config: where two chains meet, the ids of one say nothing about the other."""
    box, digest = _switching(monkeypatch)
    pending = box.node.view.id

    box.answer_all('renew', lambda to, b: {'ok': False, 'reason': 'OLD_EPOCH', 'epoch': 1,
                                           'cfg_id': (9, 9), 'gen': 3, 'cfg_digest': digest})
    box.later(T.R + 0.1)
    assert box.node.view.mode == hv.MODE_PENDING and box.node.switch is not None
    box.answer_all('renew', lambda to, b: {'ok': True, 'epoch': 1, 'cfg_id': pending, 'gen': 3})
    box.later(T.R + 0.1)
    box.answer_all('renew', lambda to, b: {'ok': True, 'epoch': 1, 'cfg_id': pending, 'gen': 3,
                                           'cfg_digest': 'f' * 64})
    box.later(T.R + 0.1)
    assert box.node.view.mode == hv.MODE_PENDING and box.store.state['role'] == hv.ROLE_ACTIVE

    box.answer_all('renew', lambda to, b: {'ok': True, 'epoch': 1, 'cfg_id': pending, 'gen': 3,
                                           'cfg_digest': digest})
    box.later(T.R + 0.1)
    assert box.node.view.mode == hv.MODE_AUTO and box.store.state['role'] == hv.ROLE_LEADER


def test_a_switch_taken_back_ends_once_every_member_holds_the_manual_config(monkeypatch):
    box, _digest = _switching(monkeypatch)
    assert box.node.switch_cancel() == ''
    box.later(0.1)
    assert box.node.view.mode == hv.MODE_MANUAL and box.node.switch['cancelled']
    back = hv.cfg_digest(box.node.view.cfg)
    box.later(0.1)
    # a member in manual mode refuses the round, and holds the config all the same
    box.answer_all('renew', lambda to, b: {'ok': False, 'reason': 'MODE_MANUAL', 'epoch': 1,
                                           'cfg_id': box.node.view.id, 'cfg_digest': back})
    box.later(T.R + 0.1)
    assert box.node.switch is None


def test_the_lease_counts_from_the_send_of_the_round():
    box = _leader()
    t0 = box.now
    box.now += 1.5
    box.answer_all('renew', _ok)
    assert box.node.lease_until == pytest.approx(t0 + T.per_round)
    assert box.node.is_active()
    box.now = t0 + T.per_round
    assert not box.node.is_active() and not box.node.holds_lease()


def test_a_leader_renews_only_at_the_epoch_it_won():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(T.R)
    assert {b['epoch'] for _, k, b, _ in box.sent if k == 'renew'} == {1}
    # an answer from a higher epoch ends it, there is no re-term
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), ok=False, epoch=2))
    assert box.restarts and box.store.state['role'] == hv.ROLE_STANDBY
    assert box.store.state['epoch'] == 1
    assert box.store.state['campaign_after']['at'] == pytest.approx(box.now + 2 * T.L)


def test_a_leader_whose_vote_moved_on_steps_down():
    box = _leader()
    box.answer_all('renew', _ok)
    box.store.state = dict(box.store.state)
    box.node.st = dict(box.node.st, epoch=2, voted_for='b')
    box.later(0.1)
    assert box.restarts


def test_no_majority_at_boot_means_standby_without_a_restart():
    box = _leader()
    box.answer_all('renew', lambda to, b: None)
    box.later(T.R)
    # it tries again within boot_wait: a voter that started a moment ago refuses a call
    # signed before its own start
    assert [s for s in box.sent if s[1] == 'renew']
    box.answer_all('renew', lambda to, b: None)
    box.later(T.boot_wait)
    assert not box.restarts and box.store.state['role'] == hv.ROLE_STANDBY
    assert not box.node.acting_process()


def test_a_late_answer_to_a_boot_round_leaves_the_standby_alone():
    box = _leader()
    while 'boot_standby' not in box.names():
        box.later(0.5)
    # the boot round of the last second is still out, and its answer names term 2
    to, _, b, tag = [s for s in box.sent if s[1] == 'renew'][-1]
    box.node.on_answer(to, tag, dict(_ok(to, b), ok=False, epoch=2))
    assert not box.restarts and not box.node.dead
    assert box.store.state['role'] == hv.ROLE_STANDBY


def test_a_second_round_at_boot_may_bring_the_majority():
    box = _leader()
    box.answer_all('renew', lambda to, b: None)
    box.later(T.R)
    box.answer_all('renew', _ok)
    assert box.node.acting_process() and box.node.is_active()


def test_the_boot_round_goes_out_every_second_at_a_long_lease():
    # at L = 75 one round every R is one round in boot_wait: voters that come up a moment
    # after the leader would get none, and the group waits minutes for an election
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(lease_s=75), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', lambda to, b: None)
    for _ in range(13):
        box.later(1.0)
        assert [s for s in box.sent if s[1] == 'renew'], box.now - box.node.started
        box.answer_all('renew', lambda to, b: None)
    box.later(1.0)
    box.answer_all('renew', _ok)
    assert box.node.acting_process() and box.node.is_active()
    # leading, it is one round every R again
    box.later(1.0)
    assert not [s for s in box.sent if s[1] == 'renew']


def test_after_boot_the_next_round_comes_inside_the_lease():
    # the boot round asked for 20 s while the 118 s config was not committed, and its
    # answers commit it: the next round is still due inside the 20 s round's lease
    g = genesis(lease_s=20)
    c2 = hv.make_cfg(g, 1, 'a', body(lease_s=118), KEYS['a'][1])
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', c2, chain=[g], role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', _holds(box))
    assert box.node._is_committed() and box.node.is_active()
    assert box.node.next_round_at < box.node.lease_until


def test_acting_waits_for_take_after():
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 1020.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2)
    box.answer_all('renew', _ok)
    assert box.node.acting_process() and box.node.holds_lease() and not box.node.is_active()
    while box.now + T.R < 1020:
        box.later(T.R)
        box.answer_all('renew', _ok)
    box.now = 1019.9
    assert box.node.holds_lease() and not box.node.is_active()
    box.now = 1020.0
    assert box.node.is_active()


def test_take_after_from_another_boot():
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'old', 'at': 5.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2)
    box.answer_all('renew', _ok)
    assert box.node.acting_from == pytest.approx(box.node.started + T.W_take)
    # a value from another boot under the same id (no boot id on this host) is capped
    led['take_after'] = {'boot_id': 'boot-1', 'at': 99999.0}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2)
    box.answer_all('renew', _ok)
    assert box.node.acting_from == pytest.approx(box.node.started + T.W_take)


def test_w_take_follows_the_longest_lease_held():
    # the leader before may have counted its last round on the 60 s config
    g, c2 = _shrunk()
    box = settled(Box('b', c2, chain=[g], voted_for='a', restart_on_win=False),
                  hv.Timings(60).hold_after_start + 1)
    assert box.node.campaign_now() == ''
    box.answer_all('vote', lambda to, b: {'granted': True, 'epoch': 1, 'cv': (1, 5), 'cfg_id': (1, 2)})
    box.answer_all('vote', lambda to, b: {'granted': True, 'epoch': 2, 'cv': (1, 5), 'cfg_id': (1, 2)})
    n = box.node
    assert n.st['role'] == hv.ROLE_LEADER
    assert n.acting_from == pytest.approx(box.now + hv.Timings(60).W_take)
    assert n.st['led']['take_after']['at'] == pytest.approx(box.now + hv.Timings(60).W_take)
    # and after a host reboot
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'old', 'at': 5.0}}
    box = Box('a', c2, chain=[g], role=hv.ROLE_LEADER, led=led, epoch=2)
    box.answer_all('renew', _ok)
    assert box.node.acting_from == pytest.approx(box.node.started + hv.Timings(60).W_take)


def test_a_round_that_is_due_is_due_now():
    box = _leader()
    box.answer_all('renew', _ok)
    box.now += 1
    assert box.node.next_wake() > box.now
    box.node.change_cfg(lambda b: dict(b, voters=b['voters'][:2] + [dict(b['voters'][2], site='x')]))
    assert box.node.next_wake() == box.now


def test_while_a_longer_lease_is_not_committed_the_shorter_one_counts():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(0.1)
    box.node.change_cfg(lambda b: dict(b, lease_s=30))
    box.later(0.01)
    assert box.node.view.lease_s == 30
    t0 = box.now
    box.answer_all('renew', _ok)
    assert box.node.lease_until == pytest.approx(t0 + hv.Timings(20).per_round)
    box.later(T.R + 0.01)
    sent = [b for _, k, b, _ in box.sent if k == 'renew']
    assert sent and all(b['lease_s'] == 20 for b in sent)
    t1 = box.now
    # the answers of this round commit the change; the round still counts by the 20 it
    # asked for, a voter on the old config promised no more
    box.answer_all('renew', _holds(box))
    assert box.node.lease_until == pytest.approx(t1 + hv.Timings(20).per_round)
    box.later(T.R + 0.01)
    t2 = box.now
    assert all(b['lease_s'] == 30 for _, k, b, _ in box.sent if k == 'renew')
    box.answer_all('renew', _holds(box))
    assert box.node.lease_until == pytest.approx(t2 + hv.Timings(30).per_round)


def _long_leader():
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(lease_s=60), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', _ok)
    assert box.node.lease_until == pytest.approx(box.now + hv.Timings(60).per_round)
    return box


def test_a_shorter_lease_cuts_the_leaders_lease_at_once():
    box = _long_leader()
    box.later(1)
    box.node.change_cfg(lambda b: dict(b, lease_s=15))
    box.later(0.01)
    assert box.node.view.lease_s == 15
    assert box.node.lease_until == pytest.approx(box.now + hv.Timings(15).per_round)


def test_a_round_that_left_before_the_cut_counts_the_shorter_lease():
    box = _long_leader()
    box.later(hv.Timings(60).R)
    early = [s for s in box.sent if s[1] == 'renew']
    box.sent.clear()
    assert early and all(b['lease_s'] == 60 for _, _, b, _ in early)
    box.later(0.5)
    box.node.change_cfg(lambda b: dict(b, lease_s=15))
    box.later(0.01)
    cut = box.node.lease_until
    # the 60 s round comes back after the cut and would put the long lease back
    for to, _, b, tag in early:
        box.node.on_answer(to, tag, _ok(to, b))
    assert box.node.lease_until == pytest.approx(cut)


def test_a_grant_promises_what_the_candidate_asks_for():
    # a voter on an older config with a shorter lease promises the candidate's longer one
    box = settled(Box('c', genesis(lease_s=15)))
    assert box.vote('b', 2, **{}) and box.node.promise_until == pytest.approx(box.now + 1.1 * 15)
    box2 = settled(Box('c', genesis(lease_s=15)))
    req = {'epoch': 2, 'candidate': 'b', 'pre': False, 'why': 'timer', 'cv': (1, 5),
           'cfg_id': (1, 1), 'lease_s': 30}
    assert box2.node.on_request('b', 'vote', req)['granted']
    assert box2.node.promise_until == pytest.approx(box2.now + 1.1 * 30)


def test_make_leader_wants_a_voter_that_answers():
    box = _leader()
    # b answers after the majority was there, c not at all
    box.answer_all('renew', lambda to, b: _ok(to, b) if to == 'b' else None)
    box.answer_all('renew', lambda to, b: None)
    assert box.node.transfer_to('c') == 'UNREACHABLE'
    assert box.node.transfer_to('d') == 'NOT_CANDIDATE'
    assert box.node.transfer_to('b') == ''
    assert box.node.transfer_to('b') == 'BUSY'
    # writes pause while the target catches up
    assert box.node.is_active() and not box.node.may_write()


def test_the_hand_over_is_on_disk_before_release_to_goes_out():
    box = _leader()
    box.answer_all('renew', _ok)
    on_disk = []

    def send(to, kind, b, tag):
        if b.get('release_to'):
            on_disk.append(box.store.state.get('released'))
        box._send(to, kind, b, tag)
    box.node.send = send
    assert box.node.transfer_to('b') == ''
    box.later(0.01)
    assert on_disk and all(r == {'to': 'b', 'epoch': 2} for r in on_disk)
    # it crashes right after and comes back: as a standby, without a round in its old term
    again = Box('a', box.store.state['cfg'], state=box.store.state, start=box.now + 1)
    assert not [s for s in again.sent if s[1] == 'renew']
    assert again.store.state['role'] == hv.ROLE_STANDBY and not again.node.acting_process()
    assert 'boot_standby' in again.names()


def test_a_hand_over_that_cannot_be_written_is_refused():
    box = _leader()
    box.answer_all('renew', _ok)
    box.sent.clear()
    assert box.node.transfer_to('b') == ''
    box.store.fail = True
    box.later(0.01)
    assert not [b for _, k, b, _ in box.sent if b.get('release_to')]
    assert 'transfer_refused' in box.names() and box.node.transfer is None
    assert box.node.is_active() and box.node.may_write()


def test_a_round_from_before_the_release_gives_no_lease_back():
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(data='abcd', witness='w'), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', _ok)
    box.later(T.R)
    out = {to: (b, tag) for to, k, b, tag in box.sent if k == 'renew'}
    box.sent.clear()
    # b answers at once, c and d late: a and b are two of five, no majority yet
    box.node.on_answer('b', out['b'][1], _ok('b', out['b'][0]))
    assert box.node.transfer_to('b') == ''
    box.later(0.01)
    assert [b for _, k, b, _ in box.sent if b.get('release_to')]
    assert not box.node.holds_lease()
    for to in 'cd':
        box.node.on_answer(to, out[to][1], _ok(to, out[to][0]))
    assert not box.node.holds_lease()


def test_until_switching_off_reached_a_majority_the_leader_needs_its_lease():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(0.1)
    assert box.node.switch_off() == ''
    box.later(0.01)
    assert box.node.view.mode == hv.MODE_MANUAL and box.node.lease_mode()
    box.sent.clear()
    box.now += T.per_round
    assert not box.node.is_active()
    box.node.tick()
    assert box.restarts


def test_switching_off_reached_a_majority():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(0.1)
    box.node.switch_off()
    box.later(0.01)
    box.answer_all('renew', _holds(box, ok=False, reason='MODE_MANUAL'))
    assert box.store.state['role'] == hv.ROLE_ACTIVE and not box.node.lease_mode()
    box.now += 10 * T.L
    assert box.node.is_active()


def test_a_commit_counts_who_holds_the_config_by_its_digest():
    """A leader whose state went back makes a config under an id its members passed
    already: their answers name that id, and they hold another config under it."""
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(data='abcde'), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', _ok)
    box.later(0.1)
    assert box.node.switch_off() == ''
    box.later(0.01)
    assert box.node.view.id == (1, 2)
    other = 'f' * 64
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), cfg_id=(1, 2), cfg_digest=other))
    assert not box.node._is_committed() and box.store.state['role'] == hv.ROLE_LEADER
    box.later(T.R)
    box.answer_all('renew', _holds(box, ok=False, reason='MODE_MANUAL'))
    assert box.node._is_committed() and box.store.state['role'] == hv.ROLE_ACTIVE


def test_a_leader_that_hears_of_a_config_of_its_term_it_does_not_hold_leaves():
    box = _leader()
    box.answer_all('renew', _ok)
    assert box.node.is_active()
    box.later(T.R)
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), cfg_id=(1, 2) if to == 'c' else (1, 1)))
    assert box.store.state['role'] == hv.ROLE_STANDBY and box.restarts
    assert 'voter config [1, 2], newer than the [1, 1] held here' in box.restarts[0]


def test_a_newer_config_of_an_older_term_is_one_the_leader_before_left_behind():
    """It never reached a majority (the new leader won with votes that hold its own
    config or older), and the new leader's first config goes past it."""
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2, voted_for='a')
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), cfg_id=(1, 2) if to == 'c' else (1, 1)))
    assert box.node.is_active() and box.store.state['role'] == hv.ROLE_LEADER
    box.later(0.01)
    assert box.node.view.id == (2, 2)


def test_a_leader_that_boots_into_a_term_its_members_moved_past_stays_a_standby():
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), cfg_id=(1, 3)))
    assert box.store.state['role'] == hv.ROLE_STANDBY and not box.node.acting_process()
    assert not box.restarts and 'boot_standby' in box.names()


def test_a_leader_that_leaves_before_its_switch_back_went_through_drops_it():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(0.1)
    assert box.node.switch_off() == ''
    box.later(0.01)
    assert box.node.view.mode == hv.MODE_MANUAL
    box.now += T.per_round
    box.node.tick()
    st = box.store.state
    assert st['role'] == hv.ROLE_STANDBY and st['cfg']['body']['mode'] == hv.MODE_AUTO
    assert hv.pair(st['cfg']['id']) == (1, 1) and 'switch_off_dropped' in box.names()
    # one that went through stays: a majority holds it
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(0.1)
    box.node.switch_off()
    box.later(0.01)
    box.store.fail = True
    box.answer_all('renew', _holds(box, ok=False, reason='MODE_MANUAL'))
    assert box.node._is_committed() and box.store.state['role'] == hv.ROLE_LEADER
    box.store.fail = False
    box.node.step_down('test')
    assert box.store.state['cfg']['body']['mode'] == hv.MODE_MANUAL


def test_a_manual_active_that_takes_an_automatic_config_from_a_vote_request_is_a_standby():
    g = genesis(mode=hv.MODE_MANUAL)
    auto_cfg = hv.make_cfg(g, 1, 'a', body(), KEYS['a'][1])
    box = settled(Box('a', g, role=hv.ROLE_ACTIVE, voted_for=None))
    # a pre-vote takes nothing
    assert box.vote('b', 2, pre=True, cfg_id=(1, 2), chain=[auto_cfg])['granted']
    assert box.store.state['role'] == hv.ROLE_ACTIVE and not box.restarts
    ans = box.vote('b', 2, cfg_id=(1, 2), chain=[auto_cfg])
    assert ans['granted'] and box.store.state['role'] == hv.ROLE_STANDBY
    assert box.store.state['voted_for'] == 'b' and box.store.state['cfg'] == auto_cfg
    assert box.restarts and ('step_down', {'why': box.restarts[0], 'by_hand': True}) in box.events
    # refused, it leaves all the same
    box = Box('a', g, role=hv.ROLE_ACTIVE, voted_for=None)
    ans = box.vote('b', 2, cfg_id=(1, 2), chain=[auto_cfg])
    assert ans['reason'] == 'HOLD_AFTER_START' and box.store.state['role'] == hv.ROLE_STANDBY
    assert box.restarts


def test_an_ack_from_a_voter_the_config_dropped_does_not_count():
    led = {'epoch': 1, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(data='abcd', witness='w'), role=hv.ROLE_LEADER, led=led)
    box.answer_all('renew', _ok)
    booted = box.node.lease_until
    box.later(T.R)
    out = {to: (b, tag) for to, k, b, tag in box.sent if k == 'renew'}
    box.sent.clear()
    box.node.on_answer('d', out['d'][1], _ok('d', out['d'][0]))
    # d is taken out while the round is on its way; then b answers
    box.node.change_cfg(lambda b: dict(b, voters=[r for r in b['voters'] if r['id'] != 'd']))
    box.later(0.01)
    assert box.node.view.n == 4 and box.node.view.m == 3
    box.node.on_answer('b', out['b'][1], _ok('b', out['b'][0]))
    # a and b are two of the four voters now: no majority, no lease from this round
    assert box.node.lease_until == booted
    box.node.on_answer('c', out['c'][1], _ok('c', out['c'][0]))
    assert box.node.lease_until > booted


def test_a_grant_from_a_voter_the_config_dropped_does_not_count():
    g = genesis(data='abcd', witness='w')
    c2 = hv.make_cfg(g, 1, 'a', body('abc', 'w'), KEYS['a'][1])
    box = settled(Box('b', g, voted_for='a'))
    box.node.campaign_now()
    out = {to: (b, tag) for to, k, b, tag in box.sent if k == 'vote'}

    def yes():
        return {'granted': True, 'epoch': 1, 'cv': (1, 5), 'cfg_id': (1, 1)}
    box.node.on_answer('d', out['d'][1], yes())
    # c holds the config without d and hands it over
    box.node.on_answer('c', out['c'][1], {'granted': False, 'reason': 'OLD_CFG', 'epoch': 1,
                                          'cv': (1, 5), 'cfg_id': (1, 2), 'chain': [c2]})
    assert box.node.view.n == 4
    box.node.on_answer('w', out['w'][1], yes())
    # b and w are two of the four voters now: no real vote yet
    assert 'vote' not in box.names()


def test_confirm_needs_a_round_that_started_after_it():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(T.R)
    first = [s for s in box.sent if s[1] == 'renew']
    box.sent.clear()
    # a round is out; the step is asked for right after it left, and gets one of its own
    # at once - there is no spacing between rounds
    box.now += 0.05
    seen = []
    box.node.confirm(5, seen.append)
    own = [s for s in box.sent if s[1] == 'renew']
    assert not seen and own and all(s[2]['epoch'] == 1 for s in own)
    for to, _, b, tag in first:
        box.node.on_answer(to, tag, _ok(to, b))
    assert seen == [], 'answered by a round that started before the step was asked for'
    box.answer_all('renew', _ok)
    assert seen == [True]
    # a round that misses its majority fails the confirm
    box.now += 0.5
    box.node.confirm(5, seen.append)
    box.answer_all('renew', lambda to, b: None)
    assert seen == [True, False]


def test_confirm_wants_enough_lease_left():
    box = _leader()
    box.answer_all('renew', _ok)
    box.now += 0.5
    seen = []
    box.node.confirm(T.per_round, seen.append)
    box.now += 0.4
    box.answer_all('renew', _ok)
    assert seen == [False]


def test_a_clock_step_forces_a_round():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(1)
    box.sent.clear()
    box.wall_offset += 3600
    box.later(0.1)
    assert 'clock_jump' in box.names()
    assert [s for s in box.sent if s[1] == 'renew']


def test_crossing_answers_quarantine_nobody_a_rollback_does():
    box = _leader()

    def gen(g):
        return lambda to, b: dict(_ok(to, b), gen=g)
    box.answer_all('renew', gen(10))
    box.later(T.R)
    first = [s for s in box.sent if s[1] == 'renew']
    box.sent.clear()
    box.later(0.5)
    box.node.confirm(0, lambda ok: None)
    # the answers of the later round come first with the higher gen, then the older
    # round's answers with a lower one: the older round started before, nothing wrong
    box.answer_all('renew', gen(12))
    for to, _, b, tag in first:
        box.node.on_answer(to, tag, dict(_ok(to, b), gen=11))
    box.later(T.R)
    box.answer_all('renew', gen(13))
    assert 'suspect' not in box.names()
    # a gen below one from a round that completed before this round started
    box.later(T.R)
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), gen=3 if to == 'b' else 14))
    assert ('suspect', {'voter': 'b', 'gen': 3, 'seen': 13}) in box.events


def test_a_crossing_answer_never_lowers_the_config_a_voter_holds():
    box = _leader()
    box.answer_all('renew', _ok)
    box.later(0.1)
    box.node.change_cfg(lambda b: dict(b, voters=b['voters'][:2] + [dict(b['voters'][2], site='x')]))
    box.later(0.01)
    assert box.node.view.id == (1, 2)
    box.sent.clear()
    box.later(0.01)
    first = [s for s in box.sent if s[1] == 'renew']
    box.sent.clear()
    assert first and all('chain' in b for _, _, b, _ in first)
    box.later(0.5)
    box.node.confirm(0, lambda ok: None)
    # the later round's answers come first, from voters that took (1, 2); then the first
    # round's, from before they took it
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), cfg_id=(1, 2)))
    for to, _, b, tag in first:
        box.node.on_answer(to, tag, _ok(to, b))
    box.later(T.R)
    sent = [(to, b) for to, k, b, _ in box.sent if k == 'renew']
    assert sent and not any('chain' in b for _, b in sent)
    # a lower id in the answer to a newer round: b lost the config, it gets the chain again
    box.answer_all('renew', lambda to, b: dict(_ok(to, b), cfg_id=(1, 1) if to == 'b' else (1, 2)))
    box.later(T.R)
    assert [to for to, k, b, _ in box.sent if k == 'renew' and 'chain' in b] == ['b']


def test_the_new_leader_commits_its_own_config_before_any_change():
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 0.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2, voted_for='a')
    box.node.change_cfg(lambda b: dict(b, voters=b['voters'][:2] + [dict(b['voters'][2], site='x')]))
    box.answer_all('renew', _ok)
    box.later(0.01)
    assert box.node.view.id == (2, 2) and box.node.view.cfg['body'] == genesis()['body']
    # the change waits for the no-op to reach a majority of the config before it
    box.later(0.01)
    assert box.node.view.id == (2, 2)
    box.answer_all('renew', _holds(box))
    box.later(0.01)
    assert box.node.view.id == (2, 3)


def test_a_winner_acts_only_after_w_take():
    box = settled(Box('b', genesis(), voted_for='a', restart_on_win=False))
    assert box.node.campaign_now() == ''
    box.answer_all('vote', lambda to, b: {'granted': True, 'epoch': 1, 'cv': (1, 5), 'cfg_id': (1, 1)})
    box.answer_all('vote', lambda to, b: {'granted': True, 'epoch': 2, 'cv': (1, 5), 'cfg_id': (1, 1)})
    n = box.node
    assert n.st['role'] == hv.ROLE_LEADER and n.holds_lease() and not n.is_active()
    assert n.acting_from == pytest.approx(box.now + T.W_take)
    won = [b for _, k, b, _ in box.sent if k == 'renew']
    assert won and all(b.get('hold_s') == T.won_hold for b in won)


def test_the_winner_restarts_by_default():
    box = settled(Box('b', genesis(), voted_for='a'))
    box.node.campaign_now()
    box.answer_all('vote', lambda to, b: {'granted': True, 'epoch': 1, 'cv': (1, 5), 'cfg_id': (1, 1)})
    box.answer_all('vote', lambda to, b: {'granted': True, 'epoch': 2, 'cv': (1, 5), 'cfg_id': (1, 1)})
    assert box.restarts == ['won the election']
    assert box.store.state['led']['take_after']['at'] == pytest.approx(box.now + T.W_take)


def test_a_candidate_does_not_count_itself_inside_the_hold_after_start():
    box = Box('b', genesis(), voted_for='b', epoch=1)
    box.node.campaign_now()
    assert box.sent and all(b['pre'] for _, k, b, _ in box.sent)
    assert 'b' not in box.node._campaign.acks


def test_planned_restart_holds_the_voters_and_keeps_the_lead():
    box = _leader()
    box.answer_all('renew', _ok)
    box.sent.clear()
    assert box.node.planned_restart(90) == ''
    held = [b for _, k, b, _ in box.sent if k == 'renew']
    assert held and all(b['hold_s'] == 90 for b in held)
    assert box.restarts and box.store.state['role'] == hv.ROLE_LEADER
    assert not box.node.is_active()


@pytest.mark.parametrize('boot_id', ['', 'boot-1'])
def test_a_step_down_backoff_from_an_earlier_process_does_not_outlive_a_fresh_one(boot_id):
    """campaign_after is written on the lease clock of the process that stepped down. A
    host with an empty boot id, or one that keeps it over a reboot, starts the next clock
    near 0, and the old value would hold the timer for the old uptime: a live majority
    of former leaders that never campaigns. It waits no longer than a fresh step-down."""
    cfg = genesis()
    st = hv.new_state(cfg, role=hv.ROLE_STANDBY, epoch=3, kind=hv.KIND_DATA, cv=(3, 5))
    st.update(voted_for='b', campaign_after={'boot_id': boot_id, 'started': 999999.0, 'at': 5e5})
    box = Box('a', cfg, state=st, boot_id=boot_id, start=100.0)
    cap = box.node.started + T.boot_wait + T.lost_lease_backoff
    assert box.node.election_at <= cap + 1e-6
    # counterproof: the same value written by this very process is honoured in full
    st2 = dict(st, campaign_after={'boot_id': boot_id, 'started': None, 'at': 5e5})
    box2 = Box('a', cfg, state=st2, boot_id=boot_id, start=100.0)
    box2.node.st['campaign_after'] = dict(st2['campaign_after'], started=box2.node.started)
    box2.node._arm_timer(box2.now)
    if boot_id:
        assert box2.node.election_at >= 5e5


def test_members_do_not_all_campaign_the_moment_a_hold_ends():
    """A planned-restart hold ends at the same instant on every member: each one's
    election waits a random part of L/4 past it, so they do not split the vote."""
    times = []
    for seed in (7, 11, 23):
        box = settled(Box('c', genesis()))
        box.node.rng = random.Random(seed)
        box.renew('b', 2, hold_s=90)
        end = box.node.promise_until
        assert end <= box.node.election_at <= end + T.L / 4
        times.append(box.node.election_at - end)
    assert len(set(round(t, 6) for t in times)) == 3


def test_a_leader_that_acts_at_once_says_so_at_its_boot():
    """take_after lies behind it: acting starts with the boot round, and so does the line,
    not a tick later."""
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 990.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2)
    box.answer_all('renew', _ok)
    names = box.names()
    assert box.node.is_active() and names.index('acting') == names.index('booted') + 1
    box.later(T.R)
    assert box.names().count('acting') == 1


def test_the_first_gate_past_the_takeover_wait_says_acting_before_the_tick():
    """take_after lies ahead at boot, and the loop wakes late for it (lab E6b: a write
    38 ms after acting_from, before the line). The gate that finds the wait over says
    'acting' (acting_seen), once; is_active() itself says nothing."""
    led = {'epoch': 2, 'cv': (1, 5), 'take_after': {'boot_id': 'boot-1', 'at': 1010.0}}
    box = Box('a', genesis(), role=hv.ROLE_LEADER, led=led, epoch=2)
    box.answer_all('renew', _ok)
    assert 'booted' in box.names() and 'acting' not in box.names()
    assert box.node.acting_from == pytest.approx(1010.0)
    assert not box.node.acting_seen() and not box.node.acting_said
    box.now = 1010.04
    said = box.names()
    assert box.node.is_active() and box.names() == said
    assert box.node.acting_seen() and box.names() == said + ['acting']
    assert box.events[-1][1] == {'epoch': 2}
    assert box.node.acting_said and not box.node.acting_seen()
    box.later(T.R)
    assert box.names().count('acting') == 1


def test_a_promise_that_ends_before_the_timer_leaves_the_timer_as_it_was():
    """The normal case: the promise from a renewal ends before heard_at + P + jitter, so
    no second random part is drawn on top of the timer's own."""
    box = settled(Box('c', genesis()))
    draws = []

    class Counting(random.Random):
        def uniform(self, a, b):
            draws.append((a, b))
            return super().uniform(a, b)
    box.node.rng = Counting(7)
    box.renew('b', 2)
    heard = box.node.heard_at
    assert box.node.promise_until < box.node.election_at
    assert heard + T.P <= box.node.election_at <= heard + T.P + T.L / 4
    assert draws == [(0, T.L / 4)]


# --- a clock off the majority of the members (Q15) ---

def _timer_box(me, skewed, seed=7):
    """A member past its hold that took a renewal of a: its timer runs from there.
    skewed() is what the host says about its clock."""
    box = settled(Box(me, genesis(), skewed=skewed))
    box.node.rng = random.Random(seed)
    box.renew('a', 1)
    return box


def _fire(box):
    """Turn the clock to the timer and tick: the vote calls sent so far."""
    box.now = box.node.election_at
    box.node.tick()
    return [b for _to, kind, b, _tag in box.sent if kind == 'vote']


def test_a_member_whose_clock_is_off_the_majority_campaigns_one_lease_later():
    """Two timers fire at the same moment. The member with a right clock asks for votes,
    the one off the majority waits one lease more, and by then the other one won."""
    right = _timer_box('b', lambda: False)
    off = _timer_box('c', lambda: True)
    fired = off.node.election_at
    assert right.node.election_at == fired

    votes = _fire(right)
    assert votes and all(b['pre'] for b in votes)
    assert _fire(off) == []
    assert off.node.election_at == pytest.approx(fired + T.L)
    assert [info for name, info in off.events if name == 'campaign_deferred'] == [{'until': fired + T.L}]


def test_a_member_off_the_majority_still_campaigns_after_the_extra_lease():
    """The deferral never blocks an election: once the extra lease is over the member
    campaigns, its clock as far off as before. A group whose clocks all drifted apart
    still elects one."""
    off = _timer_box('c', lambda: True)
    assert _fire(off) == []
    votes = _fire(off)
    assert votes and all(b['pre'] for b in votes) and off.node.campaigning()


def test_the_extra_lease_comes_with_a_renewal_or_a_vote_granted():
    """A renewal and a vote it grants arm the timer anew: the next time it fires the
    member waits again, so a member with a right clock gets the first try."""
    off = _timer_box('c', lambda: True)
    assert _fire(off) == []
    off.renew('a', 1)
    assert off.node.deferred_at is None
    fired = off.node.election_at
    assert _fire(off) == [] and off.node.election_at == pytest.approx(fired + T.L)
    # b asks for votes in the meantime and gets c's: its timer starts over, and so does
    # the wait
    assert off.vote('b', 2)['granted'] and off.node.deferred_at is None
    off.sent.clear()
    fired = off.node.election_at
    assert _fire(off) == [] and off.node.election_at == pytest.approx(fired + T.L)


def test_a_lost_try_of_its_own_brings_no_second_wait():
    """It waited its lease and nobody with a right clock won meanwhile: after a campaign
    of its own that failed it tries again at the back-off as every member does. One more
    lease per try would leave a group whose clocks all drifted apart without a leader for
    a lease longer with every round it loses (the bound is I6 plus one lease)."""
    off = _timer_box('c', lambda: True)
    assert _fire(off) == []
    deferred = off.node.deferred_at
    assert _fire(off)
    off.answer_all('vote', lambda to, b: {'granted': False, 'epoch': 1, 'reason': 'PROMISED'})
    assert not off.node.campaigning() and off.node.deferred_at == deferred
    off.sent.clear()
    lost_at = off.now
    votes = _fire(off)
    assert votes and all(b['pre'] for b in votes)
    assert T.L / 2 <= off.now - lost_at <= T.L
    assert off.names().count('campaign_deferred') == 1


def test_a_member_whose_clock_is_off_votes_as_before():
    """It only waits with its own campaign: its vote keeps the majority there."""
    box = settled(Box('c', genesis(), skewed=lambda: True))
    assert box.vote('b', 2, pre=True)['granted']
    assert box.vote('b', 2)['granted'] and box.store.state['voted_for'] == 'b'
    assert box.renew('b', 2)['ok'] and box.node.promise_to == 'b'


def test_make_leader_is_not_put_off_by_the_clock():
    """The admin picked this member: the pre-vote goes out at once."""
    box = settled(Box('c', genesis(), skewed=lambda: True))
    assert box.node.campaign_now() == ''
    assert [b for _to, kind, b, _tag in box.sent if kind == 'vote']


def test_a_clock_off_changes_nothing_in_manual_mode():
    """A member of a manual group never campaigns, and nobody asks about its clock."""
    asked = []
    box = settled(Box('c', genesis(mode=hv.MODE_MANUAL), skewed=lambda: asked.append(1) or True))
    box.renew('a', 1)
    box.later(10 * T.L)
    assert box.sent == [] and asked == [] and 'campaign_deferred' not in box.names()
