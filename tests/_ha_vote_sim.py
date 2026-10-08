"""A deterministic simulator for the lease protocol in pegaprox/core/ha_vote.py (#625 stage 2).

Every member is an ha_vote.Node driven by this module, one event at a time in true time:
  * a lease clock per member with a rate error (0.9-1.1 of true time), slew phases,
    freezes (a paused VM) and host reboots (a new boot id, the clock starts over)
  * a wall clock per member with an offset, and steps; signed calls outside the 120 s
    window, or signed before the receiver's process started, are refused (ha.py)
  * the watch of every data member: every WATCH_EVERY seconds it measures the wall clock
    of each member that answers (the witness too), and a member off the majority of
    what it measured within SEEN_FRESH puts its timer campaign off (Q15, ha._clock_off)
  * directed links with a delay, jitter (so answers cross and come late), drops and
    blackholes; a cut also takes what is in flight
  * pauses (SIGSTOP: the clock runs on, calls queue up) and crashes; a restart builds a
    new Node from the persisted state, a rollback hands it an older one, and a full disk
    fails the next few writes (SimStore.fail)
  * the data a leader writes (cv), pulled by the members, captured when a snapshot
    would wipe it (orphans), and the irreversible steps it takes after a confirm

After every event the invariants I1-I8 of the design (section 11.1) are checked in true
time against what the nodes believe and against what the simulator knows. Nothing here
is random outside Sim.rng, so a seed replays exactly.

MK Oct 2026 (#625)
"""
import hashlib
import heapq
import math
import random
import zlib
from collections import deque

from pegaprox.core import ha_vote as hv

INF = math.inf
SIGNATURE_WINDOW = 120
# the watch: one look at the members per pass of the HA loop (ha.DEFAULT_INTERVAL), the
# first a few seconds after a start, and what it saw counts for LEASE_SEEN_FRESH
WATCH_EVERY = 30.0
WATCH_FIRST = 5.0
SEEN_FRESH = 120.0


class Violation(AssertionError):
    pass


# --- keys: a fast stand-in for Ed25519, or the real thing ---

def _fast_keys(iid):
    secret = ('k-' + iid).encode()

    def sign(message):
        return hashlib.sha256(secret + message).hexdigest()
    return iid, sign


def _fast_verify(public_key, message, sig):
    return sig == hashlib.sha256(('k-' + public_key).encode() + message).hexdigest()


def _ed25519_keys(iid):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(iid.encode()).digest())
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode(), hv.ed25519_signer(base64.b64encode(raw).decode())


class SimClock:
    """A lease clock: value = base + (t - t0) * rate, frozen or not."""

    __slots__ = ('rate', 't0', 'v0', 'frozen', 'boot_id')

    def __init__(self, t, value, rate, boot_id):
        self.t0, self.v0, self.rate, self.frozen, self.boot_id = t, value, rate, False, boot_id

    def at(self, t):
        return self.v0 if self.frozen else self.v0 + (t - self.t0) * self.rate

    def rebase(self, t):
        self.v0 = self.at(t)
        self.t0 = t

    def set_rate(self, t, rate):
        self.rebase(t)
        self.rate = rate

    def freeze(self, t):
        self.rebase(t)
        self.frozen = True

    def thaw(self, t):
        self.t0 = t
        self.frozen = False

    def true_of(self, value, t):
        if self.frozen:
            return INF
        return t + (value - self.at(t)) / self.rate


class SimStore:
    def __init__(self, state):
        self.state = state
        self.history = deque([state], maxlen=400)
        self.fail = 0

    def load(self):
        return self.state

    def save(self, st):
        if self.fail:
            self.fail -= 1
            raise OSError('No space left on device')
        self.state = st
        self.history.append(st)


class _Hooks:
    __slots__ = ('sim', 'm')

    def __init__(self, sim, m):
        self.sim, self.m = sim, m

    def restart(self, why):
        self.m.restart_why = why

    def event(self, name, info):
        self.sim._on_event(self.m, name, info)

    def snapshot(self):
        return {'data': self.m.data}

    def apply_snapshot(self, frm, ans):
        snap = ans.get('snapshot') or {}
        cv = hv.pair(ans.get('cv'))
        if cv is None:
            return None
        self.sim._apply(self.m, snap.get('data', frozenset()), cv, frm, catchup=True)
        return cv


class Member:
    def __init__(self, sim, iid, kind, site, voter, may_lead, keys):
        self.sim = sim
        self.iid = iid
        self.kind = kind
        self.site = site
        self.voter = voter
        self.may_lead = may_lead
        self.public_key, self.sign = keys
        self.clock = SimClock(0.0, sim.rng.uniform(1000, 5000), 1.0, f'{iid}-boot0')
        self.wall_offset = 0.0
        self.wall_frozen = None
        self.store = None
        self.node = None
        self.inc = 0
        self.up = False
        self.paused = False
        self.queue = []
        self.data = frozenset()
        self.orphans = set()
        self.start_wall = -INF
        self.wake_at = INF
        self.restart_why = None
        # the promises this member made that may still run: (holder, until, boot id, inc,
        # effective); until is on the lease clock of that boot, or true time (boot None)
        self.ghosts = []
        self.out_of_model = False
        self.hold_disabled = False
        self.lease_t0 = -INF
        self.lease_end = -INF
        self.hooks = _Hooks(sim, self)
        self.downtime = (2.0, 25.0)
        self.boots = 0
        self.no_pull = False
        # the leader epoch of the last snapshot applied, kept with the data
        self.applied_epoch = 0
        self.same_instant = (None, 0)
        self.booted_at = None
        # what the watch of this process measured: member -> (skew or 'window', true time)
        self.seen = {}

    def wall(self):
        if self.wall_frozen is not None:
            return self.wall_frozen
        return self.sim.now + self.wall_offset

    def lease_clock(self):
        return self.clock.at(self.sim.now)

    def send(self, to, kind, body, tag):
        self.sim._transmit(self, to, kind, body, tag)

    def __repr__(self):
        return f'<{self.iid}>'


class Sim:
    """One run. Build the group with add(), start() it, script faults with at(), run()."""

    def __init__(self, seed, *, lease_s=20, keep_w_take=True, restart_on_win=True,
                 crypto='fast', delay=(0.0005, 0.004), jitter=0.002, late=0.0,
                 writes=0.4, steps=0.3, check=True, collect=False):
        self.seed = seed
        self.rng = random.Random(seed)
        self.now = 0.0
        self.heap = []
        self.seq = 0
        self.members = {}
        self.order = []
        self.lease_s = lease_s
        self.keep_w_take = keep_w_take
        self.restart_on_win = restart_on_win
        self.crypto = crypto
        self.verify = _fast_verify if crypto == 'fast' else hv.ed25519_verify
        self.t = hv.Timings(lease_s, keep_w_take)
        self._by_lease = {lease_s: self.t}
        self.links = {}
        self.link_delay = {}
        self.base_delay = delay
        self.jitter = jitter
        self.late = late
        self.p_write = writes
        self.p_step = steps
        self.check_on = check
        # collect: note every violation and run on, for a counterproof that wants to see
        # which invariants a broken rule breaks
        self.collect = collect
        self.log = deque(maxlen=300)
        self.events = 0
        # what the checks know
        self.winners = {}
        self.grants = {}
        self.floors = {}
        self.committed = {}
        self.writes = {}
        self.wid = 0
        self.effects = []
        self.refused_at_node = []
        self.elections = []
        self.counts = {}
        self.violations = []
        self.allow_dual_actors = False
        self.rollbacks = 0
        self.round_sent = {}
        self.round_lease = {}
        self.claims = None
        self.claim_watch = 30.0
        self._acting_now = {}
        self.first_acting_after = None
        self.committed_cfg = {}
        self.counted = {}
        self.downs = []
        self.on_event_hook = None

    # --- the group ---

    def add(self, iid, kind=hv.KIND_DATA, site='', voter=True, may_lead=True):
        keys = _fast_keys(iid) if self.crypto == 'fast' else _ed25519_keys(iid)
        m = Member(self, iid, kind, site, voter, may_lead, keys)
        self.members[iid] = m
        self.order.append(iid)
        return m

    def body(self, mode=hv.MODE_AUTO, exclude=()):
        voters, witness = [], None
        for iid in self.order:
            if iid in exclude:
                continue
            m = self.members[iid]
            if m.kind == hv.KIND_WITNESS:
                witness = {'id': iid, 'public_key': m.public_key, 'site': m.site}
            else:
                voters.append({'id': iid, 'public_key': m.public_key, 'voter': m.voter,
                               'may_lead': m.may_lead, 'site': m.site})
        return {'mode': mode, 'lease_s': self.lease_s, 'voters': voters, 'witness': witness,
                'quarantined': []}

    def start(self, leader, *, mode=hv.MODE_AUTO, epoch=1, skew=2.0, rates=None, jitter_start=0.5,
              exclude=(), boot_at=None):
        """Every member on the same genesis config, `leader` holding epoch `epoch`. Members in
        `exclude` run, hold the genesis and are not in it (a witness about to be added).
        boot_at {member: true time} starts those members later (a cold start)."""
        lm = self.members[leader]
        body = self.body(mode, exclude)
        assert not hv.body_error(body), hv.body_error(body)
        genesis = hv.make_cfg(None, epoch, leader, body, lm.sign)
        for iid in self.order:
            m = self.members[iid]
            if mode == hv.MODE_AUTO:
                role = hv.ROLE_LEADER if iid == leader else (
                    hv.ROLE_WITNESS if m.kind == hv.KIND_WITNESS else hv.ROLE_STANDBY)
            else:
                role = hv.ROLE_ACTIVE if iid == leader else (
                    hv.ROLE_WITNESS if m.kind == hv.KIND_WITNESS else hv.ROLE_STANDBY)
            st = hv.new_state(genesis, role=role, epoch=epoch, kind=m.kind, cv=(epoch, 0))
            if mode == hv.MODE_AUTO:
                st['voted_for'] = leader
                if iid == leader:
                    st['led'] = {'epoch': epoch, 'cv': (epoch, 0),
                                 'take_after': {'boot_id': m.clock.boot_id, 'at': 0.0}}
            m.store = SimStore(st)
            m.wall_offset = self.rng.uniform(-skew / 2, skew / 2)
            rate = rates.get(iid) if rates else None
            m.clock.rate = rate if rate is not None else 1.0
            if mode == hv.MODE_AUTO and iid == leader:
                self.winners[epoch] = leader
        for iid in self.order:
            t = self.rng.uniform(0, jitter_start)
            self.at((boot_at or {}).get(iid, t), self._boot, self.members[iid])
        self.at(1.0, self._automation)
        self.at(1.5, self._pulls)

    # --- the event loop ---

    def at(self, t, fn, *args):
        self.seq += 1
        heapq.heappush(self.heap, (t, self.seq, fn, args))

    def after(self, dt, fn, *args):
        self.at(self.now + dt, fn, *args)

    def run(self, until):
        heap = self.heap
        while heap and heap[0][0] <= until:
            t, _, fn, args = heapq.heappop(heap)
            if t > self.now:
                self.now = t
            fn(*args)
            self.events += 1
            if self.violations and not self.collect:
                raise Violation(self.report())
        self.now = until
        if self.check_on:
            self._check()
            if self.violations and not self.collect:
                raise Violation(self.report())

    def report(self):
        lines = [f'seed {self.seed} at t={self.now:.3f}: ' + '; '.join(self.violations[:3])]
        lines += list(self.log)[-60:]
        return '\n'.join(lines)

    def note(self, text):
        self.log.append(f'{self.now:9.3f} {text}')

    def bump(self, name):
        self.counts[name] = self.counts.get(name, 0) + 1

    def fail(self, text):
        if self.collect and text in self.violations:
            return
        self.violations.append(text)
        self.note('VIOLATION ' + text)

    def broken(self):
        """The invariants that failed, by name (I1 ... I8)."""
        return {v.split(':')[0] for v in self.violations}

    # --- processes ---

    def _boot(self, m):
        if m.up:
            return
        m.up = True
        m.paused = False
        m.queue = []
        m.inc += 1
        m.restart_why = None
        m.wake_at = INF
        m.start_wall = m.wall()
        m.out_of_model = False
        m.lease_t0 = -INF
        m.lease_end = -INF
        m.node = hv.Node(m.iid, m.kind, store=m.store, clock=m.lease_clock, wall=m.wall,
                         send=m.send, hooks=m.hooks, rng=random.Random(self.rng.random()),
                         sign=m.sign, verify=self.verify, boot_id=m.clock.boot_id,
                         restart_on_win=self.restart_on_win, keep_w_take=self.keep_w_take,
                         skewed=lambda m=m: self.skewed(m.iid))
        m.booted_at = self.now
        # memory only, like the runtime of the process: the watch starts over
        m.seen = {}
        if m.kind == hv.KIND_DATA:
            self.after(WATCH_FIRST, self._watch, m, m.inc)
        if m.hold_disabled:
            # a fault: this process behaves as if it had run for long, it forgot its promise
            # and grants at once
            m.node.started -= m.node.t.hold_after_start + 1
            m.node.hold_until = m.node.started
        self.note(f'{m.iid} up ({m.node.st["role"]} epoch {m.node.epoch})')
        self._after(m)

    def _down(self, m, why, downtime=None):
        if not m.up:
            return
        self._acting_end(m)
        m.up = False
        m.node = None
        m.inc += 1
        m.queue = []
        m.paused = False
        m.wake_at = INF
        if m.clock.frozen:
            m.clock.thaw(self.now)
        m.wall_frozen = None
        lo, hi = downtime if downtime is not None else m.downtime
        self.downs.append((self.now, m.iid, why))
        self.note(f'{m.iid} down ({why})')
        if hi is not None:
            self.after(self.rng.uniform(lo, hi), self._boot, m)

    def crash(self, iid, downtime=None):
        m = self.members[iid]
        self._down(m, 'crash', downtime)

    def stop(self, iid):
        self._down(self.members[iid], 'stopped', (0, None))

    def boot(self, iid):
        self._boot(self.members[iid])

    def reboot_host(self, iid, downtime=(20.0, 40.0)):
        m = self.members[iid]
        # the lease clock is gone, what is left of a promise goes on in true time. A lease
        # rests on a promise for L of true time from receipt, and 1.1 L on a voter clock
        # 10% fast is just that (design 4.2): left / 1.1 is what the promise is sure to
        # cover. left / 0.9 would want a voter that cannot know its clock rate to hold 22%
        # longer than any lease can need
        ghosts = []
        for g in m.ghosts:
            if g[2] == m.clock.boot_id:
                left = g[1] - m.clock.at(self.now)
                if left > 0:
                    ghosts.append((g[0], self.now + left / 1.1, None, None, None))
            elif g[2] is None and self.now < g[1]:
                ghosts.append(g)
        m.ghosts = ghosts
        m.boots += 1
        m.clock = SimClock(self.now, self.rng.uniform(0, 5), m.clock.rate, f'{iid}-boot{m.boots}')
        self._down(m, 'host reboot', downtime)

    def rollback(self, iid, back, downtime=(1.0, 3.0)):
        """The member comes back with a state file `back` writes old (a RAM snapshot revert)."""
        m = self.members[iid]
        hist = list(m.store.history)
        old = hist[max(0, len(hist) - 1 - back)]
        self.rollbacks += 1
        self._down(m, f'rollback by {back} writes', downtime)
        m.store.state = old
        m.store.history.append(old)

    def pause(self, iid, freeze_clock=False):
        m = self.members[iid]
        if not m.up or m.paused:
            return
        m.paused = True
        if freeze_clock:
            m.clock.freeze(self.now)
            m.wall_frozen = m.wall()
            if m.node and (m.node.holds_lease() or m.node.is_active()):
                m.out_of_model = True
        self.note(f'{iid} paused' + (' (clock frozen)' if freeze_clock else ''))

    def resume(self, iid):
        m = self.members[iid]
        if not m.up or not m.paused:
            return
        m.paused = False
        if m.clock.frozen:
            m.clock.thaw(self.now)
            m.wall_frozen = None
        self.note(f'{iid} resumed')
        m.wake_at = INF
        queue, m.queue = m.queue, []
        if m.node:
            m.node.tick()
            self._after(m)
        for item in queue:
            if not m.up or m.paused:
                break
            if item[0] == 'req':
                self._handle_request(m, item[1])
            else:
                self._take_answer(m, *item[1:])

    def set_rate(self, iid, rate):
        m = self.members[iid]
        m.clock.set_rate(self.now, rate)
        if m.node:
            self._after(m, check=False)

    def wall_step(self, iid, delta):
        m = self.members[iid]
        m.wall_offset += delta
        # ha._process_started is the wall clock now less the lease clock's age: it moves
        # with a step
        m.start_wall += delta
        self.note(f'{iid} wall clock steps {delta:+.0f} s')

    def set_walls(self, offsets):
        """Every wall clock in `offsets` at true time + its offset, as steps."""
        for iid, off in offsets.items():
            self.wall_step(iid, off - self.members[iid].wall_offset)

    # --- the watch and the clock skew (Q15) ---

    def _watch(self, m, inc):
        """One look of m's watch at the others, as ha._ask_members and ha._ask_witness take
        it: the skew of each member that answers its status call, 'window' for one that
        refuses it for its time. A data member that does not answer is forgotten at once,
        the witness only once what it said is stale."""
        if m.inc != inc:
            return
        if not m.paused:
            for o in self.members.values():
                if o is m:
                    continue
                answers = (o.up and not o.paused and self.link(m.iid, o.iid) == 'up'
                           and self.link(o.iid, m.iid) == 'up')
                if answers:
                    skew = o.wall() - m.wall()
                    m.seen[o.iid] = ('window' if abs(skew) > SIGNATURE_WINDOW else skew, self.now)
                elif o.kind == hv.KIND_DATA:
                    m.seen.pop(o.iid, None)
        self.after(WATCH_EVERY, self._watch, m, inc)

    def skewed(self, iid):
        """ha._clock_off for member `iid`: more than SKEW_LIMIT off more than half of the
        members it measured within SEEN_FRESH, False with none measured."""
        measured = off = 0
        for skew, at in self.members[iid].seen.values():
            if self.now - at > SEEN_FRESH:
                continue
            measured += 1
            off += skew == 'window' or abs(skew) > hv.SKEW_LIMIT
        return measured > 0 and 2 * off > measured

    # --- the network ---

    def link(self, a, b):
        return self.links.get((a, b), 'up')

    def cut(self, a, b, both=True, how='blackhole'):
        self.links[(a, b)] = how
        if both:
            self.links[(b, a)] = how

    def heal(self, a, b, both=True):
        self.links.pop((a, b), None)
        if both:
            self.links.pop((b, a), None)

    def isolate(self, iid, how='blackhole'):
        for other in self.order:
            if other != iid:
                self.cut(iid, other, how=how)
        self.note(f'{iid} isolated')

    def partition(self, *groups, how='blackhole'):
        where = {}
        for i, g in enumerate(groups):
            for iid in g:
                where[iid] = i
        for a in self.order:
            for b in self.order:
                if a != b and where.get(a) != where.get(b):
                    self.links[(a, b)] = how
        self.note('partition ' + ' | '.join(','.join(g) for g in groups))

    def heal_all(self):
        self.links.clear()
        self.note('healed')

    def set_delay(self, a, b, base, jitter=None):
        self.link_delay[(a, b)] = (base, self.jitter if jitter is None else jitter)

    def _delay(self, a, b):
        base, jitter = self.link_delay.get((a, b), (None, None))
        if base is None:
            lo, hi = self.base_delay
            base = lo + (hi - lo) * ((zlib.crc32(f'{a}>{b}'.encode()) % 1000) / 1000.0)
            jitter = self.jitter
        d = base + self.rng.expovariate(1.0 / jitter) if jitter else base
        if self.late and self.rng.random() < self.late:
            d += self.rng.uniform(0.3, 3.0)
        return d

    def _transmit(self, src, to, kind, body, tag):
        if kind == 'renew' and not body.get('switch'):
            if self.winners.get(body['epoch']) != src.iid:
                self.fail(f'I2: {src.iid} renews at epoch {body["epoch"]}, '
                          f'won by {self.winners.get(body["epoch"])}')
        if type(tag) is int:
            key = (src.iid, src.inc, tag)
            if key not in self.round_sent:
                self.round_sent[key] = self.now
            # the lease a round asks for, as it went out: I7 checks the round by this,
            # not by what the node says it counted
            if isinstance(body, dict) and body.get('lease_s') is not None:
                self.round_lease.setdefault(key, body['lease_s'])
        how = self.link(src.iid, to)
        if how == 'blackhole':
            return
        rec = (src.iid, src.inc, to, kind, body, tag, src.wall())
        if how == 'drop':
            self.after(self._delay(src.iid, to), self._answer, to, rec, None)
            return
        self.after(self._delay(src.iid, to), self._deliver, rec)

    def _deliver(self, rec):
        frm, finc, to, kind, body, tag, wall_sent = rec
        if self.link(frm, to) != 'up':
            return
        m = self.members[to]
        if not m.up:
            # connection refused
            if self.link(to, frm) == 'up':
                self.after(self._delay(to, frm), self._answer, to, rec, None)
            return
        if m.paused:
            m.queue.append(('req', rec))
            return
        self._handle_request(m, rec)

    def _handle_request(self, m, rec):
        frm, finc, to, kind, body, tag, wall_sent = rec
        here = m.wall()
        if abs(here - wall_sent) > SIGNATURE_WINDOW or wall_sent < m.start_wall:
            ans = {'ok': False, 'reason': 'HA_CLOCK'}
            self.bump('refused HA_CLOCK')
        elif kind == 'pull':
            ans = self._serve_pull(m, body)
        else:
            ans = m.node.on_request(frm, kind, body)
        self._answer(to, rec, ans)
        self._after(m)

    def _answer(self, by, rec, ans):
        frm, finc = rec[0], rec[1]
        how = self.link(by, frm)
        if how == 'blackhole':
            return
        if how == 'drop':
            ans = None
        self.after(self._delay(by, frm), self._answer_arrives, frm, finc, by, rec, ans)

    def _answer_arrives(self, to, inc, by, rec, ans):
        if ans is not None and self.link(by, to) != 'up':
            return
        m = self.members[to]
        if not m.up or m.inc != inc:
            return
        if m.paused:
            m.queue.append(('ans', by, rec, ans))
            return
        self._take_answer(m, by, rec, ans)

    def _take_answer(self, m, by, rec, ans):
        if rec[1] != m.inc:
            return
        if rec[3] == 'pull':
            self._pulled(m, by, ans)
        else:
            m.node.on_answer(by, rec[5], ans)
        self._after(m)

    # --- after every event ---

    def _after(self, m, check=True):
        if m.node is not None and m.node.dead:
            self._down(m, m.restart_why or 'exit')
        elif m.node is not None and not m.paused:
            w = m.node.next_wake()
            if w is not None:
                t = m.clock.true_of(w, self.now) + 1e-6
                if t < m.wake_at - 1e-9:
                    m.wake_at = t
                    self.at(t, self._wake, m, m.inc)
        if check and self.check_on:
            self._check()

    def _wake(self, m, inc):
        if m.inc != inc or m.node is None:
            return
        if m.paused:
            m.wake_at = INF
            return
        if self.now + 1e-9 < m.wake_at:
            return
        t, k = m.same_instant
        m.same_instant = (self.now, k + 1 if t == self.now else 0)
        if m.same_instant[1] > 1000:
            self.fail(f'{m.iid} wakes over and over at the same instant')
            return
        m.wake_at = INF
        m.node.tick()
        self._after(m)

    # --- the invariants ---

    def _check(self):
        holders = []
        actors = []
        for m in self.members.values():
            n = m.node
            if n is None:
                continue
            active = n.is_active()
            if active != (m.iid in self._acting_now):
                if active:
                    self._acting_now[m.iid] = self.now
                    if self.first_acting_after is not None and self.first_acting_after[1] is None:
                        self.first_acting_after = (self.first_acting_after[0], self.now, m.iid)
                else:
                    self._acting_end(m)
            if m.out_of_model:
                if not active and not n.holds_lease() and not m.clock.frozen:
                    m.out_of_model = False
                continue
            if active:
                actors.append(m)
            if n.lease_mode() and n.holds_lease():
                holders.append(m)
                # I7: the lease rests on a majority round sent no longer ago than a lease
                # by that round's lease_s lasts on a clock running 10% slow
                if self.now > m.lease_end + 1e-6:
                    self.fail(f'I7: {m.iid} holds a lease from a round sent at {m.lease_t0:.3f}')
        if len(holders) > 1:
            self.fail('I1: ' + ', '.join(f'{m.iid}@{m.node.led_epoch}' for m in holders)
                      + ' hold a lease at once')
        if len(actors) > 1 and not self.allow_dual_actors:
            self.fail('I3: ' + ', '.join(m.iid for m in actors) + ' act at once')

    def _timings(self, lease_s):
        t = self._by_lease.get(lease_s)
        if t is None:
            t = self._by_lease[lease_s] = hv.Timings(lease_s, self.keep_w_take)
        return t

    def _acting_end(self, m):
        self._acting_now.pop(m.iid, None)

    def _on_event(self, m, name, info):
        if self.on_event_hook is not None:
            self.on_event_hook(m, name, info)
        self.bump(name)
        if name == 'promise':
            # this process keeps the longest promise itself; one an earlier process made to
            # the same holder runs on next to a shorter one made now. A promise to another
            # holder means that one won its term (D4)
            m.ghosts = [g for g in m.ghosts if g[3] != m.inc and g[0] == info['holder']
                        and self._ghost_runs(m, g)]
            m.ghosts.append((info['holder'], info['until'], m.clock.boot_id, m.inc, info['effective']))
            return
        if name == 'round':
            return
        if name == 'granted':
            self._check_grant(m, info)
            return
        if name == 'lease':
            key = (m.iid, m.inc, info['tag'])
            sent = self.round_sent.get(key, self.now)
            asked = self.round_lease.get(key, info['lease_s'])
            m.lease_t0 = max(m.lease_t0, sent)
            m.lease_end = max(m.lease_end, sent + self._timings(min(asked, info['lease_s'])).per_round / 0.9)
            v = m.node.view
            acks = info['acks']
            if not acks <= (v.counting | {m.iid}) or len(acks & v.counting) < v.m:
                self.fail(f'I7: {m.iid} counts {sorted(acks)} as a majority of {sorted(v.counting)}')
            return
        self.note(f'{m.iid} {name} ' + ' '.join(
            f'{k}={v}' for k, v in info.items() if k not in ('cfg', 'prev', 'grants', 'acks')))
        if name == 'elected':
            self._check_elected(m, info)
        elif name == 'vote' and not info['allowance']:
            # a candidate's vote for itself is a grant as well
            self._check_promises(m, m.iid, info['epoch'])
        elif name == 'floor':
            e = info['epoch']
            if info['floor'] > self.floors.get(e, hv.ZERO):
                self.floors[e] = info['floor']
        elif name == 'cfg':
            cfg, prev = info['cfg'], info['prev']
            # counted here, not with the module's own helper, so a broken guard shows
            va, vb = hv.CfgView(prev), hv.CfgView(cfg)
            if va.m + vb.m <= len(va.voters | vb.voters):
                self.fail(f'I8: config {cfg["id"]} does not overlap the one before')
        elif name == 'cfg_committed':
            cfg = info['cfg']
            cid, dg = hv.pair(cfg['id']), hv.cfg_digest(cfg)
            if self.committed.setdefault(cid, dg) != dg:
                self.fail(f'I8: two committed configs with id {cid}')
            self.committed_cfg[cid] = cfg
        elif name == 'acting' and self.claims is not None:
            self._write_claims(m)
        elif name == 'transfer':
            # the leader nudges the target, which pulls at once
            self.after(0.001, self.pull, info['to'])

    def _check_grant(self, m, info):
        cand, epoch = info['candidate'], info['epoch']
        self.grants.setdefault((cand, epoch), []).append((m.iid, m.kind, info['cv'], info['floor']))
        if not info['allowance']:
            self._check_promises(m, cand, epoch)

    def _check_promises(self, m, cand, epoch):
        for g in m.ghosts:
            if g[0] not in (None, cand) and self._ghost_runs(m, g):
                self.fail(f'I4: {m.iid} grants {cand} at {epoch} while its promise to {g[0]} runs')
                return

    def _ghost_runs(self, m, g):
        holder, until, boot, inc, effective = g
        if inc == m.inc:
            # the same process: the hold of a hold_s renewal counts as well
            until = max(until, effective)
        if boot == m.clock.boot_id:
            return m.clock.at(self.now) < until
        return boot is None and self.now < until

    def _check_elected(self, m, info):
        epoch = info['epoch']
        won = self.winners.setdefault(epoch, m.iid)
        if won != m.iid:
            self.fail(f'I2: {m.iid} and {won} both won epoch {epoch}')
        self.elections.append((self.now, m.iid, epoch, info.get('why')))
        cv = info['cv']
        for voter, kind, vcv, vfloor in self.grants.get((m.iid, epoch), ()):
            if voter == m.iid:
                continue
            if kind == hv.KIND_DATA and vcv is not None and cv < vcv:
                self.fail(f'I5: {m.iid} won at cv {cv} with a vote of {voter} at {vcv}')
            if kind == hv.KIND_WITNESS and cv < (vfloor or hv.ZERO):
                self.fail(f'I5: {m.iid} won at cv {cv} below the witness floor {vfloor}')
        if not self.rollbacks:
            for e, f in self.floors.items():
                if e < epoch and cv < f:
                    self.fail(f'I5: {m.iid} won epoch {epoch} at cv {cv} below the floor {f} of epoch {e}')
        acks = info.get('acks') or frozenset()
        self.counted[(m.iid, epoch)] = acks
        v = m.node.view
        if info.get('why') != 'switch' and (not acks <= v.counting or len(acks) < v.m):
            self.fail(f'I2: {m.iid} counts {sorted(acks)} as a majority of {sorted(v.counting)}')

    # --- what the leader does with its lease ---

    def _automation(self):
        for iid in self.order:
            m = self.members[iid]
            if not m.up or m.paused or m.node is None or not m.node.is_active():
                continue
            if self.rng.random() < self.p_write and m.node.may_write():
                cv = m.node.bump_cv()
                if cv is not None:
                    self.wid += 1
                    m.data = m.data | {self.wid}
                    self.writes[self.wid] = (m.iid, cv, self.now)
            if self.rng.random() < self.p_step:
                need = self.rng.choice((0.0, self.t.need))
                kind = self.rng.choice(('api', 'ssh'))
                inc = m.inc
                asked = self.now
                m.node.confirm(need, lambda ok, m=m, inc=inc, need=need, kind=kind, asked=asked:
                               self._step(m, inc, need, kind, asked, ok))
                self._after(m)
        self.after(self.rng.uniform(1.0, 2.0), self._automation)

    def _step(self, m, inc, need, kind, asked, ok):
        if not ok or m.inc != inc or m.node is None:
            self.bump('confirm failed')
            return
        n = m.node
        epoch = n.led_epoch if n.led_epoch is not None else n.epoch
        if not n.is_active():
            self.fail(f'I3: {m.iid} confirmed a step while not acting')
        for o in self.members.values():
            if o is m or o.node is None:
                continue
            if o.node.is_active() and not o.out_of_model and not self.allow_dual_actors:
                self.fail(f'I3: {m.iid} takes a step while {o.iid} acts')
        for t, iid, e, k, _ in reversed(self.effects[-50:]):
            if e > epoch and not self.allow_dual_actors:
                self.fail(f'I3: {m.iid} acts at epoch {epoch} after {iid} acted at {e}')
                break
        if kind == 'ssh' and self.claims is not None:
            if not self._claim_ok(m, epoch):
                self.refused_at_node.append((self.now, m.iid, epoch))
                self.bump('refused at the node')
                return
        self.effects.append((self.now, m.iid, epoch, kind, asked))

    # --- the data ---

    def _pulls(self):
        for iid in self.order:
            m = self.members[iid]
            if not m.up or m.paused or m.node is None or m.kind != hv.KIND_DATA:
                continue
            n = m.node
            src = n.leader_seen
            if src is None or src == iid or n.is_active() or n.max_leader_cv is None \
                    or n.max_leader_cv == n.cv or m.no_pull:
                continue
            self.pull(iid)
        self.after(self.rng.uniform(1.5, 3.0), self._pulls)

    def pull(self, iid):
        m = self.members[iid]
        n = m.node
        if n is None or not m.up or m.paused or n.leader_seen in (None, iid) or m.no_pull:
            return
        self._transmit(m, n.leader_seen, 'pull', {}, ('pull', self.seq))

    def inject(self, frm, to, kind, body):
        """A call `frm` once sent arrives again (a replay below the signature layer)."""
        rec = (frm, -1, to, kind, body, ('replay', self.seq), self.members[to].wall())
        self.note(f'replay {kind} {frm}->{to} {body}')
        self.after(0.001, self._deliver, rec)

    def _serve_pull(self, m, body):
        n = m.node
        if n.lease_mode() and n.holds_lease():
            return {'ok': True, 'cv': n.cv, 'data': m.data, 'epoch': n.led_epoch}
        return {'ok': False}

    def _pulled(self, m, by, ans):
        if not ans or not ans.get('ok') or m.node is None:
            return
        if ans['epoch'] < m.node.epoch:
            return
        # a late answer from the same leader carries an older snapshot than the one held:
        # applying it would put this voter back below the floor a majority acked. Only a
        # newer leader's snapshot may be lower (its writes win, ours are captured)
        if ans['epoch'] < m.applied_epoch or (ans['epoch'] == m.applied_epoch
                                              and hv.pair(ans['cv']) < m.node.cv):
            self.bump('stale snapshot dropped')
            return
        m.applied_epoch = ans['epoch']
        self._apply(m, ans['data'], ans['cv'], by)

    def _apply(self, m, data, cv, frm, catchup=False):
        lost = m.data - data
        if lost:
            # what apply_snapshot would wipe is kept and reported (orphan capture, 4.11)
            m.orphans |= lost
            self.bump('orphans captured')
        m.data = data
        if not catchup:
            m.node.set_cv(cv)

    def lost_writes(self):
        """Writes a leader took that no member holds, captured or not (G4)."""
        held = set()
        for m in self.members.values():
            held |= m.data
            held |= m.orphans
        return sorted(w for w in self.writes if w not in held)

    # --- the cluster claim (6.3), only where a scenario turns it on ---

    def enable_claims(self):
        self.claims = {}
        self.at(self.now + self.claim_watch, self._claim_watch)

    def _write_claims(self, m):
        e = m.node.led_epoch if m.node.led_epoch is not None else m.node.epoch
        cur = self.claims.get('c1')
        if cur is None or cur[0] < e:
            self.claims['c1'] = (e, m.iid)
            self.note(f'claim c1 = epoch {e} by {m.iid}')
        elif cur[0] > e:
            m.node.step_down('a newer claim on c1')
            self._after(m)

    def force_claim(self, iid, epoch):
        self.claims['c1'] = (epoch, iid)
        self.note(f'claim c1 = epoch {epoch} by {iid} (forced)')

    def _claim_ok(self, m, epoch):
        return self.claims.get('c1') == (epoch, m.iid)

    def _claim_watch(self):
        cur = self.claims.get('c1')
        for m in list(self.members.values()):
            if m.node is None or not m.up or m.paused or not m.node.is_active() or cur is None:
                continue
            e = m.node.led_epoch if m.node.led_epoch is not None else m.node.epoch
            if cur[0] > e and cur[1] != m.iid:
                self.note(f'{m.iid} sees the claim of {cur[1]} at {cur[0]}')
                m.node.step_down('a newer claim on c1')
                self._after(m)
        self.after(self.claim_watch, self._claim_watch)

    # --- helpers for the scenarios ---

    def leader(self):
        """The member that acts right now, None for none."""
        act = [m.iid for m in self.members.values() if m.node is not None and m.node.is_active()]
        return act[0] if len(act) == 1 else None

    def holder(self):
        h = [m.iid for m in self.members.values() if m.node is not None and m.node.lease_mode()
             and m.node.holds_lease()]
        return h[0] if len(h) == 1 else None

    def node(self, iid):
        return self.members[iid].node

    def wait_for(self, pred, limit, step=0.5):
        end = self.now + limit
        while self.now < end:
            if pred():
                return True
            self.run(min(end, self.now + step))
        return pred()

    def committed_cfgs(self):
        return list(self.committed_cfg.values())

    def down_count(self, iid, since):
        """How often `iid` went down on its own (a step-down, a lost lease, a win) since then."""
        return sum(1 for t, i, why in self.downs
                   if i == iid and t > since
                   and why not in ('stopped', 'crash', 'won the election', 'planned restart'))

    def mark_heal(self):
        ld = self.leader()
        self.first_acting_after = (self.now, self.now if ld else None, ld)

    def time_to_leader(self):
        if self.first_acting_after is None or self.first_acting_after[1] is None:
            return None
        return self.first_acting_after[1] - self.first_acting_after[0]


def bound_i6(t):
    """I6: after a heal, one acting leader within P + L/4 + T_vote + W_take + 5 s."""
    return t.P + t.L / 4 + t.T_vote + t.W_take + 5
