"""Automatic failover for the warm standby (#625, stage 2): who may lead, and for how long.

The group elects its leader by majority. A voter writes its vote to disk before it
answers and promises the winner a lease; every renewal of the leader that reaches it
renews the promise. The leader counts its lease from the send time of the last round a
majority answered, on a clock that only runs forward (CLOCK_BOOTTIME), and a little
shorter than any voter promises it. So two instances never hold a valid lease at the
same moment, as long as every lease clock runs within 10% of true time and what the
voters write to disk survives.

The rules, in the words of the design:
  * a vote needs automatic mode, a candidate that votes in my latest voter config, a
    term above mine (or mine with no other vote in it), no live promise to anyone else
    unless the leader handed this term to exactly this candidate, the hold after my
    process start, and a candidate at least as fresh as I am (config version cv,
    voter config id)
  * a pre-vote asks the same and changes nothing, so a member that is only cut off
    never raises the term
  * a leader renews only at the epoch it won by votes. Any higher epoch it sees ends
    its leadership; there is no re-term
  * the voter config is a chain: each config carries the digest of the one before it
    and is signed by a data voter of that one. One change at a time, and a new leader
    commits a config of its own epoch before it changes anything
  * a winner acts only W_take after its vote round, which keeps the old and the new
    acting interval apart even if a voter forgot its promise
  * the hold after a start and W_take go by the longest lease_s in the config chain: a
    promise made under a longer lease may outlive the config. A promise the chain on
    disk would not cover (its config was trimmed off or dropped with a branch) is
    written down before the answer, and the hold after a start runs to its end. A
    leader that shortens the lease cuts its own lease to the new length at once
  * a leader that hands its term on writes that down before it lets go, and comes back
    from a crash as a standby
  * a renewal is taken from a data voter of the voter config held, and from one leader
    per term: a second member that renews in a term gets nothing from a voter whose
    promise to the first still runs, and a leader that hears one leaves
  * a round of a switch between the modes carries a config and never a lease. A member
    in automatic mode refuses it, and the switch counts a member only on its ack of
    the pending config, named by digest: where two chains meet in one group, the ids
    of one say nothing about the other
  * a config is committed once a majority holds it by digest, as every answer names
    it. A leader that hears of a config of its own term it does not hold leaves (its
    state went back), and one that leaves before its switch back to manual mode was
    committed drops that config: the group stays automatic
  * a manual active that takes an automatic config from a vote request is a standby
    from that write on

This module is the protocol and nothing else. It imports neither Flask, the database
nor requests: a Node reads the time from the clock it is handed, sends through the
transport it is handed and writes its state through the store it is handed. ha.py
drives it (its section "automatic failover"); tests/test_ha_vote_sim.py drives it in a
simulator with a clock per member, directed cuts, pauses and restarts.
AUTO_MODE_SHIPPED keeps automatic mode off until the confirm sites, the cluster claim
and the transfer routes are in.

MK Oct 2026 (#625)
"""
import base64
import hashlib
import json
import math
import time

# Automatic mode is refused until the confirm sites, the cluster claim and Make leader
# are in (slices S4, S6 and S7). Every group runs in manual mode until then.
AUTO_MODE_SHIPPED = False
NOT_SHIPPED_ERROR = 'Automatic failover is not available in this release yet'

MODE_MANUAL = 'manual'
MODE_PENDING = 'auto_pending'
MODE_AUTO = 'auto'
MODES = (MODE_MANUAL, MODE_PENDING, MODE_AUTO)

KIND_DATA = 'data'
KIND_WITNESS = 'witness'

# the strings ha.py uses. 'leader' is the active of an automatic group and 'witness'
# the role in the witness's own state file; an older release reads both as passive
ROLE_STANDALONE = 'standalone'
ROLE_ACTIVE = 'active'
ROLE_STANDBY = 'standby'
ROLE_LEADER = 'leader'
ROLE_WITNESS = 'witness'

# data members, as in ha.py; the witness is counted on its own
MAX_MEMBERS = 4
MAX_WITNESSES = 1
MAX_VOTERS = MAX_MEMBERS + MAX_WITNESSES
MIN_VOTERS = 3
EPOCH_MAX = 2 ** 31 - 1

LEASE_DEFAULT = 20
LEASE_MIN = 15
LEASE_MAX = 120
# the longest a renewal may ask its voters to hold for the leader (a planned restart)
HOLD_MAX = 120
PLANNED_HOLD = 90
# how many configs before the newest one every member keeps
CFG_KEEP = 16
SITE_MAX = 64
# automatic mode needs the members' wall clocks this close together
SKEW_LIMIT = 5
# a step of the wall clock against the lease clock that forces a confirm round
CLOCK_JUMP = 2
# Confirm rounds (4.5) start the moment a caller has no round out that started after it,
# up to this many out at once; past that, callers share the next one, which starts as
# one of them comes back
CONFIRM_IN_FLIGHT = 4
# what the voters are protected by whatever the callers do: confirm rounds per second.
# A data member answering through the real app (pywsgi, TLS, the lease fast path in
# app.py) spends about 1.05 ms of CPU per renewal under load (MK Oct 2026, #625: 1.0-1.15
# ms measured with 50 writers on LAN, 2 ms through Flask before): 450 a second is about
# half a core of it, with what it spends idle
CONFIRM_RATE_MAX = 450
# unanswered calls one voter may hold from confirm rounds. A confirm round passes a voter
# that holds this many (a slow or a dead one) and asks the others; the renewal every R
# goes to everyone
CONFIRM_PER_VOTER = 16
SWITCH_TIMEOUT = 600
TRANSFER_CATCHUP = 10
CATCHUP_TIMEOUT = 10

ZERO = (0, 0)
_INF = math.inf

_BOOTTIME = getattr(time, 'CLOCK_BOOTTIME', None)


def ha_clock():
    """Lease time. CLOCK_BOOTTIME on Linux: system-wide, it survives execv, keeps running
    through a suspend and never steps with the wall clock. time.monotonic() elsewhere."""
    if _BOOTTIME is not None:
        return time.clock_gettime(_BOOTTIME)
    return time.monotonic()


def read_boot_id():
    """The kernel's id of this boot. A lease clock value only means something within it."""
    try:
        with open('/proc/sys/kernel/random/boot_id') as f:
            return f.read().strip()
    except OSError:
        return ''


class Timings:
    """Every duration of the protocol, worked out from the lease length L (design,
    section 9). keep_w_take=False is the short takeover wait of D + G the owner may still
    choose instead (Q2); the default keeps the full one."""

    __slots__ = ('L', 'R', 'renew_timeout', 'P', 'D', 'per_round', 'T_vote', 'G', 'W_take',
                 'hold_after_start', 'won_hold', 'boot_wait', 'boot_retry', 'confirm_timeout',
                 'need', 'lost_lease_backoff')

    def __init__(self, lease_s=LEASE_DEFAULT, keep_w_take=True):
        L = float(lease_s)
        self.L = L
        self.R = L / 5
        self.renew_timeout = min(2.0, self.R / 2)
        # a voter promises P on its own clock from receipt, the leader counts per_round
        # on its own clock from the send: a leader running 10% slow is done by
        # (0.9 L - D) / 0.9 = L - 1.11 D, a voter running 10% fast holds until L
        self.P = 1.1 * L
        self.D = max(2.0, 0.05 * L)
        self.per_round = 0.9 * L - self.D
        self.T_vote = 2.0
        self.G = 5.0
        self.W_take = (1.1 * (L + self.T_vote) if keep_w_take else 0.0) + self.D + self.G
        self.hold_after_start = self.P + self.D
        self.won_hold = L + 60
        self.boot_wait = 15.0
        # at boot a round goes out this often until boot_wait ends, whatever L is: a
        # voter that came up late, or refused a call signed before its start, gets
        # another one
        self.boot_retry = min(self.R, 1.0)
        self.confirm_timeout = 2.0
        self.need = 5.0
        self.lost_lease_backoff = 2 * L

    def election_delay(self, rng, lower_reach=False):
        return self.P + rng.uniform(0, self.L / 4) + (self.L / 2 if lower_reach else 0.0)

    def lost_election_backoff(self, rng):
        return rng.uniform(self.L / 2, self.L)


# the longest a restart ever holds others off: a promise at LEASE_MAX and its margin
HOLD_AFTER_START_MAX = Timings(LEASE_MAX).hold_after_start


def majority(n):
    return n // 2 + 1


def pair(value):
    """A cv or a config id as a tuple (JSON hands them back as lists), None for anything else."""
    if isinstance(value, (list, tuple)) and len(value) == 2:
        a, b = value
        if type(a) is int and type(b) is int and 0 <= a <= EPOCH_MAX and b >= 0:
            return (a, b)
    return None


def _is_epoch(value):
    return type(value) is int and 0 <= value <= EPOCH_MAX


# --- the voter config ----------------------------------------------------------

class CfgRefused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def cfg_digest(cfg):
    """sha256 over everything of a config but its signature."""
    unsigned = {k: cfg.get(k) for k in ('id', 'prev', 'by', 'body')}
    return hashlib.sha256(b'pegaprox-ha-cfg\0' + _canonical(unsigned)).hexdigest()


def body_error(body):
    """What is wrong with a config body, '' when nothing is."""
    if not isinstance(body, dict):
        return 'not a config'
    mode = body.get('mode')
    if mode not in MODES:
        return 'mode'
    lease_s = body.get('lease_s')
    if type(lease_s) is not int or not LEASE_MIN <= lease_s <= LEASE_MAX:
        return 'lease_s'
    voters = body.get('voters')
    if not isinstance(voters, list) or len(voters) > MAX_MEMBERS:
        return 'voters'
    seen = set()
    for rec in voters:
        if not isinstance(rec, dict):
            return 'voters'
        iid = rec.get('id')
        if not isinstance(iid, str) or not iid or iid in seen:
            return 'voters'
        if not isinstance(rec.get('public_key'), str):
            return 'voters'
        if type(rec.get('voter')) is not bool or type(rec.get('may_lead')) is not bool:
            return 'voters'
        site = rec.get('site', '')
        if not isinstance(site, str) or len(site) > SITE_MAX:
            return 'voters'
        seen.add(iid)
    witness = body.get('witness')
    if witness:
        if not isinstance(witness, dict):
            return 'witness'
        wid = witness.get('id')
        if not isinstance(wid, str) or not wid or wid in seen:
            return 'witness'
        if not isinstance(witness.get('public_key'), str):
            return 'witness'
        site = witness.get('site', '')
        if not isinstance(site, str) or len(site) > SITE_MAX:
            return 'witness'
    quarantined = body.get('quarantined', [])
    if not isinstance(quarantined, list):
        return 'quarantined'
    ids = set(voter_ids(body))
    if any(q not in ids for q in quarantined):
        return 'quarantined'
    if mode != MODE_MANUAL and len(ids) < MIN_VOTERS:
        return 'too few voters'
    return ''


def voter_ids(body):
    """Who votes: the data members with the vote flag and the witness."""
    ids = [rec['id'] for rec in body.get('voters') or () if rec.get('voter')]
    witness = body.get('witness')
    if witness:
        ids.append(witness['id'])
    return ids


class CfgView:
    """What a config says, worked out once: the voters, the majority and the voters whose
    answers count (a quarantined voter stays in n, its acks and votes do not count)."""

    __slots__ = ('cfg', 'id', 'mode', 'lease_s', 'voters', 'n', 'm', 'counting', 'data',
                 'members', 'records', 'witness')

    def __init__(self, cfg):
        body = cfg['body']
        self.cfg = cfg
        self.id = pair(cfg['id'])
        self.mode = body['mode']
        self.lease_s = body['lease_s']
        self.records = {rec['id']: rec for rec in body.get('voters') or ()}
        witness = body.get('witness') or None
        self.witness = witness['id'] if witness else None
        self.voters = frozenset(voter_ids(body))
        self.n = len(self.voters)
        self.m = majority(self.n)
        quarantined = set(body.get('quarantined') or ())
        self.counting = frozenset(i for i in self.voters if i not in quarantined)
        self.data = frozenset(i for i, rec in self.records.items() if rec.get('voter'))
        self.members = frozenset(list(self.records) + ([self.witness] if self.witness else []))

    def candidate(self, iid, timer):
        """A data voter that is not quarantined; on a timer it also needs may_lead."""
        rec = self.records.get(iid)
        if not rec or not rec.get('voter') or iid not in self.counting:
            return False
        return bool(rec.get('may_lead')) or not timer


def make_cfg(prev, epoch, by, body, sign):
    """The config after `prev` (None for the first one), created by the leader `by` at its
    epoch and signed with its key."""
    if prev is None:
        cid = [epoch, 1]
        prev_digest = ''
    else:
        pid = pair(prev['id'])
        cid = [max(epoch, pid[0]), pid[1] + 1]
        prev_digest = cfg_digest(prev)
    cfg = {'id': cid, 'prev': prev_digest, 'by': by, 'body': body}
    cfg['sig'] = sign(bytes.fromhex(cfg_digest(cfg)))
    return cfg


def link_error(prev, cfg, verify):
    """'' when `cfg` follows `prev`: the next version at the same or a later epoch, the
    digest of `prev` in it, a valid body, and signed by a data voter of `prev`."""
    pid, cid = pair(prev.get('id')), pair(cfg.get('id'))
    if not pid or not cid or cid[1] != pid[1] + 1 or cid[0] < pid[0]:
        return 'BAD_CFG'
    if cfg.get('prev') != cfg_digest(prev):
        return 'BAD_CFG'
    if body_error(cfg.get('body')):
        return 'BAD_CFG'
    signer = None
    for rec in prev['body'].get('voters') or ():
        if rec.get('id') == cfg.get('by') and rec.get('voter'):
            signer = rec
    sig = cfg.get('sig')
    if signer is None or not isinstance(sig, str):
        return 'BAD_CFG'
    if not verify(signer.get('public_key') or '', bytes.fromhex(cfg_digest(cfg)), sig):
        return 'BAD_CFG'
    return ''


def newer_chain(held, segment, verify):
    """This member's chain (oldest first) with the configs of `segment` that are newer
    than its newest one, each checked against the config before it; None when nothing
    in `segment` is newer.

    The first newer config hangs off a config this member holds, by digest. That need
    not be its newest: a config the leader before made and never committed is left
    behind when the next leader's chain goes another way, and it can only be left
    behind if it never reached a majority. A config that hangs off nothing held here
    raises CfgRefused('CFG_GAP'), and the member has to pair again."""
    top = pair(held[-1]['id'])
    new = []
    for c in segment or ():
        cid = pair(c.get('id')) if isinstance(c, dict) else None
        if cid and cid > top:
            new.append((cid, c))
    if not new:
        return None
    new.sort(key=lambda x: x[0])
    first = new[0][1]
    at = None
    for i, c in enumerate(held):
        if cfg_digest(c) == first.get('prev'):
            at = i
    if at is None:
        raise CfgRefused('CFG_GAP')
    chain = list(held[:at + 1])
    for _, c in new:
        why = link_error(chain[-1], c, verify)
        if why:
            raise CfgRefused(why)
        chain.append(c)
    return chain[-(CFG_KEEP + 1):]


def chain_after(chain, known):
    """The configs a member that holds `known` (None: we do not know) is missing."""
    if known is None:
        return list(chain)
    return [c for c in chain if pair(c['id']) > known]


def takes_switch_back(body, held_mode):
    """Whether a voter that holds a config in `held_mode` takes anything from the renewal
    `body`. A round marked taken_back hands out the manual config that took a pending
    switch back; its sender need not lead, so only a voter that holds a pending config
    takes it, and only where the newest config it carries is a manual one."""
    if body.get('taken_back') is not True:
        return True
    seg = body.get('chain') if isinstance(body.get('chain'), list) else []
    top = max((c for c in seg if isinstance(c, dict) and pair(c.get('id'))),
              key=lambda c: pair(c['id']), default=None)
    return (held_mode == MODE_PENDING and top is not None
            and (top.get('body') or {}).get('mode') == MODE_MANUAL)


def longest_lease(chain):
    """The longest lease_s in a chain. A promise made under any config of it, and a lease
    counted on one, may still run after the config moved on to a shorter one."""
    return max(c['body']['lease_s'] for c in chain)


def majorities_intersect(a, b):
    """Every majority of the voters of `a` shares a voter with every majority of `b`."""
    va, vb = CfgView(a), CfgView(b)
    return va.m + vb.m > len(va.voters | vb.voters)


def floor_of(cvs, m):
    """The highest cv that at least m of `cvs` hold, None with fewer than m."""
    if len(cvs) < m:
        return None
    return sorted(cvs, reverse=True)[m - 1]


def catchup_source(refusals, my_cv):
    """Where a candidate refused as stale pulls first (D1): the freshest voter that named
    itself fresher. A witness refusal names nobody (it holds no data); then the data voter
    with the highest cv among the answers, if it is ahead of us."""
    named = []
    below_floor = False
    seen = []
    for frm, ans in refusals:
        cv = pair(ans.get('cv'))
        if cv is not None:
            seen.append((cv, frm))
        reason = ans.get('reason')
        fresher = ans.get('fresher') or {}
        if reason == 'STALE' and pair(fresher.get('cv')) and fresher.get('id') == frm:
            named.append((pair(fresher['cv']), frm))
        elif reason == 'BELOW_FLOOR':
            below_floor = True
    if named:
        cv, frm = max(named)
        return frm if my_cv is None or cv > my_cv else None
    if below_floor and seen:
        cv, frm = max(seen)
        if my_cv is None or cv > my_cv:
            return frm
    return None


def ed25519_signer(private_b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return lambda message: base64.b64encode(key.sign(message)).decode()


def ed25519_verify(public_b64, message, sig_b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
        key.verify(base64.b64decode(sig_b64, validate=True), message)
        return True
    except Exception:
        return False


def new_state(cfg, *, role, epoch=0, kind=KIND_DATA, cv=ZERO):
    """The lease part of a fresh state file."""
    return {
        'role': role,
        'epoch': epoch,
        'voted_for': None,
        'gen': 0,
        'cfg': cfg,
        'cfg_chain': [],
        'cv': tuple(cv) if kind == KIND_DATA else None,
        'base_cv': tuple(cv) if kind == KIND_DATA else None,
        'floor_cv': ZERO,
        'led': None,
        # {to, epoch}: this leader handed the term after led.epoch to `to` (7.1)
        'released': None,
        'campaign_after': None,
        # {boot_id, until, len}: a promise the configs on disk would not cover
        'promised': None,
    }


def _read_promised(rec):
    """(boot id, until, len) of the promise record on disk, None for none or a broken one.
    len is capped: a restart never holds longer than a promise can run."""
    if not isinstance(rec, dict):
        return None
    until, length = rec.get('until'), rec.get('len')
    for x in (until, length):
        if type(x) not in (int, float) or not math.isfinite(x):
            return None
    return rec.get('boot_id'), until, min(max(length, 0.0), HOLD_AFTER_START_MAX)


def _normalized(st):
    st = dict(st)
    for key in ('cv', 'base_cv', 'floor_cv'):
        if st.get(key) is not None:
            st[key] = pair(st[key]) or ZERO
    if st.get('floor_cv') is None:
        st['floor_cv'] = ZERO
    led = st.get('led')
    if led:
        st['led'] = dict(led, cv=pair(led.get('cv')) or ZERO)
    st.setdefault('voted_for', None)
    st.setdefault('gen', 0)
    st.setdefault('cfg_chain', [])
    st.setdefault('released', None)
    st.setdefault('campaign_after', None)
    st.setdefault('promised', None)
    return st


# --- one instance ---------------------------------------------------------------

class _Round:
    __slots__ = ('tag', 'kind', 't0', 'deadline', 'epoch', 'targets', 'answered', 'acks',
                 'refusals', 'cvs', 'gens', 'majority', 'done', 'why', 'catchup_done', 'lease_s',
                 'passed')

    def __init__(self, tag, kind, t0, deadline, epoch):
        self.tag, self.kind, self.t0, self.deadline, self.epoch = tag, kind, t0, deadline, epoch
        self.targets = frozenset()
        # the voters a confirm round did not ask (Node._confirm_plan)
        self.passed = frozenset()
        self.answered = set()
        self.acks = set()
        self.refusals = []
        self.cvs = {}
        self.gens = {}
        self.majority = False
        self.done = False
        self.why = ''
        self.catchup_done = False
        # the lease length this round asked for: what every voter that answered promised
        self.lease_s = LEASE_DEFAULT


class Node:
    """The lease protocol of one instance, without any I/O of its own.

    clock()      lease time, CLOCK_BOOTTIME semantics (ha_clock in the product)
    wall()       wall time, only for the clock-step check and what renewals report
    store        load() -> the lease state, save(state) writes it durably (file and
                 directory fsynced) before it returns and raises when it cannot
    send(to, kind, body, tag)
                 hands a call to the transport. It must not call back into the node
                 synchronously; the answer comes back as on_answer(frm, tag, answer),
                 None when the call failed. A call that is never answered just times
                 out here
    hooks        restart(why): take the exit path, this node is done
                 event(name, info): audit and test log
                 snapshot(): what a catch-up pull hands out
                 apply_snapshot(frm, answer) -> the cv now held, or None
    rng          random.Random, for the election timer

    The host calls tick() at next_wake() at the latest (lease time), on_request for every
    signed peer call and on_answer for every answer. The gates read is_active(),
    holds_lease() and acting_process(); confirm(need, cb) runs a fresh majority round
    before an irreversible step.

    The host applies the snapshots of one leader epoch in the order that leader made them
    and never lowers cv through set_cv with an older one (ha.py holds _pull_lock across
    the fetch and apply_snapshot). A late answer applied after a newer one would put this
    member back below a floor a majority already acked. Only a newer leader's snapshot
    may carry a lower cv; what it replaces is captured, not wiped (4.11)."""

    def __init__(self, me, kind, *, store, clock, wall, send, hooks, rng, sign, verify,
                 boot_id='', restart_on_win=True, keep_w_take=True, lower_reach=None):
        self.me = me
        self.kind = kind
        self.store = store
        self.clock = clock
        self.wall = wall
        self.send = send
        self.hooks = hooks
        self.rng = rng
        self.sign = sign
        self.verify = verify
        self.boot_id = boot_id
        self.restart_on_win = restart_on_win
        self.keep_w_take = keep_w_take
        self.lower_reach = lower_reach or (lambda: False)
        loaded = store.load()
        if not loaded:
            raise ValueError('no lease state')
        self.st = _normalized(loaded)
        self._chain = list(self.st['cfg_chain']) + [self.st['cfg']]
        self._held_lease = 0
        self._set_view()
        now = clock()
        self.started = now
        # the hold after start (rule 5) covers the longest lease any config on disk may
        # have promised before this start, and a promise written down because no config
        # on disk covers it. It is fixed here: what this process promises from now on it
        # keeps in memory, and a shorter config taken later never cuts it
        self.hold_until = now + Timings(self._held_lease, keep_w_take).hold_after_start
        rec = _read_promised(self.st['promised'])
        if rec is not None:
            boot, until, length = rec
            # after a reboot the old lease clock means nothing here, and the promise may
            # have been made the moment before: it runs for its full length from now
            same = boot_id and boot == boot_id
            at = min(until, now + length) if same else now + length
            self.hold_until = max(self.hold_until, at)
        # every promise made before this start ends by then; _promise adds what this one makes
        self._promised_until = self.hold_until
        self.dead = False
        # the lease, memory only
        self.lease_until = 0.0
        self._acting = False
        self.acting_from = _INF
        self._acting_said = False
        # as a voter
        self.promise_to = None
        self.promise_until = -_INF
        self.lease_promise_until = -_INF
        self.allow = None
        self.heard_at = None
        self.leader_seen = None
        # (epoch, member) of the renewal this voter last took: one leader per term
        self._renewed = None
        self.max_leader_cv = None
        self.max_leader_wall = None
        self.epoch_seen = self.st['epoch']
        # as the leader
        self._rounds = {}
        self._tag = 0
        self.next_round_at = _INF
        self._last_round_t0 = -_INF
        # [decided at, need, cb, mark] per confirm still waiting for its round. mark is the
        # tag of the last round started before it: only a later one serves it, whatever
        # the clock read (a held clock reads the same before and after a pause)
        self._waiters = []
        # confirm rounds that may start before CONFIRM_RATE_MAX holds them back
        self._bucket = float(CONFIRM_IN_FLIGHT)
        self._bucket_at = now
        # voters a renewal did not reach (refused, closed, no answer in time): confirm
        # rounds pass them as owing until a round that asks everyone reaches them again
        self._unreached = set()
        self._cfg_seen = {}
        self._cfg_seen_at = {}
        # member -> (digest of the config it said it holds, start of that round): what
        # a commit counts, never the id alone
        self._held = {}
        self._cv_seen = {}
        self._acked_at = {}
        self._gens = {}
        self._suspects = []
        self._changes = []
        self._committed = None
        self.floor = self.st['floor_cv'] or ZERO
        self.transfer = None
        self.switch = None
        # member -> (digest of the config it holds, whether it acked), from the answers
        # to switch rounds only
        self._switch_said = {}
        self._booting = None
        self._jump_at = -_INF
        self._watch_last = None
        # as a candidate
        self._campaign = None
        self.election_at = _INF
        # how the last election this member ran failed: {at, kind, epoch, why, reached,
        # m, reasons}. reached counts the voters that answered at all, refusals included
        # (7.3: only a majority that does not answer may be gone)
        self.last_failed = None
        self._boot(now)

    # --- what the gates read ---

    def lease_mode(self):
        """The lease is in force: automatic mode, or a leader whose switch back to manual
        has not reached a majority yet."""
        mode = self.view.mode
        return mode == MODE_AUTO or (mode == MODE_MANUAL and self.st['role'] == ROLE_LEADER)

    def holds_lease(self):
        role = self.st['role']
        if self.dead or role in (ROLE_STANDBY, ROLE_WITNESS):
            return False
        if not self.lease_mode():
            return True
        return role == ROLE_LEADER and self.clock() < self.lease_until

    def acting_process(self):
        role = self.st['role']
        if self.dead or role in (ROLE_STANDBY, ROLE_WITNESS):
            return False
        if not self.lease_mode():
            return True
        return self._acting

    def is_active(self):
        role = self.st['role']
        if self.dead or role in (ROLE_STANDBY, ROLE_WITNESS):
            return False
        if not self.lease_mode():
            return True
        if not self._acting:
            return False
        now = self.clock()
        return self.acting_from <= now < self.lease_until

    def may_write(self):
        return self.is_active() and self.transfer is None

    @property
    def epoch(self):
        return self.st['epoch']

    @property
    def led_epoch(self):
        led = self.st.get('led')
        return led['epoch'] if led else None

    @property
    def cv(self):
        return self.st['cv']

    @property
    def chain(self):
        return list(self._chain)

    # --- persistence ---

    def _set_view(self):
        self.view = CfgView(self._chain[-1])
        self._digest = cfg_digest(self._chain[-1])
        self._prev_view = CfgView(self._chain[-2]) if len(self._chain) > 1 else None
        self.t = Timings(self.view.lease_s, self.keep_w_take)
        # never goes down in a process, even when a branch drops a config from the chain
        self._held_lease = max(self._held_lease, longest_lease(self._chain))

    def _w_take(self):
        # the old leader may have counted its last round on the longest lease held here
        return Timings(self._held_lease, self.keep_w_take).W_take

    def _promised_record(self, chain, until=-_INF):
        """What the state file has to say about the promises made (`until`: one about to
        be made): None while the hold after a restart, by the configs it keeps of `chain`,
        covers every promise that may still run; else when the last of them ends on this
        boot's lease clock and how long that is from now."""
        now = self.clock()
        end = max(self._promised_until, until)
        kept = chain[-(CFG_KEEP + 1):]
        if end <= now + Timings(longest_lease(kept)).hold_after_start:
            return None
        held = _read_promised(self.st['promised'])
        if held is not None and self.boot_id and held[0] == self.boot_id and held[1] >= end:
            return self.st['promised']
        return {'boot_id': self.boot_id, 'until': end, 'len': end - now}

    def _save(self, chain=None, promised=-_INF, **changes):
        new = dict(self.st)
        new.update(changes)
        if chain is not None:
            new['cfg'] = chain[-1]
            new['cfg_chain'] = chain[:-1][-CFG_KEEP:]
        # in the same write: a config that leaves the chain may take the cover of a
        # promise still running with it (a trim after CFG_KEEP changes, a dropped branch)
        new['promised'] = self._promised_record(list(new['cfg_chain']) + [new['cfg']], promised)
        new['gen'] = self.st['gen'] + 1
        try:
            self.store.save(new)
        except Exception as e:
            self._event('write_failed', error=str(e))
            return False
        self.st = new
        if chain is not None:
            self._chain = list(new['cfg_chain']) + [new['cfg']]
            self._set_view()
        return True

    def _event(self, name, **info):
        self.hooks.event(name, info)

    def _exit(self, why):
        self.dead = True
        self._acting = False
        self.hooks.restart(why)

    # --- boot (4.9) ---

    def _boot(self, now):
        self._watch_last = self.wall() - now
        if self.st['role'] == ROLE_LEADER and self.st.get('led') and self.lease_mode():
            rel = self.st.get('released') or {}
            if rel.get('epoch') == self.st['led']['epoch'] + 1:
                # it went down after it handed the next term on: the voters may still
                # hold that allowance, so it never renews in its old term again (7.1)
                return self._boot_failed(now, f'epoch {rel["epoch"]} was handed to {rel.get("to")}')
            # rounds at the epoch we won until one reaches a majority, for boot_wait at
            # most; nothing acts before (a voter that started a moment ago refuses calls
            # signed before its start, so the first round may well come back empty)
            self._booting = now + self.t.boot_wait
            self._start_round(now, kind='boot')
        self._arm_timer(now)

    def _booted(self, now):
        self._booting = None
        take = self.st['led'].get('take_after') or {}
        if take.get('boot_id') == self.boot_id:
            # never later than W_take after this process started: on the same boot the
            # win came before the start, so a later value is from another boot (a host
            # without a boot id reads '' every time)
            at = min(take.get('at') or 0.0, self.started + self._w_take())
        else:
            # the host rebooted: the old lease clock value means nothing here
            at = self.started + self._w_take()
        self._acting = True
        self._acting_said = False
        self.acting_from = max(now, at)
        self._event('booted', acting_from=self.acting_from)
        if self.acting_from <= now:
            # it acts at once: said now, not at the next tick after the monitor's first pass
            self._acting_said = True
            self._event('acting', epoch=self.st['led']['epoch'])

    def _boot_failed(self, now, why):
        # nothing acted yet: no restart, the process goes on as a standby. The boot rounds
        # still out close with it, or a late answer at a higher epoch would step the
        # standby down and end the process
        self._booting = None
        for r in list(self._rounds.values()):
            if r.kind == 'boot':
                r.done = True
                self._rounds.pop(r.tag, None)
        self._acting = False
        self.lease_until = min(self.lease_until, now)
        self._fail_waiters()
        dropped = self._switch_off_dropped()
        if self._save(chain=dropped, role=ROLE_STANDBY,
                      campaign_after={'boot_id': self.boot_id, 'started': self.started,
                                      'at': now + self.t.lost_lease_backoff}) and dropped:
            self._event('switch_off_dropped', epoch=self.st['epoch'])
        self._event('boot_standby', why=why)
        self._arm_timer(now)

    def _switch_off_dropped(self):
        """The chain a leader leaves its lead with, None when it keeps the one it holds.
        A switch back to manual mode that it made and never saw a majority take is not
        the group's mode (4.13): kept, it would make this instance one that is promoted
        by hand next to the leader the others elect. Where a majority took it all the
        same, its voters hand it back with their answer to the next vote."""
        v = self.view
        if (self.st['role'] == ROLE_LEADER and v.mode == MODE_MANUAL and v.cfg.get('by') == self.me
                and len(self._chain) > 1 and not self._is_committed()):
            return self._chain[:-1]
        return None

    # --- the host's entry points ---

    def tick(self):
        if self.dead:
            return
        now = self.clock()
        self._watch_clock(now)
        self._expire(now)
        if self.dead:
            return
        role = self.st['role']
        if role == ROLE_LEADER and self.lease_mode():
            self._lead(now)
        elif self.switch is not None:
            self._switch_tick(now)
        elif role == ROLE_STANDBY and self._campaign is None and now >= self.election_at:
            self._maybe_campaign(now)

    def next_wake(self):
        """The lease time of the next tick this node needs, None for none."""
        if self.dead:
            return None
        now = self.clock()
        times = [r.deadline for r in self._rounds.values() if not r.done]
        role = self.st['role']
        if role == ROLE_LEADER and self.lease_mode():
            if self.transfer is not None:
                times.append(self.transfer['until'])
            if self.transfer is None or self.transfer['phase'] == 'catchup':
                # a round that is due now (a config change, a clock step) counts as now
                times.append(self.next_round_at)
                if self._booting is not None:
                    times.append(self._booting)
                    times.append(self._last_round_t0 + self.t.boot_retry)
                elif self.lease_until > 0:
                    times.append(self.lease_until)
                if self._acting and not self._acting_said and self.acting_from > now:
                    times.append(self.acting_from)
                at = self._confirm_due(now)
                if at is not None:
                    times.append(at)
        elif self.switch is not None:
            times.append(min(self.switch['next'], self.switch['until']))
        elif role == ROLE_STANDBY and self._campaign is None and self._timer_candidate():
            times.append(self.election_at)
        times = [t for t in times if t < _INF]
        return max(now, min(times)) if times else None

    def on_request(self, frm, kind, body):
        if self.dead:
            return {'ok': False, 'reason': 'GONE'}
        now = self.clock()
        self._lease_check(now)
        if self.dead:
            return {'ok': False, 'reason': 'GONE'}
        if not isinstance(body, dict):
            return self._no('BAD_REQUEST')
        if kind == 'vote':
            return self._on_vote(frm, body, now)
        if kind == 'renew':
            return self._on_renew(frm, body, now)
        if kind == 'campaign':
            return self._on_campaign(frm, body, now)
        if kind == 'snapshot':
            return self._on_snapshot(frm, body, now)
        return self._no('UNKNOWN')

    def on_answer(self, frm, tag, ans):
        if self.dead:
            return
        now = self.clock()
        # a step of the clock since the last tick is seen before this answer serves any
        # confirm: the rounds out started before it
        self._watch_clock(now)
        if ans is not None and not isinstance(ans, dict):
            ans = None
        if ans is not None:
            e = ans.get('epoch')
            if _is_epoch(e) and e > self.epoch_seen:
                self.epoch_seen = e
        r = self._rounds.get(tag)
        if r is None or r.done:
            # late: an answer with a higher epoch still ends a leadership (4.7), and so
            # does one that names a config of our term we do not hold
            if ans is not None and self.st['role'] == ROLE_LEADER and self.lease_mode():
                e = ans.get('epoch')
                led = self.st['led']['epoch']
                why = f'epoch {e} seen' if _is_epoch(e) and e > led else ''
                if not why and (r is None or r.kind != 'switch'):
                    why = self._ahead_of_me(ans, led)
                if why:
                    if self._booting is not None:
                        self._boot_failed(now, f'{why} at boot')
                    else:
                        self._step_down(now, why)
            return
        if r.kind in ('renew', 'boot', 'release', 'switch'):
            self._renew_answer(r, frm, ans, now)
        elif r.kind in ('prevote', 'vote'):
            self._vote_answer(r, frm, ans, now)
        elif r.kind == 'catchup':
            self._catchup_answer(r, frm, ans, now)
        else:
            r.answered.add(frm)
            if r.answered >= r.targets:
                self._finish(r, now)

    # --- answers ---

    def _base(self):
        st = self.st
        return {'epoch': st['epoch'], 'cv': st['cv'], 'cfg_id': self.view.id, 'gen': st['gen'],
                'cfg_digest': self._digest}

    def _no(self, reason, **extra):
        ans = self._base()
        ans.update(ok=False, granted=False, reason=reason)
        ans.update(extra)
        return ans

    # --- voter rules (4.4) ---

    def _promise_live(self, now):
        return self.promise_to is not None and now < self.promise_until

    def _allowance(self, cand, epoch, now):
        a = self.allow
        return a is not None and a[0] == cand and a[1] == epoch and now < a[2]

    def _promise(self, holder, until, now, hold=None):
        """Promise `holder` until `until` (P from receipt, what a lease rests on), and
        while `hold` runs as well (a hold_s renewal: the winner's restart, a planned
        restart). The hold only keeps this process from voting for anyone else; a lease
        never rests on it, and the hold after start does not carry it over a restart.
        It ends with the next renewal that carries none: the leader is back. The caller
        wrote `until` down first where the configs on disk do not cover it."""
        if self._promise_live(now):
            until = max(until, self.lease_promise_until)
        effective = until if hold is None else max(until, hold)
        self._promised_until = max(self._promised_until, until)
        self.promise_to = holder
        self.lease_promise_until = until
        self.promise_until = effective
        self._event('promise', holder=holder, until=until, effective=effective)

    def _vote_rules(self, cand, T, pre, why, req, view, now):
        """The reason a vote for `cand` at T is refused, '' when it is granted (rules 1-6)."""
        if view.mode != MODE_AUTO:
            return 'MODE_MANUAL'
        if self.me not in view.voters:
            return 'NOT_VOTER'
        if not view.candidate(cand, timer=pre and why == 'timer'):
            return 'NOT_CANDIDATE'
        E, voted = self.st['epoch'], self.st['voted_for']
        if not (T > E or (T == E and voted in (None, cand))):
            return 'TERM'
        if (self._promise_live(now) and self.promise_to != cand
                and not self._allowance(cand, T, now)):
            return 'PROMISED'
        # the hold after start: whatever this process promised before it started is
        # gone from memory, and every promise it made went to its persisted voted_for.
        # The allowance lifts it as well: it came after the start from that very holder,
        # which stopped acting before it handed its term on
        if now < self.hold_until and cand != voted and not self._allowance(cand, T, now):
            return 'HOLD_AFTER_START'
        if (pair(req.get('cfg_id')) or ZERO) < view.id:
            return 'OLD_CFG'
        cv = pair(req.get('cv')) or ZERO
        if self.kind == KIND_WITNESS:
            if cv < (self.st['floor_cv'] or ZERO):
                return 'BELOW_FLOOR'
        elif cv < self.st['cv']:
            return 'STALE'
        return ''

    def _self_ok(self, T, now):
        """Rules 1-6 for my own vote. A candidate never promises itself (D8), and within
        the hold after start it does not count itself at all: a promise to a leader it
        forgot may be what that leader's lease rests on."""
        v = self.view
        if v.mode != MODE_AUTO or not v.candidate(self.me, timer=False):
            return False
        E, voted = self.st['epoch'], self.st['voted_for']
        if not (T > E or (T == E and voted in (None, self.me))):
            return False
        transfer = self._allowance(self.me, T, now)
        if self._promise_live(now) and self.promise_to != self.me and not transfer:
            return False
        if now < self.hold_until and not transfer:
            return False
        return True

    def _on_vote(self, frm, body, now):
        T = body.get('epoch')
        pre = body.get('pre') is True
        why = body.get('why') or 'timer'
        if body.get('candidate') != frm or not _is_epoch(T):
            return self._no('BAD_REQUEST')
        st = self.st
        if st['role'] == ROLE_LEADER and self.lease_mode():
            led = st['led']['epoch']
            handed = (self.transfer is not None and self.transfer['to'] == frm
                      and T == led + 1 and self._allowance(frm, T, now))
            if not handed:
                if pre or T <= led:
                    return self._no('LEADER')
                if self._booting is None:
                    self._step_down(now, f'vote request at epoch {T}')
                    return self._no('LEADER')
                self._boot_failed(now, f'vote request at epoch {T} at boot')
        try:
            chain = newer_chain(self._chain, body.get('chain'), self.verify)
        except CfgRefused as e:
            return self._no(e.code)
        view = CfgView(chain[-1]) if chain else self.view
        # a manual active that learns from a vote request that its group fails over
        # automatically is a standby from that write on, whatever it answers (4.10): an
        # active with an automatic config and no lead would neither act nor follow
        leaves = (not pre and chain is not None and self.st['role'] == ROLE_ACTIVE
                  and view.mode == MODE_AUTO)
        # Authenticate the candidate's claimed cfg_id and cv against the validated chain
        # or view. A compromised member must not win an election by claiming forged future
        # metadata without proving possession of the corresponding state.
        claimed_cfg = pair(body.get('cfg_id'))
        if claimed_cfg is not None:
            if chain is not None:
                # With a validated chain, cfg_id must match the chain's newest config
                if claimed_cfg != view.id:
                    return self._no('CFG_MISMATCH')
            else:
                # Without a chain, cfg_id must not exceed the voter's view
                if claimed_cfg > view.id:
                    return self._no('CFG_UNPROVEN')
        # The cv's epoch component must not exceed the candidate's claimed election epoch
        # or the config's epoch, as cv is bumped at the leader's epoch and the config's
        # epoch is at least the leader's epoch when it was created.
        claimed_cv = pair(body.get('cv'))
        if claimed_cv is not None:
            if claimed_cv[0] > T:
                return self._no('CV_INVALID')
            if claimed_cfg is not None and claimed_cv[0] > claimed_cfg[0]:
                return self._no('CV_INVALID')
        reason = self._vote_rules(frm, T, pre, why, body, view, now)
        if reason:
            if chain and not pre:
                if leaves:
                    if self._save(chain=chain, role=ROLE_STANDBY):
                        self._left_by_hand(frm)
                else:
                    self._save(chain=chain)
            return self._vote_no(reason, body)
        if pre:
            return dict(self._base(), ok=True, granted=True, reason='')
        # rule 8: on disk before the answer, with the promise if no config on disk covers
        # it; a failed write is no vote. A leader handing its term on promises nothing
        until = now + 1.1 * max(self._asked_lease(body), view.lease_s)
        promised = -_INF if self.st['role'] == ROLE_LEADER else until
        changes = {'role': ROLE_STANDBY} if leaves else {}
        if not self._save(chain=chain, epoch=T, voted_for=frm, promised=promised, **changes):
            return self._no('WRITE_FAILED')
        by_allowance = self._allowance(frm, T, now)
        self.allow = None
        if self.st['role'] == ROLE_LEADER:
            # the leader handed its term on and voted for the target: it is done
            self._event('granted', candidate=frm, epoch=T, allowance=by_allowance,
                        cv=self.st['cv'], floor=self.st['floor_cv'])
            self._step_down(now, 'handed over')
            return dict(self._base(), ok=True, granted=True, reason='')
        self._event('granted', candidate=frm, epoch=T, allowance=by_allowance,
                    cv=self.st['cv'], floor=self.st['floor_cv'])
        self._promise(frm, until, now)
        if self._campaign is not None:
            self._end_campaign()
        self._arm_timer(now)
        ans = dict(self._base(), ok=True, granted=True, reason='', max_leader_cv=self.max_leader_cv)
        if leaves:
            self._left_by_hand(frm)
        return ans

    def _left_by_hand(self, frm):
        # what this process started as an active must not outlive the role
        why = f'member {frm} asks for votes: the group fails over automatically'
        self._acting = False
        self._fail_waiters()
        self._event('step_down', why=why, by_hand=True)
        self._exit(why)

    @staticmethod
    def _asked_lease(body):
        lease_s = body.get('lease_s')
        return lease_s if type(lease_s) is int and LEASE_MIN <= lease_s <= LEASE_MAX else 0

    def _vote_no(self, reason, req):
        extra = {'voted_for': self.st['voted_for'], 'max_leader_cv': self.max_leader_cv}
        if reason == 'STALE':
            extra['fresher'] = {'id': self.me, 'cv': self.st['cv']}
        known = pair(req.get('cfg_id'))
        if known is not None and known < self.view.id:
            extra['chain'] = chain_after(self._chain, known)
        return self._no(reason, **extra)

    # --- renewals (4.4) ---

    def _on_renew(self, frm, body, now):
        T = body.get('epoch')
        if body.get('leader') != frm or not _is_epoch(T):
            return self._no('BAD_REQUEST')
        st = self.st
        role = st['role']
        # a round of a switch between the modes (4.13): it carries a config, never a lease.
        # Its answer names the config held here by digest, which is what the sender
        # counts; an id alone says nothing where two chains meet
        switch = body.get('switch') is True
        if role == ROLE_LEADER and self.lease_mode():
            led = st['led']['epoch']
            if T < led:
                return self._no('OLD_EPOCH')
            if T == led:
                if switch:
                    return self._no('MODE_AUTO', cfg_digest=self._digest)
                if frm not in self.view.data:
                    return self._no('NOT_VOTER')
                # a term has one leader. Another data voter that renews in ours means
                # the group has two: this one leaves, and the voters elect again
            if self._booting is None:
                self._step_down(now, f'renewal at epoch {T}')
                return self._no('GONE')
            # nothing acted in this process yet: go on as a standby
            self._boot_failed(now, f'renewal at epoch {T} at boot')
            st = self.st
            role = st['role']
        if T < st['epoch']:
            return self._no('OLD_EPOCH')
        try:
            chain = newer_chain(self._chain, body.get('chain'), self.verify)
        except CfgRefused as e:
            return self._no(e.code)
        view = CfgView(chain[-1]) if chain else self.view
        if role == ROLE_ACTIVE and frm != self.me:
            # a manual active here as well: the switch cannot go through
            return self._no('MODE_MANUAL')
        if view.mode != MODE_AUTO:
            if chain and not self._save(chain=chain):
                return self._no('WRITE_FAILED')
            said = {'cfg_digest': self._digest} if switch else {}
            if view.mode == MODE_PENDING and view.cfg.get('by') == frm:
                # an ack of the switch, nothing more: no promise, no vote
                return dict(self._base(), ok=True, **said)
            return self._no('MODE_MANUAL', **said)
        if switch:
            # this member is in automatic mode already: whoever switches is not switching
            # the group it is in. Nothing is taken from the call, no config, no term
            return self._no('MODE_AUTO', cfg_digest=self._digest)
        if frm not in view.data:
            # only a data voter of the config held here can have won a term
            return self._no('NOT_VOTER')
        if (T == st['epoch'] and self._renewed is not None and self._renewed[0] == T
                and self._renewed[1] != frm and self.promise_to == self._renewed[1]
                and self._promise_live(now)):
            # the promise this voter holds is to the leader whose renewal it took in this
            # very term. A second member renewing in it gets nothing
            return self._no('PROMISED', holder=self.promise_to)
        changes = {}
        if T > st['epoch']:
            changes['epoch'] = T
            changes['voted_for'] = frm
        elif st['voted_for'] != frm:
            # whatever this member promises in its term goes to its persisted voted_for,
            # so the hold after a restart lets nobody else through (see _vote_rules)
            changes['voted_for'] = frm
        if self.kind == KIND_WITNESS:
            floor = pair(body.get('floor_cv'))
            if floor is not None and floor > (st['floor_cv'] or ZERO):
                changes['floor_cv'] = floor
        until = now + 1.1 * max(self._asked_lease(body), view.lease_s)
        rec = self._promised_record(chain or self._chain, until)
        must = bool(chain or changes) or (rec is not None and rec != st['promised'])
        if must or (rec is None and st['promised'] is not None):
            # a record nothing needs any more goes with this write, and its failure costs
            # no renewal; a promise that has to be on disk is no promise without it
            if not self._save(chain=chain, promised=until, **changes) and must:
                return self._no('WRITE_FAILED')
        if self.allow is not None and self.allow[1] != T + 1:
            self.allow = None
        hold = body.get('hold_s')
        hold = now + min(hold, HOLD_MAX) if type(hold) in (int, float) and hold > 0 else None
        self._promise(frm, until, now, hold)
        rel = body.get('release_to')
        if isinstance(rel, dict) and rel.get('epoch') == T + 1 and isinstance(rel.get('to'), str):
            self.allow = (rel['to'], T + 1, now + self.t.P)
        cv = pair(body.get('cv'))
        if cv is not None and (self.max_leader_cv is None or cv > self.max_leader_cv):
            self.max_leader_cv = cv
            self.max_leader_wall = body.get('wall')
        self.heard_at = now
        self.leader_seen = frm
        self._renewed = (T, frm)
        if self._campaign is not None and self._campaign.epoch <= T + 1:
            self._end_campaign()
        self._arm_timer(now)
        return dict(self._base(), ok=True)

    def _on_campaign(self, frm, body, now):
        # "Make leader": the leader handed its term to us (7.1); a vote without pre-vote
        T = body.get('epoch')
        if (not _is_epoch(T) or self.st['role'] != ROLE_STANDBY or self.st['epoch'] != T
                or not self._allowance(self.me, T + 1, now) or self._campaign is not None):
            return self._no('NO_ALLOWANCE')
        self._vote(now, T + 1, 'transfer')
        return dict(self._base(), ok=True)

    def _on_snapshot(self, frm, body, now):
        # the catch-up pull of a stale candidate (4.6); only to a voter, and only while
        # no leader holds our promise
        if self.kind != KIND_DATA or not body.get('catchup'):
            return self._no('UNKNOWN')
        if frm not in self.view.voters:
            return self._no('NOT_VOTER')
        if self._promise_live(now):
            return self._no('PROMISED')
        return dict(self._base(), ok=True, snapshot=self.hooks.snapshot())

    # --- elections (4.6) ---

    def _timer_candidate(self):
        v = self.view
        return (self.kind == KIND_DATA and v.mode == MODE_AUTO
                and v.candidate(self.me, timer=True))

    def _arm_timer(self, now, backoff=None):
        if backoff is not None:
            at = now + backoff
        else:
            base = self.started if self.heard_at is None else max(self.heard_at, self.started)
            at = base + self.t.election_delay(self.rng, self.lower_reach())
            # my own vote counts only after the hold after start
            at = max(at, self.hold_until)
        if self._promise_live(now) and self.promise_until > at:
            # pushed past a promise (a planned-restart hold most of all), which ends on
            # every member at once: a random part of L/4 on top, or they split the vote
            at = self.promise_until + self.rng.uniform(0, self.t.L / 4)
        after = self.st.get('campaign_after')
        if after and after.get('boot_id') == self.boot_id:
            wait = after.get('at') or 0.0
            if after.get('started') != self.started or not self.boot_id:
                # written by an earlier process: on a host whose boot id is empty, or the
                # same after a reboot, its time is on another clock. It is a courtesy, no
                # promise rests on it - wait no longer than a fresh step-down would
                wait = min(wait, self.started + self.t.boot_wait + self.t.lost_lease_backoff)
            at = max(at, wait)
        self.election_at = at

    def _maybe_campaign(self, now):
        if not self._timer_candidate():
            return
        if self._promise_live(now):
            # never while our own promise to a leader runs
            self.election_at = self.promise_until + self.rng.uniform(0, self.t.L / 4)
            return
        self._prevote(now, 'timer')

    def campaign_now(self, why='make_leader'):
        """'Make leader' while the leader does not answer: skip the timer, keep the
        pre-vote and every rule (7.1, second case)."""
        now = self.clock()
        if (self.dead or self.st['role'] != ROLE_STANDBY or self._campaign is not None
                or not self.view.candidate(self.me, timer=False) or self.view.mode != MODE_AUTO):
            return 'NOT_CANDIDATE'
        self._prevote(now, why)
        return ''

    def _end_campaign(self):
        r = self._campaign
        if r is not None:
            r.done = True
            self._rounds.pop(r.tag, None)
        self._campaign = None

    def _lost(self, now, why):
        self._end_campaign()
        self._event('lost', why=why)
        self._arm_timer(now, backoff=self.t.lost_election_backoff(self.rng))

    def _new_round(self, kind, now, deadline, epoch, targets):
        self._tag += 1
        r = _Round(self._tag, kind, now, deadline, epoch)
        r.targets = frozenset(targets)
        self._rounds[r.tag] = r
        return r

    def _vote_body(self, T, pre, why, to):
        # the configs the voter may lack go along, so a witness that missed changes
        # learns the candidate's key from a config the leader before signed (D2)
        body = {'epoch': T, 'candidate': self.me, 'pre': pre, 'why': why,
                'cv': self.st['cv'], 'cfg_id': self.view.id, 'lease_s': self._lease_s()}
        seg = chain_after(self._chain, self._cfg_seen.get(to))
        if seg:
            body['chain'] = seg
        return body

    def _prevote(self, now, why, catchup_done=False):
        T = max(self.st['epoch'], self.epoch_seen) + 1
        if T > EPOCH_MAX:
            return
        v = self.view
        r = self._new_round('prevote', now, now + self.t.T_vote, T, v.voters - {self.me})
        r.why = why
        r.catchup_done = catchup_done
        if self._self_ok(T, now):
            r.acks.add(self.me)
        self._campaign = r
        self._event('prevote', epoch=T, why=why)
        for to in sorted(r.targets):
            self.send(to, 'vote', self._vote_body(T, True, why, to), r.tag)
        self._vote_progress(r, now)

    def _vote(self, now, T, why):
        st = self.st
        if st['epoch'] >= T or not self._self_ok(T, now):
            return self._lost(now, 'no longer a candidate')
        if not self._save(epoch=T, voted_for=self.me):
            return self._lost(now, 'vote not written')
        by_allowance = self._allowance(self.me, T, now)
        if self.allow is not None and self.allow[:2] == (self.me, T):
            self.allow = None
        v = self.view
        r = self._new_round('vote', now, now + self.t.T_vote, T, v.voters - {self.me})
        r.why = why
        r.lease_s = self._lease_s()
        r.acks.add(self.me)
        self._campaign = r
        self._event('vote', epoch=T, why=why, allowance=by_allowance)
        for to in sorted(r.targets):
            self.send(to, 'vote', self._vote_body(T, False, why, to), r.tag)
        self._vote_progress(r, now)

    def _vote_answer(self, r, frm, ans, now):
        r.answered.add(frm)
        if ans is not None:
            cid = pair(ans.get('cfg_id'))
            if cid is not None:
                self._saw_cfg(frm, cid, r.t0)
            seg = ans.get('chain')
            if seg:
                try:
                    chain = newer_chain(self._chain, seg, self.verify)
                except CfgRefused:
                    chain = None
                if chain:
                    self._save(chain=chain)
                    if self.view.mode != MODE_AUTO or not self.view.candidate(self.me, False):
                        return self._lost(now, 'voter config moved on')
            if ans.get('granted') and frm in self.view.counting:
                r.acks.add(frm)
                r.cvs[frm] = pair(ans.get('cv'))
            else:
                r.refusals.append((frm, ans))
                e = ans.get('epoch')
                if r.kind == 'vote' and _is_epoch(e) and e > r.epoch:
                    return self._lost(now, f'epoch {e} seen')
        self._vote_progress(r, now)

    def _saw_cfg(self, frm, cid, t0):
        # answers cross: one to an older round never lowers what a newer one said. A lower
        # id in the answer to a newer round is a voter that lost configs (a rollback); it
        # gets the chain again
        if cid >= self._cfg_seen.get(frm, cid) or t0 > self._cfg_seen_at.get(frm, -_INF):
            self._cfg_seen[frm] = cid
            self._cfg_seen_at[frm] = max(t0, self._cfg_seen_at.get(frm, -_INF))

    def _vote_progress(self, r, now):
        if r.done:
            return
        m = self.view.m
        acks = r.acks & self.view.counting
        if len(acks) >= m:
            r.acks = acks
            r.done = True
            self._rounds.pop(r.tag, None)
            if r.kind == 'prevote':
                self._campaign = None
                self._vote(now, r.epoch, r.why)
            else:
                self._won(r, now)
        elif len(acks) + len(r.targets - r.answered) < m:
            self._vote_failed(r, now)

    def _vote_failed(self, r, now):
        r.done = True
        self._rounds.pop(r.tag, None)
        self._campaign = None
        reached = ({self.me} | r.acks | {frm for frm, _a in r.refusals}) & self.view.counting
        self.last_failed = {'at': now, 'kind': r.kind, 'epoch': r.epoch, 'why': r.why,
                            'reached': len(reached), 'm': self.view.m,
                            'reasons': sorted({str(a.get('reason') or '') for _f, a in r.refusals})}
        self._event('campaign_failed', **self.last_failed)
        if r.kind == 'prevote' and not r.catchup_done:
            src = catchup_source(r.refusals, self.st['cv'])
            if src is not None and self.kind == KIND_DATA:
                c = self._new_round('catchup', now, now + CATCHUP_TIMEOUT, r.epoch, [src])
                c.why = r.why
                self._campaign = c
                self._event('catchup', source=src)
                self.send(src, 'snapshot', {'catchup': True}, c.tag)
                return
        self._lost(now, f'{r.kind} failed')

    def _catchup_answer(self, r, frm, ans, now):
        r.done = True
        self._rounds.pop(r.tag, None)
        self._campaign = None
        cv = None
        if ans is not None and ans.get('ok'):
            cv = self.hooks.apply_snapshot(frm, ans)
        if cv is None or not self._save(cv=pair(cv) or self.st['cv']):
            return self._lost(now, 'catch-up failed')
        self._prevote(now, 'catchup' if r.why == 'timer' else r.why, catchup_done=True)

    def _won(self, r, now):
        T = r.epoch
        take_after = {'boot_id': self.boot_id, 'at': r.t0 + self._w_take()}
        cv = self.st['cv']
        led = {'epoch': T, 'cv': cv, 'take_after': take_after}
        if not self._save(role=ROLE_LEADER, led=led, base_cv=cv, released=None):
            return self._lost(now, 'win not written')
        self._campaign = None
        self._event('elected', epoch=T, why=r.why, acks=frozenset(r.acks), grants=dict(r.cvs),
                    cv=cv, t0=r.t0)
        # every voter that granted promised from receipt, for at least what we asked
        L = min(r.lease_s, self._lease_s())
        self.lease_until = r.t0 + self._per_round(L)
        self._event('lease', tag=r.tag, t0=r.t0, until=self.lease_until, acks=frozenset(r.acks),
                    lease_s=L)
        self._start_round(now, kind='won', extra={'hold_s': self.t.won_hold})
        if self.restart_on_win:
            # the winner restarts and acts from take_after (Q12 a); W_take covers the restart
            self._exit('won the election')
            return
        self._acting = True
        self._acting_said = False
        self.acting_from = take_after['at']

    # --- leading (4.5) ---

    def _lease_s(self):
        # while a change of lease_s is not committed the shorter one is asked for
        L = self.view.lease_s
        if len(self._chain) > 1 and not self._is_committed():
            L = min(L, self._chain[-2]['body']['lease_s'])
        return L

    def _timings(self, lease_s):
        return self.t if lease_s == self.view.lease_s else Timings(lease_s, self.keep_w_take)

    def _per_round(self, lease_s):
        # a round counts by the lease_s it sent: that is what its voters promised at least
        return self._timings(lease_s).per_round

    def _is_committed(self):
        return self._committed is not None and self._committed >= self.view.id

    def _start_round(self, now, kind='renew', extra=None, skip=frozenset()):
        led_epoch = self.st['led']['epoch']
        v = self.view
        deadline = now + (self.t.boot_wait if kind == 'boot' else self.t.renew_timeout)
        r = self._new_round('renew' if kind == 'won' else kind, now, deadline, led_epoch,
                            v.members - {self.me} - skip)
        r.passed = frozenset(skip)
        if self.me in v.counting:
            r.acks.add(self.me)
        r.lease_s = lease_s = self._lease_s()
        base = {'epoch': led_epoch, 'leader': self.me, 'lease_s': lease_s, 'cv': self.st['cv'],
                'wall': self.wall(), 'floor_cv': self.floor}
        if extra:
            base.update(extra)
        for to in sorted(r.targets):
            known = self._cfg_seen.get(to)
            body = base
            if known is None or known < v.id:
                body = dict(base, chain=chain_after(self._chain, known))
            self.send(to, 'renew', body, r.tag)
        if kind in ('renew', 'boot', 'won'):
            if not skip:
                # a round that passed a voter is no renewal of that voter's promise
                self.next_round_at = now + self._timings(lease_s).R
            self._last_round_t0 = now
        self._event('round', tag=r.tag, kind=kind, epoch=led_epoch)
        return r

    def _ahead_of_me(self, ans, epoch):
        """Why this leader is not the one its members follow, '' when it is: an answer
        names a voter config of the term it leads that it does not hold. Only the leader
        of a term makes configs of it, so its state file went back (a backup put back,
        a VM snapshot reverted), or a second chain exists. Whatever it would make from
        here has an id its members passed already."""
        cid = pair(ans.get('cfg_id'))
        if cid is not None and cid > self.view.id and cid[0] >= epoch:
            return f'a member holds voter config {list(cid)}, newer than the {list(self.view.id)} held here'
        return ''

    def _renew_answer(self, r, frm, ans, now):
        r.answered.add(frm)
        if ans is None:
            if r.kind in ('renew', 'boot'):
                self._unreached.add(frm)
        else:
            self._unreached.discard(frm)
        if ans is not None:
            e = ans.get('epoch')
            if r.kind != 'switch' and _is_epoch(e) and e > r.epoch:
                if self._booting is not None:
                    return self._boot_failed(now, f'epoch {e} seen at boot')
                return self._step_down(now, f'epoch {e} seen')
            why = self._ahead_of_me(ans, r.epoch) if r.kind != 'switch' else ''
            if why:
                if self._booting is not None:
                    return self._boot_failed(now, why)
                return self._step_down(now, why)
            cid = pair(ans.get('cfg_id'))
            if cid is not None:
                self._saw_cfg(frm, cid, r.t0)
            digest = ans.get('cfg_digest')
            if isinstance(digest, str) and r.t0 >= self._held.get(frm, ('', -_INF))[1]:
                # answers cross: one to an older round never replaces what a newer said
                self._held[frm] = (digest, r.t0)
            cv = pair(ans.get('cv'))
            if cv is not None:
                self._cv_seen[frm] = cv
            gen = ans.get('gen')
            if type(gen) is int:
                self._gen_check(frm, gen, r)
                r.gens[frm] = gen
            if ans.get('ok') and frm in self.view.counting:
                r.acks.add(frm)
                # rounds overlap and come back in any order
                self._acked_at[frm] = max(r.t0, self._acked_at.get(frm, -_INF))
                if cv is not None and frm in self.view.data:
                    r.cvs[frm] = cv
            if r.kind == 'switch':
                digest = ans.get('cfg_digest')
                if isinstance(digest, str):
                    self._switch_said[frm] = (digest, ans.get('ok') is True)
        if r.kind == 'switch':
            if r.answered >= r.targets:
                self._finish(r, now)
            return
        self._commit_check(now)
        if self.dead or self.st['role'] != ROLE_LEADER:
            return
        if not r.majority:
            # counted by the config held now: an ack from a voter that a change took out
            # while the round was on its way does not count
            counted = r.acks & self.view.counting
            if len(counted) >= self.view.m:
                r.acks = counted
                self._majority(r, now)
        if r.answered >= r.targets and not r.done:
            self._finish(r, now)
        # a round back, or a voter that answered: whoever waits for one may get it now
        self._confirm_round(now)

    def _majority(self, r, now):
        r.majority = True
        if r.kind in ('renew', 'boot'):
            # once the release went out this leader stopped for good: a round that left
            # before it and comes back now gives it no lease back
            if self.transfer is None or self.transfer['phase'] == 'catchup':
                # by the shorter of what the round asked for and what is asked now, so a
                # round that left before a shorter lease came in does not undo the cut
                L = min(r.lease_s, self._lease_s())
                self.lease_until = max(self.lease_until, r.t0 + self._per_round(L))
                self._event('lease', tag=r.tag, t0=r.t0, until=self.lease_until,
                            acks=frozenset(r.acks), lease_s=L)
            cvs = list(r.cvs.values())
            if self.me in self.view.data:
                cvs.append(self.st['cv'])
            f = floor_of(cvs, self.view.m)
            if f is not None and f > self.floor:
                self.floor = f
                self._event('floor', floor=f, epoch=r.epoch)
        if r.kind == 'boot' and self._booting is not None:
            self._booted(now)
        if r.kind in ('renew', 'boot'):
            self._resolve_waiters(r, now, True)

    def _finish(self, r, now):
        if r.done:
            return
        r.done = True
        self._rounds.pop(r.tag, None)
        for frm, gen in r.gens.items():
            hist = self._gens.setdefault(frm, [])
            hist.append((now, gen))
            if len(hist) > 8:
                del hist[0]
        if r.kind in ('renew', 'boot') and not r.majority:
            # the voters asked made no majority after all: the ones it passed because
            # their last call failed are asked again, by one more round for whoever
            # waits now, before the waiters are told no
            again = bool(r.passed & self._unreached)
            self._unreached.clear()
            if again:
                self._confirm_round(now)
            self._resolve_waiters(r, now, False)

    def _gen_check(self, frm, gen, r):
        # D9: only a round that completed before this one started counts, so answers
        # that cross never make a healthy voter look restored from an old state
        best = None
        for done_at, g in self._gens.get(frm, ()):
            if done_at < r.t0 and (best is None or g > best):
                best = g
        if best is not None and gen < best and frm in self.view.counting \
                and frm not in self._suspects:
            self._suspects.append(frm)
            self._event('suspect', voter=frm, gen=gen, seen=best)

    def _expire(self, now):
        for r in list(self._rounds.values()):
            if r.done or now < r.deadline:
                continue
            if r.kind in ('prevote', 'vote'):
                self._vote_failed(r, now)
            elif r.kind == 'catchup':
                r.done = True
                self._rounds.pop(r.tag, None)
                self._campaign = None
                self._lost(now, 'catch-up timed out')
            else:
                self._finish(r, now)
            if self.dead:
                return
        if self._waiters:
            late = [w for w in self._waiters if now > w[0] + self.t.confirm_timeout + self.t.renew_timeout]
            if late:
                self._waiters = [w for w in self._waiters if w not in late]
                for w in late:
                    w[2](False)

    def _lease_check(self, now):
        if (self.st['role'] == ROLE_LEADER and self.lease_mode() and self._booting is None
                and (self.transfer is None or self.transfer['phase'] == 'catchup')
                and now >= self.lease_until):
            self._lose(now, 'lease ran out')

    def _lead(self, now):
        st = self.st
        led = st['led']
        # renew only at the epoch we won (A1)
        if st['epoch'] != led['epoch'] or st['voted_for'] != self.me:
            return self._step_down(now, 'the term moved on')
        if self._booting is not None:
            if now >= self._booting:
                return self._boot_failed(now, 'no majority at boot')
            if now >= min(self.next_round_at, self._last_round_t0 + self.t.boot_retry):
                self._start_round(now, kind='boot')
            return
        if self.transfer is not None:
            self._transfer_tick(now)
            if self.dead or self.transfer is None or self.transfer['phase'] != 'catchup':
                return
        if now >= self.lease_until:
            return self._lose(now, 'lease ran out')
        self._confirm_round(now)
        if now >= self.next_round_at:
            self._start_round(now)
        if self._acting and not self._acting_said and self.acting_from <= now:
            self._acting_said = True
            self._event('acting', epoch=led['epoch'])
        self._cfg_work(now)

    def _cfg_work(self, now):
        if not self._acting or now < self.acting_from or self.transfer is not None:
            return
        v = self.view
        led_epoch = self.st['led']['epoch']
        if v.id[0] < led_epoch:
            # a config of our own epoch before any change (the fix for the one-at-a-time bug)
            return self._new_cfg(now, v.cfg['body'], 'no-op')
        if not self._is_committed():
            return
        body = v.cfg['body']
        quarantined = list(body.get('quarantined') or ())
        for s in self._suspects:
            if s not in quarantined and s in v.counting:
                return self._new_cfg(now, dict(body, quarantined=quarantined + [s]), 'quarantine')
        if self._changes:
            # off the queue once it is written: a write that failed is tried again
            change = self._changes[0]
            new = change(body)
            if new is None or body_error(new):
                self._changes.pop(0)
                return self._event('change_refused', why=body_error(new) if new else 'no change')
            nxt = {'id': [0, 0], 'body': new}
            if not majorities_intersect(v.cfg, nxt):
                # one voter in or out per change, or two majorities in a row may miss
                # each other (I8)
                self._changes.pop(0)
                return self._event('change_refused', why='more than one voter at once')
            if self._new_cfg(now, new, 'change'):
                self._changes.pop(0)

    def _new_cfg(self, now, body, why):
        """Make the next config and write it; False when it is not on disk."""
        prev = self._chain[-1]
        cfg = make_cfg(prev, self.st['led']['epoch'], self.me, body, self.sign)
        if not self._save(chain=self._chain + [cfg]):
            return False
        if body['lease_s'] < prev['body']['lease_s']:
            # a shorter lease cuts what this leader holds at once: from here on no lease
            # rests on the old length, even once that config has left every chain
            self.lease_until = min(self.lease_until, now + self._per_round(body['lease_s']))
        self._event('cfg', cfg=cfg, prev=prev, why=why)
        self.next_round_at = min(self.next_round_at, now)
        return True

    def change_cfg(self, change):
        """Queue a change of the voter config: change(body) -> the new body. One at a time,
        only once the config before it reached a majority."""
        if self.st['role'] != ROLE_LEADER:
            return 'NOT_LEADER'
        self._changes.append(change)
        self.next_round_at = min(self.next_round_at, self.clock())
        return ''

    def cancel_change(self, change):
        """Take a queued change back before it is made. False when it is made already
        (or was refused): it is no longer in the queue."""
        if change in self._changes:
            self._changes.remove(change)
            return True
        return False

    def cfg_seen(self, member):
        """The voter config id `member` last said it holds, None while it said none."""
        return self._cfg_seen.get(member)

    def cv_seen(self, member):
        """The cv `member` last answered a round of this leader with, None while it said none."""
        return self._cv_seen.get(member)

    def change_pending(self):
        """Whether a change of the voter config waits or is on its way: one queued, the
        newest config not committed yet, or the config of a new term still to come
        (4.12). The next change waits for all of it."""
        if self._changes or not self._is_committed():
            return True
        led = self.st.get('led')
        return bool(led) and self.view.id[0] < led['epoch']

    def campaigning(self):
        return self._campaign is not None

    def readmit(self, voter):
        """The admin looked at a quarantined voter and takes it back (4.5). What this
        leader held against it goes with the change, or the next pass would quarantine
        it again: the generations it saw before, and the suspicion itself."""
        if self.st['role'] != ROLE_LEADER:
            return 'NOT_LEADER'
        if voter not in (self.view.cfg['body'].get('quarantined') or ()):
            return 'NOT_QUARANTINED'
        if voter in self._suspects:
            self._suspects.remove(voter)
        self._gens.pop(voter, None)
        return self.change_cfg(lambda body: dict(
            body, quarantined=[q for q in body.get('quarantined') or () if q != voter]))

    def _commit_check(self, now):
        v = self.view
        if not self._is_committed():
            prev = self._prev_view
            if prev is None:
                self._committed = v.id
                return
            # who holds this very config, by its digest: an id says nothing where this
            # leader's state went back and it made a config under an id its members
            # passed already
            holders = {self.me} | {i for i, (digest, _t0) in self._held.items() if digest == self._digest}
            if len(holders & prev.counting) < prev.m:
                return
            self._committed = v.id
            self._event('cfg_committed', cfg=v.cfg)
        if v.mode == MODE_MANUAL and self.st['role'] == ROLE_LEADER:
            # switched off: the role decides again (4.13). A write that fails is tried
            # again with the next answer, and until it is on disk the lease decides
            if not self._save(role=ROLE_ACTIVE):
                return
            self._fail_waiters()
            self._event('manual', epoch=self.st['epoch'])

    # --- confirm before acting (4.5) ---

    def confirm(self, need, cb):
        """cb(ok) once a majority round that started after this call came back with at
        least `need` seconds of lease left, cb(False) when it does not. Manual mode and a
        standalone instance confirm at once.

        There is no spacing between rounds. A call that no round out can serve (none
        started after it) starts one at once, while fewer than CONFIRM_IN_FLIGHT are out;
        else it waits with the others for the next, which starts as one comes back. A
        round serves every call made up to its start, whichever order rounds come back
        in. CONFIRM_RATE_MAX caps the rounds a second whatever the callers do."""
        if self.dead:
            return cb(False)
        if not self.lease_mode():
            return cb(self.is_active())
        now = self.clock()
        self._watch_clock(now)
        if not self.is_active():
            return cb(False)
        self._waiters.append([max(now, self._jump_at), need, cb, self._tag])
        self._confirm_round(now)

    def _flying(self):
        """The renewal rounds out that may still serve a confirm: no majority yet, not done."""
        return [r for r in self._rounds.values()
                if r.kind in ('renew', 'boot') and not r.majority and not r.done]

    def _owed(self):
        """voter -> calls of the leader's rounds it has not answered yet."""
        owed = {}
        for r in self._rounds.values():
            if r.kind in ('renew', 'boot', 'release') and not r.done:
                for to in r.targets - r.answered:
                    owed[to] = owed.get(to, 0) + 1
        return owed

    def _confirm_plan(self, now):
        """(when the next confirm round may start, the voters it passes), None when no
        round is wanted (each confirm waiting has a round out that started after it) or
        none can start before a round out comes back: as many are out as may be, or the
        voters it could ask hold too many calls of ours to make a majority. A voter whose
        last call failed counts as owing too (_unreached), while the others can make the
        majority without it: a member that refuses or drops connections costs no confirm
        round a call, the renewal every R still goes to it."""
        if not self._waiters or self.dead or self._booting is not None:
            return None
        if self.st['role'] != ROLE_LEADER or (self.transfer is not None and self.transfer['phase'] != 'catchup'):
            return None
        flying = self._flying()
        newest = max((r.tag for r in flying), default=0)
        if all(w[3] < newest for w in self._waiters) or len(flying) >= CONFIRM_IN_FLIGHT:
            return None
        skip = frozenset(i for i, n in self._owed().items() if n >= CONFIRM_PER_VOTER)
        if len(self.view.counting - skip - self._unreached) >= self.view.m:
            skip |= self._unreached & self.view.members
        elif len(self.view.counting - skip) < self.view.m:
            return None
        self._bucket = min(float(CONFIRM_IN_FLIGHT),
                           self._bucket + max(0.0, now - self._bucket_at) * CONFIRM_RATE_MAX)
        self._bucket_at = now
        at = now if self._bucket >= 1 else now + (1 - self._bucket) / CONFIRM_RATE_MAX
        return at, skip

    def _confirm_due(self, now):
        plan = self._confirm_plan(now)
        return plan[0] if plan is not None else None

    def _confirm_round(self, now):
        plan = self._confirm_plan(now)
        if plan is None or plan[0] > now:
            return
        self._bucket -= 1
        self._start_round(now, skip=plan[1])

    def _resolve_waiters(self, r, now, ok):
        if not self._waiters:
            return
        # a round serves every confirm made before it started. One that failed fails only
        # those no other round out can serve any more
        newest = 0 if ok else max((x.tag for x in self._flying() if x is not r), default=0)
        keep = []
        done = []
        for w in self._waiters:
            if r.tag > w[3] >= newest:
                done.append(w)
            else:
                keep.append(w)
        self._waiters = keep
        for w in done:
            # checked once more right before the step goes out
            w[2](ok and self.is_active() and self.lease_until - self.clock() >= w[1])

    def _fail_waiters(self):
        waiters, self._waiters = self._waiters, []
        for w in waiters:
            w[2](False)

    def watch_clock(self):
        """The look at the clock a tick or an answer takes, for a caller about to act on
        what an earlier round said (the transport guard): a step seen here voids it."""
        if not self.dead:
            self._watch_clock(self.clock())

    def _watch_clock(self, now):
        # a step of the wall clock against the lease clock does not drop the lease (an NTP
        # step would cost a failover), it forces a fresh round before any step goes out
        d = self.wall() - now
        last, self._watch_last = self._watch_last, d
        if last is None or abs(d - last) <= CLOCK_JUMP:
            return
        if self.st['role'] == ROLE_LEADER and self.lease_mode():
            self._jump_at = now
            # no round out from before the step serves anyone
            for w in self._waiters:
                w[0] = max(w[0], now)
                w[3] = self._tag
            self.next_round_at = now
            self._event('clock_jump', by=d - last)

    # --- losing the lease (4.7, 4.8) ---

    def _step_down(self, now, why):
        if self.dead:
            return
        self.lease_until = min(self.lease_until, now)
        self._acting = False
        self._fail_waiters()
        dropped = self._switch_off_dropped()
        if self._save(chain=dropped, role=ROLE_STANDBY,
                      campaign_after={'boot_id': self.boot_id, 'started': self.started,
                                      'at': now + self.t.lost_lease_backoff}) and dropped:
            self._event('switch_off_dropped', epoch=self.st['epoch'])
        self._event('step_down', why=why)
        self._exit(why)

    def _lose(self, now, why):
        self._event('lease_lost', why=why)
        self._step_down(now, why)

    def step_down(self, why):
        """Leave the lead now, from outside the protocol: a newer claim on a cluster (6.3)
        or a tombstone. A manual active goes passive the same way."""
        if self.dead:
            return
        if self.st['role'] == ROLE_LEADER and self.lease_mode():
            return self._step_down(self.clock(), why)
        if self.st['role'] == ROLE_ACTIVE:
            self._save(role=ROLE_STANDBY)
            self._event('step_down', why=why)
            self._exit(why)

    # --- handing the term on (7.1, 7.2) ---

    def transfer_to(self, target):
        now = self.clock()
        v = self.view
        if self.st['role'] != ROLE_LEADER or not self.lease_mode() or not self.is_active():
            return 'NOT_LEADER'
        if self.transfer is not None:
            return 'BUSY'
        if target == self.me or not v.candidate(target, timer=False):
            return 'NOT_CANDIDATE'
        if now - self._acked_at.get(target, -_INF) > 2 * self.t.R + self.t.renew_timeout:
            return 'UNREACHABLE'
        self.transfer = {'to': target, 'phase': 'catchup', 'until': now + TRANSFER_CATCHUP}
        self._event('transfer', to=target)
        self.next_round_at = min(self.next_round_at, now)
        return ''

    def _transfer_tick(self, now):
        t = self.transfer
        led_epoch = self.st['led']['epoch']
        if t['phase'] == 'catchup':
            if self._cv_seen.get(t['to']) == self.st['cv']:
                # the hand-over is on disk before release_to goes out: a crash from here
                # on comes back as a standby, never as the leader the voters let go of
                if not self._save(released={'to': t['to'], 'epoch': led_epoch + 1}):
                    self.transfer = None
                    self._event('transfer_refused', why='hand-over not written')
                    return
                # stop acting first, then hand the next term to exactly this member
                self.lease_until = min(self.lease_until, now)
                self._acting = False
                self._fail_waiters()
                self._event('acting_stop', why='transfer')
                self.allow = (t['to'], led_epoch + 1, now + self.t.P)
                r = self._start_round(now, kind='release',
                                      extra={'release_to': {'to': t['to'], 'epoch': led_epoch + 1}})
                t.update(phase='release', round=r.tag, until=now + self.t.renew_timeout)
            elif now >= t['until']:
                self.transfer = None
                self._event('transfer_refused', why='could not catch up')
        elif t['phase'] == 'release':
            r = self._rounds.get(t['round'])
            if r is None or r.done or r.majority or now >= t['until']:
                c = self._new_round('campaign', now, now + self.t.renew_timeout, led_epoch, [t['to']])
                self.send(t['to'], 'campaign', {'epoch': led_epoch}, c.tag)
                t.update(phase='wait', until=now + self.t.T_vote + 2 * self.t.renew_timeout + 1)
        elif now >= t['until']:
            self._lose(now, 'the transfer did not complete')

    def planned_restart(self, hold_s=PLANNED_HOLD):
        """Restart the leader without a failover: stop acting, ask the voters to hold for
        hold_s, exit. After the restart it renews at the epoch it won (7.2)."""
        now = self.clock()
        if self.st['role'] != ROLE_LEADER or not self.lease_mode() or self.dead:
            return 'NOT_LEADER'
        self.lease_until = min(self.lease_until, now)
        self._acting = False
        self._fail_waiters()
        # planned: the members say "leader restarting" for the hold, not "taking over"
        self._start_round(now, kind='release', extra={'hold_s': min(hold_s, HOLD_MAX), 'planned': True})
        self._event('planned_restart', hold_s=hold_s)
        self._exit('planned restart')
        return ''

    # --- switching modes (4.13) ---

    def switch_on(self):
        if not AUTO_MODE_SHIPPED:
            return 'NOT_SHIPPED'
        now = self.clock()
        v = self.view
        if self.dead or self.st['role'] != ROLE_ACTIVE or v.mode != MODE_MANUAL or self.switch:
            return 'NOT_ACTIVE'
        body = dict(v.cfg['body'], mode=MODE_PENDING)
        why = body_error(body)
        if why:
            return 'TOO_FEW_VOTERS' if why == 'too few voters' else 'BAD_CFG'
        cfg = make_cfg(self._chain[-1], self.st['epoch'], self.me, body, self.sign)
        if not self._save(chain=self._chain + [cfg]):
            return 'WRITE_FAILED'
        self.switch = {'id': pair(cfg['id']), 'until': now + SWITCH_TIMEOUT, 'next': now}
        self._switch_said = {}
        self._event('switch_pending', cfg=cfg)
        return ''

    def switch_cancel(self):
        """Take a pending switch back before every member acked it: the one that runs, or
        one a restart of this instance left behind (the config on disk is pending, made
        here, and nothing drives it any more). The members get the manual config again."""
        now = self.clock()
        v = self.view
        if (self.dead or self.st['role'] != ROLE_ACTIVE or v.mode != MODE_PENDING
                or v.cfg.get('by') != self.me):
            return 'NOT_PENDING'
        if self.switch is None:
            self.switch = {'id': v.id, 'until': now, 'next': now}
        elif not self.switch.get('cancelled'):
            self.switch['until'] = now
        return ''

    def _switch_tick(self, now):
        s = self.switch
        v = self.view
        E = self.st['epoch']
        # who holds the config this switch is about: by its digest, from an answer to a
        # round of this switch. The pending one counts only where it was acked - a
        # refusal holds nothing, whatever config id stands in it
        cancelled = bool(s.get('cancelled'))
        holders = {self.me} | {i for i, (digest, ok) in self._switch_said.items()
                               if digest == self._digest and (ok or cancelled)}
        if s.get('cancelled'):
            # hand the manual config back to whoever took the pending one, then stop
            if holders >= v.members or now >= s['until']:
                self.switch = None
                return
        elif now >= s['until']:
            cfg = make_cfg(self._chain[-1], E, self.me, dict(v.cfg['body'], mode=MODE_MANUAL), self.sign)
            if self._save(chain=self._chain + [cfg]):
                s.update(cancelled=True, id=pair(cfg['id']), until=now + SWITCH_TIMEOUT, next=now)
                self._event('switch_cancelled')
            return
        elif holders >= v.members:
            cfg = make_cfg(self._chain[-1], E, self.me, dict(v.cfg['body'], mode=MODE_AUTO), self.sign)
            led = {'epoch': E, 'cv': self.st['cv'], 'take_after': {'boot_id': self.boot_id, 'at': now}}
            if not self._save(chain=self._chain + [cfg], role=ROLE_LEADER, led=led, voted_for=self.me,
                              released=None):
                return
            self.switch = None
            self._committed = None
            self._acting = True
            self._acting_said = False
            self.acting_from = now
            self.next_round_at = now
            self._event('elected', epoch=E, why='switch', acks=frozenset(), grants={},
                        cv=self.st['cv'], t0=now)
            self._start_round(now)
            return
        if now >= s['next']:
            r = self._new_round('switch', now, now + self.t.renew_timeout, E, v.members - {self.me})
            for to in sorted(r.targets):
                known = self._cfg_seen.get(to)
                body = {'epoch': E, 'leader': self.me, 'switch': True, 'lease_s': v.lease_s}
                if known is None or known < v.id:
                    body['chain'] = chain_after(self._chain, known)
                self.send(to, 'renew', body, r.tag)
            s['next'] = now + self.t.R

    def switch_off(self):
        now = self.clock()
        v = self.view
        if self.dead or self.st['role'] != ROLE_LEADER or v.mode != MODE_AUTO or not self.is_active():
            return 'NOT_LEADER'
        if not self._is_committed():
            return 'BUSY'
        if not self._new_cfg(now, dict(v.cfg['body'], mode=MODE_MANUAL), 'switch off'):
            return 'WRITE_FAILED'
        return ''

    def manual_promote_refusal(self):
        """The manual promote answers 409 HA_AUTO_MODE in automatic and pending mode."""
        return 'HA_AUTO_MODE' if self.view.mode in (MODE_AUTO, MODE_PENDING) else ''

    def promote_manual(self, epoch):
        if self.manual_promote_refusal():
            return self.manual_promote_refusal()
        if not self._save(role=ROLE_ACTIVE, epoch=max(epoch, self.st['epoch'])):
            return 'WRITE_FAILED'
        return ''

    # --- data the host keeps ---

    def bump_cv(self):
        """The leader's configuration changed: one more step of cv (4.11)."""
        if not self.may_write():
            return None
        E = self.st['led']['epoch'] if self.st.get('led') else self.st['epoch']
        cv = self.st['cv']
        new = (E, cv[1] + 1) if cv[0] == E else (E, 1)
        if not self._save(cv=new):
            return None
        return new

    def set_cv(self, cv):
        """A member applied a snapshot that carries `cv`."""
        cv = pair(cv)
        if cv is None or self.kind != KIND_DATA:
            return False
        return self._save(cv=cv)
