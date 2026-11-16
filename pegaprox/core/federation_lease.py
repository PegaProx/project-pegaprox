"""Leases of the federation: who may write a cluster that is enrolled, and how a cluster
moves from one member to another.

A cluster a member enrolled is written only while a majority of the agreed view backs
that member's lease on it. The rules, and why they make two writers impossible:

  * a voter holds at most one live promise per cluster, and promises a new candidate only
    once the old promise ran out plus LEASE_SKEW. The promise is on disk before the vote
    leaves. There are no terms: one live promise per voter is all the protocol needs.
  * the holder's lease ends at round_start + LEASE_SECONDS - LEASE_WRITE_MARGIN on its
    own clock, and every promise behind it started at receipt, after round_start, and
    lasts LEASE_SECONDS on the voter's clock: with clock rates within the HA module's
    10% bound the lease ends before any promise behind it.
  * a candidate counts a grant only from a voter that holds the same view (the digest of
    the member list), and the view changes one member at a time under a majority lock
    (the reserved lease id MEMBERS_LOCK): any majority of one view and any majority of the
    next overlap, so two candidates with majorities would need one voter promising both.
  * that overlap holds between views one step apart only. A lease counted under a view
    can still run when the view is two changes further on (remove one member, then
    another, while the holder sits behind the gap), and a majority of the newer view
    may then share no voter with it. Every change of the view therefore starts a settle
    span of LEASE_SECONDS + LEASE_SKEW at each voter that takes it, in which the voter
    grants no cluster ask at all: no adoption, no renewal, no ask of the owner itself (a
    live promise says nothing about the view its lease was counted under, and an old
    owner's ask is no adoption). A view two steps on needs a majority of the step
    between to have left the older view, which the older lease's voters had not done
    when it was counted, so every voter of the newer view took its last change after
    that lease began - and its settle span outlasts it. The cost: after every change of
    the view the leases pause until the settle span is over (writes to enrolled clusters
    wait up to about half a minute). The members lock is not a cluster and goes on.
  * a promise carries an id of its own (pid) that the grant answers with. A release
    names the pid it gives back, so a release that arrives late never ends a newer
    promise of the same holder, and a round that a release overtook writes no lease.
    Each round carries a mark that grows from round to round (the wall clock, never
    below the last mark, which the lease file keeps across a restart, taken with the
    snapshot of the leases under the lock a release takes too). A voter keeps
    the mark with the promise and refuses a renewal from an older round ('stale'): a
    round that a release overtook, delayed on its way, would otherwise swap the pid of
    the newer round's promise for one it then gives back.
  * a voter keeps a bounded record of the cluster ids whose rows it dropped (an
    unenroll, a removed member, an orphan sweep) and the member that led them, and only
    where its own state shows that member led the id (its row, or its last promise). With
    no row left it refuses another candidate's ask for such an id with 'owner': an old
    owner that was cut off while its cluster moved on finds a majority naming the new
    leader and turns its row into a mirror, instead of leasing the id again from voters
    that forgot it.
  * a hand-over (release) and an adoption are marked in the identity row, which the HA
    sync carries: a promoted standby, or a host whose lease file was removed, neither
    leases a cluster that was handed over nor asks for an adopted one as a plain renewal
    (which voters that still name the old owner would refuse, and the round would hand
    the row back).
  * promises survive a service restart (CLOCK_BOOTTIME keeps running and the file keeps
    them). After a reboot, or when this host becomes the acting host of its HA group (the
    HA epoch moved), the voter refuses every ask for LEASE_SECONDS + LEASE_SKEW, so every
    promise it might have forgotten has run out first. An epoch that moves while the
    same host stays acting (it takes its first standby, or leaves its group) is no
    promotion: ha.py says so beforehand (note_epoch_kept), and there is no hold.
  * the cluster rows and the 'adopt' flag decide only WHO may ask (liveness, squatting);
    they never let a voter hold two live promises, so a wrong or stale row can delay an
    owner but never create a second writer.

A round asks every member side by side, one call each carrying every cluster this
instance owns. The round is driven by the cluster rows this instance owns, so a lease that
lapsed in an outage comes back by itself once a majority answers again.

MK Nov 2026
"""
import logging
import math
import re
import secrets
import time
from collections import Counter

from pegaprox.core import federation as fed
from pegaprox.core.federation import FederationError, MEMBERS_LOCK, CLUSTER_ID_RE

LEASE_SECONDS = 30
LEASE_RENEW_AFTER = fed.LEASE_RENEW_AFTER
LEASE_WRITE_MARGIN = 2.0
# how far apart the clocks of the members may be (ha_vote's SKEW_LIMIT)
LEASE_SKEW = 5
VOTE_TIMEOUT = fed.VOTE_TIMEOUT
MAX_ASKS_PER_CALL = 256
MAX_PROMISES = 1024
MAX_PROMISES_PER_CANDIDATE = 256
# with two sites a lease needs both, so either outage locks the other: no failover, only
# lockout. Enrolling starts at three
MIN_SITES_TO_ENROLL = 3
OWNER_CACHE_SECONDS = 5
# a view change is made in one lock round: a member that keeps renewing the members lock
# past this blocks every other change, so the voter stops renewing it and makes that
# member wait out a cool-down before it gets the lock again
MEMBERS_LOCK_MAX = LEASE_SECONDS
MEMBERS_LOCK_COOL = LEASE_SECONDS
# after a voter took a change of the view it grants no cluster ask for this long (a new
# lease, a renewal and an adoption alike); the members lock goes on
SETTLE_SECONDS = LEASE_SECONDS + LEASE_SKEW
PID_RE = re.compile(r'[0-9a-f]{16}')
# dead promises go only when the table runs over its bound, and only once they are this
# old on the lease clock: a dead promise still says whom this voter backed last
PROMISE_GC_AGE = 3600
LEASE_PATH = fed.LEASE_PATH


def _lease_now():
    """The lease clock: CLOCK_BOOTTIME where there is one, the monotonic clock otherwise.
    A wall clock that jumps (NTP stepping back, a VM restore) must not lengthen a lease
    past its end or wake a promise early."""
    try:
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return time.monotonic()


def _clock_kind():
    try:
        time.clock_gettime(time.CLOCK_BOOTTIME)
        return 'boottime'
    except (AttributeError, OSError):
        return 'monotonic'


def _boot_id():
    held = fed._runtime.get('boot_id')
    if held is None:
        from pegaprox.core import ha_vote
        held = fed._runtime['boot_id'] = ha_vote.read_boot_id() or ''
    return held


def _ha_epoch():
    try:
        from pegaprox.core import ha
        return int(ha.epoch())
    except Exception:
        return 0


def _clock_mark():
    """What the promises and leases on file are valid under: this boot, this HA epoch, and
    a lease clock that keeps running across a service restart. Without CLOCK_BOOTTIME or a
    readable boot id a restart cannot be told from a reboot, and the mark carries the
    process start, so every start holds."""
    mark = {'boot_id': _boot_id(), 'ha_epoch': _ha_epoch(), 'kind': _clock_kind()}
    if mark['kind'] != 'boottime' or not mark['boot_id']:
        mark['process'] = int(fed._PROCESS_STARTED)
    return mark


def check_clock(st, missing=False):
    """The clock check, at the load of the lease file and in every vote and round. Returns
    True when it changed `st` (the caller saves it).

    The same mark: nothing, a service restart keeps every promise and every lease. Any
    other (a reboot, this host became the acting one of its HA group, no CLOCK_BOOTTIME):
    every lease of this instance closes, every promise it gave ends now, and the voter
    holds - refuses every ask, its own included - for LEASE_SECONDS + LEASE_SKEW. A lease
    file that is gone while the view holds other members starts the hold too: the voter
    may have promised before it lost the file."""
    mark = _clock_mark()
    held = st.get('clock') or {}
    if held == mark and not missing:
        return False
    kept = st.get('epoch_kept')
    st['epoch_kept'] = None
    if (not missing and held and isinstance(kept, dict)
            and held.get('ha_epoch') == kept.get('from') and mark['ha_epoch'] == kept.get('to')
            and dict(held, ha_epoch=mark['ha_epoch']) == mark):
        # the HA epoch moved while this host stayed the acting one (note_epoch_kept): its
        # file holds every promise it gave and every lease it holds
        st['clock'] = mark
        return True
    if missing and not fed.members():
        st['clock'] = mark
        return True
    now = _lease_now()
    for rec in (st.get('my_leases') or {}).values():
        rec['expires'] = 0
    for rec in (st.get('promises') or {}).values():
        if not rec.get('released'):
            rec['until'] = now
    st['hold_until'] = now + LEASE_SECONDS + LEASE_SKEW
    # a settle span on the old clock means nothing on this one; the hold covers it
    st['view_changed'] = 0.0
    st['clock'] = mark
    logging.warning('[FED] the lease clock or the HA role of this host changed (a reboot, '
                    'a promotion, or a lease file that is gone): the leases held here are '
                    f'closed and this instance votes for nobody for '
                    f'{LEASE_SECONDS + LEASE_SKEW} s')
    return True


def note_epoch_kept(old, new):
    """The HA epoch of this host moves from `old` to `new` while the host stays the acting
    one of its group: an active takes its first standby (0 to 1), or leaves its group (to
    0). Its lease file holds everything it promised and holds, so the next clock check
    takes the new epoch without the hold a promotion needs. core/ha.py calls this before
    it writes the new epoch; a promotion never does."""
    def go(st):
        if (st.get('clock') or {}).get('ha_epoch') != int(old):
            return False
        st['epoch_kept'] = {'from': int(old), 'to': int(new)}
        return True
    fed._mutate_leases(go)


def hold_left(st=None):
    st = st if st is not None else fed._lease_state()
    return max(0.0, float(st.get('hold_until') or 0) - _lease_now())


def note_view_change():
    """This instance took a change of the view (its own, a commit, a catch-up, a join): its
    settle span starts now."""
    def go(st):
        st['view_changed'] = _lease_now()
        return True
    fed._mutate_leases(go)


def settle_left(st=None):
    st = st if st is not None else fed._lease_state()
    changed = float(st.get('view_changed') or 0)
    if changed <= 0:
        return 0.0
    return max(0.0, changed + SETTLE_SECONDS - _lease_now())


# --- whose rows are whose ------------------------------------------------------------------

def _owner_map():
    """{cluster id: fed_owner} of every enrolled row and every mirror, cached for a few
    seconds and dropped by every change of ownership. Raises FederationError when the
    clusters table cannot be read: the gate fails closed on it."""
    held = fed._runtime.get('owners')
    now = time.monotonic()
    if held is not None and 0 <= now - held[1] < OWNER_CACHE_SECONDS:
        return held[0]
    try:
        rows = fed._db().conn.execute(
            "SELECT id, fed_owner FROM clusters WHERE fed_owner != ''").fetchall()
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')
    owners = {r['id']: r['fed_owner'] for r in rows}
    fed._runtime['owners'] = (owners, now)
    return owners


def drop_owner_cache():
    fed._runtime['owners'] = None


def cluster_owner(cluster_id):
    """The member a cluster row says its writes belong to: '' for one this instance holds
    alone, None for a row that is not there. One query; raises FederationError when the
    table cannot be read."""
    try:
        row = fed._db().conn.execute('SELECT fed_owner FROM clusters WHERE id = ?',
                                     (cluster_id,)).fetchone()
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')
    if row is None:
        return None
    return row['fed_owner'] or ''


def takes_writes_for(cluster_id):
    """The gate every write on a cluster goes through. No owner: this instance's own, no
    lease asked. Another member's: never. Ours: while this instance holds a live lease
    that it did not release. No database query and no file read on the way."""
    owner = _owner_map().get(cluster_id)
    if not owner:
        return True
    if owner != fed.instance_id():
        return False
    rec = (fed._lease_state().get('my_leases') or {}).get(cluster_id)
    return bool(rec and not rec.get('released') and _lease_now() < (rec.get('expires') or 0))


def holds(cluster_id):
    """Whether this instance holds a live, unreleased lease on `cluster_id` (the members
    lock included)."""
    rec = (fed._lease_state().get('my_leases') or {}).get(cluster_id)
    return bool(rec and not rec.get('released') and _lease_now() < (rec.get('expires') or 0))


def holds_any_lease():
    now = _lease_now()
    return any(not rec.get('released') and now < (rec.get('expires') or 0)
               for cid, rec in (fed._lease_state().get('my_leases') or {}).items()
               if cid != MEMBERS_LOCK)


def promised_to(cluster_id, candidate):
    """Whether this voter holds a live promise for `cluster_id` naming `candidate`."""
    rec = (fed._lease_state().get('promises') or {}).get(cluster_id)
    return bool(rec and rec.get('candidate') == candidate and _promise_live(rec, _lease_now()))


def backed_candidates():
    """{cluster id: candidate} of every promise this voter holds, live or dead: whom it
    backed last for each cluster."""
    return {cid: rec.get('candidate') for cid, rec in
            (fed._lease_state().get('promises') or {}).items() if rec.get('candidate')}


def _promise_live(rec, now):
    until = rec.get('until') or 0
    return until > 0 and now <= until + LEASE_SKEW


def _valid_mark(value):
    """The round mark of a batch of asks, None for none or anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) and 0 < value < 1e11 else None


def _mark_of(rec):
    value = (rec or {}).get('round')
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _round_mark(st):
    """The mark of the next round of this instance: the wall clock, and never less than
    the last one plus a little. Taken under fed._lock with the snapshot of the leases, so
    a round that started before a release carries a smaller mark than any round after
    it. The last mark is kept in the lease state `st` and saved with it, so a restart
    after the wall clock stepped back goes on from it, and the voters do not refuse its
    rounds as stale. The wall clock lets the next host of the HA group go on from about
    where this one left off."""
    last = max(float(fed._runtime.get('round_mark') or 0.0), float(st.get('round_mark') or 0.0))
    mark = max(time.time(), last + 1e-6)
    fed._runtime['round_mark'] = st['round_mark'] = mark
    return mark


# --- the vote ------------------------------------------------------------------------------

def _valid_ask(ask):
    if not isinstance(ask, dict):
        return None
    cid = ask.get('cluster_id')
    if not isinstance(cid, str) or not (cid == MEMBERS_LOCK or CLUSTER_ID_RE.fullmatch(cid)):
        return None
    adopt = ask.get('adopt', False)
    if not isinstance(adopt, bool):
        return None
    return {'cluster_id': cid, 'adopt': adopt}


def _valid_release(item):
    """(cluster id, pid) of one release, None for anything else: a release names the
    promise it gives back."""
    if not isinstance(item, dict):
        return None
    cid, pid = item.get('cluster_id'), item.get('pid')
    if not isinstance(cid, str) or not (cid == MEMBERS_LOCK or CLUSTER_ID_RE.fullmatch(cid)):
        return None
    if not isinstance(pid, str) or not PID_RE.fullmatch(pid):
        return None
    return cid, pid


def _end_promises(promises, sender, rels):
    """End the promises `rels` names, where each still is the one given to `sender` under
    that pid. Returns the cluster ids ended."""
    out = []
    for cid, pid in rels:
        rec = promises.get(cid)
        if (rec and rec.get('candidate') == sender and not rec.get('released')
                and rec.get('pid') == pid):
            rec['until'] = 0
            rec['released'] = True
            out.append(cid)
    return out


def _evict_dead(promises, now, owners):
    """Keep the table at MAX_PROMISES: dead promises go, oldest first, those of ids this
    voter holds no row of before the others (for a row, the last candidate is what the
    owner-follow rule of the mirrors reads). A live promise is never evicted, and the
    live bounds keep the live ones under MAX_PROMISES."""
    over = len(promises) - MAX_PROMISES
    if over <= 0:
        return False
    dead = [(cid in owners, float(r.get('until') or 0), cid) for cid, r in promises.items()
            if not _promise_live(r, now)]
    dead.sort()
    for _row, _until, cid in dead[:over]:
        del promises[cid]
    return bool(dead)


def cast_votes(sender, body):
    """A voter's answer to one batch of asks and releases from `sender`: (http status,
    answer). One implementation, the peer route and the self vote both. Every promise is
    on disk before the answer is returned.

    Per ask: refused 'hold' while this voter holds after a clock change, 'held' while a
    live promise names another candidate, 'owner' when this voter's row of the cluster
    names another owner and the ask is no adoption (or, with the row gone, the member its
    record of the dropped row names), 'cluster' for an adoption of a cluster it holds no
    row of, 'settling' for any cluster ask in the settle span after a view change, 'stale'
    for a renewal from a round older than the one the promise answered, 'busy' for a
    members lock held or asked past its bound, 'full' at the bounds; granted
    otherwise, with the promise's pid, the owner this voter's row names (for the members
    lock a signed grant). Batch refusals: 400 'body', 409 'candidate', 'member' or 'view'."""
    if not isinstance(body, dict):
        return 400, {'reason': 'body'}
    if body.get('candidate') != sender:
        return 409, {'reason': 'candidate'}
    raw_asks, raw_rel = body.get('asks', []), body.get('releases', [])
    raw_unen = body.get('unenroll', [])
    if (not isinstance(raw_asks, list) or not isinstance(raw_rel, list)
            or not isinstance(raw_unen, list)
            or len(raw_asks) > MAX_ASKS_PER_CALL or len(raw_rel) > MAX_ASKS_PER_CALL
            or len(raw_unen) > MAX_ASKS_PER_CALL):
        return 400, {'reason': 'body'}
    asks = [_valid_ask(a) for a in raw_asks]
    rels = [_valid_release(r) for r in raw_rel]
    if any(a is None for a in asks) or any(r is None for r in rels) or not all(
            isinstance(c, str) and CLUSTER_ID_RE.fullmatch(c) for c in raw_unen):
        return 400, {'reason': 'body'}
    mark = _valid_mark(body.get('round'))
    me = fed.instance_id()
    if not me or (sender != me and sender not in fed.members()):
        return 409, {'reason': 'member'}
    digest, epoch = fed.view_digest(), fed.view_epoch()
    if asks and body.get('view') != digest:
        # releases need no agreed view: they only ever end the sender's own promise
        answer = {'reason': 'view', 'view': digest, 'epoch': epoch,
                  'released': _release_promises(sender, rels)}
        return 409, answer
    votes, pids, cert = {}, {}, None
    # the rows, the dropped records, an unenroll and the votes under one lock: an
    # unenroll confirmed here and an adoption granted here never pass each other
    with fed._lock:
        try:
            owners = _owner_map() if (asks or raw_unen) else {}
            dropped = fed.dropped_records() if asks else {}
            st = fed._lease_state()
            changed = check_clock(st)
            now = _lease_now()
            promises = st['promises']
            unenrolled = []
            if raw_unen:
                unenrolled = _take_unenroll(sender, raw_unen, owners, promises, now,
                                            holding=float(st.get('hold_until') or 0) > now)
                if asks and unenrolled:
                    owners = _owner_map()
        except FederationError as e:
            logging.warning(f'[FED] a lease vote could not read the cluster owners: {e}')
            return 503, {'reason': 'unavailable'}
        released = _end_promises(promises, sender, rels)
        changed = changed or bool(released)
        hold_until = float(st.get('hold_until') or 0)
        settling = settle_left(st)
        live = [r for r in promises.values() if _promise_live(r, now)]
        total = len(live)
        per = Counter(r.get('candidate') for r in live)
        for ask in asks:
            cid = ask['cluster_id']
            if hold_until > now:
                votes[cid] = {'granted': False, 'reason': 'hold',
                              'retry_after': int(math.ceil(hold_until - now))}
                continue
            rec = promises.get(cid)
            alive = bool(rec) and _promise_live(rec, now)
            renewal = alive and rec.get('candidate') == sender
            if alive and not renewal:
                votes[cid] = {'granted': False, 'reason': 'held',
                              'holder': rec.get('candidate') or '',
                              'owner': owners.get(cid) or '',
                              'retry_after': int(math.ceil(rec['until'] + LEASE_SKEW - now))}
                continue
            if renewal and mark is not None and mark < _mark_of(rec):
                # an older round of the sender, delayed on its way: the promise answers a
                # newer one, whose pid backs a lease, and stays as it is
                votes[cid] = {'granted': False, 'reason': 'stale'}
                continue
            owner = owners.get(cid)
            if not (owner in (None, sender) or ask['adopt']):
                votes[cid] = {'granted': False, 'reason': 'owner', 'owner': owner}
                continue
            if owner is None and not ask['adopt'] and cid != MEMBERS_LOCK:
                gone = dropped.get(cid)
                if gone and gone != sender:
                    votes[cid] = {'granted': False, 'reason': 'owner', 'owner': gone}
                    continue
            if ask['adopt'] and cid != MEMBERS_LOCK and owner is None:
                # an adoption takes a cluster over that this voter knows as some member's:
                # one that holds no row of it backs nobody's adoption (an owner that
                # unenrolled the cluster had the rows dropped for exactly that)
                votes[cid] = {'granted': False, 'reason': 'cluster', 'owner': ''}
                continue
            if cid != MEMBERS_LOCK and settling > 0:
                # every cluster ask, a renewal and the owner's own included: a lease
                # counted under the view two changes back may still run, and a majority
                # of this view need not share a voter with it
                votes[cid] = {'granted': False, 'reason': 'settling',
                              'retry_after': int(math.ceil(settling))}
                continue
            if cid == MEMBERS_LOCK:
                if renewal and now - float(rec.get('first') or now) >= MEMBERS_LOCK_MAX:
                    rec['cool_until'] = float(rec['until']) + LEASE_SKEW + MEMBERS_LOCK_COOL
                    changed = True
                    votes[cid] = {'granted': False, 'reason': 'busy',
                                  'retry_after': int(math.ceil(rec['cool_until'] - now))}
                    continue
                if (not alive and rec and rec.get('candidate') == sender
                        and now < float(rec.get('cool_until') or 0)):
                    votes[cid] = {'granted': False, 'reason': 'busy',
                                  'retry_after': int(math.ceil(rec['cool_until'] - now))}
                    continue
            if not alive:
                if total >= MAX_PROMISES or per[sender] >= MAX_PROMISES_PER_CANDIDATE:
                    votes[cid] = {'granted': False, 'reason': 'full'}
                    continue
                total += 1
                per[sender] += 1
            new = {'candidate': sender, 'until': now + LEASE_SECONDS, 'released': False,
                   'pid': secrets.token_hex(8),
                   'round': mark if mark is not None else (_mark_of(rec) if renewal else 0.0)}
            if cid == MEMBERS_LOCK:
                new['first'] = float(rec.get('first') or now) if renewal else now
                cert = fed.lock_cert(sender, digest, epoch)
            promises[cid] = new
            votes[cid] = {'granted': True, 'owner': owners.get(cid) or ''}
            pids[cid] = new['pid']
            changed = True
        if len(promises) > MAX_PROMISES:
            changed = _evict_dead(promises, now, owners) or changed
        if changed:
            fed._save_leases(st)
    out = {'view': digest, 'epoch': epoch, 'votes': votes, 'released': released}
    if pids:
        out['pids'] = pids
    if cert:
        out['lock_cert'] = cert
    if raw_unen:
        out['unenrolled'] = unenrolled
    return 200, out


def _take_unenroll(sender, cids, owners, promises, now, holding=False):
    """The owner of a cluster takes it out of the federation: this voter drops its mirror
    of it (only where its row follows that owner) and keeps a record that the id was the
    sender's, so neither an adoption from here nor another candidate's ask gets backed once
    the owner treats it as its own again. The record is written only where this voter's
    own state shows the sender led the id - its row named the sender, or the last promise
    it gave for the id did. An id it knows nothing of is acknowledged without one: a
    member's word alone never makes the voters refuse another member's ask. Returns the
    ids this voter holds no mirror of. The promise behind the owner's lease ends with its
    release, by pid.

    Called under fed._lock with the promise table (cast_votes). An id this voter backs
    another member for right now (a live promise, an adoption under way) is neither
    dropped nor confirmed: the sender would treat the cluster as its own beside the
    lease that promise counts for. Nothing is confirmed while the voter holds after a
    clock change either: it may have forgotten such a promise."""
    out, noted = [], []
    if holding:
        return out
    conn = fed._db().conn
    dropped = False
    for cid in cids:
        owner = owners.get(cid)
        if owner not in (None, sender):
            continue
        p = promises.get(cid)
        if p and p.get('candidate') != sender and _promise_live(p, now):
            continue
        if owner == sender:
            conn.execute('DELETE FROM clusters WHERE id = ? AND fed_owner = ?', (cid, sender))
            dropped = True
            noted.append(cid)
        elif (p or {}).get('candidate') == sender:
            noted.append(cid)
        out.append(cid)
    if dropped:
        conn.commit()
        drop_owner_cache()
    fed.note_dropped((cid, sender) for cid in noted)
    return out


def _release_promises(sender, rels):
    if not rels:
        return []
    out = []

    def go(st):
        out.extend(_end_promises(st['promises'], sender, rels))
        return bool(out)
    fed._mutate_leases(go)
    return out


# --- the round -------------------------------------------------------------------------------

def _wanted(owners, mine, me, only, adopt, handed=frozenset()):
    """The ids a round asks for. A cluster handed over is not asked for, whether the lease
    file says so or the identity row does (`handed`); only an explicit `only` (an enroll)
    takes it back."""
    if owners is not None:
        wanted = {cid for cid, owner in owners.items() if owner == me}
        wanted |= {cid for cid, rec in mine.items()
                   if not rec.get('released') and owners.get(cid) == me}
    else:
        wanted = {cid for cid, rec in mine.items()
                  if not rec.get('released') and cid != MEMBERS_LOCK}
    wanted -= {cid for cid, rec in mine.items() if rec.get('released')}
    wanted -= set(handed)
    wanted |= set(adopt)
    if only is not None:
        only = set(only)
        allowed = wanted | set(adopt) | {MEMBERS_LOCK}
        if owners is not None:
            allowed |= {cid for cid, owner in owners.items() if owner == me}
        wanted = only & allowed
    return wanted


def _rseq(rec):
    return int((rec or {}).get('rseq') or 0)


def lease_round(only=None, adopt=frozenset(), no_convert=frozenset(), tick=False):
    """One round of asks for every lease this instance wants, every member asked side by
    side, one call each. Returns {cluster id: {'held', 'votes', 'needed', 'lost_to',
    'refusals', 'holders'}}. Never raises for one broken cluster: an owner table that
    cannot be read renews what the lease file holds and nothing else.

    A lease is written only when its entry is still the one the round started from: a
    release (or a forget) that came in while the asks were out wins, and the promises the
    round got are given back. `no_convert`: ids whose 'lost_to' evidence must not turn the
    row into a mirror (a fresh enroll of an id another member leads is only refused).
    `tick`: the background round, which the voters count apart from the rounds an admin
    starts, so a burst of those never starves the renewals.

    A cluster adopted here is asked for with the adoption flag (adopted_from in the
    identity row) until a majority of the grants come from voters whose rows name this
    instance. With the flag no voter refuses for its row naming the old owner, so only
    live promises of another member (a real leader) count as 'lost_to' evidence."""
    me = fed.instance_id()
    if not me:
        return {}
    adopt = set(adopt or ())
    no_convert = set(no_convert or ())
    with fed._lock:
        st = fed._lease_state()
        if check_clock(st):
            fed._save_leases(st)
        mine = {cid: dict(rec) for cid, rec in st['my_leases'].items()}
        mark = _round_mark(st)
    try:
        owners = _owner_map()
    except FederationError as e:
        fed._say_once('round-owners', f'[FED] a lease round could not read the cluster '
                                      f'owners and renews only what it holds: {e}')
        owners = None
    marked = fed.adopted_from()
    wanted = _wanted(owners, mine, me, only, adopt, fed.handed_over_ids())
    ids = fed.view_ids()
    if len(ids) < 2:
        # a view of one holds no cluster lease: a removed or departed instance must not
        # lease its old clusters to itself while the federation may have adopted them
        wanted &= {MEMBERS_LOCK}
    if not wanted:
        return {}
    order = sorted(wanted)
    asks = [{'cluster_id': cid,
             'adopt': cid in adopt or cid in marked
             or bool((mine.get(cid) or {}).get('adopted'))}
            for cid in order]
    chunks = [asks[i:i + MAX_ASKS_PER_CALL] for i in range(0, len(asks), MAX_ASKS_PER_CALL)]
    digest, epoch = fed.view_digest(), fed.view_epoch()

    def body(chunk):
        out = {'candidate': me, 'view': digest, 'epoch': epoch, 'asks': chunk,
               'releases': [], 'round': mark}
        if tick:
            out['tick'] = True
        return out
    round_start = _lease_now()
    peers = sorted(fed.members())
    voters = [me] + peers
    answers = [[cast_votes(me, body(c)) for c in chunks]]
    got = fed._parallel(lambda iid: [fed.call_peer(iid, 'POST', LEASE_PATH, body(c),
                                                   read_timeout=VOTE_TIMEOUT)[:2]
                                     for c in chunks], peers, max_workers=len(peers) or 1)
    answers += [a or [] for a in got]
    grants, refusals, owner_says, holders = Counter(), {}, {}, {}
    # grants from voters whose own row names this instance as the owner
    rows_mine = Counter()
    new_pids, certs = {}, {}
    behind = False
    for voter_id, voter in zip(voters, answers):
        for status, data in voter:
            if status == 200 and isinstance(data, dict) and data.get('view') == digest:
                pids_in = data.get('pids') if isinstance(data.get('pids'), dict) else {}
                for cid, v in (data.get('votes') or {}).items():
                    if cid not in wanted or not isinstance(v, dict):
                        continue
                    if v.get('granted') is True:
                        grants[cid] += 1
                        if v.get('owner') == me:
                            rows_mine[cid] += 1
                        pid = pids_in.get(cid)
                        if isinstance(pid, str) and PID_RE.fullmatch(pid):
                            new_pids.setdefault(cid, {})[voter_id] = pid
                        if cid == MEMBERS_LOCK and isinstance(data.get('lock_cert'), str):
                            certs[voter_id] = data['lock_cert'][:200]
                        continue
                    reason = v.get('reason') if isinstance(v.get('reason'), str) else 'other'
                    refusals.setdefault(cid, Counter())[reason] += 1
                    # the voter's own row of the cluster names its owner, whether the
                    # refusal is for that or for a live promise: a majority of rows naming
                    # another member is the evidence that member's adoption committed
                    if reason in ('owner', 'held') and isinstance(v.get('owner'), str) \
                            and v['owner']:
                        owner_says.setdefault(cid, Counter())[v['owner']] += 1
                    if reason == 'held' and isinstance(v.get('holder'), str):
                        holders.setdefault(cid, Counter())[v['holder']] += 1
            else:
                if (status == 409 and isinstance(data, dict) and data.get('reason') == 'view'
                        and isinstance(data.get('epoch'), int) and data['epoch'] > epoch):
                    behind = True
                reason = 'view' if (isinstance(data, dict) and data.get('reason') == 'view') \
                    else 'down'
                for cid in order:
                    refusals.setdefault(cid, Counter())[reason] += 1
    need = fed.needed(len(ids))
    view = set(fed.members())
    results, lost, stale = {}, [], []
    settled = [cid for cid in order if cid in marked and rows_mine[cid] >= need]
    with fed._lock:
        st = fed._lease_state()
        held = st['my_leases']
        now = _lease_now()
        for cid in order:
            before = mine.get(cid)
            cur = held.get(cid)
            g = grants[cid]
            reasons = dict(refusals.get(cid) or {})
            if (before is not None and cur is None) or _rseq(cur) != _rseq(before):
                # released or forgotten while the asks were out: no lease from this round
                if new_pids.get(cid):
                    stale.append((cid, new_pids[cid]))
                results[cid] = {'held': False, 'votes': g, 'needed': need, 'lost_to': '',
                                'refusals': reasons, 'holders': {}, 'released': True}
                continue
            rec = cur or {}
            pids = dict(rec.get('pids') or {})
            pids.update(new_pids.get(cid) or {})
            if g >= need:
                was_live = bool(rec) and not rec.get('released') and now < (rec.get('expires') or 0)
                held[cid] = {'expires': round_start + LEASE_SECONDS - LEASE_WRITE_MARGIN,
                             'since': rec.get('since') if was_live else round_start,
                             'votes': g, 'needed': need, 'released': False,
                             'adopted': bool(rec.get('adopted')) or cid in adopt,
                             'lost_to': '', 'refusals': reasons, 'pids': pids,
                             'rseq': _rseq(rec)}
                if cid == MEMBERS_LOCK:
                    held[cid]['certs'] = certs
                if not was_live and cid != MEMBERS_LOCK:
                    logging.info(f'[FED] lease on {cid} held ({g}/{need} votes)')
                results[cid] = {'held': True, 'votes': g, 'needed': need, 'lost_to': '',
                                'refusals': reasons, 'holders': {}}
                continue
            lost_to = ''
            for owner, n in (owner_says.get(cid) or {}).items():
                if n >= need and owner in view and owner != me:
                    lost_to = owner
            if rec or cid in mine or pids:
                new = dict(rec, votes=g, needed=need, refusals=reasons, pids=pids)
                new.setdefault('expires', 0)
                if lost_to and not rec.get('lost_to') and cid not in no_convert:
                    logging.warning(f'[FED] cluster {cid} is led by {lost_to} as a majority '
                                    'of the federation says')
                if cid not in no_convert:
                    new['lost_to'] = lost_to or rec.get('lost_to') or ''
                if rec.get('since') and now >= (rec.get('expires') or 0):
                    # `since` marks a lease that was held: said once when it is gone
                    if cid != MEMBERS_LOCK:
                        logging.warning(f'[FED] lease on {cid} lost ({g}/{need} votes)')
                    new['since'] = 0
                held[cid] = new
            if lost_to and cid != MEMBERS_LOCK and cid not in no_convert:
                lost.append((cid, lost_to))
            results[cid] = {'held': False, 'votes': g, 'needed': need, 'lost_to': lost_to,
                            'refusals': reasons,
                            'holders': dict(holders.get(cid) or {})}
        fed._save_leases(st)
    if settled:
        # the voters' rows name this instance now: the asks go without the flag again
        fed._mark_clusters('adopted', drop=settled)
    for cid, pids in stale:
        _send_releases(cid, pids)
    for cid, owner in lost:
        _convert_lost(cid, owner)
    if behind:
        try:
            fed.catch_up()
        except Exception as e:
            logging.warning(f'[FED] catching up with the federation failed: {e}')
    return results


def _send_releases(cluster_id, pids, to=None, old=None):
    """Give back the promises `pids` ({voter: pid}) names, each voter told in parallel
    about its own. This instance's own promise ends here, by its pid."""
    _send_releases_many({cluster_id: dict(pids or {})}, to=to, old=old)


def _send_releases_many(items, to=None, old=None):
    """_send_releases for several clusters at once ({cluster id: {voter: pid}}): each
    voter hears of all of its own in one call (up to MAX_ASKS_PER_CALL per call)."""
    me = fed.instance_id()
    items = {cid: dict(pids or {}) for cid, pids in items.items()}
    own = [(cid, pids.pop(me)) for cid, pids in items.items() if pids.get(me)]
    if own:
        def go(st):
            return bool(_end_promises(st['promises'], me, own))
        fed._mutate_leases(go)
    old = old if old is not None else fed.members()
    targets = sorted(old) if to is None else [t for t in to if t != me]
    per = {}
    for t in targets:
        rels = [{'cluster_id': cid, 'pid': pids[t]} for cid, pids in sorted(items.items())
                if pids.get(t)]
        if rels:
            per[t] = rels
    if not per:
        return
    view, epoch = fed.view_digest(), fed.view_epoch()

    def tell(iid):
        rec = old.get(iid)
        rels = per[iid]
        for i in range(0, len(rels), MAX_ASKS_PER_CALL):
            body = {'candidate': me, 'view': view, 'epoch': epoch, 'asks': [],
                    'releases': rels[i:i + MAX_ASKS_PER_CALL]}
            if rec is None:
                fed.call_peer(iid, 'POST', LEASE_PATH, body, read_timeout=VOTE_TIMEOUT)
            else:
                fed._call(iid, rec, 'POST', LEASE_PATH, body, read_timeout=VOTE_TIMEOUT)
    fed._parallel(tell, sorted(per))


def release(cluster_id, to=None, hand_over=True):
    """Give the lease on `cluster_id` up: the entry here closes and stays released (a round
    in flight writes no lease over it), this voter's own promise ends, and every member
    that granted one hears it in one parallel batch, by the pid it gave. The row keeps
    this instance as its owner of record; taking it back is an enroll.

    `hand_over` (the admin's Hand over, and every caller that leaves the row led here)
    also marks the cluster in the identity row, which the HA sync carries: no host of
    this HA group leases it again until it is enrolled again.

    What is still under way on the cluster from here (node commands, SSH clients) is
    stopped before the voters hear of it: once they do, another site may adopt it at
    once."""
    _release_many([cluster_id], to=to, hand_over=hand_over, cut=True)
    return True


def _cut(cluster_ids):
    """Stop what this instance still has under way on `cluster_ids` (ha_transport)."""
    from pegaprox.core import ha_transport
    for cid in cluster_ids:
        if cid != MEMBERS_LOCK:
            ha_transport.cut_cluster(cid)


def _release_many(cluster_ids, to=None, hand_over=False, cut=False):
    me = fed.instance_id()
    ours = set()
    for cid in cluster_ids:
        if cid == MEMBERS_LOCK:
            continue
        try:
            # a row led here with no entry yet (an enroll whose first round is still out)
            # gets a released one, which that round finds; a row that is gone gets none
            if cluster_owner(cid) == me:
                ours.add(cid)
        except FederationError:
            pass
    if hand_over and ours:
        # before the lease file: a host that dies in between still knows
        fed._mark_clusters('handed_over', add={cid: {} for cid in ours})
    taken = {}

    def go(st):
        for cid in cluster_ids:
            rec = st['my_leases'].get(cid)
            if rec is None and cid in ours:
                rec = st['my_leases'][cid] = {'expires': 0}
            if rec is not None:
                taken[cid] = dict(rec.get('pids') or {})
                taken[cid].pop(me, None)
                rec['released'] = True
                rec['expires'] = 0
                rec['rseq'] = _rseq(rec) + 1
            p = st['promises'].get(cid)
            if p and p.get('candidate') == me:
                p['until'] = 0
                p['released'] = True
        return True
    fed._mutate_leases(go)
    if cut:
        _cut(cluster_ids)
    _send_releases_many(taken, to=to)


def lock_certs():
    """{voter: signed grant} of the members lock this instance holds now."""
    rec = (fed._lease_state().get('my_leases') or {}).get(MEMBERS_LOCK) or {}
    return dict(rec.get('certs') or {})


def release_lock(to=None):
    """The members lock after a view change, or after a lock round that failed: given
    back, and its entry here forgotten."""
    release(MEMBERS_LOCK, to=to, hand_over=False)

    def go(st):
        return st['my_leases'].pop(MEMBERS_LOCK, None) is not None
    fed._mutate_leases(go)


def forget_cluster(cluster_id):
    """A cluster row that was deleted here: its lease is given back and forgotten."""
    release(cluster_id, hand_over=False)

    def go(st):
        return st['my_leases'].pop(cluster_id, None) is not None
    fed._mutate_leases(go)
    _unmark(cluster_id)
    drop_owner_cache()


def _unmark(*cluster_ids):
    """The row is no longer led here (or led here again by an enroll): neither the hand-over
    nor the adoption mark stands for it."""
    for key in ('handed_over', 'adopted'):
        fed._mark_clusters(key, drop=cluster_ids)


# --- ownership: enroll, unenroll, adopt, and losing a cluster ---------------------------------

def _set_owner(cluster_id, owner, expect=None):
    try:
        conn = fed._db().conn
        if expect is None:
            cur = conn.execute('UPDATE clusters SET fed_owner = ? WHERE id = ?',
                               (owner, cluster_id))
        else:
            cur = conn.execute('UPDATE clusters SET fed_owner = ? WHERE id = ? AND '
                               'fed_owner = ?', (owner, cluster_id, expect))
        conn.commit()
    except Exception as e:
        raise FederationError(f'The owner of cluster {cluster_id} could not be set: {e}')
    finally:
        drop_owner_cache()
    return cur.rowcount


def _site(iid):
    return (fed.member_record(iid) or {}).get('site') or (iid or '')[:8]


def _refusal_sentence(r):
    votes, need = r.get('votes', 0), r.get('needed', 0)
    text = f'The federation did not back the lease ({votes}/{need} votes)'
    holders = r.get('holders') or {}
    reasons = r.get('refusals') or {}
    if holders:
        text += f' - held by {_site(max(holders, key=holders.get))}'
    elif reasons.get('owner'):
        text += ' - the id is enrolled by another site: cluster ids must be unique in the federation'
    elif reasons.get('hold'):
        text += ' - a site just restarted its host and votes again in a few seconds'
    elif reasons.get('settling'):
        text += (' - the sites changed members a moment ago, and every lease waits until '
                 'each lease counted before that change has run out; try again in '
                 f'{SETTLE_SECONDS} s')
    elif reasons.get('busy'):
        text += ' - another change of the federation is under way; try again in a minute'
    elif reasons.get('view'):
        text += ' - the sites do not agree on the member list yet; try again after a sync'
    return text


def _lease_summary(cluster_id):
    rec = (fed._lease_state().get('my_leases') or {}).get(cluster_id) or {}
    now = _lease_now()
    return {'cluster_id': cluster_id,
            'held': bool(not rec.get('released') and now < (rec.get('expires') or 0)),
            'remaining_s': max(0, int((rec.get('expires') or 0) - now)),
            'votes': rec.get('votes', 0), 'needed': rec.get('needed', 0),
            'adopted': bool(rec.get('adopted'))}


def _cluster_row(cluster_id):
    try:
        return fed._db().conn.execute(
            'SELECT fed_owner, cluster_type FROM clusters WHERE id = ?',
            (cluster_id,)).fetchone()
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')


def enroll_cluster(cluster_id):
    """Put a local Proxmox VE cluster under the federation's rule: this instance becomes
    its writer with a majority behind it. Without a majority the row is as it was."""
    if not isinstance(cluster_id, str) or not CLUSTER_ID_RE.fullmatch(cluster_id):
        raise FederationError('That cluster id cannot be enrolled', code='FED_BAD_ID')
    if len(fed.view_ids()) < MIN_SITES_TO_ENROLL:
        raise FederationError('A lease with two sites needs both, so any outage of one '
                              'locks the other: enroll clusters once three or more sites '
                              'are paired', code='FED_TOO_FEW_SITES')
    row = _cluster_row(cluster_id)
    if row is None:
        raise FederationError('No such cluster here', code='FED_NOT_FOUND')
    if (row['cluster_type'] or 'proxmox') != 'proxmox':
        raise FederationError('Only Proxmox VE clusters can be enrolled: their writes are '
                              'the ones the federation fences', code='FED_TYPE')
    me = fed.instance_id()
    owner = row['fed_owner'] or ''
    if owner and owner != me:
        raise FederationError('That cluster belongs to another member', code='FED_FOREIGN',
                              home=owner)
    _set_owner(cluster_id, me)
    # a local row that another member leads under the same id is refused, never handed
    # over: the 'lost_to' evidence converts only a row this instance led before
    fresh = {cluster_id} if not owner else set()
    r = lease_round(only={cluster_id}, no_convert=fresh).get(cluster_id) or {}
    if r.get('held'):
        # enrolled again: a hand-over is taken back
        fed._mark_clusters('handed_over', drop=[cluster_id])
        return _lease_summary(cluster_id)
    try:
        # only where the row is still this instance's: a row that became a mirror stays one
        _set_owner(cluster_id, owner, expect=me)
    except FederationError as e:
        # the row left owned holds the gate shut: an owner without a lease writes nothing
        logging.warning(f'[FED] enroll of {cluster_id} could not roll the owner back: {e}')
    if not owner:
        release(cluster_id, hand_over=False)

        def go(st):
            return st['my_leases'].pop(cluster_id, None) is not None
        fed._mutate_leases(go)
    text = _refusal_sentence(r)
    taken_by = _taken_by(r) if fresh else ''
    if taken_by:
        text = (f'The federation did not back the lease - {_site(taken_by)} leads a cluster '
                f'with this id: cluster ids must be unique in the federation')
    raise FederationError(text, code='FED_NO_QUORUM',
                          votes=r.get('votes', 0), needed=r.get('needed', 0))


def _taken_by(r):
    """The member a majority of refusals names as the leader of the id, '' for none."""
    if r.get('lost_to'):
        return r['lost_to']
    holders = r.get('holders') or {}
    if holders and max(holders.values()) >= (r.get('needed') or 1):
        return max(holders, key=holders.get)
    return ''


def unenroll_cluster(cluster_id, force=False):
    """Take a cluster out of the federation's rule: the lease goes, the row is this
    instance's alone again. Needs this instance's live lease; force is the operator's
    override for a federation that is gone for good."""
    owner = cluster_owner(cluster_id)
    if owner is None:
        raise FederationError('No such cluster here', code='FED_NOT_FOUND')
    me = fed.instance_id()
    if owner != me:
        if owner:
            raise FederationError('That cluster belongs to another member',
                                  code='FED_FOREIGN', home=owner)
        raise FederationError('That cluster is not enrolled', code='FED_NOT_ENROLLED')
    if not force and not holds(cluster_id):
        raise FederationError('Unenroll needs this instance\'s lease on the cluster. If it '
                              'was released, enroll it again first. If the other sites are '
                              'gone for good and none of them adopted it, unenroll with '
                              'force.', code='FED_NO_LEASE')
    if not force:
        # a majority drops its mirror first: until then another site could still adopt
        # the cluster, and two would write it once this instance treats it as its own
        acks, need = _tell_unenroll([cluster_id])
        if acks.get(cluster_id, 0) < need:
            raise FederationError(f'Unenroll needs a majority of the sites to drop their '
                                  f'copy of the cluster: {acks.get(cluster_id, 0)} of {need} '
                                  f'needed confirmed. It stays enrolled; try again when the '
                                  f'sites answer', code='FED_NO_QUORUM',
                                  votes=acks.get(cluster_id, 0), needed=need)
    _finish_unenroll([cluster_id])
    return True


def unenroll_clusters(cluster_ids):
    """Unenroll every cluster of `cluster_ids` this instance holds a live lease on, with
    one unenroll notice and one release per member for all of them (a leave). Returns
    (done, blocked): the ids unenrolled, and the ids that are not (no live lease here, or
    no majority dropped its copy)."""
    me = fed.instance_id()
    ready, blocked = [], []
    for cid in cluster_ids:
        (ready if cluster_owner(cid) == me and holds(cid) else blocked).append(cid)
    if not ready:
        return [], blocked
    acks, need = _tell_unenroll(ready)
    done = [cid for cid in ready if acks.get(cid, 0) >= need]
    blocked += [cid for cid in ready if cid not in done]
    _finish_unenroll(done)
    return done, blocked


def _finish_unenroll(cluster_ids):
    """The rows are this instance's alone again: owners cleared, leases given back in one
    batch, the ids on record as this instance's (its own vote backs no other candidate
    for them either). The owners go first, so the clusters count as this instance's own
    while the releases are out, and the watch of ha_transport stops nothing under way on
    them."""
    if not cluster_ids:
        return
    me = fed.instance_id()
    for cid in cluster_ids:
        _set_owner(cid, '', expect=me)
    _release_many(cluster_ids, hand_over=False)
    fed.note_dropped([(cid, me) for cid in cluster_ids])

    def go(st):
        gone = [cid for cid in cluster_ids if st['my_leases'].pop(cid, None) is not None]
        return bool(gone)
    fed._mutate_leases(go)
    _unmark(*cluster_ids)


def _tell_unenroll(cluster_ids):
    """Every member hears that this instance takes `cluster_ids` out of the federation, in
    one call per member (per MAX_ASKS_PER_CALL ids). Returns ({cluster id: confirmations},
    needed), this instance counted."""
    me = fed.instance_id()
    cluster_ids = list(cluster_ids)
    chunks = [cluster_ids[i:i + MAX_ASKS_PER_CALL]
              for i in range(0, len(cluster_ids), MAX_ASKS_PER_CALL)]
    view, epoch = fed.view_digest(), fed.view_epoch()

    def tell(iid):
        out = set()
        for chunk in chunks:
            body = {'candidate': me, 'view': view, 'epoch': epoch, 'asks': [],
                    'releases': [], 'unenroll': chunk}
            status, data = fed.call_peer(iid, 'POST', LEASE_PATH, body,
                                         read_timeout=VOTE_TIMEOUT)[:2]
            if status == 200 and isinstance(data, dict):
                out |= {c for c in (data.get('unenrolled') or []) if c in chunk}
        return out
    peers = sorted(fed.members())
    acks = Counter({cid: 1 for cid in cluster_ids})
    for got in fed._parallel(tell, peers):
        for cid in got or ():
            acks[cid] += 1
    return dict(acks), fed.needed(len(fed.view_ids()))


def adopt_cluster(cluster_id, force=False):
    """Take over the cluster of a member that is gone for good (or that released it).
    The lease is the fence: the voters grant it only past the old owner's promise. The
    credentials and the owner change in one transaction; any failure gives the lease back
    and leaves the row as it was. Raises FederationError with what stands in the way."""
    if not isinstance(cluster_id, str) or not CLUSTER_ID_RE.fullmatch(cluster_id):
        raise FederationError('That cluster id cannot be adopted', code='FED_BAD_ID')
    row = _cluster_row(cluster_id)
    if row is None:
        raise FederationError('No such cluster here - sync first, the mirror must exist',
                              code='FED_NOT_FOUND')
    owner = row['fed_owner'] or ''
    me = fed.instance_id()
    if not owner:
        raise FederationError('That cluster is this instance\'s own already',
                              code='FED_NOT_ENROLLED')
    if owner == me:
        raise FederationError('That cluster is already led here', code='FED_LED_HERE')
    if owner not in fed.members():
        raise FederationError('Its owner is not in the federation\'s view: adopt the '
                              'clusters of a lost site before you remove it',
                              code='FED_NOT_MEMBER')
    if (row['cluster_type'] or 'proxmox') != 'proxmox':
        raise FederationError('Only Proxmox VE clusters can be adopted', code='FED_TYPE')
    if len(fed.view_ids()) < 2:
        raise FederationError('A federation of one holds no lease', code='FED_TOO_FEW_SITES')
    status, _b, _h = fed.call_peer(owner, 'GET', fed.STATUS_PATH, read_timeout=5)
    p = (fed._lease_state().get('promises') or {}).get(cluster_id) or {}
    released_by_owner = p.get('candidate') == owner and bool(p.get('released'))
    if status == 200 and not released_by_owner:
        raise FederationError('The owner answered and has not released the cluster. '
                              'Release it there, or wait until that site is gone',
                              code='FED_OWNER_ALIVE')
    if fed._peer_key(owner) is None and not force:
        raise FederationError('The field key of the owner is not held here - without it '
                              'the credentials cannot cross over. Adopt with force to take '
                              'the cluster without them', code='FED_NO_KEY')
    r = lease_round(only={cluster_id}, adopt={cluster_id}).get(cluster_id) or {}
    if not r.get('held'):
        _give_back(cluster_id)
        raise FederationError(_refusal_sentence(r) + ' - the owner\'s lease may still '
                              'stand', code='FED_NO_QUORUM', votes=r.get('votes', 0),
                              needed=r.get('needed', 0))
    conn = fed._db().conn
    try:
        fed._begin(conn)
        _reseat_credentials(conn, cluster_id, owner, force)
        cur = conn.execute('UPDATE clusters SET fed_owner = ? WHERE id = ? AND fed_owner = ?',
                           (me, cluster_id, owner))
        if cur.rowcount != 1:
            raise FederationError('The cluster row changed while it was adopted - try again')
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        _give_back(cluster_id)
        if isinstance(e, FederationError):
            raise
        raise FederationError(f'The adoption did not go through and changed nothing: {e}')
    finally:
        drop_owner_cache()
    # in the identity row: whichever host of this HA group asks next, it asks with the
    # adoption flag while the voters' rows still name the old owner
    fed._mark_clusters('adopted', add={cluster_id: {'from': owner}})
    fed._mark_clusters('handed_over', drop=[cluster_id])
    out = _lease_summary(cluster_id)
    out['notes'] = ['node_credentials', 'ha_claim']
    return out


def _give_back(cluster_id):
    release(cluster_id, hand_over=False)

    def go(st):
        return st['my_leases'].pop(cluster_id, None) is not None
    fed._mutate_leases(go)


def _reseat_credentials(conn, cluster_id, owner, force):
    """Open the mirrored credential columns with the owner's federation field key and seal
    them with this instance's database key, inside the caller's transaction. A value
    another reader sealed with the database key around a wrapped one opens too. Anything
    else raises, or clears the column under force."""
    db = fed._db()
    cols = fed.CLUSTER_ENCRYPTED_COLUMNS
    row = conn.execute(f'SELECT {", ".join(cols)} FROM clusters WHERE id = ?',
                       (cluster_id,)).fetchone()
    if row is None:
        raise FederationError('The cluster row is gone')
    updates = {}
    for col in cols:
        value = row[col]
        if not value:
            continue
        try:
            if value.startswith(fed.FIELD_PREFIX):
                plain = fed.unwrap_credential(value, owner, cluster_id, col)
            elif value.startswith(('aes256:', 'gAAAA')):
                plain = db._decrypt(value)
                if plain.startswith(fed.FIELD_PREFIX):
                    plain = fed.unwrap_credential(plain, owner, cluster_id, col)
            else:
                raise FederationError(f'{col} is no credential this instance can open')
            updates[col] = db._encrypt(plain) if plain else ''
        except Exception as e:
            if not force:
                raise FederationError(f'The credentials did not open with the owner\'s '
                                      f'federation key: {e}', code='FED_NO_KEY')
            logging.warning(f'[FED] adoption of {cluster_id} clears {col} (did not open)')
            updates[col] = ''
    if updates:
        conn.execute(f'UPDATE clusters SET {", ".join(f"{c} = ?" for c in updates)} '
                     f'WHERE id = ?', list(updates.values()) + [cluster_id])


def may_convert(cluster_id, home):
    """Whether a row led here may become `home`'s mirror from `home`'s snapshot: this
    instance holds no live lease on it, it released the cluster (its lease file or the
    hand-over mark of the identity row says so) or a majority said `home` leads it, and
    its own promise for the cluster names `home`."""
    st = fed._lease_state()
    rec = (st.get('my_leases') or {}).get(cluster_id) or {}
    if not rec.get('released') and _lease_now() < (rec.get('expires') or 0):
        return False
    released = rec.get('released') or cluster_id in fed.handed_over_ids()
    if not (released or rec.get('lost_to') == home):
        return False
    return ((st.get('promises') or {}).get(cluster_id) or {}).get('candidate') == home


def _convert_lost(cluster_id, owner):
    """A majority of the voters refuses this instance's ask because their rows say `owner`
    leads the cluster: the adoption there committed and travelled. The row here becomes
    a mirror of `owner` with its credentials cleared; `owner`'s next snapshot fills them."""
    me = fed.instance_id()
    cols = fed.CLUSTER_ENCRYPTED_COLUMNS
    try:
        conn = fed._db().conn
        cleared = ', '.join(f"{c} = ''" for c in cols)
        cur = conn.execute(f'UPDATE clusters SET fed_owner = ?, {cleared} '
                           f'WHERE id = ? AND fed_owner = ?', (owner, cluster_id, me))
        conn.commit()
    except Exception as e:
        logging.warning(f'[FED] cluster {cluster_id} could not be handed to {owner}: {e}')
        return False
    drop_owner_cache()
    if not cur.rowcount:
        return False
    note_lost(cluster_id, owner)
    return True


def note_lost(cluster_id, owner):
    """After a row led here became `owner`'s mirror: the lease entry goes, the manager
    stops, and the audit log says it once."""
    def go(st):
        return st['my_leases'].pop(cluster_id, None) is not None
    fed._mutate_leases(go)
    try:
        _unmark(cluster_id)
    except Exception as e:
        logging.warning(f'[FED] the marks of {cluster_id} could not be cleared: {e}')
    drop_owner_cache()
    _cut([cluster_id])
    _stop_manager(cluster_id)
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.cluster_lost',
                  f'cluster {cluster_id} now led by {_site(owner)}', ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the hand-over of {cluster_id} could not be audited: {e}')
    logging.warning(f'[FED] cluster {cluster_id} is now led by {owner} - its manager here '
                    'stopped')


def _stop_manager(cluster_id):
    try:
        from pegaprox import globals as g
        mgr = g.cluster_managers.pop(cluster_id, None)
        if mgr is not None:
            mgr.stop()
    except Exception as e:
        logging.warning(f'[FED] the manager of {cluster_id} did not stop cleanly: {e}')


# --- what the admin page reads -------------------------------------------------------------

def lease_status():
    """The leases this instance holds and the promises it gave, without clock values."""
    st = fed._lease_state()
    now = _lease_now()
    handed, marked = fed.handed_over_ids(), fed.adopted_from()
    out = {'leases': {}, 'promises': {}, 'hold_s': int(math.ceil(hold_left(st)))}
    for cid, rec in (st.get('my_leases') or {}).items():
        if cid == MEMBERS_LOCK:
            continue
        out['leases'][cid] = {
            'held': bool(not rec.get('released') and now < (rec.get('expires') or 0)),
            'remaining_s': max(0, int((rec.get('expires') or 0) - now)),
            'votes': int(rec.get('votes') or 0), 'needed': int(rec.get('needed') or 0),
            'released': bool(rec.get('released')) or cid in handed,
            'adopted': bool(rec.get('adopted')) or cid in marked,
            'lost_to': rec.get('lost_to') or ''}
    for cid, rec in (st.get('promises') or {}).items():
        out['promises'][cid] = {
            'candidate': rec.get('candidate') or '',
            'remaining_s': max(0, int((rec.get('until') or 0) - now))
            if _promise_live(rec, now) else 0,
            'released': bool(rec.get('released'))}
    return out


def renew(cluster_id):
    """One round for one cluster now: {'cluster', 'renewed', 'votes', 'needed', 'lost_to'}.
    A released cluster is not taken back by a renewal (that is an enroll)."""
    rec = (fed._lease_state().get('my_leases') or {}).get(cluster_id) or {}
    if rec.get('released') or cluster_id in fed.handed_over_ids():
        return {'cluster': cluster_id, 'renewed': False, 'votes': 0, 'needed': 0,
                'lost_to': rec.get('lost_to') or '', 'released': True}
    r = lease_round(only={cluster_id}).get(cluster_id) or {}
    return {'cluster': cluster_id, 'renewed': bool(r.get('held')),
            'votes': r.get('votes', 0), 'needed': r.get('needed', 0),
            'lost_to': r.get('lost_to', '')}
