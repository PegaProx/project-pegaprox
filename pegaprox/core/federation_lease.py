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

Two members. One of two is no majority, so a view of two adds a rule. The owner of a
cluster holds its lease on its own vote while the other member gives no signed answer at
all, or answers only 'hold', once that member granted it the cluster under this view
(the 'ok' notes of the ownership records); any other answer of that member stops the
renewal. The other member never adopts on its own: it writes a cluster of the owner only
after a takeover its admin confirmed (take_over_clusters), refused while the owner answers
or was heard lately. Every change of a cluster's owner leaves an ownership record the new
owner signs, with a generation that grows per cluster; records are made and exchanged in
every view size and acted on in a view of two only, where the old owner gives a cluster
up at the first contact that carries a record which beats its own (take_records). The
members lock still needs both. The settle span covers the step to three members as well:
a lease held alone is backed by the holder's own promise, given before it took the change.

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
# a federation of one holds no lease; with two, the owner holds alone while the other site
# gives no answer, and the other site takes a cluster over only by hand
MIN_SITES_TO_ENROLL = 2
# ownership records carried by one lease-vote body
MAX_RECORDS_PER_CALL = 32
KIND_RANK = fed.KIND_RANK
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
    it writes the new epoch; a promotion never does. Kept with the disaster recovery off as
    well: switched on later, its clock then holds no promotion that did not happen."""
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
    members lock held or asked past its bound, 'taken' for the members lock while a
    takeover of a cluster of the sender is not confirmed by it yet, 'full' at the bounds;
    granted otherwise, with the promise's pid, the owner this voter's row names (for the
    members lock a signed grant). Batch refusals: 400 'body', 409 'candidate', 'member' or
    'view', 503 'unavailable'.

    The ownership records in the body are taken first (take_records), before the view and
    the hold are looked at, and 'records_upto' is echoed once they are stored; a body whose
    records cannot be stored gets no vote at all. The answer (200, and 409 'view') carries
    'records': for every id asked, the record held here when it names another owner than
    the sender, and with 'taken' the takeovers the sender has not confirmed."""
    if not isinstance(body, dict):
        return 400, {'reason': 'body'}
    if body.get('candidate') != sender:
        return 409, {'reason': 'candidate'}
    raw_asks, raw_rel = body.get('asks', []), body.get('releases', [])
    raw_unen = body.get('unenroll', [])
    raw_recs, upto = body.get('records', []), body.get('records_upto')
    if (not isinstance(raw_asks, list) or not isinstance(raw_rel, list)
            or not isinstance(raw_unen, list) or not isinstance(raw_recs, list)
            or len(raw_asks) > MAX_ASKS_PER_CALL or len(raw_rel) > MAX_ASKS_PER_CALL
            or len(raw_unen) > MAX_ASKS_PER_CALL or len(raw_recs) > MAX_RECORDS_PER_CALL):
        return 400, {'reason': 'body'}
    if not all(isinstance(r, dict) for r in raw_recs) or (
            upto is not None and (isinstance(upto, bool) or not isinstance(upto, int)
                                  or upto < 0)):
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
    extra, taken, left_out = {}, [], False
    # the switch of the disaster recovery and what it governs under the lock the switch takes
    # (set_dr_enabled): records are taken in only while it is on, and with it off the
    # members lock alone is voted on. Records a sender still carries from before are left
    # out then rather than refusing its members lock: they wait for the recovery to be on
    with fed._lock:
        if not fed.dr_enabled():
            if any(a['cluster_id'] != MEMBERS_LOCK for a in asks) or \
                    any(cid != MEMBERS_LOCK for cid, _pid in rels) or \
                    ((raw_recs or raw_unen) and not asks):
                return 409, {'reason': 'dr_off'}
            left_out = bool(raw_recs or raw_unen)
            raw_recs, raw_unen = [], []
        if sender != me and raw_recs:
            try:
                if not take_records(sender, raw_recs)['echo']:
                    return 503, {'reason': 'unavailable'}
            except FederationError as e:
                logging.warning(f'[FED] a lease vote could not read the ownership records: {e}')
                return 503, {'reason': 'unavailable'}
    if sender != me:
        try:
            if upto is not None and not left_out:
                # taken in up to there; records left out are not confirmed, the sender keeps them
                extra['records_upto'] = upto
            cids = [a['cluster_id'] for a in asks]
            given = _answer_records(sender, cids)
            if MEMBERS_LOCK in cids:
                taken = _unechoed_takeovers(sender)
                given += [r for r in taken if r['cluster_id'] not in
                          {g['cluster_id'] for g in given}]
        except FederationError as e:
            logging.warning(f'[FED] a lease vote could not read the ownership records: {e}')
            return 503, {'reason': 'unavailable'}
        if given:
            extra['records'] = given
    digest, epoch = fed.view_digest(), fed.view_epoch()
    if asks and body.get('view') != digest:
        # releases need no agreed view: they only ever end the sender's own promise
        answer = {'reason': 'view', 'view': digest, 'epoch': epoch,
                  'released': _release_promises(sender, rels)}
        answer.update(extra)
        return 409, answer
    votes, pids, cert = {}, {}, None
    # the rows, the dropped records, an unenroll and the votes under one lock: an
    # unenroll confirmed here and an adoption granted here never pass each other
    with fed._lock:
        if not fed.dr_enabled() and (raw_unen or any(a['cluster_id'] != MEMBERS_LOCK
                                                     for a in asks)):
            # switched off since the look above: no promise on a cluster outlives it
            return 409, {'reason': 'dr_off'}
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
            if cid == MEMBERS_LOCK and taken:
                # no change of the members while the sender may still write a cluster this
                # voter took over: the records ride on this answer, the echo of its next
                # round confirms them
                votes[cid] = {'granted': False, 'reason': 'taken',
                              'retry_after': LEASE_RENEW_AFTER}
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
    out.update(extra)
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


def lease_round(only=None, adopt=frozenset(), no_convert=frozenset(), tick=False,
                both=frozenset(), takeover=frozenset()):
    """One round of asks for every lease this instance wants, every member asked side by
    side, one call each. Returns {cluster id: {'held', 'votes', 'needed', 'lost_to',
    'refusals', 'holders', 'alone'}}, in a view of two with 'peer' as well (what the other
    member answered for the id, _peer_states). Never raises for one broken cluster: an
    owner table that cannot be read renews what the lease file holds and nothing else.

    A lease is written only when its entry is still the one the round started from: a
    release (or a forget) that came in while the asks were out wins, and the promises the
    round got are given back. `no_convert`: ids whose 'lost_to' evidence must not turn the
    row into a mirror (a fresh enroll of an id another member leads is only refused).
    `tick`: the background round, which the voters count apart from the rounds an admin
    starts, so a burst of those never starves the renewals.

    A cluster adopted here is asked for with the adoption flag (adopted_from in the
    identity row) until a majority of the grants come from voters whose rows name this
    instance. With the flag no voter refuses for its row naming the old owner, so only
    live promises of another member (a real leader) count as 'lost_to' evidence.

    In a view of two a lease is held on this instance's own vote as well ('alone'): while
    the other member is silent or in its hold, for a cluster led here that it granted
    under this view and generation (the 'ok' notes). `both`: ids that need the other
    member's grant all the same (an enroll). `takeover`: ids an admin takes over by hand,
    held alone only when the other member gave no signed answer at all ('owner_answered').
    The ownership records go out with the first call to each member (the rest, past one
    batch, right after the round to a member that echoed it) and come back in the answers:
    an id this round gave up to a record (take_records) gets no lease, and a round of two
    whose view moved while the asks were out writes none."""
    me = fed.instance_id()
    if not me:
        return {}
    adopt = set(adopt or ())
    no_convert = set(no_convert or ())
    both, takeover = set(both or ()), set(takeover or ())
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
    two = len(ids) == 2
    order = sorted(wanted)
    asks = [{'cluster_id': cid,
             'adopt': cid in adopt or cid in marked
             or bool((mine.get(cid) or {}).get('adopted'))}
            for cid in order]
    chunks = [asks[i:i + MAX_ASKS_PER_CALL] for i in range(0, len(asks), MAX_ASKS_PER_CALL)]
    digest, epoch = fed.view_digest(), fed.view_epoch()
    peers = sorted(fed.members())
    sent = {}
    for iid in peers:
        try:
            sent[iid] = _records_for(iid)
        except FederationError as e:
            fed._say_once(('round-records', iid), f'[FED] the ownership records for {iid} '
                                                  f'cannot be read: {e}')
            sent[iid] = ([], 0)

    def body(chunk, iid=None):
        out = {'candidate': me, 'view': digest, 'epoch': epoch, 'asks': chunk,
               'releases': [], 'round': mark}
        if tick:
            out['tick'] = True
        recs, upto = sent.get(iid) or ([], 0)
        if recs:
            out['records'], out['records_upto'] = recs, upto
        return out
    round_start = _lease_now()
    voters = [me] + peers
    answers = [[cast_votes(me, body(c)) for c in chunks]]
    got = fed._parallel(lambda iid: [fed.call_peer(iid, 'POST', LEASE_PATH,
                                                   body(c, iid if i == 0 else None),
                                                   read_timeout=VOTE_TIMEOUT)[:2]
                                     for i, c in enumerate(chunks)],
                        peers, max_workers=len(peers) or 1)
    answers += [a or [] for a in got]
    # the records first: a cluster another member took over is given up here before this
    # round could renew it
    fenced, more = _take_answer_records(peers, answers[1:], chunks, sent, no_convert)
    if fed.take_end():
        return {}
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
                reason = data.get('reason') if (isinstance(data, dict) and data.get('reason')
                                                in ('view', 'dr_off')) else 'down'
                for cid in order:
                    refusals.setdefault(cid, Counter())[reason] += 1
    own = {}
    for status, data in answers[0]:
        if status == 200 and isinstance(data, dict) and isinstance(data.get('votes'), dict):
            own.update(data['votes'])
    peer_state, peer_votes, answered = {}, {}, False
    alone = set()
    if two:
        peer_state, peer_votes, answered = _peer_states(answers[1], chunks, digest, fenced)
        alone = _alone_ok(order, own, peer_state, answered, owners, me, digest, epoch,
                          adopt, both, takeover)
    need = fed.needed(len(ids))
    view = set(fed.members())
    results, lost, stale = {}, [], []
    settled = [cid for cid in order if cid in marked and rows_mine[cid] >= need]
    with fed._lock:
        st = fed._lease_state()
        held = st['my_leases']
        now = _lease_now()
        # a third site that joined while the asks were out: the other member's answer was
        # counted for a view that is gone, and a lease of two needs no step past it
        moved = two and fed.view_digest() != digest
        for cid in order:
            before = mine.get(cid)
            cur = held.get(cid)
            g = grants[cid]
            reasons = dict(refusals.get(cid) or {})
            extra = {'alone': False}
            if two:
                extra['peer'] = peer_state.get(cid, 'silent')
            if cid in takeover:
                extra['owner_answered'] = answered
            if isinstance(own.get(cid), dict) and own[cid].get('granted') is not True:
                extra['own_refused'] = str(own[cid].get('reason') or '')
            gone = (before is not None and cur is None) or _rseq(cur) != _rseq(before)
            if gone or moved:
                # released or forgotten while the asks were out: no lease from this round
                if new_pids.get(cid):
                    stale.append((cid, new_pids[cid]))
                results[cid] = dict(extra, held=False, votes=g, needed=need, lost_to='',
                                    refusals=reasons, holders={}, released=gone)
                if cid in fenced:
                    results[cid]['taken_by'] = fenced[cid]
                continue
            rec = cur or {}
            pids = dict(rec.get('pids') or {})
            pids.update(new_pids.get(cid) or {})
            by_self = g < need and cid in alone
            if g >= need or by_self:
                was_live = bool(rec) and not rec.get('released') and now < (rec.get('expires') or 0)
                held[cid] = {'expires': round_start + LEASE_SECONDS - LEASE_WRITE_MARGIN,
                             'since': rec.get('since') if was_live else round_start,
                             'votes': g, 'needed': need, 'released': False,
                             'adopted': bool(rec.get('adopted')) or cid in adopt,
                             'lost_to': '', 'refusals': reasons, 'pids': pids,
                             'rseq': _rseq(rec), 'alone': by_self}
                if cid == MEMBERS_LOCK:
                    held[cid]['certs'] = certs
                if not was_live and cid != MEMBERS_LOCK:
                    logging.info(f'[FED] lease on {cid} held ({g}/{need} votes'
                                 f'{", alone: the other site does not answer" if by_self else ""})')
                extra['alone'] = by_self
                results[cid] = dict(extra, held=True, votes=g, needed=need, lost_to='',
                                    refusals=reasons, holders={})
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
            results[cid] = dict(extra, held=False, votes=g, needed=need, lost_to=lost_to,
                                refusals=reasons, holders=dict(holders.get(cid) or {}))
        fed._save_leases(st)
    if two and not moved and owners is not None:
        _note_ok([cid for cid in order if cid in peer_votes and owners.get(cid) == me
                  and peer_votes[cid].get('owner') in ('', me)], digest, epoch)
    if settled:
        # the voters' rows name this instance now: the asks go without the flag again
        fed._mark_clusters('adopted', drop=settled)
    for cid, pids in stale:
        _send_releases(cid, pids)
    for cid, owner in lost:
        _convert_lost(cid, owner)
    if more:
        # a body carries one batch of records: a member that echoed a full one gets the
        # rest now, so a site that cannot call here hears of every takeover in this round
        push_records(more)
    if behind:
        try:
            fed.catch_up()
        except Exception as e:
            logging.warning(f'[FED] catching up with the federation failed: {e}')
    return results


def _take_answer_records(peers, answers, chunks, sent, no_convert):
    """The echoes and the ownership records in the members' answers to one round, taken
    after the calls and before the leases are written. Returns ({cluster id: new owner} of
    the ids given up here to a record of the member that answered, the members that echoed
    a full batch of this instance's records and may have more due)."""
    fenced, more = {}, []
    for iid, voter in zip(peers, answers):
        recs, upto, refused = [], None, set()
        for (status, data), chunk in zip(voter, chunks):
            if not status or not isinstance(data, dict):
                continue
            echo = data.get('records_upto')
            if isinstance(echo, int) and not isinstance(echo, bool):
                upto = echo
            if isinstance(data.get('records'), list):
                recs += data['records'][:len(chunk) + MAX_RECORDS_PER_CALL]
            votes = data.get('votes') if isinstance(data.get('votes'), dict) else {}
            # the member's own row names itself the owner: with its record, the evidence a
            # site of two gives a cluster up on (take_records)
            refused |= {cid for cid, v in votes.items() if isinstance(v, dict)
                        and v.get('reason') in ('owner', 'held') and v.get('owner') == iid}
        try:
            mine, top = sent.get(iid) or ([], 0)
            if upto is not None and mine:
                _note_acked(iid, min(upto, top))
                if len(mine) >= MAX_RECORDS_PER_CALL:
                    more.append(iid)
            if recs:
                named = {r.get('cluster_id') for r in recs
                         if isinstance(r, dict) and r.get('owner') == iid}
                # every record of the answer, one per id asked: a site whose clusters were
                # all taken over stops each of them at this answer
                fenced.update(take_records(iid, recs, owner_refusals=refused & named,
                                           no_convert=no_convert, cap=len(recs))['fenced'])
        except FederationError as e:
            fed._say_once(('round-records', iid), f'[FED] the ownership records {iid} '
                                                  f'answered with could not be taken: {e}')
    return fenced, more


def _peer_states(voter, chunks, digest, fenced):
    """What the other member of a view of two answered for each id of a round: 'silent'
    (no signed answer to any call of the round: it is down, cut off, switched off or a
    standby), 'granted', 'hold' (its host restarted, it grants nobody), 'taken' (its record
    took the id from here) or 'veto' (any other signed answer, and no answer to the call
    of the id while it answered another). Returns (states, its grants, whether it gave any
    signed answer)."""
    states, grants, answered = {}, {}, False
    for i, chunk in enumerate(chunks):
        status, data = voter[i] if i < len(voter) else (0, None)
        answered = answered or bool(status)
        votes = data.get('votes') if (status == 200 and isinstance(data, dict)
                                      and data.get('view') == digest) else None
        votes = votes if isinstance(votes, dict) else {}
        for ask in chunk:
            cid = ask['cluster_id']
            v = votes.get(cid)
            if cid in fenced:
                states[cid] = 'taken'
            elif not status:
                states[cid] = 'silent'
            elif isinstance(v, dict) and v.get('granted') is True:
                states[cid] = 'granted'
                grants[cid] = v
            elif isinstance(v, dict) and v.get('reason') == 'hold':
                states[cid] = 'hold'
            else:
                states[cid] = 'veto'
    if answered:
        # it runs and reaches us: a call it left unanswered is a lost one, no outage, and
        # the records of those ids would have come back in that very answer
        states = {cid: 'veto' if v == 'silent' else v for cid, v in states.items()}
    return states, grants, answered


def _alone_ok(order, own, peer_state, answered, owners, me, digest, epoch, adopt, both,
              takeover):
    """The ids of a round of two this instance may hold on its own vote. Its own vote
    granted, and: an id taken over by hand while the other member gave no signed answer
    at all; any other id led here while that member is silent or in its hold, with no
    record of another owner held here, and granted by that member under this view and
    generation once (the 'ok' note). Never the members lock, an enroll, or an adoption."""
    try:
        held = fed.ownership()
    except FederationError as e:
        fed._say_once('alone-records', f'[FED] the ownership records cannot be read, no lease '
                                       f'is held alone: {e}')
        return set()
    out = set()
    for cid in order:
        v = own.get(cid)
        if cid == MEMBERS_LOCK or cid in both or not (isinstance(v, dict)
                                                      and v.get('granted') is True):
            continue
        if cid in takeover:
            if not answered:
                out.add(cid)
            continue
        if peer_state.get(cid) not in ('silent', 'hold') or cid in adopt:
            continue
        if owners is None or owners.get(cid) != me:
            continue
        rec = held['records'].get(cid)
        if rec is not None and rec.get('owner') != me:
            continue
        ok = held['ok'].get(cid) or {}
        if (ok.get('view'), ok.get('epoch'), ok.get('gen')) == \
                (digest, epoch, fed.known_gen(cid, held)):
            out.add(cid)
    return out


def _note_ok(cids, digest, epoch):
    """The other member of a view of two granted these clusters led here, its row naming
    this instance or none: each may be held alone under this view and generation from now
    on. Written only when a note changes; notes of rows no longer led here go with it."""
    me = fed.instance_id()

    def stale(own):
        return [cid for cid in cids
                if {k: (own['ok'].get(cid) or {}).get(k) for k in ('view', 'epoch', 'gen')}
                != {'view': digest, 'epoch': epoch, 'gen': fed.known_gen(cid, own)}]
    try:
        if not stale(fed.ownership()):
            return

        def go(own):
            led = {r['id'] for r in fed._db().conn.execute(
                'SELECT id FROM clusters WHERE fed_owner = ?', (me,)).fetchall()}
            for cid in stale(own):
                if cid in led:
                    own['ok'][cid] = {'view': digest, 'epoch': epoch,
                                      'gen': fed.known_gen(cid, own), 'at': int(time.time())}
            for cid in [c for c in own['ok'] if c not in led]:
                del own['ok'][cid]
            return True
        fed._mutate_ownership(go)
    except FederationError as e:
        fed._say_once('ok-notes', f'[FED] the grants of the other site could not be noted: {e}')


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
    nor the adoption mark stands for it, nor the other site's grant of a view of two."""
    for key in ('handed_over', 'adopted'):
        fed._mark_clusters(key, drop=cluster_ids)
    try:
        if set(cluster_ids) & set(fed.ownership().get('ok') or {}):
            def go(own):
                return bool([own['ok'].pop(cid) for cid in cluster_ids if cid in own['ok']])
            fed._mutate_ownership(go)
    except FederationError as e:
        logging.warning(f'[FED] the grant notes of {", ".join(cluster_ids)} could not be '
                        f'dropped: {e}')


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
    elif reasons.get('taken'):
        text += ' - a takeover is not known at every site yet; try again in a few seconds'
    elif reasons.get('view'):
        text += ' - the sites do not agree on the member list yet; try again after a sync'
    elif reasons.get('dr_off'):
        text += ' - a site has its disaster recovery off; switch it on there'
    return text


def _lease_summary(cluster_id):
    rec = (fed._lease_state().get('my_leases') or {}).get(cluster_id) or {}
    now = _lease_now()
    return {'cluster_id': cluster_id,
            'held': bool(not rec.get('released') and now < (rec.get('expires') or 0)),
            'remaining_s': max(0, int((rec.get('expires') or 0) - now)),
            'votes': rec.get('votes', 0), 'needed': rec.get('needed', 0),
            'adopted': bool(rec.get('adopted')), 'alone': bool(rec.get('alone'))}


def _cluster_row(cluster_id):
    try:
        return fed._db().conn.execute(
            'SELECT fed_owner, cluster_type FROM clusters WHERE id = ?',
            (cluster_id,)).fetchone()
    except Exception as e:
        raise FederationError(f'The clusters table cannot be read: {e}')


def enroll_cluster(cluster_id, by=''):
    """Put a local Proxmox VE cluster under the federation's rule: this instance becomes
    its writer with a majority behind it; with two sites both must grant it. Without that
    the row is as it was. The enroll leaves an ownership record (with two sites, and the
    other site's grant, the note that lets this instance hold the cluster alone)."""
    if not isinstance(cluster_id, str) or not CLUSTER_ID_RE.fullmatch(cluster_id):
        raise FederationError('That cluster id cannot be enrolled', code='FED_BAD_ID')
    if len(fed.view_ids()) < MIN_SITES_TO_ENROLL:
        raise FederationError('A federation of one holds no lease: pair a second site first',
                              code='FED_TOO_FEW_SITES')
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
    # a record that names another owner never turns the row into a mirror while the enroll
    # is under way (take_records): a local row of an id another member leads is refused
    fresh_enrolls = fed._runtime.setdefault('fresh_enrolls', set())
    fresh_enrolls.add(cluster_id)
    try:
        # under the lock a switch-off of the disaster recovery decides under: an enroll
        # never lands on a site that just switched it off
        with fed._lock:
            if not fed.dr_enabled():
                raise FederationError(fed.DR_OFF_ERROR, code='FED_DR_OFF')
            _set_owner(cluster_id, me)
        # a local row that another member leads under the same id is refused, never handed
        # over: the 'lost_to' evidence converts only a row this instance led before
        fresh = {cluster_id} if not owner else set()
        r = lease_round(only={cluster_id}, no_convert=fresh,
                        both={cluster_id}).get(cluster_id) or {}
        if r.get('held'):
            # enrolled again: a hand-over is taken back
            fed._mark_clusters('handed_over', drop=[cluster_id])
            _note_new_owner(cluster_id, 'enroll', '', by)
            if len(fed.view_ids()) == 2:
                # the other site just granted it and holds the record before the admin sees
                # the enroll; with more sites the next round carries it, and a site that is
                # down costs the request nothing
                _push_records(sorted(fed.members()))
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
    finally:
        fresh_enrolls.discard(cluster_id)
    text = _refusal_sentence(r)
    taken_by = _taken_by(r) if fresh else ''
    if taken_by:
        text = (f'The federation did not back the lease - {_site(taken_by)} leads a cluster '
                f'with this id: cluster ids must be unique in the federation')
    elif r.get('peer') == 'silent':
        other = next(iter(fed.members()), '')
        text = f'With two sites, enrolling needs both to answer: {_site(other)} did not'
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


def adopt_cluster(cluster_id, force=False, by=''):
    """Take over the cluster of a member that is gone for good (or that released it).
    The lease is the fence: the voters grant it only past the old owner's promise. The
    credentials, the owner and the ownership record change in one transaction; any
    failure gives the lease back and leaves the row as it was. Raises FederationError
    with what stands in the way.

    With two sites one of two is no majority: an adoption needs the owner to answer and
    to have handed the cluster over (both grant it). An owner that does not answer is
    FED_USE_TAKEOVER: its cluster is taken over by hand (take_over_clusters)."""
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
    two = len(fed.view_ids()) == 2
    status, _b, _h = fed.call_peer(owner, 'GET', fed.STATUS_PATH, read_timeout=5)
    if two and not status:
        raise FederationError(f'{_site(owner)} does not answer. With two sites a cluster whose '
                              'owner does not answer is taken over by hand: use Manual '
                              'takeover', code='FED_USE_TAKEOVER', owner=owner)
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
    try:
        # with two sites the old owner's grant of the adoption is the note itself
        gen = _commit_new_owner(cluster_id, owner, 'adopt', by, force, ok=two)
    except FederationError:
        _give_back(cluster_id)
        raise
    # in the identity row: whichever host of this HA group asks next, it asks with the
    # adoption flag while the voters' rows still name the old owner
    fed._mark_clusters('adopted', add={cluster_id: {'from': owner}})
    fed._mark_clusters('handed_over', drop=[cluster_id])
    if two:
        _push_records(sorted(fed.members()))
    out = _lease_summary(cluster_id)
    out['generation'] = gen
    out['notes'] = ['node_credentials', 'ha_claim']
    return out


def _commit_new_owner(cluster_id, owner, kind, by, force, ok=False):
    """The row of `owner`'s cluster becomes this instance's (an adoption, a takeover): its
    credentials opened with the owner's field key and sealed with this instance's database
    key, the owner set, and the signed record of the change (generation one past the
    highest known) stored, all in one transaction under the lock. `ok`: the note that lets
    a site of two hold the cluster alone. Returns the generation; raises FederationError
    and changes nothing on any failure."""
    me = fed.instance_id()
    made = {}
    with fed._lock:
        conn = fed._db().conn
        try:
            fed._begin(conn)
            _reseat_credentials(conn, cluster_id, owner, force)
            cur = conn.execute('UPDATE clusters SET fed_owner = ? WHERE id = ? AND '
                               'fed_owner = ?', (me, cluster_id, owner))
            if cur.rowcount != 1:
                raise FederationError(f'The cluster row changed while it was '
                                      f'{"adopted" if kind == "adopt" else "taken over"} - '
                                      'try again')

            def keep(own):
                gen = fed.known_gen(cluster_id, own) + 1
                fed.store_record(own, fed.sign_owner_record(cluster_id, gen, kind, owner, by),
                                 conn)
                if ok:
                    own['ok'][cluster_id] = {'view': fed.view_digest(),
                                             'epoch': fed.view_epoch(), 'gen': gen,
                                             'at': int(time.time())}
                made['gen'] = gen
                return True
            fed._ownership_in_tx(conn, keep)
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            if isinstance(e, FederationError):
                raise
            raise FederationError(f'The {"adoption" if kind == "adopt" else "takeover"} did '
                                  f'not go through and changed nothing: {e}')
        finally:
            fed._runtime['ownership'] = None
            drop_owner_cache()
    return made['gen']


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


def note_lost(cluster_id, owner, record=None):
    """After a row led here became `owner`'s mirror: the lease entry goes, the manager
    stops, and the audit log says it once - for a step-down on `owner`'s ownership
    `record`, with when and by whom the cluster moved."""
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
        if record is None:
            log_audit('system', 'federation.cluster_lost',
                      f'cluster {cluster_id} now led by {_site(owner)}', ip_address='federation')
        else:
            site = _site(owner)
            when = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(record.get('at') or 0))
            if record.get('kind') == 'takeover':
                text = (f'cluster {cluster_id} was taken over by hand at {site} on {when} by '
                        f'{record.get("by") or "an admin"} (generation {record.get("gen")}): '
                        f'this instance stopped writing to it and follows {site} now; what it '
                        f'sent to the cluster since then went out beside {site}')
            else:
                text = (f'cluster {cluster_id} was adopted by {site} on {when} (generation '
                        f'{record.get("gen")}): this instance stopped writing to it and '
                        f'follows {site} now')
            log_audit('system', 'federation.cluster_stepped_down', text,
                      ip_address='federation')
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


# --- two members: records, takeover ----------------------------------------------------------
#
# MK Nov 2026 - one of two is no majority. The owner of a cluster holds it alone while the
# other site is silent (lease_round), and the other site writes it only after its admin
# confirmed the owner is down (take_over_clusters). What fences that is the ownership
# record: signed, numbered per cluster, kept across restarts in the synced key, pushed to
# the old owner until it echoes, put in every answer to its asks and in every snapshot,
# and checked by the old owner on every contact (take_records).

def take_records(sender, raw, owner_refusals=frozenset(), no_convert=frozenset(),
                 cap=MAX_RECORDS_PER_CALL):
    """Take the ownership records `sender` handed over (a lease-vote body, its answers to
    a round, its snapshot): each one that validates and beats the record held for its
    cluster is kept, in every view size. In a view of two they act as well: a cluster led
    here whose record names the other member as its owner by adoption or takeover is given
    up at once (_step_down), and a record of this instance's own adoption or takeover that
    comes back newer than what is held leads the cluster here again (_resume). With no
    newer record a cluster is given up only on the other member's own evidence
    (`owner_refusals`: its answer refused the id naming itself, and showed this record),
    and never in an enroll (`no_convert`, an enroll under way). Whether a record acts is
    decided before anything is stored. A record that gives a cluster up is kept first: if
    the row then does not move, it still holds nothing alone here or on a standby, and
    each delivery of it tries again until the step-down is noted (stopped_at). A record
    that leads a cluster here again is kept only by the transaction that moves the row, so
    one that fails keeps nothing and the next delivery acts again. Returns {'echo': whether
    the records are stored, False while a row such a record moves did not move, 'fenced':
    {cluster id: new owner}}. Called outside any lock and transaction of the caller."""
    out = {'echo': True, 'fenced': {}}
    if not isinstance(raw, list) or not raw:
        return out
    try:
        entries = fed._view_entries(fed.identity() or {})
        held = fed.ownership()['records']
    except FederationError as e:
        logging.warning(f'[FED] the ownership records of {sender} wait: {e}')
        out['echo'] = False
        return out
    best = {}
    for item in raw[:cap]:
        if not isinstance(item, dict) or not isinstance(item.get('cluster_id'), str):
            continue
        cid = item['cluster_id']
        mine = held.get(cid)
        if mine is not None and item.get('sig') == mine.get('sig'):
            # the record held here, signed and checked when it was stored
            rec = fed.wire_record(mine)
        else:
            rec = fed.valid_owner_record(item, entries)
            if rec is None:
                continue
        if cid in best and not fed.record_beats(rec, best[cid][0]):
            continue
        best[cid] = (rec, fed.record_beats(rec, mine))
    # three or more sites: a majority decides, the records are only kept
    acting, waiting = _acting_records(best, held, owner_refusals, no_convert) \
        if len(fed.view_ids()) == 2 else ({}, set())
    # a record whose row could not be read is not stored yet: stored, the next delivery
    # would no longer count it as newer, and its step or return would never be judged
    newer = {cid: rec for cid, (rec, beats) in best.items()
             if beats and acting.get(cid) != 'resume' and cid not in waiting}
    if newer:
        def go(own):
            got = [cid for cid, rec in newer.items()
                   if fed.record_beats(rec, own['records'].get(cid))]
            for cid in got:
                fed.store_record(own, newer[cid])
            return bool(got)
        try:
            fed._mutate_ownership(go)
        except Exception as e:
            logging.warning(f'[FED] the ownership records of {sender} could not be stored: {e}')
            out['echo'] = False
            return out
    for cid, step in sorted(acting.items()):
        rec = best[cid][0]
        if step == 'down':
            _step_down(cid, rec)
            # given up or not, this round writes no lease for it
            out['fenced'][cid] = rec['owner']
        else:
            _resume(cid, rec)
    if acting:
        try:
            held = fed.ownership()['records']
        except FederationError:
            held = {}
        for cid, step in acting.items():
            rec, beats = best[cid]
            got = held.get(cid)
            if step == 'down':
                waits = got is None or (got.get('sig') == rec['sig']
                                        and not got.get('stopped_at'))
            else:
                waits = beats and not (got is not None and (got.get('sig') == rec['sig']
                                                            or fed.record_beats(got, rec)))
            if waits:
                out['echo'] = False
    if waiting:
        out['echo'] = False
    return out


def _acting_records(best, held, owner_refusals, no_convert):
    """({cluster id: 'down' or 'resume'}, {cluster ids whose row could not be read}) for
    the records of `best` that move a row in a view of two, judged against the records
    `held` before any of them is stored. A record held already whose step-down was never
    noted gives the cluster up again."""
    me, members = fed.instance_id(), fed.members()
    enrolling = fed._runtime.get('fresh_enrolls') or set()
    acting, waiting = {}, set()
    for cid, (rec, beats) in sorted(best.items()):
        try:
            row = cluster_owner(cid)
        except FederationError as e:
            logging.warning(f'[FED] the ownership record of {cid} waits: {e}')
            waiting.add(cid)
            continue
        kept = held.get(cid)
        undone = kept is not None and kept.get('sig') == rec['sig'] \
            and not kept.get('stopped_at')
        if (row == me and rec['owner'] != me and rec['owner'] in members
                and rec['kind'] in ('adopt', 'takeover')
                and not (kept is not None and fed.record_beats(kept, rec))
                and cid not in enrolling and cid not in no_convert
                and (beats or undone or cid in owner_refusals)):
            acting[cid] = 'down'
        elif (beats and rec['owner'] == me and rec['kind'] in ('adopt', 'takeover')
              and row and row == rec['from'] and rec['from'] in members):
            acting[cid] = 'resume'
    return acting, waiting


def _step_down(cluster_id, rec):
    """The other member of a view of two leads `cluster_id` by `rec`. The gate shuts first:
    the lease entry released past any round in flight, and this instance's own promise for
    the cluster ended, so the new owner's ask is granted. Then what runs on the cluster
    stops, and the row becomes the new owner's mirror with its credentials cleared, the
    record kept with when this instance stopped, in one transaction. A host that dies half
    way never writes again and finishes at the next contact. True when the row moved."""
    me = fed.instance_id()

    def shut(st):
        lease = st['my_leases'].setdefault(cluster_id, {'expires': 0})
        lease.update(released=True, expires=0, rseq=_rseq(lease) + 1)
        p = st['promises'].get(cluster_id)
        if p and p.get('candidate') == me:
            p['until'] = 0
            p['released'] = True
        return True
    cleared = ', '.join(f"{c} = ''" for c in fed.CLUSTER_ENCRYPTED_COLUMNS)
    # one hold of the lock every record is stored under, from the look at the records to
    # the move of the row: a newer record cannot come in between, so the lease and the
    # work it would keep are never given up for a move that then does not happen
    with fed._lock:
        try:
            held = fed.ownership()['records'].get(cluster_id)
        except FederationError as e:
            logging.warning(f'[FED] the step-down of {cluster_id} waits: {e}')
            return False
        if held is not None and held.get('sig') != rec['sig'] and fed.record_beats(held, rec):
            logging.info(f'[FED] cluster {cluster_id} stays here: a record newer than the one '
                         f'naming {rec["owner"]} came in meanwhile')
            return False
        fed._mutate_leases(shut)
        _cut([cluster_id])
        stopped = int(time.time())
        conn = fed._db().conn
        try:
            fed._begin(conn)

            def keep(own):
                held = own['records'].get(cluster_id)
                if held is not None and held.get('sig') == rec['sig']:
                    held['stopped_at'] = stopped
                elif held is not None and fed.record_beats(held, rec):
                    # only another process writing the key could have put it there
                    raise FederationError('a newer record of the cluster came in meanwhile')
                else:
                    fed.store_record(own, rec, conn, stopped_at=stopped)
                own['ok'].pop(cluster_id, None)
                return True
            fed._ownership_in_tx(conn, keep)
            cur = conn.execute(f'UPDATE clusters SET fed_owner = ?, {cleared} WHERE id = ? '
                               f'AND fed_owner = ?', (rec['owner'], cluster_id, me))
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            logging.warning(f'[FED] cluster {cluster_id} could not be handed to '
                            f'{rec["owner"]}, the next contact tries again: {e}')
            return False
        finally:
            fed._runtime['ownership'] = None
            drop_owner_cache()
    if not cur.rowcount:
        return False
    note_lost(cluster_id, rec['owner'], record=rec)
    return True


def _resume(cluster_id, rec):
    """A record of this instance's own adoption or takeover of `cluster_id` came back from
    the old owner, newer than what is held here: the HA sync had not carried it when this
    host took over. The other member holds it as its newest for the cluster and follows
    this instance, so the row is led here again, its credentials opened with the old
    owner's field key (what does not open is cleared)."""
    me = fed.instance_id()
    old = rec['from']
    try:
        with fed._lock:
            conn = fed._db().conn
            try:
                fed._begin(conn)
                _reseat_credentials(conn, cluster_id, old, True)
                cur = conn.execute('UPDATE clusters SET fed_owner = ? WHERE id = ? AND '
                                   'fed_owner = ?', (me, cluster_id, old))
                if cur.rowcount != 1:
                    raise FederationError('the cluster row changed meanwhile')

                def keep(own):
                    held = own['records'].get(cluster_id)
                    if held is None or held.get('sig') != rec['sig']:
                        if not fed.record_beats(rec, held):
                            raise FederationError('a newer record of the cluster came in '
                                                  'meanwhile')
                        fed.store_record(own, rec, conn)
                    own['ok'][cluster_id] = {'view': fed.view_digest(), 'epoch': fed.view_epoch(),
                                             'gen': rec['gen'], 'at': int(time.time())}
                    return True
                fed._ownership_in_tx(conn, keep)
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                fed._runtime['ownership'] = None
                drop_owner_cache()
    except Exception as e:
        logging.warning(f'[FED] cluster {cluster_id} could not be led here again: {e}')
        return False
    fed._mark_clusters('adopted', add={cluster_id: {'from': old}})
    start_manager(cluster_id)
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.cluster_resumed',
                  f'cluster {cluster_id} is led here again: the record of its '
                  f'{"takeover" if rec["kind"] == "takeover" else "adoption"} (generation '
                  f'{rec["gen"]}) came back from {_site(old)}', ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the return of {cluster_id} could not be audited: {e}')
    return True


def _records_for(iid):
    """The records member `iid` has not echoed yet, oldest first, at most
    MAX_RECORDS_PER_CALL, as they travel, with the highest number among them."""
    own = fed.ownership()
    done = int(own['acked'].get(iid) or 0)
    due = sorted((int(r.get('n') or 0), cid) for cid, r in own['records'].items()
                 if int(r.get('n') or 0) > done)[:MAX_RECORDS_PER_CALL]
    if not due:
        return [], 0
    return [fed.wire_record(own['records'][cid]) for _n, cid in due], due[-1][0]


def _answer_records(sender, cids):
    """For each id `sender` asks for, the record held here when it names another owner."""
    if not cids:
        return []
    held = fed.ownership()['records']
    return [fed.wire_record(held[cid]) for cid in cids
            if cid in held and held[cid].get('owner') != sender]


def _unechoed_takeovers(iid):
    """This instance's takeovers of clusters of `iid` that `iid` has not echoed yet."""
    own = fed.ownership()
    me, done = fed.instance_id(), int(own['acked'].get(iid) or 0)
    return [fed.wire_record(r) for _cid, r in sorted(own['records'].items())
            if r.get('kind') == 'takeover' and r.get('owner') == me and r.get('from') == iid
            and int(r.get('n') or 0) > done][:MAX_RECORDS_PER_CALL]


def _note_acked(iid, upto):
    """Member `iid` echoed the records up to number `upto`: they are not pushed to it again,
    and a takeover of one of its clusters among them is confirmed - it stepped down."""
    if upto <= int(fed.ownership()['acked'].get(iid) or 0):
        return
    me, confirmed = fed.instance_id(), []

    def go(own):
        if upto <= int(own['acked'].get(iid) or 0):
            return False
        own['acked'][iid] = upto
        now = int(time.time())
        for cid, r in own['records'].items():
            if (r.get('kind') == 'takeover' and r.get('owner') == me and r.get('from') == iid
                    and int(r.get('n') or 0) <= upto and not r.get('confirmed_at')):
                r['confirmed_at'] = now
                confirmed.append((cid, r.get('gen')))
        return True
    fed._mutate_ownership(go)
    if confirmed:
        from pegaprox.utils.audit import log_audit
        for cid, gen in sorted(confirmed):
            try:
                log_audit('system', 'federation.takeover_confirmed',
                          f'{_site(iid)} stepped down from cluster {cid} (generation {gen})',
                          ip_address='federation')
            except Exception as e:
                logging.warning(f'[FED] the confirmed takeover of {cid} could not be '
                                f'audited: {e}')


def _push_records(iids):
    """Records-only calls to each member of `iids` that has records to echo, side by side,
    best effort (counted with the releases at the receiver): one batch a call, the next
    once the member echoed the whole batch, until none is due or a call goes unanswered.
    Returns the members that echoed."""
    me, view = fed.instance_id(), fed.members()
    todo = sorted({iid for iid in iids if iid != me and iid in view})
    digest, epoch = fed.view_digest(), fed.view_epoch()

    def push(item):
        iid, (recs, upto) = item
        body = {'candidate': me, 'view': digest, 'epoch': epoch, 'asks': [], 'releases': [],
                'records': recs, 'records_upto': upto}
        status, data = fed.call_peer(iid, 'POST', LEASE_PATH, body,
                                     read_timeout=VOTE_TIMEOUT)[:2]
        echo = data.get('records_upto') if status == 200 and isinstance(data, dict) else None
        if isinstance(echo, int) and not isinstance(echo, bool):
            return min(echo, upto)
        return None
    echoed = set()
    for _ in range(fed.MAX_OWNER_RECORDS // MAX_RECORDS_PER_CALL + 1):
        due = {}
        for iid in todo:
            try:
                recs, upto = _records_for(iid)
            except FederationError:
                continue
            if recs:
                due[iid] = (recs, upto)
        if not due:
            break
        todo = []
        batches = sorted(due.items())
        for (iid, (_recs, upto)), got in zip(batches, fed._parallel(push, batches)):
            if got is not None:
                _note_acked(iid, got)
                echoed.add(iid)
                if got == upto:
                    todo.append(iid)
    return sorted(echoed)


def push_records(iids=None):
    """The sync tick (every member), or a round that saw a member echo a full batch: each
    one with records to echo gets them."""
    try:
        return _push_records(sorted(fed.members()) if iids is None else iids)
    except FederationError as e:
        fed._say_once('push-records', f'[FED] the ownership records could not be pushed: {e}')
        return []


def takeover_wait(iid):
    """Seconds until member `iid` may be taken over by hand (or removed as gone): while a
    promise this voter gave it lives, plus the skew, and for SETTLE_SECONDS after it was
    last heard (a signed call from it, a signed answer of it). 0 when nothing stands in
    the way. On the lease clock: a step of the wall clock lets nothing through early."""
    now = _lease_now()
    waits = [0.0]
    for rec in (fed._lease_state().get('promises') or {}).values():
        if rec.get('candidate') == iid and _promise_live(rec, now):
            waits.append(float(rec['until']) + LEASE_SKEW - now)
    heard = (fed._runtime.get('heard') or {}).get(iid)
    if heard is not None:
        waits.append(SETTLE_SECONDS - (now - heard))
    return max(0, int(math.ceil(max(waits))))


def _takeover_refusal(cluster_id, owner):
    """(code, sentence) for an id that cannot be taken over from `owner`, None for one
    that can."""
    if not isinstance(cluster_id, str) or not CLUSTER_ID_RE.fullmatch(cluster_id):
        return 'FED_BAD_ID', 'That cluster id cannot be taken over'
    row = _cluster_row(cluster_id)
    if row is None:
        return 'FED_NOT_FOUND', 'No such cluster here - sync first, the copy must exist'
    held = row['fed_owner'] or ''
    if not held:
        return 'FED_NOT_ENROLLED', 'That cluster is this instance\'s own already'
    if held == fed.instance_id():
        return 'FED_LED_HERE', 'That cluster is already led here'
    if held != owner:
        return 'FED_FOREIGN', f'That cluster is not led by {_site(owner)}'
    if (row['cluster_type'] or 'proxmox') != 'proxmox':
        return 'FED_TYPE', 'Only Proxmox VE clusters can be taken over'
    return None


def take_over_clusters(owner, cluster_ids=None, by='', force=False):
    """Take over by hand, in a federation of two, the clusters of `owner` this instance
    holds a copy of (every one, or `cluster_ids`): the admin confirmed `owner` is down.
    Refused on a standby, with three or more sites, in the hold or the settle span, while
    a promise to `owner` lives or `owner` was heard within SETTLE_SECONDS
    (FED_OWNER_RECENT), and while it answers (FED_OWNER_ALIVE), the status probe first and
    the round itself after it. One round for all of them, held on this instance's own
    vote; each cluster then moves in a transaction of its own with a takeover record one
    generation past the highest known (_commit_new_owner). The record goes to `owner`
    only once it is made, so an owner that comes back during the round steps down for
    nothing that failed. Returns {'owner', 'taken': [{'cluster_id', 'generation'}],
    'failed': {cluster id: {'code', 'error'}}}."""
    if fed._ha_standby() or not fed._ha_active():
        raise FederationError('This instance is not the acting host of its HA group - ask its '
                              'active', code='FED_STANDBY')
    with fed._one_change():
        return _take_over(owner, cluster_ids, by, force)


def _take_over(owner, cluster_ids, by, force):
    ids, digest = fed.view_ids(), fed.view_digest()
    if len(ids) > 2:
        raise FederationError('Take over by hand is for a federation of two sites. With three '
                              'or more, Take over adopts by majority', code='FED_NOT_TWO_SITES')
    if len(ids) < 2:
        raise FederationError('A federation of one holds no lease', code='FED_TOO_FEW_SITES')
    if owner not in fed.members():
        raise FederationError('No such member of this federation', code='FED_NOT_MEMBER')
    site = _site(owner)
    if cluster_ids is None:
        try:
            cluster_ids = [r['id'] for r in fed._db().conn.execute(
                'SELECT id FROM clusters WHERE fed_owner = ? ORDER BY id', (owner,)).fetchall()]
        except Exception as e:
            raise FederationError(f'The clusters table cannot be read: {e}')
    if not cluster_ids:
        raise FederationError(f'{site} leads no cluster this instance holds a copy of',
                              code='FED_NOTHING_TO_TAKE')
    failed, wanted = {}, []
    for cid in dict.fromkeys(cluster_ids):
        refused = _takeover_refusal(cid, owner)
        if refused:
            failed[str(cid)[:64]] = {'code': refused[0], 'error': refused[1]}
        else:
            wanted.append(cid)
    out = {'owner': owner, 'site': site, 'taken': [], 'failed': failed}
    if not wanted:
        return out
    hold, settle = hold_left(), settle_left()
    if hold > 0:
        n = int(math.ceil(hold))
        raise FederationError(f'This host restarted or took over in its HA group and votes '
                              f'again in {n} s', code='FED_HOLD', retry_after=n)
    if settle > 0:
        n = int(math.ceil(settle))
        raise FederationError(f'The member list changed a moment ago; try again in {n} s',
                              code='FED_SETTLING', retry_after=n)
    wait = takeover_wait(owner)
    if wait > 0:
        raise FederationError(f'{site} was in contact a moment ago and may only be cut off '
                              f'for a moment: try again in {wait} s', code='FED_OWNER_RECENT',
                              retry_after=wait, owner=owner)
    alive = (f'{site} answers right now, so it is not down. Hand the cluster over there '
             '(Hand over), then take it over here with Take over')
    if fed.call_peer(owner, 'GET', fed.STATUS_PATH, read_timeout=5)[0]:
        raise FederationError(alive, code='FED_OWNER_ALIVE', owner=owner)
    if fed._peer_key(owner) is None and not force:
        raise FederationError('The field key of the owner is not held here - without it the '
                              'credentials cannot cross over. Take over with force to take '
                              'the cluster without them', code='FED_NO_KEY')
    r = lease_round(only=set(wanted), adopt=set(wanted), takeover=set(wanted))
    if any((r.get(cid) or {}).get('owner_answered') for cid in wanted):
        for cid in wanted:
            _give_back(cid)
        raise FederationError(alive, code='FED_OWNER_ALIVE', owner=owner)
    if fed.view_digest() != digest:
        for cid in wanted:
            _give_back(cid)
        raise FederationError('The member list changed during the takeover - try again',
                              code='FED_VIEW')
    for cid in wanted:
        res = r.get(cid) or {}
        if not res.get('held'):
            _give_back(cid)
            if res.get('own_refused') == 'held':
                failed[cid] = {'code': 'FED_OWNER_RECENT',
                               'error': f'This instance backed {site} for the cluster a moment '
                                        f'ago; try again in {SETTLE_SECONDS} s'}
            else:
                failed[cid] = {'code': 'FED_NO_QUORUM', 'error': _refusal_sentence(res)}
            continue
        try:
            gen = _commit_new_owner(cid, owner, 'takeover', by, force, ok=True)
        except FederationError as e:
            _give_back(cid)
            failed[cid] = {'code': e.code, 'error': str(e)}
            continue
        fed._mark_clusters('adopted', add={cid: {'from': owner, 'takeover': gen}})
        fed._mark_clusters('handed_over', drop=[cid])
        out['taken'].append({'cluster_id': cid, 'generation': gen})
        logging.warning(f'[FED] cluster {cid} taken over by hand from {owner} by {by} '
                        f'(generation {gen})')
    if out['taken']:
        _push_records([owner])
    return out


def take_over_cluster(cluster_id, by='', force=False):
    """take_over_clusters for one cluster, its owner read from the row. Raises its failure
    as a FederationError with the code. Returns {'cluster_id', 'generation', 'owner'}."""
    if fed._ha_standby() or not fed._ha_active():
        raise FederationError('This instance is not the acting host of its HA group - ask its '
                              'active', code='FED_STANDBY')
    if not isinstance(cluster_id, str) or not CLUSTER_ID_RE.fullmatch(cluster_id):
        raise FederationError('That cluster id cannot be taken over', code='FED_BAD_ID')
    row = _cluster_row(cluster_id)
    owner = (row['fed_owner'] or '') if row is not None else ''
    if row is not None and owner and owner != fed.instance_id() and owner not in fed.members():
        raise FederationError('Its owner is not in the federation\'s view', code='FED_NOT_MEMBER')
    refused = _takeover_refusal(cluster_id, owner)
    if refused:
        raise FederationError(refused[1], code=refused[0])
    out = take_over_clusters(owner, [cluster_id], by=by, force=force)
    if out['taken']:
        return dict(out['taken'][0], owner=owner)
    err = out['failed'].get(cluster_id) or {}
    raise FederationError(err.get('error') or 'The takeover did not go through',
                          code=err.get('code'))


def return_alone(reason):
    """A federation of one after a change both sites took (the other site left, or was
    removed with its agreement): no site is left that could hold this instance's enrolled
    clusters, and none could take one over unconfirmed (the members lock waits for that,
    'taken'). They are this instance's own again at once. Idempotent; the sync tick
    repairs a crash in between. A site that left or was removed keeps its rows closed: its
    view epoch is 0 then."""
    if fed.view_epoch() <= 0 or fed.members():
        return []
    try:
        cids = fed.own_enrolled_ids()
    except FederationError as e:
        logging.warning(f'[FED] the clusters led here cannot be read to return them: {e}')
        return []
    if not cids:
        return []
    _finish_unenroll(cids)
    try:
        fed._reset_ownership()
    except FederationError as e:
        logging.warning(f'[FED] the ownership records could not be cleared: {e}')
    logging.warning(f'[FED] {len(cids)} cluster(s) are this instance\'s own again: no other '
                    f'site is left ({reason})')
    try:
        from pegaprox.utils.audit import log_audit
        log_audit('system', 'federation.clusters_returned',
                  f'{len(cids)} cluster(s) are this instance\'s own again: no other site is '
                  f'left in the federation ({reason})', ip_address='federation')
    except Exception as e:
        logging.warning(f'[FED] the returned clusters could not be audited: {e}')
    return cids


def start_manager(cluster_id):
    """The manager of a cluster led here now (an adoption, a takeover, a resume) starts
    the way a standby's rebuild starts one. True when it runs; an unreachable cluster
    stays led here and its manager is tried again at the next start."""
    try:
        from pegaprox.core.db import get_db
        cluster = get_db().get_cluster(cluster_id)
        if cluster:
            from pegaprox import globals as g
            from pegaprox.app import _start_managers
            _start_managers({cluster_id: cluster}, only=())
            return cluster_id in getattr(g, 'cluster_managers', {})
    except Exception as e:
        logging.warning(f'[FED] the manager of {cluster_id} did not start yet: {e}')
    return False


def forget_leases(cluster_ids):
    """The rows are this instance's own now, unfenced: their lease entries go, and the
    promise this instance gave itself for each ends."""
    me = fed.instance_id()

    def go(st):
        for cid in cluster_ids:
            st['my_leases'].pop(cid, None)
            p = st['promises'].get(cid)
            if p and p.get('candidate') == me:
                p['until'] = 0
                p['released'] = True
        return True
    if cluster_ids:
        fed._mutate_leases(go)


def drop_kept(cluster_ids, owner):
    """The removed side: the clusters the other site kept when it carried on alone. The
    gate shuts, what runs on them stops, and their rows go here."""
    if not cluster_ids:
        return
    me = fed.instance_id()

    def shut(st):
        for cid in cluster_ids:
            lease = st['my_leases'].setdefault(cid, {'expires': 0})
            lease.update(released=True, expires=0, rseq=_rseq(lease) + 1)
        return True
    fed._mutate_leases(shut)
    _cut(cluster_ids)
    try:
        conn = fed._db().conn
        for cid in cluster_ids:
            conn.execute('DELETE FROM clusters WHERE id = ? AND fed_owner = ?', (cid, me))
        conn.commit()
    except Exception as e:
        logging.warning(f'[FED] the clusters {owner} kept could not be dropped here: {e}')
    drop_owner_cache()
    for cid in cluster_ids:
        _stop_manager(cid)
    fed.note_dropped((cid, owner) for cid in cluster_ids)
    forget_leases(cluster_ids)
    _unmark(*cluster_ids)


def _note_new_owner(cluster_id, kind, from_, by):
    """The record of a change of owner made outside a transaction of its own (an enroll),
    with the grant note of a view of two: both sites granted it."""
    two = len(fed.view_ids()) == 2

    def go(own):
        gen = fed.known_gen(cluster_id, own) + 1
        fed.store_record(own, fed.sign_owner_record(cluster_id, gen, kind, from_, by))
        if two:
            own['ok'][cluster_id] = {'view': fed.view_digest(), 'epoch': fed.view_epoch(),
                                     'gen': gen, 'at': int(time.time())}
        return True
    try:
        fed._mutate_ownership(go)
    except Exception as e:
        logging.warning(f'[FED] the record of the {kind} of {cluster_id} could not be kept: {e}')


# --- what the admin page reads -------------------------------------------------------------

def lease_status():
    """The leases this instance holds and the promises it gave, without clock values. Per
    lease also whether it is held alone, the generation of its record, and for a cluster
    taken over here by hand when and from whom (and when the old owner confirmed it); and
    'stepped_down', the clusters taken from this instance by hand or by adoption in the
    last seven days, with when it stopped writing to them."""
    st = fed._lease_state()
    now = _lease_now()
    handed, marked = fed.handed_over_ids(), fed.adopted_from()
    me = fed.instance_id()
    try:
        records = fed.ownership().get('records') or {}
    except FederationError as e:
        logging.warning(f'[FED] the ownership records cannot be read for the status: {e}')
        records = {}
    out = {'leases': {}, 'promises': {}, 'hold_s': int(math.ceil(hold_left(st))),
           'stepped_down': {}}
    for cid, rec in (st.get('my_leases') or {}).items():
        if cid == MEMBERS_LOCK:
            continue
        r = records.get(cid) or {}
        taken = r.get('kind') == 'takeover' and r.get('owner') == me
        out['leases'][cid] = {
            'held': bool(not rec.get('released') and now < (rec.get('expires') or 0)),
            'remaining_s': max(0, int((rec.get('expires') or 0) - now)),
            'votes': int(rec.get('votes') or 0), 'needed': int(rec.get('needed') or 0),
            'released': bool(rec.get('released')) or cid in handed,
            'adopted': bool(rec.get('adopted')) or cid in marked,
            'lost_to': rec.get('lost_to') or '', 'alone': bool(rec.get('alone')),
            'gen': fed.known_gen(cid, {'records': records}),
            'takeover': {'from': r.get('from') or '', 'at': r.get('at') or 0,
                         'by': r.get('by') or '', 'confirmed_at': r.get('confirmed_at') or 0}
            if taken else None}
    week = time.time() - 7 * 86400
    for cid, r in records.items():
        if r.get('from') == me and r.get('stopped_at') and (r.get('at') or 0) > week:
            out['stepped_down'][cid] = {'owner': r.get('owner') or '', 'kind': r.get('kind'),
                                        'at': r.get('at') or 0, 'by': r.get('by') or '',
                                        'stopped_at': r.get('stopped_at') or 0}
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
            'lost_to': r.get('lost_to', ''), 'alone': bool(r.get('alone'))}
