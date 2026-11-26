# -*- coding: utf-8 -*-
"""The VMID a guest migrated from ESXi lands under.

MK Nov 2026 (#1339) - the migration always took /cluster/nextid: the lowest free id on the
cluster, gaps included, outside a tenant's VMID range and outside any scheme the operator
keeps (a block per customer, ids an IaC tool owns). A caller may name the VMID now, per guest
in a bulk run too. Without one the guest gets the next free id inside the caller's tenant
range, the way GET /api/clusters/<id>/nextid offers it, and the cluster's own next id
otherwise.

A chosen id is checked when the migration is asked for: inside the tenant range of a caller
who is no admin, free on the target, and not promised to another migration of this process.
The VM shell is created minutes later, after the planning steps, so the task asks Proxmox VE
again right before it. Taken by then, the migration fails and says so: it never moves on to
another id on its own.

The question to Proxmox VE is GET /cluster/nextid?vmid=N. It refuses an id in use, and on
9.3 with the datacenter option next-id 'enforce' also one outside its lower/upper range or,
with 'unique', one used before (pve-guest-common, assert_id_satisfies_next_id_settings).

Proxmox VE reserves nothing for an id it answers. An id a migration of this process is about
to create is held here while that migration runs, so two of them never get the same one and
an automatic pick steps over an id another migration was given.
"""

import logging
import re
import threading
import time

VMID_MIN, VMID_MAX = 100, 999999999
# candidates an automatic pick in a tenant range asks Proxmox VE about before it gives up
PICK_TRIES = 25
# a hold taken for a migration that never got registered lapses after this
UNSTARTED_SECONDS = 120
# how old the guest list of an automatic pick may be (the read cache of the manager)
RESOURCES_MAX_AGE = 5

_DIGITS = re.compile(r'[0-9]{1,10}')
_lock = threading.Lock()
# (cluster_id, vmid) -> (owner, alive): ids a migration of this process is about to create
_claims = {}


def parse(raw, field='target_vmid'):
    """The chosen VMID of a request as an int, None when none was given. ValueError for
    anything that is no whole number Proxmox VE takes as a VMID."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    msg = f'{field} is a whole number from {VMID_MIN} to {VMID_MAX}, or empty for the next free one'
    if isinstance(raw, bool):
        raise ValueError(msg)
    if isinstance(raw, int):
        v = raw
    elif isinstance(raw, str) and _DIGITS.fullmatch(raw.strip()):
        v = int(raw.strip())
    else:
        raise ValueError(msg)
    if not VMID_MIN <= v <= VMID_MAX:
        raise ValueError(msg)
    return v


def free_ids(rows, start, end, skip=()):
    """The VMIDs from start to end that no guest in rows (cluster resources) has and that are
    not in skip, lowest first."""
    taken = set(skip or ())
    for r in rows or ():
        try:
            taken.add(int(r.get('vmid')))
        except (TypeError, ValueError, AttributeError):
            continue
    for v in range(int(start), int(end) + 1):
        if v not in taken:
            yield v


def _pve_reason(r):
    try:
        body = r.json() or {}
    except Exception:
        body = {}
    errs = body.get('errors') if isinstance(body, dict) else None
    why = errs.get('vmid') if isinstance(errs, dict) else None
    if not why and isinstance(errs, dict) and errs:
        why = next(iter(errs.values()))
    why = why or getattr(r, 'reason', '') or getattr(r, 'text', '') or f'HTTP {r.status_code}'
    return str(why).strip()[:200]


def ask(mgr, vmid):
    """What Proxmox VE says of vmid as the VMID of a new guest: ('free', ''), ('taken', why)
    for one in use or used before, ('range', why) for one its next-id range refuses,
    ('unknown', why) when it gave no answer."""
    try:
        r = mgr._api_get(f'https://{mgr.host}:{mgr.api_port}/api2/json/cluster/nextid?vmid={int(vmid)}')
    except Exception as e:
        return 'unknown', f'no answer ({type(e).__name__})'
    if r.status_code == 200:
        return 'free', ''
    why = _pve_reason(r)
    if r.status_code == 400:
        return ('range' if 'boundary' in why else 'taken'), why
    return 'unknown', why


# --- ids promised to a migration of this process ---------------------------------------------

def _live(key):
    held = _claims.get(key)
    if held is None:
        return None
    try:
        alive = bool(held[1]())
    except Exception:
        alive = False
    if not alive:
        _claims.pop(key, None)
        return None
    return held[0]


def holder(cluster_id, vmid):
    """Who holds vmid on the cluster now, None when nobody"""
    with _lock:
        return _live((str(cluster_id), int(vmid)))


def claim(cluster_id, vmid, owner, alive, replaces=None):
    """Hold vmid on the cluster for owner while alive() is true. None when it is owner's now,
    else who holds it. replaces: an owner whose hold this one takes over (a bulk run handing
    a guest's id to the migration it starts)."""
    key = (str(cluster_id), int(vmid))
    with _lock:
        have = _live(key)
        if have is not None and have != owner and (replaces is None or have != replaces):
            return have
        _claims[key] = (owner, alive)
        return None


def claimed(cluster_id):
    """The ids held on the cluster"""
    cid = str(cluster_id)
    with _lock:
        return {v for (c, v) in list(_claims) if c == cid and _live((c, v)) is not None}


def let_go(cluster_id, vmid, owner):
    key = (str(cluster_id), int(vmid))
    with _lock:
        if (_claims.get(key) or (None,))[0] == owner:
            del _claims[key]


def release(owner):
    """Every id owner holds is free again"""
    with _lock:
        for key in [k for k, h in _claims.items() if h[0] == owner]:
            del _claims[key]


def until_over(lookup, mid):
    """alive() of a hold taken for a migration about to be registered: true while that
    migration runs, and for a short while before it is there at all"""
    since = time.time()

    def alive():
        t = lookup(mid)
        if t is None:
            return time.time() - since < UNSTARTED_SECONDS
        return getattr(t, 'status', '') == 'running'
    return alive


# --- the checks of a request -----------------------------------------------------------------

def caller_range(user):
    """(start, end, strict) of the caller's tenant VMID range, (0, 0, False) for none. strict:
    no id outside it, for a caller who is no admin. An admin may name any id, so their full
    range falls back to the cluster's next id. Raises TenantRangeUnknown when the tenant table
    could not be read for a caller who is no admin."""
    from pegaprox.utils.rbac import acts_as_admin, quota_tenant, tenant_vmid_range, TenantRangeUnknown
    admin = acts_as_admin(user)
    try:
        start, end = tenant_vmid_range(quota_tenant(user))
    except TenantRangeUnknown:
        if not admin:
            raise
        logging.warning("[V2P] tenant table unreadable, an admin's migration takes the cluster's next VMID")
        return 0, 0, False
    return start, end, bool(start) and not admin


def refusal(user, cluster_id, mgr, vmid, mine=()):
    """(status, message) of why user may not land a guest under the chosen vmid on the
    cluster now, None when they may. mine: holders of it that are this request's own."""
    from pegaprox.utils.rbac import acts_as_admin, check_tenant_vmid, quota_tenant
    if not acts_as_admin(user):
        ok, msg = check_tenant_vmid(quota_tenant(user), vmid)
        if not ok:
            return 403, msg
    have = holder(cluster_id, vmid)
    if have is not None and have not in mine:
        return 409, f'VMID {vmid} is promised to another ESXi migration under way - choose another one'
    state, why = ask(mgr, vmid)
    if state == 'free':
        return None
    if state == 'unknown':
        return 502, f'The target cluster could not say whether VMID {vmid} is free: {why}'
    return 409, (f'VMID {vmid} cannot be used on the target cluster: {why} - choose another one, '
                 f'or leave it empty for the next free one')


def bind(task, vmid, start, end, strict, owner):
    """What the task needs to get its VMID without the request: the chosen id, or the range
    an automatic pick keeps to, and the holder name of its hold."""
    task._vmid_pick = {'vmid': vmid, 'range': (start, end) if start else None,
                       'strict': bool(strict), 'owner': owner}


# --- in the task, right before the VM shell is created -----------------------------------------

def _unread(rows):
    return not isinstance(rows, list) or getattr(rows, 'unavailable', False) is True


def _pick_in_range(mgr, cid, start, end, owner, alive):
    """(vmid, None), (None, why) when no pick can be made, (None, None) when the range is full"""
    try:
        # a few seconds old is fine: the list only names candidates, Proxmox VE confirms each
        # one, and the guests of a bulk run share one walk of the cluster instead of one each
        rows = mgr.get_vm_resources(max_age=RESOURCES_MAX_AGE)
    except Exception as e:
        rows = None
        logging.warning(f"[V2P] guests of {cid} unreadable for a VMID pick: {e}")
    if _unread(rows):
        return None, (f'The guests of the target cluster could not be read, so no free VMID in the '
                      f'tenant range {start}-{end} could be picked')
    tries = 0
    for v in free_ids(rows, start, end, skip=claimed(cid)):
        if claim(cid, v, owner, alive) is not None:
            continue
        state, why = ask(mgr, v)
        if state == 'free':
            return v, None
        let_go(cid, v, owner)
        if state != 'taken':
            return None, f'No VMID in the tenant range {start}-{end} could be picked: VMID {v}: {why}'
        tries += 1
        if tries >= PICK_TRIES:
            return None, (f'No free VMID found in the tenant range {start}-{end}: the first {PICK_TRIES} '
                          f'the guest list showed as free are taken')
    return None, None


def _cluster_next(mgr, cid, owner, alive):
    """Proxmox VE's own next id, or the next one up when a migration here holds that one.
    Without an owner nothing is held: the answer as it always was."""
    try:
        resp = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/nextid")
        v = int(resp.json().get('data', 100)) if resp.status_code == 200 else None
        if not v:
            return None, 'Cannot allocate Proxmox VMID'
    except Exception as e:
        return None, f'Proxmox API error: {e}'
    if owner is None:
        return v, None
    first = v
    for _ in range(PICK_TRIES):
        # one held here went to a migration that has not created its guest yet, which
        # Proxmox VE does not know of: the next one up, if Proxmox VE takes that
        if holder(cid, v) is None:
            state, why = ('free', '') if v == first else ask(mgr, v)
            if state == 'free' and claim(cid, v, owner, alive) is None:
                return v, None
            if state not in ('free', 'taken'):
                return None, f'Cannot allocate Proxmox VMID: VMID {v}: {why}'
        v += 1
    return None, 'Cannot allocate Proxmox VMID: the next ones are held by other ESXi migrations'


def allocate(mgr, task):
    """(vmid, None) for the VMID the migration creates its guest under, (None, why) when it
    gets none. The chosen one only if Proxmox VE still takes it."""
    pick = getattr(task, '_vmid_pick', None)
    if not pick:
        # no route bound it (both routes do): the cluster's next id, nothing held
        return _cluster_next(mgr, None, None, None)
    cid = str(task.target_cluster)
    owner = pick.get('owner') or f'task:{task.id}'

    def alive():
        return getattr(task, 'status', '') == 'running'

    chosen = pick.get('vmid')
    rng = pick.get('range')
    if chosen:
        if pick.get('strict') and rng and not rng[0] <= chosen <= rng[1]:
            return None, f"VMID {chosen} is outside this tenant's range ({rng[0]}-{rng[1]})"
        if claim(cid, chosen, owner, alive) is not None:
            return None, (f'VMID {chosen} went to another ESXi migration after this one was checked. '
                          f'Nothing was created on the target - start it again with another VMID')
        state, why = ask(mgr, chosen)
        if state == 'free':
            return chosen, None
        let_go(cid, chosen, owner)
        if state == 'unknown':
            return None, (f'The target cluster could not say whether VMID {chosen} is still free ({why}). '
                          f'Nothing was created there')
        return None, (f'VMID {chosen} was taken on the target cluster after the migration was checked '
                      f'({why}). Nothing was created there - start the migration again with another '
                      f'VMID, or without one for the next free one')
    if rng:
        got, why = _pick_in_range(mgr, cid, rng[0], rng[1], owner, alive)
        if got or why:
            return got, why
        if pick.get('strict'):
            return None, f'No free VMID is left in the tenant range {rng[0]}-{rng[1]} on the target cluster'
        logging.info(f"[V2P] tenant range {rng[0]}-{rng[1]} full on {cid}, an admin's migration "
                     f"takes the cluster's next VMID")
    return _cluster_next(mgr, cid, owner, alive)


def reset_for_tests():
    with _lock:
        _claims.clear()
