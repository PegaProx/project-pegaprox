# -*- coding: utf-8 -*-
"""Change plans with four-eyes approval - NS Oct 2026.

A plan says what is going to change on a cluster and when. Whoever asks for it submits it,
a second administrator approves or rejects it, and config drift (api/drift.py) marks the
deviations inside an approved plan as planned. This stage runs nothing and blocks nothing:
a direct action on the cluster is not asked about a plan.

Who approves:
  * changes.approve is held by administrators; a custom role may hold it too.
  * Whoever requested a plan never approves or rejects it. The comparison is on the
    account, so a second session or an API token of the same account is the same person.
  * An administrator approves any plan of a cluster they reach. A holder who is not one
    (a tenant's administrator) approves plans for guests they reach themselves, and none
    that change something the cluster's tenants share: nodes, storage, network, firewall,
    HA, backup jobs, access or the cluster options.

The table is shared with the standbys (core/ha.py SYNC_TABLES); a write that reaches a
standby goes to the active like every other write.
"""
import json
import logging
import uuid

from flask import Blueprint, g, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth, build_authz_user
from pegaprox.utils.rbac import (acts_as_admin, has_permission, get_user_clusters,
                                 user_can_access_vm, tenant_vmid_range, acting_tenant,
                                 TenantRangeUnknown)
from pegaprox.api.helpers import bounded_limit, caller_is_scoped, check_cluster_access
from pegaprox.core import changes as plans
from pegaprox.core.db import get_db

bp = Blueprint('changes', __name__)

# plans read before the caller's own filter cuts the list down
SCAN = 2000


# --- the caller ------------------------------------------------------------------------

def _me():
    return request.session.get('user', '') or ''


def _caller():
    return build_authz_user(_me(), request.session)


def _same_person(a, b):
    return bool(a) and str(a).strip().lower() == str(b or '').strip().lower()


def _audit(action, plan, detail=''):
    try:
        from pegaprox.utils.audit import log_audit
        text = f"change plan {plan['id']} '{plan['title']}'" + (f' - {detail}' if detail else '')
        log_audit(_me(), action, text, cluster_id=plan['cluster_id'])
    except Exception as e:
        logging.debug(f"[changes] audit entry failed: {e}")


def _json_error(msg, http, code=None, **extra):
    body = {'error': msg}
    if code:
        body['code'] = code
    body.update(extra)
    return jsonify(body), http


# --- rows ------------------------------------------------------------------------------

def _plan(row):
    d = dict(row)
    try:
        d['scope'] = json.loads(d.get('scope') or '{}')
    except ValueError:
        d['scope'] = {'kind': '', 'targets': []}
    return d


def _load(pid):
    try:
        r = get_db().query_one('SELECT * FROM change_plans WHERE id = ?', (pid,))
    except Exception:
        logging.exception('[changes] plan not read')
        return None
    return _plan(r) if r else None


def _stamp():
    return plans.iso_utc(plans.now_utc())


def _cluster_known(cid):
    if cid in cluster_managers:
        return True
    try:
        return get_db().query_one('SELECT 1 FROM clusters WHERE id = ?', (cid,)) is not None
    except Exception:
        return False


# --- scope and reach -------------------------------------------------------------------

def _guests_reached(user, cid, vmids):
    # a list names the same guests plan after plan, and each plan is asked twice in _view:
    # one answer per guest and request
    memo = getattr(g, '_chg_reached', None)
    if memo is None:
        memo = g._chg_reached = {}
    who = (user.get('username'), user.get('effective_role'))
    for v in vmids:
        key = who + (cid, int(v))
        if key not in memo:
            memo[key] = user_can_access_vm(user, cid, int(v), 'vm.view')
        if not memo[key]:
            return False
    return True


def _in_own_tenant(user, cid, vmids):
    """A guest is in the caller's tenant when the cluster is one of their tenant's, they
    reach the guest, and, where their tenant has a slice of VMIDs, it lies inside it."""
    # NS Oct 2026 - a VM ACL or a pool grant reaches a guest on someone else's cluster, a
    # '*' row every account; neither makes it theirs to approve for. Same line as the role
    # fall-through in rbac.user_can_access_vm.
    try:
        own = get_user_clusters(user, include_pools=False)
    except Exception:
        logging.exception('[changes] clusters of the approver not read')
        return False
    if own is not None and cid not in own:
        return False
    if not _guests_reached(user, cid, vmids):
        return False
    tenant = acting_tenant(user)
    if tenant is None:
        return True
    try:
        start, end = tenant_vmid_range(tenant)
    except TenantRangeUnknown:
        return False
    if start == 0:
        return True
    return all(start <= int(v) <= end for v in vmids)


def _request_refusal(user, cid, scope):
    """Why this caller may not put this scope in a plan on this cluster, or None."""
    if scope['kind'] in plans.CLUSTER_WIDE:
        if caller_is_scoped(user, cid):
            return 'this plan changes the whole cluster, which is beyond what you reach here'
        return None
    if not _guests_reached(user, cid, scope['targets']):
        return 'one of the guests is outside what you reach'
    return None


def _approval_refusal(plan, user):
    """(code, why) when this caller may not approve the plan whatever its state, else None."""
    if _same_person(plan['requested_by'], _me()):
        return 'own_plan', 'you requested this plan: a second person approves it'
    return _approval_scope_refusal(plan, user)


def _approval_scope_refusal(plan, user):
    if not has_permission(user, 'changes.approve'):
        return 'no_permission', 'you may not approve change plans'
    ok, _err = check_cluster_access(plan['cluster_id'])
    if not ok:
        return 'out_of_scope', 'this cluster is outside what you reach'
    if acts_as_admin(user):
        return None
    kind = plan['scope'].get('kind')
    if kind != 'guests':
        return 'out_of_scope', 'only an administrator approves a change that affects the whole cluster'
    if not _in_own_tenant(user, plan['cluster_id'], plan['scope'].get('targets') or []):
        return 'out_of_scope', 'a guest of this plan is outside your tenant'
    return None


def _visible(plan, user, cache):
    cid = plan['cluster_id']
    if cid not in cache:
        cache[cid] = check_cluster_access(cid)[0]
    if not cache[cid]:
        return False
    if _same_person(plan['requested_by'], _me()):
        return True
    if not caller_is_scoped(user, cid):
        return True
    # confined to some guests: the plans for guests they reach, nothing about the cluster
    s = plan['scope']
    return s.get('kind') == 'guests' and _guests_reached(user, cid, s.get('targets') or [])


def _view(plan, user, now):
    """The plan as the page gets it, with what this caller may do with it right now."""
    out = dict(plan)
    st = plan['status']
    me = _me()
    mine = _same_person(plan['requested_by'], me)
    out['display_status'] = plans.derived_status(plan, now)
    out['expired'] = out['display_status'] == 'expired'
    out['mine'] = mine
    blocked = None
    if st == 'submitted':
        blocked = _approval_refusal(plan, user)
    out['approve_blocked'] = blocked[0] if blocked else ''
    out['approve_blocked_reason'] = blocked[1] if blocked else ''
    can_request = has_permission(user, 'changes.request')
    # who may close a plan is only worked out for a plan that is still open
    closer = st in ('draft', 'submitted', 'approved') and (
        (mine and can_request) or _approval_scope_refusal(plan, user) is None)
    out['can'] = {
        'edit': mine and can_request and st == 'draft',
        'submit': mine and can_request and st == 'draft',
        'approve': st == 'submitted' and blocked is None and not out['expired'],
        'reject': st == 'submitted' and blocked is None,
        'cancel': closer,
        'done': st == 'approved' and closer,
    }
    return out


# --- reads -----------------------------------------------------------------------------

@bp.route('/api/changes', methods=['GET'])
@require_auth(perms=['changes.view'])
def list_changes():
    cid = request.args.get('cluster', '') or request.args.get('cluster_id', '')
    status = request.args.get('status', '')
    if status and status not in plans.STATUSES + ('expired',):
        return _json_error('unknown status', 400, statuses=list(plans.STATUSES) + ['expired'])
    limit = bounded_limit(request.args.get('limit'), default=200, maximum=500)
    user, now = _caller(), plans.now_utc()
    where, args = [], []
    try:
        if cid:
            ok, err = check_cluster_access(cid)
            if not ok:
                return err
            reach = [cid]
        else:
            # NS Oct 2026 - only the clusters the caller reaches go into the read: the newest
            # SCAN rows of all of them left a tenant nothing of its own once others had more
            reach = [r['cluster_id'] for r in get_db().query('SELECT DISTINCT cluster_id FROM change_plans')
                     if check_cluster_access(r['cluster_id'])[0]]
            if not reach:
                return jsonify({'changes': [], 'me': _me()})
        where.append(f"cluster_id IN ({','.join('?' * len(reach))})")
        args.extend(reach)
        # expired is derived; the read takes the open plans whose window is over, and the
        # filter below has the last word
        if status == 'expired':
            where.append("status IN ('draft', 'submitted', 'approved') AND window_end < ?")
            args.append(plans.iso_utc(now))
        elif status:
            where.append('status = ?')
            args.append(status)
        rows = get_db().query('SELECT * FROM change_plans WHERE ' + ' AND '.join(where)
                              + ' ORDER BY updated_at DESC, id LIMIT ?', tuple(args) + (SCAN,))
    except Exception:
        logging.exception('[changes] list not read')
        return _json_error('internal error', 500)
    cache, out = {}, []
    for r in rows:
        p = _plan(r)
        if status == 'expired' and plans.derived_status(p, now) != 'expired':
            continue
        if not _visible(p, user, cache):
            continue
        out.append(_view(p, user, now))
        if len(out) >= limit:
            break
    return jsonify({'changes': out, 'me': _me()})


@bp.route('/api/changes/<pid>', methods=['GET'])
@require_auth(perms=['changes.view'])
def get_change(pid):
    p = _load(pid)
    user = _caller()
    # a plan the caller may not see is, to them, a plan that is not there
    if not p or not _visible(p, user, {}):
        return _json_error('not found', 404)
    return jsonify(_view(p, user, plans.now_utc()))


# --- writes ----------------------------------------------------------------------------

def _text(body, key, limit, required=False):
    """(value, error) of a text field of the body."""
    v = body.get(key, '')
    if v is None:
        v = ''
    if not isinstance(v, str):
        return None, f'{key} must be text'
    v = v.strip()
    if required and not v:
        return None, f'{key} is required'
    if len(v) > limit:
        return None, f'{key} is at most {limit} characters'
    return v, None


def _window_fields(body, current=None):
    """(start iso or None, end iso or None, error): the stored shape of the window in the body."""
    out = []
    for key in ('window_start', 'window_end'):
        if key not in body and current is not None:
            out.append(current.get(key))
            continue
        raw = body.get(key)
        if raw in (None, ''):
            out.append(None)
            continue
        dt = plans.parse_utc(raw)
        if dt is None:
            return None, None, f'{key} is not a date and time'
        out.append(plans.iso_utc(dt))
    start, end = plans.parse_utc(out[0]), plans.parse_utc(out[1])
    if start and end and end <= start:
        return None, None, 'the window must end after it starts'
    return out[0], out[1], None


@bp.route('/api/changes', methods=['POST'])
@require_auth(perms=['changes.request'])
def create_change():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _json_error('a JSON object is required', 400)
    cid = body.get('cluster_id')
    if not isinstance(cid, str) or not cid:
        return _json_error('cluster_id is required', 400)
    # a cluster outside the caller's reach answers like one that does not exist
    ok, _err = check_cluster_access(cid)
    if not ok or not _cluster_known(cid):
        return _json_error('cluster not found', 404)
    title, e1 = _text(body, 'title', plans.TITLE_MAX, required=True)
    desc, e2 = _text(body, 'description', plans.TEXT_MAX)
    scope, e3 = plans.clean_scope(body.get('scope'))
    start, end, e4 = _window_fields(body)
    err = e1 or e2 or e3 or e4
    if err:
        return _json_error(err, 400)
    user = _caller()
    why = _request_refusal(user, cid, scope)
    if why:
        return _json_error(f'Access denied: {why}', 403)
    now = _stamp()
    row = {
        'id': uuid.uuid4().hex[:12], 'cluster_id': cid, 'title': title, 'description': desc,
        'scope': json.dumps(scope), 'window_start': start, 'window_end': end, 'status': 'draft',
        'requested_by': _me(), 'requester_tenant': str(user.get('tenant_id') or ''),
        'created_at': now, 'updated_at': now,
    }
    try:
        db = get_db()
        db.conn.execute(
            'INSERT INTO change_plans (id, cluster_id, title, description, scope, window_start, '
            'window_end, status, requested_by, requester_tenant, created_at, updated_at) '
            'VALUES (:id, :cluster_id, :title, :description, :scope, :window_start, :window_end, '
            ':status, :requested_by, :requester_tenant, :created_at, :updated_at)', row)
        db.conn.commit()
    except Exception:
        logging.exception('[changes] plan not stored')
        return _json_error('internal error', 500)
    plan = _load(row['id'])
    _audit('change.create', plan, f"scope {scope['kind']}")
    return jsonify(_view(plan, user, plans.now_utc())), 201


def _own_plan(pid):
    """(plan, None) for a plan the caller requested and may see, else (None, error response)."""
    p = _load(pid)
    user = _caller()
    if not p or not _visible(p, user, {}):
        return None, _json_error('not found', 404)
    if not _same_person(p['requested_by'], _me()):
        return None, _json_error('Access denied: only the person who requested a plan changes it', 403)
    return p, None


def _step(plan, action):
    """The status `action` leads to from the plan's, or None when the plan is not there."""
    return plans.TRANSITIONS.get(plan['status'], {}).get(action)


_VERBS = {'submit': 'submitted', 'approve': 'approved', 'reject': 'rejected',
          'cancel': 'cancelled', 'done': 'marked done'}


def _not_now(plan, action):
    return _json_error(f"a plan that is {plan['status']} cannot be {_VERBS[action]}",
                       409, code='INVALID_TRANSITION', status=plan['status'])


def _move(plan, action, sets, keep=()):
    """Write the transition and the fields with it; False when the plan changed under us.
    keep: columns that must still hold what the caller read and judged."""
    after = plans.TRANSITIONS[plan['status']][action]
    cols = dict(sets, status=after, updated_at=_stamp())
    sql = ('UPDATE change_plans SET ' + ', '.join(f'{k} = ?' for k in cols) + ' WHERE id = ? AND status = ?'
           + ''.join(f' AND {k} IS ?' for k in keep))
    db = get_db()
    cur = db.conn.execute(sql, tuple(cols.values()) + (plan['id'], plan['status'])
                          + tuple(plan[k] for k in keep))
    db.conn.commit()
    return cur.rowcount == 1


@bp.route('/api/changes/<pid>', methods=['PUT'])
@require_auth(perms=['changes.request'])
def edit_change(pid):
    p, bad = _own_plan(pid)
    if bad:
        return bad
    if p['status'] != 'draft':
        return _json_error('only a draft is edited: cancel this plan and request a new one', 409,
                           code='INVALID_TRANSITION', status=p['status'])
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return _json_error('a JSON object is required', 400)
    sets = {}
    if 'title' in body:
        v, err = _text(body, 'title', plans.TITLE_MAX, required=True)
        if err:
            return _json_error(err, 400)
        sets['title'] = v
    if 'description' in body:
        v, err = _text(body, 'description', plans.TEXT_MAX)
        if err:
            return _json_error(err, 400)
        sets['description'] = v
    user = _caller()
    if 'scope' in body:
        scope, err = plans.clean_scope(body.get('scope'))
        if err:
            return _json_error(err, 400)
        why = _request_refusal(user, p['cluster_id'], scope)
        if why:
            return _json_error(f'Access denied: {why}', 403)
        sets['scope'] = json.dumps(scope)
    if 'window_start' in body or 'window_end' in body:
        start, end, err = _window_fields(body, p)
        if err:
            return _json_error(err, 400)
        sets['window_start'], sets['window_end'] = start, end
    if not sets:
        return _json_error('nothing to change', 400)
    sets['updated_at'] = _stamp()
    try:
        db = get_db()
        cur = db.conn.execute('UPDATE change_plans SET ' + ', '.join(f'{k} = ?' for k in sets)
                              + " WHERE id = ? AND status = 'draft'", tuple(sets.values()) + (pid,))
        db.conn.commit()
    except Exception:
        logging.exception('[changes] plan not stored')
        return _json_error('internal error', 500)
    if cur.rowcount != 1:
        return _json_error('the plan changed meanwhile', 409, code='INVALID_TRANSITION')
    plan = _load(pid)
    _audit('change.edit', plan, ', '.join(sorted(k for k in sets if k != 'updated_at')))
    return jsonify(_view(plan, user, plans.now_utc()))


@bp.route('/api/changes/<pid>/submit', methods=['POST'])
@require_auth(perms=['changes.request'])
def submit_change(pid):
    p, bad = _own_plan(pid)
    if bad:
        return bad
    if _step(p, 'submit') is None:
        return _not_now(p, 'submit')
    start, end = plans.parse_utc(p['window_start']), plans.parse_utc(p['window_end'])
    why = plans.window_problem(start, end)
    if why:
        return _json_error(why, 400, code='BAD_WINDOW')
    user = _caller()
    # what the requester reaches today, not when the draft was written
    refusal = _request_refusal(user, p['cluster_id'], p['scope'])
    if refusal:
        return _json_error(f'Access denied: {refusal}', 403)
    try:
        # a draft is edited without the window rules; one edited since they were checked
        # above is not submitted with them unchecked (an edited scope was judged by the edit)
        moved = _move(p, 'submit', {}, keep=('window_start', 'window_end'))
    except Exception:
        logging.exception('[changes] plan not stored')
        return _json_error('internal error', 500)
    if not moved:
        return _json_error('the plan changed meanwhile', 409, code='INVALID_TRANSITION')
    plan = _load(pid)
    _audit('change.submit', plan, f"window {plan['window_start']} to {plan['window_end']}")
    return jsonify(_view(plan, user, plans.now_utc()))


def _reviewable(pid):
    """(plan, user, None) for a submitted plan the caller may decide on, else an error response."""
    p = _load(pid)
    user = _caller()
    if not p or not _visible(p, user, {}):
        return None, user, _json_error('not found', 404)
    refusal = _approval_refusal(p, user)
    if refusal:
        return None, user, _json_error(f'Access denied: {refusal[1]}', 403, code=refusal[0].upper())
    return p, user, None


@bp.route('/api/changes/<pid>/approve', methods=['POST'])
@require_auth(perms=['changes.approve'])
def approve_change(pid):
    p, user, bad = _reviewable(pid)
    if bad:
        return bad
    if _step(p, 'approve') is None:
        return _not_now(p, 'approve')
    if plans.window_over(p):
        return _json_error('the window of this plan is over: request a new one', 409, code='WINDOW_OVER')
    now = _stamp()
    try:
        moved = _move(p, 'approve', {'approved_by': _me(), 'approved_at': now})
    except Exception:
        logging.exception('[changes] plan not stored')
        return _json_error('internal error', 500)
    if not moved:
        return _json_error('the plan changed meanwhile', 409, code='INVALID_TRANSITION')
    plan = _load(pid)
    _audit('change.approve', plan, f"requested by {plan['requested_by']}")
    return jsonify(_view(plan, user, plans.now_utc()))


@bp.route('/api/changes/<pid>/reject', methods=['POST'])
@require_auth(perms=['changes.approve'])
def reject_change(pid):
    p, user, bad = _reviewable(pid)
    if bad:
        return bad
    body = request.get_json(silent=True)
    reason, err = _text(body if isinstance(body, dict) else {}, 'reason', plans.REASON_MAX, required=True)
    if err:
        return _json_error(err, 400)
    if _step(p, 'reject') is None:
        return _not_now(p, 'reject')
    try:
        moved = _move(p, 'reject', {'rejected_by': _me(), 'rejected_at': _stamp(), 'reject_reason': reason})
    except Exception:
        logging.exception('[changes] plan not stored')
        return _json_error('internal error', 500)
    if not moved:
        return _json_error('the plan changed meanwhile', 409, code='INVALID_TRANSITION')
    plan = _load(pid)
    _audit('change.reject', plan, reason)
    return jsonify(_view(plan, user, plans.now_utc()))


def _close(pid, action):
    """cancel and done: the requester, or someone who may approve this plan."""
    p = _load(pid)
    user = _caller()
    if not p or not _visible(p, user, {}):
        return _json_error('not found', 404)
    mine = _same_person(p['requested_by'], _me())
    if not ((mine and has_permission(user, 'changes.request')) or _approval_scope_refusal(p, user) is None):
        return _json_error('Access denied: only the requester or someone who may approve it does that', 403)
    if _step(p, action) is None:
        return _not_now(p, action)
    try:
        moved = _move(p, action, {})
    except Exception:
        logging.exception('[changes] plan not stored')
        return _json_error('internal error', 500)
    if not moved:
        return _json_error('the plan changed meanwhile', 409, code='INVALID_TRANSITION')
    plan = _load(pid)
    _audit(f'change.{action}', plan)
    return jsonify(_view(plan, user, plans.now_utc()))


@bp.route('/api/changes/<pid>/cancel', methods=['POST'])
@require_auth(perms=['changes.view'])
def cancel_change(pid):
    return _close(pid, 'cancel')


@bp.route('/api/changes/<pid>/done', methods=['POST'])
@require_auth(perms=['changes.view'])
def done_change(pid):
    return _close(pid, 'done')
