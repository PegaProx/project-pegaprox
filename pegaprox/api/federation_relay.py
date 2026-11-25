# -*- coding: utf-8 -*-
"""Linked mode routes: other sites' clusters, worked on from this instance.

The entry (this site, E): /api/federation/relay/<iid>/clusters/<raw>[/...] takes what
RemotePaths moved there, signed in like any route, and sends it to the site that leads the
cluster (L). /api/federation/linked is the list of every site's clusters for the caller,
each site asked through the same relay.

The leading side (L): RELAY_PATH takes a member's relayed request, checks its signature
from the headers before it reads the body, and runs it through this app as the mirror of
the account the sender homes (core/federation_relay.py). /api/federation/linked/self is
what a site answers for the list, inside such a request only.

The routes answer 404 FED_DISABLED while the federation is off. The gate is this
blueprint's own; no app-wide hook comes with linked mode.

MK Nov 2026
"""
import contextvars
import io
import json
import logging
import os
import sys
import threading
import time

from flask import Blueprint, Response, current_app, jsonify, request

from pegaprox.core import federation as fed
from pegaprox.core import federation_migrate as fmig
from pegaprox.core import federation_relay as relay
from pegaprox.core import federation_signin as fsign
from pegaprox.core import federation_stream as fstream
from pegaprox.core import ha_wire
from pegaprox.core import migration_tunnel
from pegaprox.api.realtime import sock
from pegaprox.constants import PEGAPROX_VERSION
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import RELAY_ENVIRON, lift_body_deadline, require_auth

bp = Blueprint('federation_relay', __name__)


_PREFIX = '/api/federation/relay/'


# cluster routes that answer relayed requests only, which do not exist while off: they
# refuse on their own, after the hooks every cluster route passes
RELAY_ONLY_ENDPOINTS = frozenset({'federation_relay.console_token',
                                  'federation_relay.migration_target'})


@bp.before_request
def _refuse_while_switched_off():
    if fed.enabled() or request.endpoint in RELAY_ONLY_ENDPOINTS:
        return None
    return jsonify({'error': fed.FED_DISABLED_ERROR, 'code': 'FED_DISABLED'}), 404


def _fail(status, code, error, **extra):
    body = {'code': code, 'error': error}
    body.update(extra)
    resp = jsonify(body)
    resp.status_code = status
    return resp


def _home_of(username):
    """The instance id that homes `username` here: '' for an account of this instance."""
    from pegaprox.core.db import get_db
    row = get_db().conn.execute('SELECT fed_home FROM users WHERE username = ?',
                                (username,)).fetchone()
    return (row['fed_home'] or '') if row is not None else ''


def _site_of(iid):
    rec = fed.member_record(iid) or {}
    return {'iid': iid, 'site': rec.get('site') or iid[:8], 'url': rec.get('url') or ''}


def _token_role(session):
    """The built-in role an API token acts with here (its own, floored to its owner's), or
    None for a token whose role is a custom one."""
    role = session.get('effective_role') or session.get('role')
    return role if role in relay.TOKEN_ROLES else None


def _caller(session):
    """(principal, None) of this request's caller for the relay, or (None, refusal) when the
    caller cannot work on other sites' clusters from here: an API token with a custom role,
    an account another site homes that did not sign in here through it."""
    user = session.get('user') or ''
    if session.get('api_token'):
        if _token_role(session) is None:
            return None, _fail(403, 'FED_RELAY_TOKEN', 'An API token with a custom role works at '
                                                       'its own site only: a token with a '
                                                       "built-in role works on other sites' "
                                                       'clusters too')
        if _home_of(user):
            return None, _elsewhere(user)
        return {'user': user, 'home': fed.instance_id(),
                'sh': relay.session_handle(f"token:{session.get('token_id')}"),
                'ip': get_client_ip() or '', 'tok': _token_role(session)}, None
    sid = request.headers.get('X-Session-ID') or request.cookies.get('session_id') or ''
    if _home_of(user):
        principal = fsign.principal(sid, user, get_client_ip())
        return (principal, None) if principal else (None, _elsewhere(user))
    return {'user': user, 'home': fed.instance_id(), 'sh': relay.session_handle(sid),
            'ip': get_client_ip() or ''}, None


def _elsewhere(user):
    return _fail(403, 'FED_HOME_ELSEWHERE', 'Your account belongs to another site: sign in '
                                            "again to work on other sites' clusters from here, "
                                            'or work from your home site',
                 home=_site_of(_home_of(user)))


# --- the entry ---------------------------------------------------------------------------------

_RELAY_RULES = ('/api/federation/relay/<iid>/clusters/<raw>',
                '/api/federation/relay/<iid>/clusters/<raw>/<path:rest>')


def relay_entry(iid, raw, rest=''):
    """A request for a cluster of member `iid`, run there as the caller."""
    if request.environ.get(RELAY_ENVIRON):
        return _fail(400, 'FED_RELAY_CHAIN', 'A relayed request is not relayed again')
    if not (fed.CLUSTER_ID_RE.fullmatch(raw) and ha_wire.ID_RE.fullmatch(iid)
            and iid != fed.instance_id() and fed.member_record(iid) is not None):
        return _fail(404, 'FED_UNKNOWN_SITE', 'No such site in this federation')
    session = request.session
    principal, refused = _caller(session)
    if refused is not None:
        return refused
    method = request.method
    path = '/api' + request.path[len(_PREFIX) + len(iid):]
    rule, _args = relay.match_rule(current_app, method, path)
    reason = relay.rule_verdict(current_app, method, rule) if rule is not None else 'scope'
    if rule is not None and rule.rule in relay.SERVER_RULES:
        # this site asks for these itself (the console tunnel, a migration); a browser that
        # held what they answer would go round both
        reason = 'transport'
    site = _site_of(iid)
    if reason:
        return _fail(404, 'FED_RELAY_RULE', relay.REASONS[reason], reason=reason, **site)
    if rule.rule == relay.UPLOAD_RULE:
        return _relay_upload(iid, raw, rule, path, session, site, principal)
    write = method not in relay._SAFE_METHODS
    # the body before a slot: a client that sends it slowly holds its own request, not one
    # of the site's slots
    request.max_content_length = relay.MAX_BODY
    body = request.get_data(cache=False) if write else b''
    if relay._broken(iid):
        resp = _fail(503, 'FED_SITE_UNREACHABLE', f'{site["site"]} does not answer', **site)
        resp.headers['Retry-After'] = str(relay._BREAK_FOR)
        return resp
    if not relay.account_call(iid, principal.get('user') or ''):
        resp = _fail(429, 'FED_RELAY_BUSY', 'Too many requests to that site from your account - '
                                            'try again in a minute')
        resp.headers['Retry-After'] = '30'
        return resp
    if not relay.take_slot(iid, principal.get('user') or ''):
        resp = _fail(429, 'FED_RELAY_BUSY', 'Too many requests to that site at once - try again')
        resp.headers['Retry-After'] = '5'
        return resp
    started = time.monotonic()
    try:
        kind, status, headers, out = relay.relay_call(
            iid, method, path, request.environ.get('QUERY_STRING') or '', body,
            request.headers.get('Content-Type') or '', principal,
            read_timeout=relay.WRITE_TIMEOUT if write else relay.READ_TIMEOUT)
        relay.note_answer(iid, kind, started)
    finally:
        relay.give_slot(iid, principal.get('user') or '')
    status, headers, out = relay.browser_answer(kind, status, headers, out, write)
    if write:
        log_audit(session.get('user') or '', 'federation.relayed',
                  f'{method} {rule.rule} on cluster {raw} at {site["site"]}: {status}',
                  ip_address=get_client_ip())
    resp = Response(out, status=status)
    for k, v in headers.items():
        resp.headers[k] = v
    resp.headers[relay.SITE_HEADER] = iid
    request.environ[relay.RELAYED_ENVIRON] = True
    return resp


def _relay_upload(iid, raw, rule, path, session, site, principal):
    """An upload to a datastore of member `iid`'s cluster: written to a file here first, its
    digest signed, then sent from the file. The answer comes when the site has handed the
    upload to Proxmox, as for an upload to a cluster of this instance."""
    if relay._broken(iid):
        resp = _fail(503, 'FED_SITE_UNREACHABLE', f'{site["site"]} does not answer', **site)
        resp.headers['Retry-After'] = str(relay._BREAK_FOR)
        return resp
    # what the site lets the account do there (its list, kept half a minute): no upload is
    # written to disk here for an account that may not upload there, nor while that is not
    # known (the list unread, or the site refusing the account)
    there = relay.site_list(iid, fed.member_record(iid) or {}, principal)
    state = there.get('state')
    if state != 'ok':
        code = {v: k for k, v in relay._LIST_STATES.items()}.get(state)
        if code:
            return _fail(403, code, f'{site["site"]} does not take your account for this now',
                         **site)
        resp = _fail(503, 'FED_SITE_UNREACHABLE', f'What you may do at {site["site"]} cannot be '
                                                  'read now - try again in a moment', **site)
        resp.headers['Retry-After'] = '30'
        return resp
    if not there.get('admin') and 'storage.upload' not in (there.get('perms') or []):
        return _fail(403, 'MISSING_PERMISSION', 'Permission denied: storage.upload', **site)
    user = principal.get('user') or ''
    if not relay.take_upload(user):
        resp = _fail(429, 'FED_RELAY_BUSY', 'One of your uploads runs already - try again when '
                                            'it has finished')
        resp.headers['Retry-After'] = '30'
        return resp
    spooled, holding = None, False
    try:
        request.max_content_length = relay.MAX_UPLOAD
        try:
            spooled, digest = relay.spool(request.stream, request.content_length)
        except relay.UploadRefused as e:
            return _fail(e.status, e.code, e.error)
        # the site's slot once the file is here: a body that comes slowly, or never, holds
        # its own account's upload only, not one of the two this site sends to that one
        holding = relay.take_upload_slot(iid)
        if not holding:
            resp = _fail(429, 'FED_RELAY_BUSY', 'Too many uploads to that site at once - try '
                                                'again when one has finished')
            resp.headers['Retry-After'] = '30'
            return resp
        size = os.path.getsize(spooled)
        started = time.monotonic()
        with open(spooled, 'rb') as fh:
            kind, status, headers, out = relay.relay_call(
                iid, 'POST', path, request.environ.get('QUERY_STRING') or '',
                ctype=request.headers.get('Content-Type') or '', principal=principal,
                read_timeout=relay.UPLOAD_TIMEOUT, upload=(fh, size, digest))
        relay.note_answer(iid, kind, started)
    finally:
        relay.drop_spooled(spooled)
        if holding:
            relay._uploads_out.give(iid)
        relay.give_upload(user)
    status, headers, out = relay.browser_answer(kind, status, headers, out, True)
    log_audit(session.get('user') or '', 'federation.relayed',
              f'POST {rule.rule} on cluster {raw} at {site["site"]} ({size} bytes): {status}',
              ip_address=get_client_ip())
    resp = Response(out, status=status)
    for k, v in headers.items():
        resp.headers[k] = v
    resp.headers[relay.SITE_HEADER] = iid
    request.environ[relay.RELAYED_ENVIRON] = True
    return resp


for _i, _rule in enumerate(_RELAY_RULES):
    bp.add_url_rule(_rule, 'relay_entry' if not _i else 'relay_entry_path',
                    require_auth()(relay_entry), methods=list(relay._METHODS))


@bp.route('/api/federation/linked', methods=['GET'])
@require_auth()
def linked_sites():
    """Every other site with the clusters the caller may see there, asked through the relay.
    {home, sites: [{iid, site, url, state, clusters, perms, release}]}; home names the
    site to work from when the caller's account belongs to another site."""
    session = request.session
    from pegaprox.core import ha
    if ha.is_standby() or not fed.instance_id():
        return jsonify({'home': None, 'sites': [], 'standby': ha.is_standby()})
    principal, refused = _caller(session)
    if refused is not None:
        home = (refused.get_json() or {}).get('home')
        if home and not session.get('api_token'):
            # an account of another site that did not sign in here through it
            return jsonify({'home': home, 'sites': []})
        return refused
    roster = sorted(fed.members().items())
    sites = fed._parallel(lambda item: relay.site_list(item[0], item[1], principal), roster)
    return jsonify({'home': None, 'sites': [s for s in sites if s]})


# --- the leading side --------------------------------------------------------------------------

def _signed(nonce, rid, sender, status, headers, body):
    resp = Response(body, status=200, mimetype='application/octet-stream')
    for k, v in relay.sign_answer(nonce, rid, sender, status, headers, body).items():
        resp.headers[k] = v
    return resp


def _signed_refusal(nonce, rid, sender, status, code, error):
    return _signed(nonce, rid, sender, status, {'Content-Type': 'application/json'},
                   json.dumps({'code': code, 'error': error}).encode())


def _peer_prelude():
    """The checks every relayed request passes before its envelope is believed: (refusal,
    None) or (None, (sender, site, nonce, rid, call)).

    Unsigned refusals, before anything of the request is believed: 503 FED_STANDBY on an
    HA standby, 410 FED_REMOVED, 403 FED_CLOCK, 403 FED_NOT_MEMBER. After the signature
    checked out a refusal is signed (_signed_refusal)."""
    from pegaprox.api import federation as api_fed
    refused = api_fed._standby_refusal(acting=True)
    if refused:
        return refused, None
    kind, who, envelope = relay.header_verdict(request)
    if kind == 'removed':
        return _fail(410, 'FED_REMOVED', 'This instance was removed from the federation'), None
    if kind == 'skewed':
        return (jsonify(fed.clock_refusal(who.get('skew') or 'window', time.time(), fed._started(),
                                          request.headers.get(ha_wire.PEER_TS_HEADER))), 403), None
    if kind == 'busy':
        # signed, over the rate (counted before its nonce, so the call spent none)
        rid = str((envelope or {}).get('rid') or '')
        return _signed_refusal(request.headers.get(ha_wire.PEER_NONCE_HEADER) or '', rid,
                               who['instance_id'], 429, 'FED_RELAY_BUSY',
                               'Too many relayed requests from your site'), None
    if kind != 'member':
        ip = get_client_ip()
        if not api_fed._peer_failures.allow(ip):
            resp = _fail(429, 'FED_BUSY', 'Too many failed peer calls')
            resp.headers['Retry-After'] = '300'
            return resp, None
        logging.warning(f'[FED] refused a relayed request from {ip}')
        return _fail(403, 'FED_NOT_MEMBER', 'Not a paired federation member'), None
    sender = who['instance_id']
    site = who.get('site') or sender[:8]
    nonce = request.headers.get(ha_wire.PEER_NONCE_HEADER) or ''
    call = relay.valid_envelope(envelope)
    rid = (call or {}).get('rid') or str((envelope or {}).get('rid') or '')
    # the address limit does not count a member's relays: its own rate (counted with the
    # signature, before the nonce) and slots do, the well-formed and the malformed alike
    if call is None:
        return _signed_refusal(nonce, rid, sender, 400, 'FED_RELAY_ENVELOPE',
                               'The relayed request is not well formed'), None
    return None, (sender, site, nonce, rid, call)


@bp.route(relay.RELAY_PATH, methods=['POST'])
def peer_relay():
    """A member's relayed request for one of the accounts it homes, answered with 200 and a
    signed answer envelope that carries the status: the inner request's, or a refusal
    (FED_RELAY_*) before it ran (_peer_prelude for the ones before the signature)."""
    refused, ctx = _peer_prelude()
    if refused is not None:
        return refused
    sender, site, nonce, rid, call = ctx
    if not relay._in.take(sender):
        return _signed_refusal(nonce, rid, sender, 429, 'FED_RELAY_BUSY',
                               'Too many relayed requests from your site at once')
    try:
        request.max_content_length = relay.MAX_BODY
        body = request.get_data(cache=False)
        if relay._sha(body) != request.headers.get(relay.BODY_HEADER):
            return _signed_refusal(nonce, rid, sender, 400, 'FED_RELAY_BODY',
                                   'The body does not match its digest')
        if call['method'] in relay._SAFE_METHODS and body:
            return _signed_refusal(nonce, rid, sender, 400, 'FED_RELAY_BODY',
                                   'A read carries no body')
        rule, args = relay.match_rule(current_app, call['method'], call['path'])
        reason = relay.rule_verdict(current_app, call['method'], rule) if rule is not None \
            else 'scope'
        if not reason and rule.rule == relay.UPLOAD_RULE:
            # an upload comes to RELAY_UPLOAD_PATH, under the size limit of uploads
            reason = 'transport'
        if reason:
            return _signed_refusal(nonce, rid, sender, 404, 'FED_RELAY_RULE',
                                   relay.REASONS[reason])
        if rule.rule != relay.LIST_RULE and (args or {}).get('cluster_id') not in relay._local_ids():
            return _signed_refusal(nonce, rid, sender, 404, 'FED_RELAY_CLUSTER',
                                   'No such cluster at this site')
        row, why = relay.resolve_principal(sender, call)
        if why:
            return _signed_refusal(nonce, rid, sender, *why)
        call['body'] = body
        status, headers, out = relay.run_relayed(current_app._get_current_object(),
                                                 request.environ, call, row, site, sender)
    finally:
        relay._in.give(sender)
    return _signed(nonce, rid, sender, status, headers, out)


@bp.route(relay.RELAY_UPLOAD_PATH, methods=['POST'])
def peer_relay_upload():
    """A member's relayed upload to a datastore of one of this instance's clusters. The
    account is checked before a byte of the body is read; the body goes to a file, and
    only a file with the digest the sender signed reaches the upload route."""
    refused, ctx = _peer_prelude()
    if refused is not None:
        return refused
    sender, site, nonce, rid, call = ctx
    rule, args = relay.match_rule(current_app, call['method'], call['path'])
    if rule is None or rule.rule != relay.UPLOAD_RULE or call['method'] != 'POST':
        return _signed_refusal(nonce, rid, sender, 404, 'FED_RELAY_RULE',
                               'Only an upload to a datastore comes this way')
    if (args or {}).get('cluster_id') not in relay._local_ids():
        return _signed_refusal(nonce, rid, sender, 404, 'FED_RELAY_CLUSTER',
                               'No such cluster at this site')
    row, why = relay.resolve_principal(sender, call)
    if why:
        return _signed_refusal(nonce, rid, sender, *why)
    # the upload route's own gates, before a byte is written to this site's disk
    why = relay.upload_refusal(row, call, args['cluster_id'])
    if why:
        return _signed_refusal(nonce, rid, sender, *why)
    if not relay._uploads_in.take(sender):
        return _signed_refusal(nonce, rid, sender, 429, 'FED_RELAY_BUSY',
                               'Too many uploads from your site at once')
    # signed, the account checked, and one of the sender's few upload slots held: the body
    # may take as long as the link between the sites needs (the 30 s clock of an unknown
    # client cut every upload slower than that)
    lift_body_deadline()
    spooled = None
    try:
        request.max_content_length = relay.MAX_UPLOAD
        try:
            spooled, digest = relay.spool(request.stream, request.content_length)
        except relay.UploadRefused as e:
            return _signed_refusal(nonce, rid, sender, e.status, e.code, e.error)
        if digest != request.headers.get(relay.BODY_HEADER):
            return _signed_refusal(nonce, rid, sender, 400, 'FED_RELAY_BODY',
                                   'The upload does not match its digest')
        with open(spooled, 'rb') as fh:
            call.update(body=fh, size=os.path.getsize(spooled))
            status, headers, out = relay.run_relayed(current_app._get_current_object(),
                                                     request.environ, call, row, site, sender)
    finally:
        relay.drop_spooled(spooled)
        relay._uploads_in.give(sender)
    return _signed(nonce, rid, sender, status, headers, out)


@bp.after_request
def _sign_peer_answer(resp):
    # the sign-in routes below answer signed control calls, as the federation's own do
    from pegaprox.api import federation as api_fed
    return api_fed._sign_peer_answer(resp)


@bp.route(fsign.SIGN_IN_PATH, methods=['POST'])
def peer_sign_in():
    """A member's sign-in of an account this instance homes (core/federation_signin.py):
    the password and the second factor are checked here, nothing is opened here; 200 with
    an assertion for that member, or the refusal."""
    from pegaprox.api import federation as api_fed
    peer, refused = api_fed._peer_or_refuse(acting=True)
    if refused:
        return refused
    status, body = fsign.check_at_home(peer['instance_id'],
                                       peer.get('site') or peer['instance_id'][:8],
                                       api_fed._body(api_fed._MAX_BODY))
    return jsonify(body), status


@bp.route(fsign.RENEW_PATH, methods=['POST'])
def peer_assert_renew():
    """A fresh assertion for one this instance gave the asking member, while the account
    stands as it did at the sign-in."""
    from pegaprox.api import federation as api_fed
    peer, refused = api_fed._peer_or_refuse(acting=True)
    if refused:
        return refused
    status, body = fsign.renew_at_home(peer['instance_id'], api_fed._body(api_fed._MAX_BODY))
    return jsonify(body), status


@bp.route(relay.RELAY_STREAM_PATH, methods=['POST'])
def peer_relay_stream():
    """A member's live feed of clusters of this instance, for one of the accounts it homes
    (core/federation_stream.py): 200 with a stream of signed frames, or a refusal before it
    starts."""
    refused, ctx = _peer_prelude()
    if refused is not None:
        return refused
    sender, _site, nonce, rid, call = ctx
    if call['method'] != 'GET' or call['path'] != fstream.STREAM_RULE:
        return _fail(404, 'FED_RELAY_RULE', 'Only a live feed comes this way')
    row, why = relay.resolve_principal(sender, call)
    if why:
        return _fail(*why)
    try:
        body = fstream.leading_stream(sender, call, row, nonce, rid)
    except fstream.StreamRefused as e:
        return _fail(e.status, e.code, e.error)
    resp = Response(body, mimetype='text/event-stream')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['X-Accel-Buffering'] = 'no'
    return resp


@bp.route(relay.LIST_RULE, methods=['GET'])
@require_auth()
def linked_self():
    """The clusters of this instance the caller may reach, with the caller's permissions
    here: what another site's list shows of this one. Inside a relayed request only."""
    if not isinstance(request.environ.get(RELAY_ENVIRON), dict):
        return _fail(404, 'FED_RELAY_ONLY', 'This answers relayed requests only')
    from pegaprox.api.helpers import acting_user, caller_is_scoped, check_cluster_access
    from pegaprox.utils.rbac import acts_as_admin, get_user_permissions
    from pegaprox.utils.rbac import get_user_clusters
    user = acting_user()
    local = relay._local_ids()
    # the clusters of the account's tenant in one look; check_cluster_access (VM ACLs and
    # pools) only for the ones outside it
    allowed = get_user_clusters(user)
    allowed = None if allowed is None else set(allowed)
    rows = []
    for r in fed.own_clusters_body():
        if r.get('id') not in local:
            continue
        if allowed is not None and r['id'] not in allowed and not check_cluster_access(r['id'])[0]:
            continue
        row = {'id': r['id'], 'name': r.get('name'), 'type': r.get('type'),
               'connected': r.get('connected') is True}
        # where it stands, for the world map of the other site
        cfg = getattr(relay._local_ids().get(r['id']), 'config', None)
        for field in ('latitude', 'longitude', 'location_label'):
            value = getattr(cfg, field, None)
            if isinstance(value, (int, float, str)) and not isinstance(value, bool) and value != '':
                row[field] = value
        if not caller_is_scoped(user, r['id']):
            for field in ('nodes', 'vms'):
                if field in r:
                    row[field] = r[field]
        rows.append(row)
        if len(rows) >= relay.MAX_LIST_ROWS:
            break
    try:
        perms = sorted(get_user_permissions(user))
    except Exception as e:
        logging.warning(f'[FED] the permissions of a relayed caller could not be read: {e}')
        perms = []
    return jsonify({'release': PEGAPROX_VERSION, 'relay': relay.RELAY_VERSION, 'perms': perms,
                    'admin': acts_as_admin(user), 'clusters': rows})


# --- migrations between two sites -----------------------------------------------------------------

@bp.route('/api/federation/migrate', methods=['POST'])
@require_auth()
def federation_migrate():
    """A guest moved to a cluster of another site, or from one (core/federation_migrate.py).

    Body as POST /api/cross-cluster-migrate takes it: source_cluster, target_cluster (at
    least one of them another site's, a remote id), vmid, vm_type, source_node,
    target_node, target_storage or target_storage_map, target_bridge or target_bridge_map,
    target_vmid, online, delete_source, bwlimit. Each site checks the user itself; 200
    {message, task, transfer_network} once the migration task runs at the source."""
    session = request.session
    principal, refused = _caller(session)
    if refused is not None:
        return refused
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _fail(400, 'FED_MIGRATE', 'JSON object required')
    try:
        return jsonify(_migrate(data, session, principal))
    except fmig.MigrationRefused as e:
        return _fail(e.status, e.code, e.error)


def _pve_list(value, fallback, what):
    """(names, PVE's form) of a storage or bridge: one name, or a map source -> target."""
    if isinstance(value, dict) and value:
        for k in value:
            fmig._names([k], what)
        names = fmig._names(list(value.values()), what)
        return names, ','.join(f'{k}:{v}' for k, v in value.items())
    if value in (None, '', {}):
        value = fallback
    names = fmig._names(value, what)
    if len(names) != 1:
        raise fmig.MigrationRefused(400, f'{what} is one name or a map of source to target names')
    return names, names[0]


def _flag(data, name, default):
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise fmig.MigrationRefused(400, f'{name} is true or false')
    return value


def _site_label(cluster_id, remote):
    if remote is None:
        return f'cluster {cluster_id} here'
    raw, iid = remote
    return f'cluster {raw} at {_site_of(iid)["site"]}'


def _migrate(data, session, principal):
    from pegaprox.utils.sanitization import validate_hostname
    src_id, tgt_id = data.get('source_cluster'), data.get('target_cluster')
    if not isinstance(src_id, str) or not isinstance(tgt_id, str) or src_id == tgt_id:
        raise fmig.MigrationRefused(400, 'source_cluster and target_cluster are two clusters')
    src_mgr, src_remote = fmig.where(src_id)
    tgt_mgr, tgt_remote = fmig.where(tgt_id)
    if (src_mgr, src_remote) == (None, None) or (tgt_mgr, tgt_remote) == (None, None):
        raise fmig.MigrationRefused(404, 'Cluster not found')
    if src_remote is None and tgt_remote is None:
        raise fmig.MigrationRefused(400, 'Both clusters are this site\'s: POST '
                                         '/api/cross-cluster-migrate moves the guest')
    vmid = fmig._vmid(data.get('vmid'))
    vm_type = data.get('vm_type', 'qemu')
    if vm_type not in ('qemu', 'lxc'):
        raise fmig.MigrationRefused(400, 'vm_type is qemu or lxc')
    source_node, target_node = data.get('source_node'), data.get('target_node')
    for value, what in ((source_node, 'source_node'), (target_node, 'target_node')):
        if not isinstance(value, str) or not validate_hostname(value):
            raise fmig.MigrationRefused(400, f'{what} is a node name')
    storages, pve_storage = _pve_list(data.get('target_storage_map') or data.get('target_storage'),
                                      None, 'target_storage')
    bridges, pve_bridge = _pve_list(data.get('target_bridge_map') or data.get('target_bridge'),
                                    'vmbr0', 'target_bridge')
    target_vmid = data.get('target_vmid')
    target_vmid = fmig._vmid(target_vmid, 'target_vmid') if target_vmid not in (None, '', 0) else vmid
    online, delete_source = _flag(data, 'online', True), _flag(data, 'delete_source', True)
    bwlimit = data.get('bwlimit', 0)
    if isinstance(bwlimit, bool) or not isinstance(bwlimit, int) or not 0 <= bwlimit <= 10 ** 9:
        raise fmig.MigrationRefused(400, 'bwlimit is KiB/s, 0 for none')
    user = session.get('user') or ''
    src_label, tgt_label = _site_label(src_id, src_remote), _site_label(tgt_id, tgt_remote)
    if src_mgr is not None:
        _source_gates(src_id, vmid, vm_type, delete_source)

    # the target half: the token, made where the target cluster is led
    target_body = {'target_node': target_node, 'vm_type': vm_type, 'vmid': vmid,
                   'target_vmid': target_vmid, 'storages': storages, 'bridges': bridges,
                   'footprint': _footprint_of(src_mgr, src_remote, source_node, vm_type, vmid,
                                              principal),
                   'source': src_label}
    if src_mgr is not None:
        # MK Nov 2026 - the target's site refuses an older target node before the token
        # (core/migration_tunnel.py)
        tunnel = migration_tunnel.tunnel_version(src_mgr, source_node, vm_type)
        if tunnel is not None:
            target_body['source_tunnel'] = tunnel
    if tgt_mgr is not None:
        from pegaprox.api.helpers import acting_user, check_cluster_access
        from pegaprox.utils.rbac import has_permission
        # this site leads the target: its own gate, as its migration-target route has it
        if not has_permission(acting_user(), 'vm.migrate'):
            raise fmig.MigrationRefused(403, 'Permission denied: vm.migrate', 'MISSING_PERMISSION')
        ok, err = check_cluster_access(tgt_id)
        if not ok:
            raise fmig.MigrationRefused(err[1] if isinstance(err, tuple) else 403,
                                        'Access denied to the target cluster')
        granted = fmig.mint_target(tgt_id, target_body, acting_user(), user)
        target = fmig._LocalTarget(tgt_id)
    else:
        raw_t, iid_t = tgt_remote
        granted = _relayed_json(iid_t, 'POST', f'/api/clusters/{raw_t}/migration-target',
                                target_body, principal)
        target = fmig._RemoteTarget(iid_t, raw_t)
    name = granted.get('token_name')
    if not isinstance(granted.get('endpoint'), str) or not isinstance(name, str):
        raise fmig.MigrationRefused(502, 'The target site answered without a migration token')

    # the source half: Proxmox's remote migration, started where the source is led
    raw_s = src_remote[0] if src_remote else src_id
    path = f'/api/clusters/{raw_s}/vms/{source_node}/{vm_type}/{vmid}/remote-migrate'
    body = {'target_endpoint': granted['endpoint'], 'target_storage': pve_storage,
            'target_bridge': pve_bridge, 'target_vmid': target_vmid, 'online': online,
            'delete_source': delete_source, 'bwlimit': bwlimit}
    if migration_tunnel.known(granted.get('tunnel')) is not None:
        # the source's site holds it against its node, which the target's site could not
        body['target_tunnel'] = granted['tunnel']
    try:
        if src_mgr is not None:
            status, _h, out = _as_caller('POST', path, body)
            source = src_mgr
        else:
            kind, status, h, out = _gated_relay(
                src_remote[1], principal, 'POST', path, body=json.dumps(body).encode(),
                ctype='application/json', read_timeout=relay.WRITE_TIMEOUT)
            status, _h, out = relay.browser_answer(kind, status, h, out, True)
            sid = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
            source = fmig._RemoteSource(src_remote[1], raw_s, principal, sid)
    except BaseException:
        target.delete_api_token(name)
        raise
    try:
        started = json.loads(out or b'{}')
    except Exception:
        started = {}
    if status != 200:
        target.delete_api_token(name)
        said = str((started or {}).get('error') or '')
        if 'PVEAPIToken' in said or granted['endpoint'].split('=', 3)[-1].split(',')[0] in said:
            # Proxmox may say what it was handed: never the token's secret to the browser
            said = 'Proxmox VE refused the remote migration - see the task log at the source'
        raise fmig.MigrationRefused(status if status >= 400 else 502,
                                    said or 'The source site did not start the migration',
                                    (started or {}).get('code') or 'FED_MIGRATE')
    upid = started.get('task')
    if isinstance(upid, str) and upid:
        fmig.follow(target, source, name, upid, f'{vm_type}/{vmid}')
    else:
        logging.warning(f'[FED] migration of {vm_type}/{vmid} started without a task id: its '
                        f'token {name} lapses at the target on its own')
    log_audit(user, 'federation.migrate',
              f'{vm_type} {vmid} from {src_label} to {tgt_label}, node {target_node}: started',
              ip_address=get_client_ip())
    out = {'message': f'Migration of {vm_type} {vmid} to {tgt_label} started', 'task': upid,
           'transfer_network': granted.get('transfer_network')}
    if granted.get('quota_warning'):
        out['quota_warning'] = granted['quota_warning']
    return out


def _source_gates(cluster_id, vmid, vm_type, delete_source):
    """The checks the remote-migrate route makes on a guest of this site, before the target
    site is asked for anything: MigrationRefused when one fails."""
    from pegaprox.api.helpers import acting_user, check_cluster_access
    from pegaprox.api.vms import _require_vm_access
    from pegaprox.utils.rbac import has_permission
    if not has_permission(acting_user(), 'vm.migrate'):
        raise fmig.MigrationRefused(403, 'Permission denied: vm.migrate', 'MISSING_PERMISSION')
    ok, _err = check_cluster_access(cluster_id)
    if not ok:
        raise fmig.MigrationRefused(403, 'Access denied to the source cluster')
    for perm in ('vm.migrate',) + (('vm.delete',) if delete_source else ()):
        if _require_vm_access(cluster_id, vmid, perm, vm_type) is not None:
            raise fmig.MigrationRefused(403, f'Access denied to this guest ({perm})')


def _gated_relay(iid, principal, method, path, **kw):
    """relay_call for the migration's own calls, under the breaker, the account's rate and
    the slots every relayed call of a browser passes (relay_entry). Raises MigrationRefused."""
    user = principal.get('user') or ''
    if relay._broken(iid):
        raise fmig.MigrationRefused(503, f'{_site_of(iid)["site"]} does not answer',
                                    'FED_SITE_UNREACHABLE')
    if not relay.account_call(iid, user):
        raise fmig.MigrationRefused(429, 'Too many requests to that site from your account - '
                                         'try again in a minute', 'FED_RELAY_BUSY')
    if not relay.take_slot(iid, user):
        raise fmig.MigrationRefused(429, 'Too many requests to that site at once - try again',
                                    'FED_RELAY_BUSY')
    started = time.monotonic()
    try:
        got = relay.relay_call(iid, method, path, principal=principal, **kw)
        relay.note_answer(iid, got[0], started)
        return got
    finally:
        relay.give_slot(iid, user)


def _relayed_json(iid, method, path, body, principal):
    """The JSON answer of a relayed call, or MigrationRefused with what the browser would
    have been told."""
    kind, status, h, out = _gated_relay(iid, principal, method, path,
                                        body=json.dumps(body).encode(), ctype='application/json',
                                        read_timeout=relay.WRITE_TIMEOUT)
    status, _h, out = relay.browser_answer(kind, status, h, out, method != 'GET')
    try:
        data = json.loads(out or b'{}')
    except Exception:
        data = {}
    data = data if isinstance(data, dict) else {}
    if status != 200:
        raise fmig.MigrationRefused(status if status >= 400 else 502,
                                    data.get('error') or f'{_site_of(iid)["site"]} refused it',
                                    data.get('code') or 'FED_MIGRATE')
    return data


def _footprint_of(src_mgr, src_remote, node, vm_type, vmid, principal):
    """{cores, memory_gb, disk_gb} of the guest, for the tenant quota at the target."""
    from pegaprox.utils.rbac import config_footprint
    if src_mgr is not None:
        from pegaprox.api.helpers import guest_size
        fp = guest_size(src_mgr, node, vm_type, vmid) or {}
    else:
        raw, iid = src_remote
        kind, status, _h, out = _gated_relay(
            iid, principal, 'GET', f'/api/clusters/{raw}/vms/{node}/{vm_type}/{vmid}/config')
        if kind != 'answer' or status != 200:
            raise fmig.MigrationRefused(status if kind == 'answer' and status >= 400 else 502,
                                        'The config of the guest could not be read at its site')
        try:
            cfg = json.loads(out or b'{}')
        except Exception:
            cfg = {}
        cfg = cfg if isinstance(cfg, dict) else {}
        fp = config_footprint(cfg.get('raw') if isinstance(cfg.get('raw'), dict) else cfg,
                              vm_type) or {}
    out = {}
    for key in ('cores', 'memory_gb', 'disk_gb'):
        try:
            out[key] = max(0, float(fp.get(key) or 0))
        except (TypeError, ValueError):
            out[key] = 0
    return out


def _as_caller(method, path, body):
    """One request of this instance's own API, run as the caller of this request: the same
    session or token, the same address. (status, headers, body)"""
    env = request.environ
    data = json.dumps(body).encode()
    environ = {
        'REQUEST_METHOD': method, 'SCRIPT_NAME': '', 'PATH_INFO': path, 'QUERY_STRING': '',
        'SERVER_NAME': env.get('SERVER_NAME') or 'localhost',
        'SERVER_PORT': env.get('SERVER_PORT') or '443', 'SERVER_PROTOCOL': 'HTTP/1.1',
        'REMOTE_ADDR': env.get('REMOTE_ADDR') or '', 'HTTP_HOST': env.get('HTTP_HOST') or 'localhost',
        'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest', 'CONTENT_TYPE': 'application/json',
        'CONTENT_LENGTH': str(len(data)), 'wsgi.version': (1, 0),
        'wsgi.url_scheme': env.get('wsgi.url_scheme') or 'https', 'wsgi.input': io.BytesIO(data),
        'wsgi.errors': env.get('wsgi.errors') or sys.stderr, 'wsgi.multithread': bool(env.get('wsgi.multithread')),
        'wsgi.multiprocess': False, 'wsgi.run_once': False,
    }
    for key in ('HTTP_X_SESSION_ID', 'HTTP_COOKIE', 'HTTP_AUTHORIZATION', 'HTTP_X_FORWARDED_FOR',
                'HTTP_X_REAL_IP', 'HTTP_USER_AGENT', 'HTTP_ORIGIN'):
        if env.get(key):
            environ[key] = env[key]
    return contextvars.Context().run(relay._dispatch, current_app._get_current_object(), environ)


@bp.route(relay.MIGRATION_TARGET_RULE, methods=['POST'])
@require_auth(perms=['vm.migrate'])
def migration_target(cluster_id):
    """The target half of a migration from another site into this cluster: the checks of
    the user and the token (core/federation_migrate.py mint_target). Inside a relayed
    request only; the token goes to the asking site's server, never to a browser."""
    mark = request.environ.get(RELAY_ENVIRON)
    if not isinstance(mark, dict):
        return _fail(404, 'FED_RELAY_ONLY', 'This answers relayed requests only')
    from pegaprox.api.helpers import acting_user, check_cluster_access
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    try:
        # the member that sent it, which follows the task and drops the token: the account's
        # home only when that is the same site (not for one signed in through its home)
        return jsonify(fmig.mint_target(cluster_id, request.get_json(silent=True), acting_user(),
                                        request.session.get('user') or '',
                                        sender=mark.get('sender') or ''))
    except fmig.MigrationRefused as e:
        return _fail(e.status, e.code, e.error)


@bp.route(fmig.DROP_PATH, methods=['POST'])
def peer_migration_drop():
    """The token of a migration from another site, dropped once its task has ended: for
    the member that asked for it only, whoever's session it was (a drop takes rights away)."""
    from pegaprox.api import federation as api_fed
    peer, refused = api_fed._peer_or_refuse(acting=True)
    if refused:
        return refused
    data = api_fed._body(api_fed._MAX_BODY)
    if not fmig.drop_target(data.get('cluster_id'), data.get('token_name'), peer['instance_id']):
        return _fail(404, 'FED_MIGRATE', 'No such migration token of your site here')
    return jsonify({'dropped': True})


# --- consoles ------------------------------------------------------------------------------------

@bp.route(relay.CONSOLE_TOKEN_RULE, methods=['POST'])
@require_auth()
def console_token(cluster_id):
    """A console token of this instance for the caller, minted for a member site's tunnel
    (core/federation_relay.py): the site's server hands it to this instance's console server,
    which checks it, the cluster and the guest or node as for a browser of its own. Inside a
    relayed request only; the token never reaches a browser."""
    mark = request.environ.get(RELAY_ENVIRON)
    if not isinstance(mark, dict):
        return _fail(404, 'FED_RELAY_ONLY', 'This answers relayed requests only')
    from pegaprox.api.helpers import check_cluster_access, load_server_settings
    from pegaprox.utils.realtime import create_ws_token
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    session = request.session
    token = create_ws_token(session.get('user'),
                            session.get('effective_role') or session.get('role') or 'viewer',
                            sid=f"fed:{mark.get('home') or ''}:{mark.get('sh') or ''}")
    settings = load_server_settings() or {}
    return jsonify({'token': token, 'expires_in': 60,
                    'reverse_proxy': bool(settings.get('reverse_proxy_enabled'))})


def _console_refusal(ws, message, code=1008):
    try:
        ws.send(json.dumps({'status': 'error', 'message': message}))
        ws.close(reason=code, message=message[:120])
    except Exception:
        pass


def _pump(ws, upstream):
    """Bytes both ways until either side closes. One lock around every operation on the
    upstream socket: a read and a write on one TLS object at once break its records (#713)."""
    import gevent
    import websocket
    io_lock = threading.Lock()
    upstream.settimeout(0.05)
    running = {'on': True}

    def down():
        while running['on']:
            try:
                with io_lock:
                    opcode, data = upstream.recv_data()
            except websocket.WebSocketTimeoutException:
                gevent.sleep(0.01)
                continue
            except Exception:
                break
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                break
            try:
                ws.send(data.decode('utf-8', 'replace') if opcode == websocket.ABNF.OPCODE_TEXT
                        else data)
            except Exception:
                break
        running['on'] = False

    reader = gevent.spawn(down)
    try:
        while running['on']:
            try:
                data = ws.receive(timeout=0.1)
            except Exception as e:
                # simple-websocket raises on a read that timed out in some versions
                if isinstance(e, TimeoutError) or 'timed out' in str(e).lower():
                    continue
                break
            if data is None:
                # simple-websocket answers None for a timeout and for a closed peer alike
                if getattr(ws, 'connected', False):
                    continue
                break
            opcode = websocket.ABNF.OPCODE_TEXT if isinstance(data, str) \
                else websocket.ABNF.OPCODE_BINARY
            try:
                with io_lock:
                    upstream.settimeout(10)
                    upstream.send(data, opcode=opcode)
                    upstream.settimeout(0.05)
            except Exception:
                break
    finally:
        running['on'] = False
        reader.kill()
        for end in (upstream, ws):
            try:
                end.close()
            except Exception:
                pass


def federation_console(ws):
    """A console of another site's guest or node, opened through this instance.

    ?token= this instance's own single-use console token, ?cluster= the remote cluster id,
    ?kind= vnc, shell or term, ?node=, and for a guest ?type= and ?vmid=; the PVE ticket the
    relayed ticket call gave the browser rides along (relay.CONSOLE_PARAMS)."""
    if not fed.enabled():
        return _console_refusal(ws, fed.FED_DISABLED_ERROR)
    from pegaprox.core import ha
    if ha.is_standby():
        return _console_refusal(ws, 'This instance is a standby - open the console on its active')
    from pegaprox.utils.auth import resolve_authz_user
    from pegaprox.utils.realtime import hold_websocket, validate_ws_token
    auth = validate_ws_token(request.args.get('token') or '')
    user = resolve_authz_user(auth) if auth else None
    if not user:
        return _console_refusal(ws, 'Authentication required')
    if auth.get('api_token'):
        return _console_refusal(ws, 'A console of another site opens from a signed-in session, '
                                    'not from an API token')
    username = user['username']
    if _home_of(username):
        principal = fsign.principal(auth.get('sid'), username, get_client_ip())
        if principal is None:
            return _console_refusal(ws, "Your account belongs to another site: sign in again "
                                        "to work on other sites' clusters from here")
    else:
        principal = {'user': username, 'home': fed.instance_id(),
                     'sh': relay.session_handle(auth.get('sid') or ''),
                     'ip': get_client_ip() or ''}
    ids = relay.split_remote(request.args.get('cluster') or '')
    if not ids or ids[1] == fed.instance_id() or fed.member_record(ids[1]) is None:
        return _console_refusal(ws, 'No such site in this federation')
    raw, iid = ids
    kind = request.args.get('kind') or ''
    try:
        vmid = int(request.args.get('vmid') or 0) if kind != 'shell' else 0
    except ValueError:
        vmid = -1
    target = relay.console_target(kind, raw, request.args.get('node') or '',
                                  request.args.get('type') or '', vmid, request.args)
    if target is None:
        return _console_refusal(ws, 'Not a console of a guest or a node')
    site = _site_of(iid)
    if relay._broken(iid):
        return _console_refusal(ws, f'{site["site"]} does not answer', 1011)
    if not relay.take_tunnel(username, iid):
        return _console_refusal(ws, 'Too many consoles of other sites open', 1013)
    try:
        started = time.monotonic()
        kind_r, status, _h, body = relay.relay_call(iid, 'POST', f'/api/clusters/{raw}/console-token',
                                                    body=b'{}', ctype='application/json',
                                                    principal=principal)
        relay.note_answer(iid, kind_r, started)
        try:
            granted = json.loads(body or b'{}') if kind_r == 'answer' else {}
        except Exception:
            granted = {}
        if kind_r != 'answer' or status != 200 or not isinstance(granted.get('token'), str):
            return _console_refusal(ws, (granted or {}).get('error')
                                    or f'{site["site"]} did not open the console')
        from urllib.parse import urlencode
        path, extra = target
        query = urlencode(dict(extra, token=granted['token']))
        try:
            upstream = relay.open_console(fed.member_record(iid), kind, path, query,
                                          granted.get('reverse_proxy') is True)
        except Exception as e:
            logging.warning(f'[FED] the console of {raw} at {site["site"]} did not open: '
                            f'{type(e).__name__}')
            return _console_refusal(ws, f'The console server of {site["site"]} cannot be '
                                        'reached from this site', 1011)
        hold_websocket(username, ws, sid=auth.get('sid'))
        log_audit(username, 'federation.console',
                  f'{kind} console of {path.split("/clusters/", 1)[1]} at {site["site"]} opened',
                  ip_address=get_client_ip())
        _pump(ws, upstream)
    finally:
        relay.give_tunnel(username, iid)


# a socket of flask-sock like the other consoles; the name stays the plain function
sock.route(relay.CONSOLE_PATH)(federation_console)
