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
import json
import logging
import threading
import time

from flask import Blueprint, Response, current_app, jsonify, request

from pegaprox.core import federation as fed
from pegaprox.core import federation_relay as relay
from pegaprox.core import ha_wire
from pegaprox.api.realtime import sock
from pegaprox.constants import PEGAPROX_VERSION
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import RELAY_ENVIRON, require_auth

bp = Blueprint('federation_relay', __name__)

_PREFIX = '/api/federation/relay/'


@bp.before_request
def _refuse_while_switched_off():
    # the console token is a cluster route that answers relayed requests only, which do not
    # exist while off: it refuses on its own, after the hooks every cluster route passes
    if fed.enabled() or request.endpoint == 'federation_relay.console_token':
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


def _principal(session):
    sid = request.headers.get('X-Session-ID') or request.cookies.get('session_id') or ''
    return {'user': session.get('user') or '', 'home': fed.instance_id(),
            'sh': relay.session_handle(sid), 'ip': get_client_ip() or ''}


def _caller_refusal(session):
    """Why this caller cannot work on other sites' clusters from here, or None."""
    if session.get('api_token'):
        return _fail(403, 'FED_RELAY_TOKEN', 'API tokens are not relayed: use the token at the '
                                             'site that leads the cluster')
    home = _home_of(session.get('user') or '')
    if home:
        return _fail(403, 'FED_HOME_ELSEWHERE', 'Your account belongs to another site. Work on '
                                                "other sites' clusters from there",
                     home=_site_of(home))
    return None


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
    refused = _caller_refusal(session)
    if refused is not None:
        return refused
    method = request.method
    path = '/api' + request.path[len(_PREFIX) + len(iid):]
    rule, _args = relay.match_rule(current_app, method, path)
    reason = relay.rule_verdict(current_app, method, rule) if rule is not None else 'scope'
    if rule is not None and rule.rule == relay.CONSOLE_TOKEN_RULE:
        # the tunnel asks for it itself; a browser that held the token would bypass it
        reason = 'transport'
    site = _site_of(iid)
    if reason:
        return _fail(404, 'FED_RELAY_RULE', relay.REASONS[reason], reason=reason, **site)
    write = method not in relay._SAFE_METHODS
    # the body before a slot: a client that sends it slowly holds its own request, not one
    # of the site's slots
    request.max_content_length = relay.MAX_BODY
    body = request.get_data(cache=False) if write else b''
    if relay._broken(iid):
        resp = _fail(503, 'FED_SITE_UNREACHABLE', f'{site["site"]} does not answer', **site)
        resp.headers['Retry-After'] = str(relay._BREAK_FOR)
        return resp
    if not relay._out.take(iid):
        resp = _fail(429, 'FED_RELAY_BUSY', 'Too many requests to that site at once - try again')
        resp.headers['Retry-After'] = '5'
        return resp
    started = time.monotonic()
    try:
        kind, status, headers, out = relay.relay_call(
            iid, method, path, request.environ.get('QUERY_STRING') or '', body,
            request.headers.get('Content-Type') or '', _principal(session),
            read_timeout=relay.WRITE_TIMEOUT if write else relay.READ_TIMEOUT)
        relay.note_answer(iid, kind, started)
    finally:
        relay._out.give(iid)
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
    if session.get('api_token'):
        return _fail(403, 'FED_RELAY_TOKEN', 'API tokens are not relayed')
    from pegaprox.core import ha
    if ha.is_standby() or not fed.instance_id():
        return jsonify({'home': None, 'sites': [], 'standby': ha.is_standby()})
    home = _home_of(session.get('user') or '')
    if home:
        return jsonify({'home': _site_of(home), 'sites': []})
    principal = _principal(session)
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
    import json
    return _signed(nonce, rid, sender, status, {'Content-Type': 'application/json'},
                   json.dumps({'code': code, 'error': error}).encode())


@bp.route(relay.RELAY_PATH, methods=['POST'])
def peer_relay():
    """A member's relayed request for one of the accounts it homes.

    Unsigned refusals, before anything of the request is believed: 503 FED_STANDBY on an
    HA standby, 410 FED_REMOVED, 403 FED_CLOCK, 403 FED_NOT_MEMBER. Everything after the
    signature checked out is answered with 200 and a signed answer envelope that carries
    the status: the inner request's, or a refusal (FED_RELAY_*) before it ran."""
    from pegaprox.api import federation as api_fed
    refused = api_fed._standby_refusal(acting=True)
    if refused:
        return refused
    kind, who, envelope = relay.header_verdict(request)
    if kind == 'removed':
        return _fail(410, 'FED_REMOVED', 'This instance was removed from the federation')
    if kind == 'skewed':
        return jsonify(fed.clock_refusal(who.get('skew') or 'window', time.time(), fed._started(),
                                         request.headers.get(ha_wire.PEER_TS_HEADER))), 403
    if kind != 'member':
        ip = get_client_ip()
        if not api_fed._peer_failures.allow(ip):
            resp = _fail(429, 'FED_BUSY', 'Too many failed peer calls')
            resp.headers['Retry-After'] = '300'
            return resp
        logging.warning(f'[FED] refused a relayed request from {ip}')
        return _fail(403, 'FED_NOT_MEMBER', 'Not a paired federation member')
    sender = who['instance_id']
    site = who.get('site') or sender[:8]
    nonce = request.headers.get(ha_wire.PEER_NONCE_HEADER) or ''
    call = relay.valid_envelope(envelope)
    rid = (call or {}).get('rid') or str((envelope or {}).get('rid') or '')
    if call is None:
        return _signed_refusal(nonce, rid, sender, 400, 'FED_RELAY_ENVELOPE',
                               'The relayed request is not well formed')
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
                                                 request.environ, call, row, site)
    finally:
        relay._in.give(sender)
    return _signed(nonce, rid, sender, status, headers, out)


@bp.route(relay.LIST_RULE, methods=['GET'])
@require_auth()
def linked_self():
    """The clusters of this instance the caller may reach, with the caller's permissions
    here: what another site's list shows of this one. Inside a relayed request only."""
    if not isinstance(request.environ.get(RELAY_ENVIRON), dict):
        return _fail(404, 'FED_RELAY_ONLY', 'This answers relayed requests only')
    from pegaprox.api.helpers import acting_user, caller_is_scoped, check_cluster_access
    from pegaprox.utils.rbac import get_user_permissions
    user = acting_user()
    local = relay._local_ids()
    rows = []
    for r in fed.own_clusters_body():
        if r.get('id') not in local:
            continue
        ok, _err = check_cluster_access(r['id'])
        if not ok:
            continue
        row = {'id': r['id'], 'name': r.get('name'), 'type': r.get('type'),
               'connected': r.get('connected') is True}
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
                    'clusters': rows})


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
    token = create_ws_token(session.get('user'), session.get('role') or 'viewer',
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
            except Exception:
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
        return _console_refusal(ws, 'API tokens are not relayed')
    username = user['username']
    if _home_of(username):
        return _console_refusal(ws, "Your account belongs to another site. Work on other "
                                    "sites' clusters from there")
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
        principal = {'user': username, 'home': fed.instance_id(),
                     'sh': relay.session_handle(auth.get('sid') or ''), 'ip': get_client_ip() or ''}
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
