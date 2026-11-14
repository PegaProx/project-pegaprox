# -*- coding: utf-8 -*-
"""Federation routes (Phase 1): the admin half and the peer half.

The admin routes are a settings page: session or admin API token, admin role. The
ones that pair, join, remove a member or leave want proof that the caller is at the
keyboard - the account password, as the HA pairing does it (no API token can confirm
that). Pairing hands no key and no credential to another host in this phase, but the
registry of a federation is what the trust of every later phase stands on, so the bar
is the same as the HA group's.

The peer routes carry no session. Every member of the federation signs its call with
its Ed25519 key: X-PegaProx-Peer (its instance id), -Ts, -Nonce and -Sig over method,
path, body digest, time, nonce and our instance id, over the federation's own
signature domain (federation.SIGN_DOMAIN, not the HA group's), checked against the
public key we keep of that member (federation.peer_verdict). A member we removed gets
410 FED_REMOVED, so it knows to let go. The one route that runs before there is a
member, /api/federation/peer/join, is authenticated by the pairing code in its body
and spends it. Peer calls send X-Requested-With: XMLHttpRequest and no Origin, which
the CSRF gate in app.py already accepts, so none of this is exempted there.

The state machine behind all of it is pegaprox/core/federation.py; nothing here
decides trust on its own.

Nov 2026, three-leader federation Phase 1.
"""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from pegaprox.core import federation
from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import require_auth, build_authz_user
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.ratelimit import SlidingWindow

bp = Blueprint('federation', __name__)

# A code is 256 bits and lives 15 minutes: noise, not guessing, is what this counts
_pair_attempts = SlidingWindow(limit=5, window=300, max_keys=2048, name='fed-pair')
# Failed peer headers per address; only failures count, the real peer never lands here
_peer_failures = SlidingWindow(limit=10, window=300, max_keys=2048, name='fed-peer-auth')
# Password re-checks per account, every attempt counted
_reauth_attempts = SlidingWindow(limit=5, window=300, max_keys=2048, name='fed-reauth')
# How old a session may be when an account without a password stands in for one
_REAUTH_MAX_AGE = 600
_MAX_BODY = federation.MAX_PEER_BODY
_PEER_VERDICT = 'pegaprox.federation_peer'


def _body(limit=None):
    """The request body as a dict, {} when it is no dict. With `limit`, the raw
    body is read and measured first and one that runs past it is refused with
    413: a chunked request carries no Content-Length, so a header check alone
    never sees how large it is. force, as the HA peer routes read a notice: the
    signature covers the body, not the header a proxy might touch on the way."""
    if limit is not None and len(request.get_data(cache=True)) > limit:
        raise RequestEntityTooLarge()
    data = request.get_json(silent=True, force=True)
    return data if isinstance(data, dict) else {}


def _refuse_confined_admin():
    """403 unless the caller sees every cluster - the HA pairing's rule, walked the
    same way so the two cannot drift: a federation member is trusted with the whole
    deployment's registry, not with a tenant's slice of it. Fails closed."""
    try:
        session = getattr(request, 'session', None) or {}
        user = build_authz_user(session.get('user', ''), session)
        from pegaprox.api.auto_install import _sees_every_cluster
        unconfined = _sees_every_cluster(user)
    except Exception as e:
        logging.warning(f"[FED] could not resolve the caller's cluster scope: {e}")
        unconfined = False
    if not unconfined:
        return jsonify({'error': 'Federation pairing is only available to '
                                 'administrators who are not limited to a tenant or '
                                 'to specific clusters'}), 403
    return None


def _str(value, limit=512):
    return value if isinstance(value, str) and len(value) <= limit else ''


# --- the peer half ---------------------------------------------------------------------

def request_fed_peer():
    """Who sent this federation peer call, as federation.peer_verdict says: ('member',
    record), ('removed', tombstone), ('skewed', record) or (None, None). Worked out
    once per request - a nonce counts once. No peer call carries a query string: the
    signature covers the path alone, so one that does is nobody's."""
    env = request.environ
    if _PEER_VERDICT in env:
        return env[_PEER_VERDICT]
    verdict = (None, None)
    try:
        plain = not request.query_string and '?' not in request.path
        if plain and (request.content_length is None
                      or request.content_length <= _MAX_BODY):
            request.max_content_length = _MAX_BODY
            body = request.get_data(cache=True)
            if len(body) <= _MAX_BODY:
                verdict = federation.peer_verdict(request.headers, request.method,
                                                  request.path, body)
    except Exception as e:
        logging.warning(f"[FED] could not check a peer call to {request.path}: {e}")
        verdict = (None, None)
    env[_PEER_VERDICT] = verdict
    return verdict


def _peer_or_refuse():
    """(peer, None) when the call is from a member, else (None, response): 410
    FED_REMOVED for a member the federation took out, 401 FED_CLOCK for one whose
    signature is good but whose time is not, 401 for anybody else."""
    kind, who = request_fed_peer()
    if kind == 'member':
        return who, None
    if kind == 'removed':
        return None, (jsonify({'code': 'FED_REMOVED',
                               'error': 'This instance was removed from the '
                                        'federation - leave it and pair again'}), 410)
    if kind == 'skewed':
        # the signature is good, so this is the member itself: no failure to count
        return None, (jsonify(federation.clock_refusal(
            who.get('skew') or 'window', time.time(), federation._started(),
            request.headers.get(federation.ha_wire.PEER_TS_HEADER))), 401)
    ip = get_client_ip()
    if not _peer_failures.allow(ip):
        logging.debug(f"[FED] peer calls from {ip} over the failure budget")
        resp = jsonify({'error': 'Too many failed peer calls'})
        resp.headers['Retry-After'] = '300'
        return None, (resp, 429)
    logging.warning(f"[FED] refused a peer call from {ip} to {request.path}")
    return None, (jsonify({'error': 'Not a paired federation member',
                           'instance_id': federation.instance_id()}), 401)


@bp.route('/api/federation/peer/join', methods=['POST'])
def peer_join():
    """The joining instance's half of the pairing handshake.

    No session and no peer header: the pairing code in the body authenticates the
    call and is spent by it. The joining instance sends its https address, its
    instance id, its Ed25519 public key and a site label; the member list it gets
    back is sealed under the code's secret. A wrong code is 403 on every instance,
    whatever the federation holds - whoever holds no code learns nothing here."""
    ip = get_client_ip()
    if not _pair_attempts.allow(ip):
        resp = jsonify({'error': 'Too many pairing attempts - wait a few minutes'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    # this route reads the body before any peer gate does, so the bound is set
    # here: the platform limit where Werkzeug can run it (an oversized
    # Content-Length is refused outright) and _body()'s measured read for a
    # chunked request, which carries no length to check against
    request.max_content_length = _MAX_BODY
    data = _body(_MAX_BODY)
    try:
        out = federation.accept_join(_str(data.get('code'), 1024),
                                     _str(data.get('url'), 512),
                                     _str(data.get('instance_id'), 64),
                                     _str(data.get('public_key'), 128),
                                     _str(data.get('site'), 64),
                                     _str(data.get('key_sealed'), 2048))
    except federation.FederationError as e:
        logging.warning(f"[FED] pairing attempt from {ip} refused: {e}")
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        logging.exception(f"[FED] pairing attempt from {ip} failed: {e}")
        return jsonify({'error': 'Pairing failed'}), 500
    log_audit('system', 'federation.joined',
              f"member {data.get('instance_id')} paired "
              f"({'re-paired' if out.get('replaced') else 'new'})", ip_address=ip)
    return jsonify({'sealed': out['sealed'], 'members': out['members']})


@bp.route('/api/federation/peer/status', methods=['GET'])
def peer_status():
    """Who we are, who we know, and a summary count. Signed by the asking member."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    federation.touch(peer['instance_id'])
    return jsonify(federation.peer_status_body())


@bp.route('/api/federation/peer/member-added', methods=['POST'])
def peer_member_added():
    """A member tells us of another: any member may vouch, as the issuer of a pairing
    tells the members that paired before. The record is checked as a pairing's is."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    rec = _body().get('member')
    # a member-added notice may introduce a NEW member (the issuer vouches for
    # the joiner), but an EXISTING member's key or URL moves only with that
    # member's own word - nobody replaces a peer's identity for it
    if isinstance(rec, dict) and rec.get('instance_id') and \
            rec.get('instance_id') != peer['instance_id'] and \
            federation.member_record(rec['instance_id']) is not None:
        return jsonify({'error': 'That member is already known - only its own word '
                                 'replaces its key or address'}), 409
    kept = federation.add_member(rec, origin=peer['instance_id'])
    if kept is None:
        full = len(federation.members()) >= federation.MAX_MEMBERS
        return jsonify({'error': 'The federation holds '
                                 f'{federation.MAX_MEMBERS} members already'
                                 if full else 'No member in that notice',
                        'code': 'FED_FULL' if full else 'FED_NO_MEMBER'}), 409
    # a field key never travels in a notice: it crosses under the pairing code's
    # seal alone (the join body, the issuer's sealed answer). One left in the
    # body here is dropped - nothing on the way can hand a key over a name.
    log_audit('system', 'federation.member_added',
              f"member {kept['instance_id']} ({kept['url']}) told by "
              f"{peer['instance_id']}", ip_address=get_client_ip())
    return jsonify({'kept': True, 'instance_id': kept['instance_id']})


@bp.route('/api/federation/peer/member-removed', methods=['POST'])
def peer_member_removed():
    """A member tells us another is out. It lands as a tombstone: the next call of
    the removed member hears 410 and knows to let go."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    sender = _str(_body().get('instance_id'), 64)
    if sender == peer['instance_id']:
        # the member that says it is out itself says it in /peer/left
        return jsonify({'error': 'That member speaks for itself'}), 409
    gone = federation.remove_member(sender, by=f"peer:{peer['instance_id']}")
    if gone:
        log_audit('system', 'federation.member_removed',
                  f"member {sender} removed, told by {peer['instance_id']}",
                  ip_address=get_client_ip())
    # a member nobody held is gone either way: nothing to disagree about
    return jsonify({'removed': bool(gone)})


@bp.route('/api/federation/peer/left', methods=['POST'])
def peer_left():
    """A member leaves the federation; the push it makes on its way out. Only the
    leaving member's own signature says this - no member can throw another out by
    claiming it left."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    gone = federation.remove_member(peer['instance_id'], by='left')
    log_audit('system', 'federation.left',
              f"member {peer['instance_id']} left the federation",
              ip_address=get_client_ip())
    return jsonify({'left': bool(gone)})


# --- the admin half --------------------------------------------------------------------

def _user():
    return (getattr(request, 'session', None) or {}).get('user', 'system')


def _refuse_without_reauth(what):
    """403 unless the caller proved just now who they are, as the HA pairing does it:
    the account password in user_password, audited and rate limited when wrong. An
    OIDC account has no password to type, so its session has to be younger than ten
    minutes instead. API tokens are refused, they cannot do either."""
    session = getattr(request, 'session', None) or {}
    if session.get('api_token'):
        return jsonify({'error': 'This needs an interactive sign-in - an API token '
                                 'cannot confirm it with a password',
                        'code': 'FED_REAUTH'}), 403
    username = session.get('user', '')
    try:
        from pegaprox.core.db import get_db
        user = get_db().get_user(username)
    except Exception as e:
        logging.warning(f"[FED] could not read the account of {username} for the "
                        f"re-check: {e}")
        user = None
    if not isinstance(user, dict):
        return jsonify({'error': 'Confirm with your password', 'code': 'FED_REAUTH'}), 403

    from pegaprox.utils.oidc import OIDC_AUTH_SOURCES
    if user.get('auth_source') in OIDC_AUTH_SOURCES and not user.get('password_hash'):
        created = session.get('created_at')
        fresh = (isinstance(created, (int, float)) and not isinstance(created, bool)
                 and 0 <= time.time() - created <= _REAUTH_MAX_AGE)
        if not fresh:
            return jsonify({'error': 'Sign in again, then retry within 10 minutes',
                            'code': 'FED_REAUTH_RECENT'}), 403
        return None

    password = _body().get('user_password')
    if not isinstance(password, str) or not password or len(password) > 1024:
        return jsonify({'error': 'Confirm with your password', 'code': 'FED_REAUTH'}), 403
    if not _reauth_attempts.allow(username):
        resp = jsonify({'error': 'Too many password attempts - wait a few minutes',
                        'code': 'FED_REAUTH'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    from pegaprox.utils.auth import recheck_account_password
    ok, source = recheck_account_password(username, password, user,
                                          audit_action='federation.reauth_failed',
                                          context=what)
    if not ok:
        logging.warning(f"[FED] password re-check for {what} failed for {username} "
                        f"(auth_source={source})")
        return jsonify({'error': 'The password is not correct', 'code': 'FED_REAUTH'}), 403
    return None


@bp.route('/api/federation/status', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_status():
    """This instance, its members and the reachability it last saw. members carries
    what the registry holds; reachable says which answered a status call just now.
    The member calls go out side by side - up to four at once, one silent site costs
    its own timeout and not the sum of everybody's."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    me = federation.instance_id()
    sync = federation.sync_state()
    out = {'instance_id': me, 'public_key': federation.public_key(),
           'site': federation.own_site(), 'members': [], 'max_members':
           federation.MAX_MEMBERS}

    def ask(iid, rec):
        status, body = federation.call_peer(iid, 'GET', federation.STATUS_PATH,
                                            timeout=3)
        return {'instance_id': iid, 'url': rec.get('url') or '',
                'site': rec.get('site') or '',
                'paired_at': rec.get('paired_at') or 0,
                'last_seen': rec.get('last_seen') or 0,
                'reachable': status == 200 and isinstance(body, dict)
                and body.get('instance_id') == iid,
                'fed': body.get('fed') if isinstance(body, dict) and status == 200
                else None,
                'identity_sync': sync.get(iid)}
    roster = sorted(federation.members().items())
    if roster:
        # map keeps the answer in the registry's sorted order, whatever order the
        # members answer in
        with ThreadPoolExecutor(max_workers=min(len(roster), 4)) as pool:
            out['members'] = list(pool.map(ask, *zip(*roster)))
    pairing = federation._load().get('pairing')
    if pairing and pairing.get('expires', 0) > time.time():
        out['pairing_open'] = {'url': pairing.get('url') or '',
                               'expires_at': pairing.get('expires')}
    return jsonify(out)


@bp.route('/api/federation/members', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_members():
    """The registry - the whole deployment's trust surface. An admin capped to a
    tenant or a set of clusters has no business reading who else is in the
    federation."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    return jsonify({'instance_id': federation.instance_id(),
                    'members': sorted(federation.members().keys()),
                    'tombstones': sorted(federation.tombstones().keys())})


@bp.route('/api/federation/pairing-code', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_pairing_code():
    """A one-time code for an instance that is to join this federation through this
    one. url is this instance as the joining instance will reach it; site is our own
    label in the federation. A new code replaces an open one; it is good for 15
    minutes and for one join."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('a federation pairing code')
    if denied:
        return denied
    data = _body()
    try:
        code, expires = federation.create_pairing_code(
            _str(data.get('url'), 512), _str(data.get('fingerprint'), 256))
    except federation.FederationError as e:
        return jsonify({'error': str(e)}), 400
    site = federation.set_own_site(_str(data.get('site'), 64))
    log_audit(_user(), 'federation.pairing_code_created',
              f'federation pairing code for {data.get("url")}, valid for 15 minutes')
    return jsonify({'code': code, 'expires_at': expires, 'site': site})


@bp.route('/api/federation/join', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def join_federation():
    """Join the federation of the instance that made the code, then be a member of
    every member it listed. own_url is this instance as the others will reach it;
    site is our own label. 409 says what went wrong - a refused code, or a
    conversation with the other instance that failed; 502 only for the unexpected."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('joining a federation')
    if denied:
        return denied
    data = _body()
    try:
        out = federation.join(_str(data.get('code'), 1024), _str(data.get('own_url'), 512),
                              _str(data.get('site'), 64))
    except federation.FederationError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        logging.exception(f"[FED] join failed: {e}")
        return jsonify({'error': 'Joining the federation failed'}), 502
    log_audit(_user(), 'federation.joined',
              f"joined the federation of {out['joined']} "
              f"({len(out['members'])} members)", ip_address=get_client_ip())
    return jsonify(out)


@bp.route('/api/federation/members/<instance_id>/remove', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def remove_member(instance_id):
    """Take a member out of the federation, with a tombstone its later calls hear.
    The others are told; the member itself hears 410 on its next call."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('removing a federation member')
    if denied:
        return denied
    if not _body().get('confirm') == 'REMOVE':
        return jsonify({'error': 'Type REMOVE to take the member out'}), 400
    if instance_id == federation.instance_id():
        return jsonify({'error': 'This instance leaves - use the leave route'}), 409
    gone = federation.remove_member(instance_id, by=f'admin:{_user()}')
    if not gone:
        return jsonify({'error': 'No such member of this federation'}), 404
    log_audit(_user(), 'federation.member_removed',
              f'member {instance_id} removed from the federation',
              ip_address=get_client_ip())
    return jsonify({'removed': instance_id})


@bp.route('/api/federation/leave', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def leave_federation():
    """Leave the federation: the others are told, the registry is emptied. Pairing
    anew afterwards is a fresh start, with a fresh code."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('leaving the federation')
    if denied:
        return denied
    if not _body().get('confirm') == 'LEAVE':
        return jsonify({'error': 'Type LEAVE to leave the federation'}), 400
    had = federation.leave()
    log_audit(_user(), 'federation.left', 'left the federation',
              ip_address=get_client_ip())
    return jsonify({'left': bool(had)})


@bp.route('/api/federation/reconcile', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def reconcile():
    """Ask every member for its status and take the members it lists that this
    instance lacks - the repair for a push that did not arrive."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    learned = federation.reconcile()
    if learned:
        log_audit(_user(), 'federation.reconciled',
                  f'learned {len(learned)} member(s): {", ".join(sorted(learned))}')
    return jsonify({'learned': sorted(learned)})


# --- identity federation (Phase 2) -------------------------------------------------------

# the etag of the identity snapshot, kept for a moment: a poller's conditional GET
# costs one PRAGMA this way, not a hash of every identity row, every minute per
# member. The schema mark (SQLite bumps it on DDL, the 5 s window bounds DML) and
# the age together say when the cache is stale - as ha.py caches its reads.
_ETAG_CACHE_SECONDS = 5
_etag_lock = threading.Lock()
_etag_cache = {'home': '', 'etag': '', 'at': 0.0, 'schema': None}


def _snapshot_etag():
    """(etag, body or None) of the identity snapshot: the etag out of the short
    cache while neither the schema mark nor five seconds have moved, both built
    fresh when they have. The entry is kept per instance id - a process that
    acts for more than one (the test harness) never answers with another's etag.
    The body rides along only when it had to be built anyway - a 304 needs the
    etag alone, and the body is never cached: it is built to be served, at the
    moment it is served."""
    home = federation.instance_id()
    try:
        schema = federation._identities_conn().execute(
            'PRAGMA schema_version').fetchone()[0]
    except Exception as e:
        logging.warning(f"[FED] could not read the schema mark of the snapshot "
                        f"etag cache: {e}")
        schema = None
    now = time.time()
    with _etag_lock:
        held = dict(_etag_cache)
    if held.get('etag') and held.get('home') == home \
            and held.get('schema') == schema \
            and now - held.get('at', 0.0) < _ETAG_CACHE_SECONDS:
        return held['etag'], None
    body = federation.identity_snapshot_body()
    with _etag_lock:
        _etag_cache.update(home=home, etag=body['etag'], at=now, schema=schema)
    return body['etag'], body


@bp.route('/api/federation/peer/identities', methods=['GET'])
def peer_identities():
    """The identity snapshot, signed by this member's federation key: the body
    travels under TLS, but the answer also carries the member's own signature
    over the body digest and the moment - a caller without a cert pin can
    still tell who answered (Q2)."""
    """The users, custom roles and API tokens homed at this instance, and the
    deletes noted here - what another member pulls to mirror our identities. Signed
    by the asking member; an If-None-Match it sends against the etag it holds turns
    the answer into a 304, as the HA snapshot poll does it - and that ask is answered
    from a short-lived etag cache, so a poller that changes nothing costs nothing.
    Nothing homed at another member is served: a member answers for itself alone."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    held = request.headers.get('If-None-Match', '').strip().strip('"')
    try:
        etag, body = _snapshot_etag()
    except federation.FederationError as e:
        # a table that cannot be read is no snapshot of nothing: refuse the pull
        # outright, or the peer's diff would read the failure as "delete it all"
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': f'The identity snapshot cannot be built: {e}'}), 503
    if held and held == etag:
        resp = jsonify({'etag': etag})
        resp.status_code = 304
        resp.headers['ETag'] = f'"{etag}"'
        return resp
    if body is None:
        # the cache answered the conditional ask alone; the body is built only
        # now, to serve it
        try:
            body = federation.identity_snapshot_body()
        except federation.FederationError as e:
            return jsonify({'code': 'FED_UNAVAILABLE',
                            'error': f'The identity snapshot cannot be built: '
                                     f'{e}'}), 503
    federation.touch(peer['instance_id'])
    resp = jsonify(body)
    resp.headers['ETag'] = f'"{body["etag"]}"'
    # Q2: sign the answer - the caller verifies with our known public key
    import base64 as _b64, time as _time
    _ts = str(int(_time.time()))
    _nonce = __import__('secrets').token_urlsafe(12)
    _domain = 'pegaprox-fed-answer-1'
    _msg = chr(10).join((_domain, body['etag'], _ts, _nonce)).encode()
    _sig = federation._private().sign(_msg)
    resp.headers['X-PegaProx-Fed-Sig'] = _b64.b64encode(_sig).decode()
    resp.headers['X-PegaProx-Fed-Sig-Ts'] = _ts
    resp.headers['X-PegaProx-Fed-Sig-Nonce'] = _nonce
    return resp


@bp.route('/api/federation/sync', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def sync_identities():
    """Pull the identities of every member now: the users, roles and tokens homed
    there become mirrors here, the deletes noted there remove ours. One member's
    failure to answer never stops the others - its report says 'failed' instead."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    report = federation.sync_identities()
    total = sum(1 for r in report.values() if not (r or {}).get('failed'))
    log_audit(_user(), 'federation.sync',
              f'pulled the identities of {total} of {len(report)} member(s)',
              ip_address=get_client_ip())
    return jsonify({'members': report})


def refuse_unleased(cluster_id, what):
    """409/503 for a write to a cluster this instance does not hold a live lease
    on. None when the write may go through: an unenrolled cluster is this
    instance's own (no federation, no lease), an enrolled one wants the owner's
    live lease. A lease that just ran out says so - the split took it, not the
    admin."""
    try:
        ok = federation.takes_writes_for(cluster_id)
    except federation.FederationError as e:
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': f'Cannot tell who may write {what}: {e}'}), 503
    if ok:
        return None
    owner = federation.cluster_owner(cluster_id)
    if owner and owner != federation.instance_id():
        return jsonify({'code': 'FED_FOREIGN', 'home': owner,
                        'error': f'{what} belongs to another member of the '
                                 f'federation'}), 409
    return jsonify({'code': 'FED_NO_LEASE',
                    'error': f'The lease on {what} has run out - the federation no '
                             f'longer backs this instance there'}), 409


def refuse_foreign(table, key_vals, what):
    """409 for a write to a row of the identity federation that another member
    homed: the home decides, this instance only mirrors it. None when the row is
    ours to write (or nobody's - a row that is not there yet). A table that cannot
    be read refuses the write outright - a guard that cannot tell fails closed."""
    try:
        home = federation.foreign_home(table, tuple(key_vals))
    except federation.FederationError as e:
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': f'Cannot tell where {what} is homed - {e}'}), 503
    if not home:
        return None
    return jsonify({'code': 'FED_FOREIGN', 'home': home,
                    'error': f'{what} belongs to another instance of the federation '
                             f'- make the change there, then sync'}), 409


# --- the pull that keeps the mirrors fresh (Phase 2) -------------------------------------
#
# A join pulls once and the admin route pulls on demand; neither hears of a password
# changed or an account disabled at the home. This loop pulls every member once a
# minute - nothing more than the admin route does, on a clock.

_sync_running = False
_sync_lock = threading.Lock()
SYNC_INTERVAL = 60


def _sync_loop():
    while True:
        time.sleep(SYNC_INTERVAL)
        try:
            if federation.members():
                federation.sync_identities()
        except Exception as e:
            logging.warning(f"[FED] periodic identity sync failed: {e}")


def _lease_loop():
    while True:
        time.sleep(federation.LEASE_RENEW_AFTER)
        try:
            if federation.my_leases():
                federation.renew_leases()
        except Exception as e:
            logging.warning(f"[FED] periodic lease renewal failed: {e}")


def start_sync_worker():
    global _sync_running
    with _sync_lock:
        if _sync_running:
            return
        _sync_running = True
    # Phase 3: leases live on a third of their span (10 s for a 30 s lease), far
    # below the identity cadence - their own loop, same worker start
    t = threading.Thread(target=_sync_loop, daemon=True, name='federation-sync')
    t.start()
    t2 = threading.Thread(target=_lease_loop, daemon=True, name='federation-lease')
    t2.start()
    logging.info("[FED] workers started: identity sync (60s), lease renewal "
                 f"({federation.LEASE_RENEW_AFTER}s)")


# --- partition leases (Phase 3) ----------------------------------------------------------

# lease votes per member: a renewal asks one a round, a flood of terms is no
# renewal - the budget keeps a member from writing this disk raw (F4). What it
# must carry is every member's renewals together: a member leading L clusters
# asks 3L times per 30 s window (one round per LEASE_RENEW_AFTER, one call per
# round), and the receiver does not know L when the window opens - so the limit
# is a generous constant that holds the largest sane federation (8 members,
# ~30 enrolled clusters each) with headroom, while a term flood - hundreds of
# different clusters, or retries against refusals - still hits the wall fast.
LEASE_VOTE_BUDGET = 8 * 30 * 3 * 2 + 60


_lease_votes = SlidingWindow(limit=LEASE_VOTE_BUDGET, window=30, max_keys=256,
                             name='fed-lease-vote')


@bp.route('/api/federation/peer/lease-vote', methods=['POST'])
def peer_lease_vote():
    """One member's ask for a lease on a cluster - or its word that it is done with
    one. Signed by the asking member; a member asks for its own lease alone, and a
    promise it wins here is on this disk before the grant leaves."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    if not _lease_votes.allow(peer['instance_id']):
        resp = jsonify({'granted': False, 'reason': 'budget',
                        'error': 'Too many lease votes - the renewal asks one a round'})
        resp.headers['Retry-After'] = '30'
        return resp, 429
    answer = federation.lease_vote(peer['instance_id'], _body())
    code = 200 if (answer.get('granted') or answer.get('released')) else 409
    return jsonify(answer), code


@bp.route('/api/federation/peer/clusters', methods=['GET'])
def peer_clusters():
    """What this instance leads, for the overview of the member that asks:
    names, type and counts alone - a login never travels in this answer."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    federation.touch(peer['instance_id'])
    return jsonify({'instance_id': federation.instance_id(),
                    'clusters': federation.own_clusters_body()})


@bp.route('/api/federation/clusters', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_clusters():
    """The clusters of every member of the federation, asked live at each -
    the linked-mode view: no copy, the owner answers. A member that stays
    silent shows as unreachable, the rest of the list stands."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    return jsonify(federation.federation_clusters())


@bp.route('/api/federation/leases', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_leases():
    """The leases this instance holds and the promises it has given, with the
    owners the cluster rows name."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    out = federation.lease_status()
    try:
        conn = federation._identities_conn()
        rows = conn.execute("SELECT id, name, fed_owner FROM clusters "
                            "WHERE fed_owner != ''").fetchall()
        out['enrolled'] = {r['id']: {'name': r['name'], 'owner': r['fed_owner']}
                           for r in rows}
    except Exception as e:
        out['enrolled'] = {}
        logging.warning(f"[FED] could not read the enrolled clusters: {e}")
    return jsonify(out)


@bp.route('/api/federation/clusters/<cluster_id>/enroll', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def enroll_cluster(cluster_id):
    """Put a local cluster under the federation's rule: this instance becomes the
    writer, a majority of the members behind it."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('enrolling a cluster')
    if denied:
        return denied
    try:
        lease = federation.enroll_cluster(cluster_id)
    except federation.FederationError as e:
        return jsonify({'error': str(e)}), 409
    log_audit(_user(), 'federation.cluster_enrolled',
              f'cluster {cluster_id} enrolled, lease term {lease.get("term")}',
              ip_address=get_client_ip())
    return jsonify({'enrolled': cluster_id, 'lease': lease})


@bp.route('/api/federation/clusters/<cluster_id>/release', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def release_cluster(cluster_id):
    """Give the LEASE up and keep the enrollment: the gate stays shut here (an
    owner without a lease writes nothing) while another member takes the cluster
    over. Unenrolling is its own word."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('releasing a cluster')
    if denied:
        return denied
    if not _body().get('confirm') == 'RELEASE':
        return jsonify({'error': 'Type RELEASE to give the lease up'}), 400
    owner = federation.cluster_owner(cluster_id)
    if owner and owner != federation.instance_id():
        return jsonify({'code': 'FED_FOREIGN', 'home': owner,
                        'error': 'That cluster belongs to another member'}), 409
    federation.release_lease(cluster_id)
    log_audit(_user(), 'federation.cluster_released',
              f'lease on cluster {cluster_id} released (cluster stays enrolled)',
              ip_address=get_client_ip())
    return jsonify({'released': cluster_id, 'still_enrolled': True})


@bp.route('/api/federation/clusters/<cluster_id>/unenroll', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def unenroll_cluster(cluster_id):
    """Take a cluster out of the federation's rule altogether: lease and owner
    go, the row is this instance's alone again."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('unenrolling a cluster')
    if denied:
        return denied
    if not _body().get('confirm') == 'UNENROLL':
        return jsonify({'error': 'Type UNENROLL to take the cluster out'}), 400
    try:
        federation.unenroll_cluster(cluster_id)
    except federation.FederationError as e:
        return jsonify({'error': str(e)}), 409
    log_audit(_user(), 'federation.cluster_unenrolled',
              f'cluster {cluster_id} taken out of the federation',
              ip_address=get_client_ip())
    return jsonify({'unenrolled': cluster_id})


@bp.route('/api/federation/clusters/<cluster_id>/adopt', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def adopt_cluster(cluster_id):
    """Take over the cluster of a member that is gone for good. The voters hand
    the lease only past the old owner's promise (a live owner blocks this), and
    the mirrored credentials cross over under this instance's own key. ADOPT is
    the word; force adopts without the owner's field key, credentials and all."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    denied = _refuse_without_reauth('adopting a cluster')
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != 'ADOPT':
        return jsonify({'error': 'Type ADOPT to take the cluster over'}), 400
    try:
        lease = federation.adopt_cluster(cluster_id, force=data.get('force') is True)
    except federation.FederationError as e:
        return jsonify({'error': str(e)}), 409
    # the adopted cluster is this instance's now: its manager starts the way a
    # standby's rebuild starts one - and if the cluster is unreachable, the
    # adoption stands and the manager retries at the next boot
    started = False
    try:
        from pegaprox.core.db import get_db
        cluster = get_db().get_cluster(cluster_id)
        if cluster:
            from pegaprox import globals as g
            from pegaprox.app import _start_managers
            _start_managers({cluster_id: cluster}, only=())
            started = cluster_id in getattr(g, 'cluster_managers', {})
    except Exception as e:
        logging.warning(f"[FED] the adopted cluster {cluster_id} did not start "
                        f"its manager yet: {e}")
    log_audit(_user(), 'federation.cluster_adopted',
              f'cluster {cluster_id} adopted (lease term {lease.get("term")}, '
              f'{lease.get("votes")} votes, manager '
              f'{"started" if started else "pending"})',
              ip_address=get_client_ip())
    return jsonify({'adopted': cluster_id, 'lease': lease, 'manager': started})


@bp.route('/api/federation/clusters/<cluster_id>/renew', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def renew_cluster_lease(cluster_id):
    """One renewal round now, out of the worker's cadence. The answer says whether
    a majority still backs this instance on that cluster."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    # no re-auth: the worker asks the same round every ten seconds with no admin
    # at the keyboard - a manual renew asks nothing the lease does not already
    # back (it extends the caller's own lease, it takes nothing over). The round
    # is this cluster's alone: the worker renews the estate, not the admin's ask
    report = federation.renew_leases(cluster_id=cluster_id)
    return jsonify({'cluster': cluster_id,
                    'renewed': (report.get(cluster_id) or {}).get('renewed', False),
                    'report': report.get(cluster_id)})
