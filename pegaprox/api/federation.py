# -*- coding: utf-8 -*-
"""Federation routes: the switch, the admin half and the peer half.

The admin routes are a settings page: session or admin API token, admin role, and an
admin who sees every cluster (the HA pairing's rule). The ones that pair, join, remove a
member, leave or move a cluster want proof that the caller is at the keyboard - the
account password, as the HA pairing does it (no API token can confirm that). The switch
asks no password: switching on trusts nobody, pairing does.

The peer routes carry no session. Every member signs its call with its Ed25519 key:
X-PegaProx-Peer (its instance id), -Ts, -Nonce and -Sig over method, path, body digest,
time, nonce and our instance id, over the federation's own signature domain
(federation.SIGN_DOMAIN), checked against the key the agreed view holds for that member
(federation.peer_verdict). Every answer to such a call is signed in turn, over the
request's nonce, the status and the body (_sign_peer_answer), so the caller can tell the
member answered and nobody replayed an older answer. A member the federation removed
gets 410 FED_REMOVED. The one route that runs before there is a member,
/api/federation/peer/join, is authenticated by the pairing code in its body. Peer calls
send X-Requested-With: XMLHttpRequest and no Origin, which the CSRF gate in app.py
already accepts, so none of this is exempted there.

The state machine behind all of it is pegaprox/core/federation.py and
federation_lease.py; nothing here decides trust on its own.

MK Nov 2026
"""
import logging
import threading
import time

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from pegaprox.core import federation
from pegaprox.core import federation_lease as fed_lease
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
# lease votes per member and 30 s, in three windows. The rounds an admin starts (enroll,
# adopt, renew, a change of the members) share the first; the background rounds, one
# call per 256 clusters every 10 s, have their own, so a burst of admin rounds never
# stops the renewals; calls that only give promises back or drop copies (releases,
# unenroll notices) have the third, and a leave sends those for every cluster at once
LEASE_VOTE_BUDGET = 60
_lease_votes = SlidingWindow(limit=LEASE_VOTE_BUDGET, window=30, max_keys=256,
                             name='fed-lease-vote')
LEASE_TICK_BUDGET = 30
_lease_ticks = SlidingWindow(limit=LEASE_TICK_BUDGET, window=30, max_keys=256,
                             name='fed-lease-tick')
LEASE_RETURN_BUDGET = 60
_lease_returns = SlidingWindow(limit=LEASE_RETURN_BUDGET, window=30, max_keys=256,
                               name='fed-lease-return')


def _body(limit=None):
    """The request body as a dict, {} when it is no dict. With `limit`, the raw body is
    read and measured first and one that runs past it is refused with 413: a chunked
    request carries no Content-Length, so a header check alone never sees how large it
    is."""
    if limit is not None and len(request.get_data(cache=True)) > limit:
        raise RequestEntityTooLarge()
    data = request.get_json(silent=True, force=True)
    return data if isinstance(data, dict) else {}


def _confined():
    """True unless the caller sees every cluster - the HA pairing's rule, walked the same
    way so the two cannot drift. Fails closed."""
    try:
        session = getattr(request, 'session', None) or {}
        user = build_authz_user(session.get('user', ''), session)
        from pegaprox.api.auto_install import _sees_every_cluster
        return not _sees_every_cluster(user)
    except Exception as e:
        logging.warning(f"[FED] could not resolve the caller's cluster scope: {e}")
        return True


def _refuse_confined_admin():
    if _confined():
        return jsonify({'error': 'The federation is only available to administrators who '
                                 'are not limited to a tenant or to specific clusters'}), 403
    return None


def _caller_record():
    session = getattr(request, 'session', None) or {}
    from pegaprox.core.db import get_db
    return get_db().get_user(session.get('user', ''))


_MIRROR_ADMIN_ERROR = ('Your account is mirrored from another site. The federation of '
                       'this instance is changed by its own accounts')


def _refuse_mirror_admin(error=_MIRROR_ADMIN_ERROR):
    """403 FED_MIRROR_ADMIN for a session whose account is mirrored from another site: the
    federation of this instance is changed by its own accounts. Fails closed."""
    session = getattr(request, 'session', None) or {}
    username = session.get('user', '')
    try:
        from pegaprox.core.db import get_db
        row = get_db().conn.execute('SELECT fed_home FROM users WHERE username = ?',
                                    (username,)).fetchone()
        home = (row['fed_home'] or '') if row is not None else ''
    except Exception as e:
        logging.warning(f"[FED] could not tell where the account of {username} is homed: {e}")
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': 'Cannot tell where your account is homed'}), 503
    if home:
        return jsonify({'code': 'FED_MIRROR_ADMIN', 'home': home, 'error': error}), 403
    return None


def _str(value, limit=512):
    return value if isinstance(value, str) and len(value) <= limit else ''


def _fed_error(e, status=409):
    """The answer for a FederationError: its sentence, its code and its extra fields."""
    body = {'error': str(e)}
    if getattr(e, 'code', None):
        body['code'] = e.code
    if getattr(e, 'blockers', None):
        body['blockers'] = e.blockers
    for k, v in (getattr(e, 'extra', None) or {}).items():
        body.setdefault(k, v)
    return jsonify(body), status


# MK Nov 2026 - off, every route here answers 404 FED_DISABLED before it reads a body, a
# header or the identity. The two exceptions are the switch and its status, which the
# settings page needs to offer the switch at all.
FED_DISABLED_ERROR = federation.FED_DISABLED_ERROR
_OPEN_WHILE_OFF = {('federation.federation_status', 'GET'),
                   ('federation.federation_switch', 'POST')}


@bp.before_request
def _refuse_while_switched_off():
    if federation.enabled():
        return None
    if (request.endpoint, request.method) in _OPEN_WHILE_OFF:
        return None
    return jsonify({'error': FED_DISABLED_ERROR, 'code': 'FED_DISABLED'}), 404


# --- the peer half ---------------------------------------------------------------------

def request_fed_peer():
    """Who sent this federation peer call, as federation.peer_verdict says: ('member',
    record), ('removed', tombstone), ('skewed', record) or (None, None). Worked out once
    per request - a nonce counts once. No peer call carries a query string: the signature
    covers the path alone, so one that does is nobody's."""
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


def _standby_refusal(acting=False):
    """503 FED_STANDBY on an HA standby, which takes part through its active; with
    `acting`, also on a host that is not the acting one right now (an automatic leader
    whose HA lease ran out must stop voting)."""
    from pegaprox.core import ha
    if ha.is_standby() or (acting and not ha.is_active()):
        return jsonify({'code': 'FED_STANDBY',
                        'error': 'This instance is not the acting host of its HA group - '
                                 'ask its active'}), 503
    return None


def _peer_or_refuse(acting=False):
    """(peer, None) when the call is from a member, else (None, response): 503 FED_STANDBY
    on a standby, 410 FED_REMOVED for a member the federation took out, 403 FED_CLOCK for
    one whose signature is good but whose time is not, 403 FED_NOT_MEMBER for anybody
    else. Never a 401: no browser session is involved."""
    refused = _standby_refusal(acting)
    if refused:
        return None, refused
    kind, who = request_fed_peer()
    if kind == 'member':
        return who, None
    if kind == 'removed':
        return None, (jsonify({'code': 'FED_REMOVED',
                               'error': 'This instance was removed from the federation - '
                                        'leave it and pair again'}), 410)
    if kind == 'skewed':
        return None, (jsonify(federation.clock_refusal(
            who.get('skew') or 'window', time.time(), federation._started(),
            request.headers.get(federation.ha_wire.PEER_TS_HEADER))), 403)
    ip = get_client_ip()
    if not _peer_failures.allow(ip):
        resp = jsonify({'error': 'Too many failed peer calls'})
        resp.headers['Retry-After'] = '300'
        return None, (resp, 429)
    logging.warning(f"[FED] refused a peer call from {ip} to {request.path}")
    return None, (jsonify({'error': 'Not a paired federation member',
                           'code': 'FED_NOT_MEMBER'}), 403)


@bp.after_request
def _sign_peer_answer(resp):
    """Every answer to a signed member call carries this instance's signature over the
    request nonce, the status and the raw body: the caller checks it against the key it
    holds of us, so a captured older answer replays to nobody."""
    try:
        if not request.path.startswith('/api/federation/peer/') or \
                request.path == federation.JOIN_PATH:
            return resp
        kind, who = request.environ.get(_PEER_VERDICT) or (None, None)
        if kind not in ('member', 'removed', 'skewed') or resp.direct_passthrough:
            return resp
        raw = b'' if resp.status_code in (204, 304) else resp.get_data()
        resp.headers[federation.ANSWER_HEADER] = federation.answer_signature(
            request.method, request.path,
            request.headers.get(federation.ha_wire.PEER_NONCE_HEADER) or '',
            resp.status_code, raw, who.get('instance_id') or '')
    except Exception as e:
        logging.warning(f"[FED] could not sign the answer to {request.path}: {e}")
    return resp


@bp.route('/api/federation/peer/join', methods=['POST'])
def peer_join():
    """The joining instance's half of the pairing handshake.

    No session and no peer header: the pairing code in the body authenticates the call
    and is spent by it once a majority of the federation took the new member in. The
    joining instance sends its https address, instance id, Ed25519 public key, site
    label and certificate fingerprints; the view it gets back is sealed under the code's
    secret. 403 for a wrong code, 409 FED_NO_QUORUM or FED_FULL (the code stays open)."""
    refused = _standby_refusal(acting=True)
    if refused:
        return refused
    ip = get_client_ip()
    if not _pair_attempts.allow(ip):
        resp = jsonify({'error': 'Too many pairing attempts - wait a few minutes'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    request.max_content_length = _MAX_BODY
    data = _body(_MAX_BODY)
    fps = data.get('fingerprints') if isinstance(data.get('fingerprints'), list) else []
    try:
        out = federation.accept_join(_str(data.get('code'), 1024),
                                     _str(data.get('url'), 512),
                                     _str(data.get('instance_id'), 64),
                                     _str(data.get('public_key'), 128),
                                     _str(data.get('site'), 64),
                                     [f for f in fps[:8] if isinstance(f, str)])
    except federation.FederationError as e:
        logging.warning(f"[FED] pairing attempt from {ip} refused: {e}")
        if e.code in ('FED_NO_QUORUM', 'FED_FULL', 'FED_VIEW'):
            return _fed_error(e, 409)
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        logging.exception(f"[FED] pairing attempt from {ip} failed: {e}")
        return jsonify({'error': 'Pairing failed'}), 500
    log_audit('system', 'federation.joined',
              f"member {data.get('instance_id')} paired", ip_address=ip)
    return jsonify({'sealed': out['sealed'], 'members': out['members']})


@bp.route('/api/federation/peer/status', methods=['GET'])
def peer_status():
    """Who we are, the view we hold (epoch and digest), our field key's id and a count of
    what we manage. Signed by the asking member."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    return jsonify(federation.peer_status_body())


@bp.route('/api/federation/peer/view', methods=['GET'])
def peer_view():
    """The whole member view, for a member whose view is behind ours."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    return jsonify(federation.peer_view_body())


@bp.route('/api/federation/peer/membership', methods=['POST'])
def peer_membership():
    """A committed change of the view: one member added or removed, under the members
    lock this instance granted the sender. 409 FED_NO_LOCK or FED_VIEW when it does not
    follow from what this instance holds; it catches up later."""
    peer, refused = _peer_or_refuse(acting=True)
    if refused:
        return refused
    try:
        out = federation.apply_membership(peer['instance_id'], _body())
    except federation.FederationError as e:
        return _fed_error(e, 400 if e.code == 'FED_BAD_CHANGE' else 409)
    return jsonify(out)


@bp.route('/api/federation/peer/member-update', methods=['POST'])
def peer_member_update():
    """The sender's word about its own record: address, site label, fingerprints."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    try:
        return jsonify(federation.apply_member_update(peer['instance_id'], _body()))
    except federation.FederationError as e:
        return _fed_error(e, 400)


@bp.route('/api/federation/peer/field-key', methods=['GET'])
def peer_field_key():
    """This instance's own federation field key, which the mirrored credentials of its
    enrolled clusters are wrapped under. Never the database key."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    try:
        return jsonify(federation.field_key_body())
    except federation.FederationError as e:
        return _fed_error(e, 503)


@bp.route('/api/federation/peer/lease-vote', methods=['POST'])
def peer_lease_vote():
    """One member's batch of lease asks and releases, every cluster of a round in one
    call. Each promise this instance gives is on disk before the answer leaves."""
    peer, refused = _peer_or_refuse(acting=True)
    if refused:
        return refused
    body = _body()
    if body.get('asks'):
        window = _lease_ticks if body.get('tick') is True else _lease_votes
    else:
        window = _lease_returns
    if not window.allow(peer['instance_id']):
        resp = jsonify({'reason': 'budget', 'error': 'Too many lease votes'})
        resp.headers['Retry-After'] = '30'
        return resp, 429
    status, answer = federation.cast_votes(peer['instance_id'], body)
    return jsonify(answer), status


# the etag of the identity snapshot, kept for a moment: a poller's conditional GET costs
# one PRAGMA this way, not a hash of every identity row, every minute per member
_ETAG_CACHE_SECONDS = 5
_etag_lock = threading.Lock()
_etag_cache = {'home': '', 'etag': '', 'at': 0.0, 'schema': None}


def _snapshot_etag():
    """(etag, body or None) of the identity snapshot: the etag out of the short cache
    while neither the schema mark nor five seconds have moved, both built fresh when they
    have. The entry is kept per instance id. The body rides along only when it had to be
    built anyway."""
    home = federation.instance_id()
    try:
        schema = federation._identities_conn().execute(
            'PRAGMA schema_version').fetchone()[0]
    except Exception as e:
        logging.warning(f"[FED] could not read the schema mark of the snapshot etag "
                        f"cache: {e}")
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
    """The users, API tokens and passkeys homed at this instance and the cluster rows it
    leads, credentials wrapped under its federation field key - what another member
    pulls to mirror them. An If-None-Match against the etag the caller holds turns the
    answer into a 304. Nothing homed at another member is served."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    held = request.headers.get('If-None-Match', '').strip().strip('"')
    try:
        etag, body = _snapshot_etag()
        if held and held == etag:
            resp = jsonify({'etag': etag})
            resp.status_code = 304
            resp.headers['ETag'] = f'"{etag}"'
            return resp
        if body is None:
            body = federation.identity_snapshot_body()
    except federation.FederationError as e:
        # a table that cannot be read is no snapshot of nothing: refuse the pull outright,
        # or the peer's diff would read the failure as "delete it all"
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': f'The identity snapshot cannot be built: {e}'}), 503
    resp = jsonify(body)
    resp.headers['ETag'] = f'"{body["etag"]}"'
    return resp


@bp.route('/api/federation/peer/clusters', methods=['GET'])
def peer_clusters():
    """What this instance leads, for the linked view of the member that asks: names, type
    and counts, the first rows and how many there are. A login never travels here."""
    peer, refused = _peer_or_refuse()
    if refused:
        return refused
    return jsonify(federation.peer_clusters_body())


# --- the admin half --------------------------------------------------------------------

def _user():
    return (getattr(request, 'session', None) or {}).get('user', 'system')


def _reauth_kind(user):
    from pegaprox.utils.oidc import OIDC_AUTH_SOURCES
    if isinstance(user, dict) and user.get('auth_source') in OIDC_AUTH_SOURCES \
            and not user.get('password_hash'):
        return 'recent_session'
    return 'password'


def _refuse_without_reauth(what):
    """403 unless the caller proved just now who they are, as the HA pairing does it: the
    account password in user_password, audited and rate limited when wrong. An OIDC
    account without a password has to have signed in within ten minutes instead. API
    tokens are refused, they cannot do either."""
    session = getattr(request, 'session', None) or {}
    if session.get('api_token'):
        return jsonify({'error': 'This needs an interactive sign-in - an API token cannot '
                                 'confirm it with a password',
                        'code': 'FED_REAUTH'}), 403
    username = session.get('user', '')
    try:
        user = _caller_record()
    except Exception as e:
        logging.warning(f"[FED] could not read the account of {username} for the "
                        f"re-check: {e}")
        user = None
    if not isinstance(user, dict):
        return jsonify({'error': 'Confirm with your password', 'code': 'FED_REAUTH'}), 403
    if _reauth_kind(user) == 'recent_session':
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


def _guards(reauth=None, mirror=True):
    """The guards of a state-changing admin route, in their order: a confined admin, a
    mirrored account, then the password where `reauth` names what it confirms."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if mirror:
        denied = _refuse_mirror_admin()
        if denied:
            return denied
    if reauth:
        return _refuse_without_reauth(reauth)
    return None


def _session_fields():
    """manage, local_account and reauth: what the federation tab needs to know about the
    caller before it offers anything."""
    out = {'manage': not _confined(), 'local_account': False, 'reauth': 'password'}
    try:
        user = _caller_record()
        if isinstance(user, dict):
            from pegaprox.core.db import get_db
            row = get_db().conn.execute('SELECT fed_home FROM users WHERE username = ?',
                                        (_user(),)).fetchone()
            out['local_account'] = not (row is not None and (row['fed_home'] or ''))
            out['reauth'] = _reauth_kind(user)
    except Exception as e:
        logging.warning(f"[FED] could not read the caller's account for the status: {e}")
    return out


@bp.route('/api/federation/status', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_status():
    """The switch, and with the federation on this instance and its members.

    Any admin: enabled, forced, can_disable, disable_blockers, manage, local_account,
    reauth. With the federation on and an admin who sees every cluster (manage), also
    the identity of this instance, the view (epoch, max_sites, removed, removed_by_some,
    view_conflict), the open pairing code and every member with whether it answered just
    now. Off, nothing of the identity is read or made for this."""
    out = federation.switch_status()
    out.update(_session_fields())
    if not out['enabled'] or not out['manage']:
        return jsonify(out)
    from pegaprox.core import ha
    me = federation.instance_id() if ha.is_standby() else federation.ensure_identity()
    ident = federation.identity() or {}
    sync = federation.sync_state()
    try:
        from pegaprox.core.db import get_db
        mirrored = {r['fed_owner']: r['n'] for r in get_db().conn.execute(
            "SELECT fed_owner, COUNT(*) AS n FROM clusters WHERE fed_owner NOT IN ('', ?) "
            "GROUP BY fed_owner", (me,)).fetchall()}
    except Exception:
        mirrored = {}
    unmapped = federation.unmapped_counts()
    try:
        public = federation.public_key() if me else ''
    except federation.FederationError:
        public = ''
    out.update({'instance_id': me, 'public_key': public, 'site': federation.own_site(),
                'url': federation.own_url(), 'fingerprints': federation.own_fingerprints(),
                'members': [], 'max_sites': federation.MAX_SITES,
                'view_epoch': federation.view_epoch(),
                'removed': ident.get('removed'),
                'removed_by_some': federation.removed_by_some(),
                'view_conflict': bool(federation._runtime.get('view_conflict')),
                'field_key_id': ident.get('field_key_id') or ''})
    roster = sorted(federation.members().items())
    seen = federation._runtime.get('seen') or {}

    def ask(item):
        iid, rec = item
        status, body, _h = federation.call_peer(iid, 'GET', federation.STATUS_PATH,
                                                read_timeout=3)
        return {'instance_id': iid, 'url': rec.get('url') or '',
                'site': rec.get('site') or '',
                'fingerprints': list(rec.get('fingerprints') or []),
                'added_at': rec.get('added_at') or 0,
                'last_seen': seen.get(iid) or 0,
                'reachable': status == 200 and isinstance(body, dict)
                and body.get('instance_id') == iid,
                'removed_us': status == 410,
                'fed': body.get('fed') if isinstance(body, dict) and status == 200 else None,
                'view_epoch': ((body or {}).get('view') or {}).get('epoch')
                if isinstance(body, dict) and status == 200 else None,
                'has_key': iid in (ident.get('peer_keys') or {}),
                'mirrored_clusters': int(mirrored.get(iid) or 0),
                'unmapped': int(unmapped.get(iid) or 0),
                'identity_sync': sync.get(iid)}
    out['members'] = [m for m in federation._parallel(ask, roster) if m]
    try:
        out['pairing_open'] = federation.pairing_open()
    except federation.FederationError:
        out['pairing_open'] = None
    return jsonify(out)


@bp.route('/api/federation/switch', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def federation_switch():
    """Switch the federation on or off for the whole deployment (it travels to an HA
    standby with the settings). Body {"enabled": bool}. Switching on starts the workers;
    switching off stops them and is refused with 409 FED_IN_USE while this instance is a
    member, holds a lease or holds mirrors (leave the federation first), and with 409
    FED_FORCED while PEGAPROX_FEDERATION decides."""
    denied = _guards()
    if denied:
        return denied
    value = _body().get('enabled')
    if not isinstance(value, bool):
        return jsonify({'error': 'Send {"enabled": true} or {"enabled": false}',
                        'code': 'FED_BAD_VALUE'}), 400
    try:
        out = federation.set_enabled(value)
    except federation.FederationError as e:
        return jsonify({'code': e.code, 'error': str(e), 'blockers': e.blockers}), 409
    log_audit(_user(), 'federation.switched_on' if value else 'federation.switched_off',
              f'the federation was switched {"on" if value else "off"}',
              ip_address=get_client_ip())
    return jsonify(out)


@bp.route('/api/federation/members', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_members():
    """The view and its tombstones - the whole deployment's trust surface."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    return jsonify({'instance_id': federation.instance_id(),
                    'epoch': federation.view_epoch(),
                    'members': sorted(federation.members().keys()),
                    'tombstones': sorted(federation.tombstones().keys())})


@bp.route('/api/federation/pairing-code', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_pairing_code():
    """A one-time code for an instance that is to join this federation through this one.
    url is this instance as the joining instance will reach it (for an HA group, the
    group's service address); site is our own label. The certificate fingerprints are
    filled in by the server. A new code replaces an open one; it is good for 15 minutes
    and one join."""
    denied = _guards('a federation pairing code')
    if denied:
        return denied
    data = _body()
    try:
        code, expires = federation.create_pairing_code(
            _str(data.get('url'), 512), _str(data.get('fingerprint'), 256))
    except federation.FederationError as e:
        return _fed_error(e, 409 if e.code == 'FED_FULL' else 400)
    site = federation.set_own_site(_str(data.get('site'), 64))
    log_audit(_user(), 'federation.pairing_code_created',
              f'federation pairing code for {data.get("url")}, valid for 15 minutes')
    return jsonify({'code': code, 'expires_at': expires, 'site': site})


@bp.route('/api/federation/join', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def join_federation():
    """Join the federation of the instance that made the code. own_url is this instance as
    the others will reach it; site is our own label. 409 says what went wrong."""
    denied = _guards('joining a federation')
    if denied:
        return denied
    data = _body()
    try:
        out = federation.join(_str(data.get('code'), 1024), _str(data.get('own_url'), 512),
                              _str(data.get('site'), 64))
    except federation.FederationError as e:
        return _fed_error(e, 409)
    except Exception as e:
        logging.exception(f"[FED] join failed: {e}")
        return jsonify({'error': 'Joining the federation failed'}), 502
    log_audit(_user(), 'federation.joined',
              f"joined the federation of {out['joined']} ({len(out['members'])} members)",
              ip_address=get_client_ip())
    return jsonify(out)


@bp.route('/api/federation/members/<instance_id>/remove', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def remove_member(instance_id):
    """Take a member out, with a majority of the federation behind it (409 FED_NO_QUORUM
    without). The answer names the members that did not confirm (not_told) and the
    clusters enrolled here whose credentials the removed member may still hold."""
    denied = _guards('removing a federation member')
    if denied:
        return denied
    if _body().get('confirm') != 'REMOVE':
        return jsonify({'error': 'Type REMOVE to take the member out'}), 400
    try:
        out = federation.remove_member(instance_id, by=f'admin:{_user()}')
    except federation.FederationError as e:
        return _fed_error(e, 404 if e.code == 'FED_NOT_MEMBER' else 409)
    log_audit(_user(), 'federation.member_removed',
              f'member {instance_id} removed from the federation'
              + (f', not confirmed by {len(out["not_told"])}' if out['not_told'] else ''),
              ip_address=get_client_ip())
    return jsonify(out)


@bp.route('/api/federation/leave', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def leave_federation():
    """Leave the federation. Body {"confirm": "LEAVE", "force": bool}. Clusters enrolled
    without a live lease block it (409 FED_LEAVE_BLOCKED) unless forced; forced, a leave
    without a majority goes ahead here alone."""
    denied = _guards('leaving the federation')
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != 'LEAVE':
        return jsonify({'error': 'Type LEAVE to leave the federation'}), 400
    try:
        out = federation.leave(force=data.get('force') is True)
    except federation.FederationError as e:
        return _fed_error(e, 409)
    log_audit(_user(), 'federation.left',
              'left the federation' + (' (forced)' if data.get('force') is True else ''),
              ip_address=get_client_ip())
    return jsonify(out)


@bp.route('/api/federation/reconcile', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def reconcile():
    """Catch up with the federation now: ask every member where its view stands and take
    a newer one."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    out = federation.catch_up()
    log_audit(_user(), 'federation.reconciled',
              f'caught up with the federation: view {federation.view_epoch()}'
              + (' taken from the others' if out.get('adopted') else ''),
              ip_address=get_client_ip())
    return jsonify({'adopted': bool(out.get('adopted')), 'epoch': federation.view_epoch()})


@bp.route('/api/federation/sync', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def sync_identities():
    """Pull the identities of every member now. One member's failure to answer never
    stops the others - its report says 'failed' instead."""
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
    """409 FED_NO_LEASE for a cluster this instance may not write right now, for the
    handlers that act on clusters named in a body or a plan before a multi-step operation
    starts (every single write is fenced at its exit anyway). None when the write may go
    through, and always while the federation is switched off."""
    if not federation.enabled():
        return None
    if federation.worker_takes_writes_for(cluster_id):
        return None
    return jsonify({'code': 'FED_NO_LEASE', 'cluster': cluster_id,
                    'error': f'This instance holds no live federation lease on {what} - '
                             f'another site leads it, or the lease ran out in a network '
                             f'split'}), 409


def lease_refusal(cluster_id):
    """The 409 a write refused at its exit answers (app.py)."""
    return jsonify({'code': 'FED_NO_LEASE', 'cluster': cluster_id,
                    'error': f'This instance holds no live federation lease on cluster '
                             f'{cluster_id}, so the write was not sent. Another site may '
                             f'lead it, or the lease ran out in a network split'}), 409


def refuse_foreign(table, key_vals, what):
    """409 for a write to a row of the identity federation that another member homed: the
    home decides, this instance only mirrors it. None when the row is ours to write (or
    nobody's). A table that cannot be read refuses the write outright. A write to a row
    of this instance by a caller whose own account is a mirror is refused as well
    (refuse_mirror_caller). Always None while the federation is switched off."""
    if not federation.enabled():
        return None
    try:
        home = federation.foreign_home(table, tuple(key_vals))
    except federation.FederationError as e:
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': f'Cannot tell where {what} is homed - {e}'}), 503
    if not home:
        return refuse_mirror_caller()
    return jsonify({'code': 'FED_FOREIGN', 'home': home,
                    'error': f'{what} belongs to another instance of the federation - make '
                             f'the change there, then sync'}), 409


def refuse_mirror_caller(error=None):
    """403 FED_MIRROR_ADMIN for a caller whose account is mirrored from another site, on
    the routes that administer this instance's accounts, tenants and roles, and on what
    decides the role an LDAP or OIDC sign-in gets here: a mirrored admin that could create
    a local admin account (or give one a password, or raise one's role, or map a directory
    group of its choosing to admin) would make every change _refuse_mirror_admin keeps
    from it under that account. `error`: the sentence of the answer. Fails closed (503).
    Always None while the federation is switched off: a mirror then counts as disabled
    and is not signed in at all."""
    if not federation.enabled():
        return None
    return _refuse_mirror_admin(error or 'Your account is mirrored from another site. The '
                                         'accounts, tenants and roles of this instance are '
                                         'administered by its own accounts')


def refuse_own_mirror(what, username=None):
    """409 FED_FOREIGN when the signed-in account (or `username`) is a mirror of another
    member: its password, second factor, passkeys and tokens are its home's to change. None
    when it is not, and always None while the federation is switched off. A table that
    cannot be read refuses (503 FED_UNAVAILABLE) rather than letting the change through as
    a local one."""
    if not federation.enabled():
        return None
    if username is None:
        username = (getattr(request, 'session', None) or {}).get('user', '')
    try:
        home = federation.foreign_home('users', (username,))
    except federation.FederationError as e:
        logging.warning(f"[FED] mirror check for {what} could not tell: {e}")
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': f'Cannot tell where this account lives - {what} is '
                                 f'refused until the federation answers'}), 503
    if not home:
        return None
    return jsonify({'code': 'FED_FOREIGN', 'home': home,
                    'error': f'Your account is homed at another instance of the '
                             f'federation - {what} there'}), 409


# --- the accounts of the other members: tenant and role mapping -----------------------------

@bp.route('/api/federation/identity-map', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_identity_map():
    """The tenants and roles the accounts of every member name, what each maps onto here
    ('' = not mapped: the accounts naming it cannot sign in) and how many accounts name it,
    with the tenants and roles this instance offers to map onto."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    try:
        return jsonify(federation.identity_map_view())
    except Exception as e:
        logging.warning(f"[FED] could not read the identity mapping: {e}")
        return jsonify({'code': 'FED_UNAVAILABLE',
                        'error': 'The identity mapping cannot be read'}), 503


@bp.route('/api/federation/identity-map', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def federation_map_identity():
    """Map a tenant or a role a member's accounts name onto one of this instance. Body
    {home, kind: "tenant"|"role", home_value, local_value, user_password}. Mapping gives
    those accounts access here and wants the password; local_value "" takes a mapping
    away, which only narrows and asks none: the accounts are quarantined at once, with
    the member unreachable too. The member is pulled again right after (pulled false: it
    did not answer, the accounts follow at the next sync)."""
    data = _body()
    local_value = data.get('local_value')
    denied = _guards('mapping accounts of another site'
                     if isinstance(local_value, str) and local_value else None)
    if denied:
        return denied
    home, kind = _str(data.get('home'), 64), _str(data.get('kind'), 16)
    home_value = _str(data.get('home_value'), federation.MAX_MAP_VALUE)
    if not isinstance(local_value, str):
        return jsonify({'code': 'FED_MAP_INVALID',
                        'error': 'Say what to map onto ("" takes the mapping away)'}), 400
    try:
        out = federation.map_identity(home, kind, home_value, local_value, by=_user())
    except federation.FederationError as e:
        status = {'FED_MAP_INVALID': 400, 'FED_MAP_UNKNOWN': 404,
                  'FED_NOT_MEMBER': 404}.get(e.code, 503)
        return _fed_error(e, status)
    action = 'federation.identity_mapped' if local_value else 'federation.identity_unmapped'
    log_audit(_user(), action,
              f'{kind} "{home_value}" of member {home} '
              + (f'mapped onto "{local_value}"' if local_value else 'no longer mapped'),
              ip_address=get_client_ip())
    return jsonify(out)


@bp.route('/api/federation/clusters', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_clusters():
    """The clusters of every member, asked live at each - the linked view: no copy, the
    owner answers. A member that stays silent shows clusters null; one with more rows
    than shown says so in total."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    return jsonify(federation.federation_clusters())


@bp.route('/api/federation/leases', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def federation_leases():
    """The leases this instance holds, the promises it gave and the rows that are
    enrolled here or mirrored, with their owners. No clock values."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    out = fed_lease.lease_status()
    try:
        rows = federation._identities_conn().execute(
            "SELECT id, name, fed_owner FROM clusters WHERE fed_owner != ''").fetchall()
        out['enrolled'] = {r['id']: {'name': r['name'], 'owner': r['fed_owner']}
                           for r in rows}
    except Exception as e:
        out['enrolled'] = {}
        logging.warning(f"[FED] could not read the enrolled clusters: {e}")
    return jsonify(out)


@bp.route('/api/federation/clusters/<cluster_id>/enroll', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def enroll_cluster(cluster_id):
    """Put a local Proxmox VE cluster under the federation's rule: this instance becomes
    its writer with a majority of the sites behind it. Needs three or more sites."""
    denied = _guards('enrolling a cluster')
    if denied:
        return denied
    try:
        lease = fed_lease.enroll_cluster(cluster_id)
    except federation.FederationError as e:
        return _fed_error(e, 409)
    log_audit(_user(), 'federation.cluster_enrolled',
              f'cluster {cluster_id} enrolled ({lease.get("votes")}/{lease.get("needed")} '
              f'votes)', ip_address=get_client_ip())
    return jsonify({'enrolled': cluster_id, 'lease': lease})


@bp.route('/api/federation/clusters/<cluster_id>/release', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def release_cluster(cluster_id):
    """Give the lease up and keep the enrollment: the gate stays shut here while another
    member adopts the cluster. Taking it back is an enroll."""
    denied = _guards('releasing a cluster')
    if denied:
        return denied
    if _body().get('confirm') != 'RELEASE':
        return jsonify({'error': 'Type RELEASE to give the lease up'}), 400
    try:
        owner = federation.cluster_owner(cluster_id)
    except federation.FederationError as e:
        return _fed_error(e, 503)
    if owner is None:
        return jsonify({'code': 'FED_NOT_FOUND', 'error': 'No such cluster here'}), 404
    if owner != federation.instance_id():
        return jsonify({'code': 'FED_FOREIGN' if owner else 'FED_NOT_ENROLLED',
                        'home': owner,
                        'error': 'That cluster is not enrolled by this instance'}), 409
    federation.release(cluster_id)
    log_audit(_user(), 'federation.cluster_released',
              f'lease on cluster {cluster_id} released (cluster stays enrolled)',
              ip_address=get_client_ip())
    return jsonify({'released': cluster_id, 'still_enrolled': True})


@bp.route('/api/federation/clusters/<cluster_id>/unenroll', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def unenroll_cluster(cluster_id):
    """Take a cluster out of the federation's rule: lease and owner go. Needs this
    instance's live lease (409 FED_NO_LEASE). Body {"confirm": "UNENROLL", "force":
    true} unenrolls without it - the override for a federation that is gone for good: a
    site that adopted the cluster would then share it."""
    denied = _guards('unenrolling a cluster')
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != 'UNENROLL':
        return jsonify({'error': 'Type UNENROLL to take the cluster out'}), 400
    force = data.get('force') is True
    try:
        fed_lease.unenroll_cluster(cluster_id, force=force)
    except federation.FederationError as e:
        return _fed_error(e, 404 if e.code == 'FED_NOT_FOUND' else 409)
    if force:
        logging.warning(f'[FED] cluster {cluster_id} unenrolled with force by {_user()}')
    log_audit(_user(), 'federation.cluster_unenrolled',
              f'cluster {cluster_id} taken out of the federation'
              + (' WITH FORCE, without a lease: a site that adopted it would now share it'
                 if force else ''), ip_address=get_client_ip())
    return jsonify({'unenrolled': cluster_id, 'forced': force})


@bp.route('/api/federation/clusters/<cluster_id>/adopt', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def adopt_cluster(cluster_id):
    """Take over the cluster of a member that is gone for good or released it. The voters
    hand the lease only past the old owner's promise, and the mirrored credentials cross
    over under the owner's federation field key. ADOPT is the word; force adopts without
    the owner's key, without the credentials. Per-node root passwords and an HA cluster
    claim of the old owner do not come along."""
    denied = _guards('adopting a cluster')
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != 'ADOPT':
        return jsonify({'error': 'Type ADOPT to take the cluster over'}), 400
    try:
        lease = fed_lease.adopt_cluster(cluster_id, force=data.get('force') is True)
    except federation.FederationError as e:
        return _fed_error(e, 404 if e.code == 'FED_NOT_FOUND' else 409)
    # the adopted cluster is this instance's now: its manager starts the way a standby's
    # rebuild starts one; if the cluster is unreachable, the adoption stands and the
    # manager is tried again at the next start
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
        logging.warning(f"[FED] the adopted cluster {cluster_id} did not start its manager "
                        f"yet: {e}")
    log_audit(_user(), 'federation.cluster_adopted',
              f'cluster {cluster_id} adopted ({lease.get("votes")}/{lease.get("needed")} '
              f'votes, manager {"started" if started else "pending"})',
              ip_address=get_client_ip())
    return jsonify({'adopted': cluster_id, 'lease': lease, 'manager': started})


@bp.route('/api/federation/clusters/<cluster_id>/renew', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def renew_cluster_lease(cluster_id):
    """One round for this cluster now, out of the worker's cadence. renewed false means
    the gate is closed."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    out = fed_lease.renew(cluster_id)
    log_audit(_user(), 'federation.lease_renewed',
              f'lease round for cluster {cluster_id[:64]}: '
              + ('renewed' if out.get('renewed') else f'not renewed ({out.get("votes", 0)} of '
                                                       f'{out.get("needed", 0)} votes)'),
              ip_address=get_client_ip())
    return jsonify(out)


# --- this instance's certificate, for the pins of the others ---------------------------------

def own_fingerprints():
    """What the others pin to reach this instance: our self-signed certificate (nothing
    behind a reverse proxy or with a CA certificate) and the certificates of the other
    hosts of our HA group, so the federation keeps reaching the group after a failover."""
    out = []
    try:
        from pegaprox.api.ha import _own_fingerprint
        mine = _own_fingerprint()
        if mine:
            out.append(mine)
    except Exception as e:
        logging.debug(f"[FED] no own fingerprint: {e}")
    try:
        from pegaprox.core import ha
        for rec in ha.members():
            fp = (rec or {}).get('fingerprint')
            if fp:
                out.append(fp)
    except Exception as e:
        logging.debug(f"[FED] no fingerprints of the HA group: {e}")
    return out


federation.set_fingerprint_provider(own_fingerprints)
