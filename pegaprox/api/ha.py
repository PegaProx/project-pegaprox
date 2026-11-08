# -*- coding: utf-8 -*-
"""Warm standby routes (#625) - the admin half and the peer half.

The admin routes are a settings page: session or admin API token, admin role, and
not for an admin capped to a tenant, since pairing hands the whole deployment and
its field key to another host. The ones that pair, join, promote, unpair or remove a
member also want proof that the caller is at the keyboard: the account password, or
a fresh sign-in for an account that has none. No API token for those.

The peer routes carry no session. Every other member of the group signs its call
with its Ed25519 key: X-PegaProx-Peer (its instance id), -Ts, -Nonce and -Sig over
method, path, body, time, nonce and our instance id, checked against the public key
we keep of that member (ha.peer_verdict). A member paired before the keys still
sends "<its instance id>:<its secret>" until it has published a key. A member the
active removed gets 410 HA_REMOVED instead of 401, so it knows to let go. The one
route that runs before there is a member, /api/ha/peer/pair, is authenticated by the
pairing code in its body. Peer calls send X-Requested-With and no Origin, which the
CSRF gate in app.py already accepts, so none of this is exempted there.

A write the block in app.py would refuse on a standby goes to the active instead
(forward_to_active): the browser's request, the signed-in user and the client address
travel as the body of a signed peer call, and the active runs the request as that user
by its own accounts (peer_forward). The consoles are not among them: a standby that
serves users opens them itself, any other refuses them, see app.py.

Automatic failover (#625 stage 2) adds the switch between the two modes on the admin
side, and on the peer side the vote and the renewal of the lease (ha.lease_request).
In an automatic group the leader takes writes, hands out snapshots and takes members
only while it holds the lease (503 HA_NO_LEASE otherwise). The server refuses the
switch until ha_vote.AUTO_MODE_SHIPPED is on. Make leader hands the lead on (writes wait
meanwhile, 503 HA_TRANSFER), Force leader is the way out of a group that lost its
majority for good and ends in manual mode, and a member leaves through the leader.

The state machine behind all of it is pegaprox/core/ha.py; nothing here decides a
role on its own.

MK Sep 2026
"""
import base64
import binascii
import contextlib
import contextvars
import hashlib
import hmac
import io
import ipaddress
import logging
import os
import re
import sys
import threading
import time

from flask import Blueprint, current_app, jsonify, request, Response
from werkzeug.exceptions import RequestEntityTooLarge

from pegaprox import witness_boot
from pegaprox.constants import GITHUB_RAW_URL, MIRROR_RAW_URL
from pegaprox.core import ha, ha_vote
from pegaprox.models.permissions import ROLE_ADMIN
from pegaprox.utils.auth import require_auth, build_authz_user, lift_body_deadline
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.ratelimit import SlidingWindow
from pegaprox.utils.sanitization import sanitize_log_message
from pegaprox.api.helpers import safe_error, effective_reverse_proxy

bp = Blueprint('ha', __name__)

_MIN_INTERVAL, _MAX_INTERVAL = 5, 3600

# A code is 256 bits and lives 15 minutes, so this is about noise, not guessing.
_pair_attempts = SlidingWindow(limit=5, window=300, max_keys=2048, name='ha-pair')
# Failed peer headers per address. Only failures are counted: the real peer never
# lands here, and someone sharing its NAT cannot lock it out by guessing.
_peer_failures = SlidingWindow(limit=10, window=300, max_keys=2048, name='ha-peer-auth')
# Password re-checks per account. Every attempt counts, not only the failed ones: a
# budget that only counted failures would still wave a right guess through.
_reauth_attempts = SlidingWindow(limit=5, window=300, max_keys=2048, name='ha-reauth')
# How old a session may be when an account without a password stands in for one.
_REAUTH_MAX_AGE = 600
# A peer call's body is read whole before the caller is known, so it is capped: the
# notices are a few bytes, the snapshot is a GET.
_MAX_PEER_BODY = 64 * 1024
# A forwarded write carries its body in base64, an upload of up to FORWARD_MAX_BODY
# included. Read that far only when the header names a member that signs its calls.
_MAX_FORWARD_ENVELOPE = 4 * ((ha.FORWARD_MAX_BODY + 2) // 3) + 64 * 1024

# What a standby forwards, and what of the active's answer reaches the browser besides
# the status and the body.
_FORWARD_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE')
_FORWARD_HEADERS = ('Content-Type', 'Content-Disposition', 'Retry-After')
FORWARD_UNREACHABLE_ERROR = ('The active instance cannot be reached - act again once it is '
                             'back, or promote this standby')
FORWARD_NO_ANSWER_ERROR = ('The active instance took the change but did not answer in time - '
                           'it may still be carrying it out. Check there before you try again')
_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')
# Every write a standby forwards reaches the active from the standby's address, so they
# all share the one per-address API budget there with the standby's own sync. One user
# gets half of it.
_forward_per_user = SlidingWindow(limit=600, window=60, max_keys=4096, name='ha-forward')
# A large body is held a few times over on both instances while it travels: only a few
# at once, the rest hear 503 and try again
_FORWARD_LARGE = 1024 * 1024
_forward_large_slots = threading.BoundedSemaphore(4)


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _str(value, limit=512):
    return value.strip()[:limit] if isinstance(value, str) else ''


def _https_url(value):
    """The address as ha.valid_https_url takes it, '' when it does not. The same rule
    the other side applies to the code and to the pair call, so what passes here is
    what the peer will accept. Not cut to length first: a cut URL is another URL."""
    if not isinstance(value, str):
        return ''
    return (ha.valid_https_url(value.strip()) or '').rstrip('/')


def _user():
    return (getattr(request, 'session', None) or {}).get('user', 'system')


def _refuse_confined_admin():
    """403 unless the caller sees every cluster - the automated-installations rule,
    reused so the two cannot drift apart - and no tenant override lowers them where
    they live. Fails closed.

    The second half is not implied by the first: an admin mapped down to viewer in the
    default tenant still "sees every cluster", because an empty cluster list there
    means all of them."""
    try:
        session = getattr(request, 'session', None) or {}
        unconfined = _unconfined(build_authz_user(session.get('user', ''), session))
    except Exception as e:
        logging.warning(f"[HA] could not resolve the caller's cluster scope: {e}")
        unconfined = False
    if not unconfined:
        return jsonify({'error': 'Instance pairing is only available to administrators '
                                 'who are not limited to a tenant or to specific clusters'}), 403
    return None


def _unconfined(user):
    from pegaprox.api.auto_install import _sees_every_cluster
    from pegaprox.utils.rbac import _admin_is_capped_in_own_tenant
    return not _admin_is_capped_in_own_tenant(user) and _sees_every_cluster(user)


def unconfined_admin(username, session):
    """MK Oct 2026 (#625) - whether `username` (signed in with `session`) is an admin the
    HA routes are open to: the role, and the bar of _refuse_confined_admin. The lease
    banner names instances only to them. Fails closed."""
    try:
        user = build_authz_user(username or '', session or {})
        from pegaprox.utils.rbac import acts_as_admin
        return acts_as_admin(user) and _unconfined(user)
    except Exception as e:
        logging.warning(f"[HA] could not resolve a cluster scope for the banner: {e}")
        return False


def _refuse_without_reauth(what):
    """403 unless the caller proved just now who they are. None when they did.

    Pairing hands the field key and every stored credential to another host; promote
    and unpair decide which instance acts on the clusters. A stolen session must not
    be enough for that, so this is the bar the config backup sets: the account password
    in user_password, checked the way the backup checks it, audited and rate limited
    when wrong. An OIDC account has no password to type, so its session has to be
    younger than ten minutes instead. API tokens are refused, they cannot do either.
    `what` names the action in the audit trail."""
    session = getattr(request, 'session', None) or {}
    if session.get('api_token'):
        return jsonify({'error': 'This needs an interactive sign-in - an API token cannot '
                                 'confirm it with a password',
                        'code': 'HA_REAUTH'}), 403
    username = session.get('user', '')
    try:
        from pegaprox.core.db import get_db
        user = get_db().get_user(username)
    except Exception as e:
        logging.warning(f"[HA] could not read the account of {username} for the re-check: {e}")
        user = None
    if not isinstance(user, dict):
        return jsonify({'error': 'Confirm with your password', 'code': 'HA_REAUTH'}), 403

    from pegaprox.utils.oidc import OIDC_AUTH_SOURCES
    if user.get('auth_source') in OIDC_AUTH_SOURCES and not user.get('password_hash'):
        created = session.get('created_at')
        fresh = (isinstance(created, (int, float)) and not isinstance(created, bool)
                 and 0 <= time.time() - created <= _REAUTH_MAX_AGE)
        if not fresh:
            return jsonify({'error': 'Sign in again, then retry within 10 minutes',
                            'code': 'HA_REAUTH_RECENT'}), 403
        return None

    password = _body().get('user_password')
    if not isinstance(password, str) or not password or len(password) > 1024:
        return jsonify({'error': 'Confirm with your password', 'code': 'HA_REAUTH'}), 403
    if not _reauth_attempts.allow(username):
        resp = jsonify({'error': 'Too many password attempts - wait a few minutes',
                        'code': 'HA_REAUTH'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    from pegaprox.utils.auth import recheck_account_password
    ok, source = recheck_account_password(username, password, user,
                                          audit_action='ha.reauth_failed', context=what)
    if not ok:
        logging.warning(f"[HA] password re-check for {what} failed for {username} (auth_source={source})")
        return jsonify({'error': 'The password is not correct', 'code': 'HA_REAUTH'}), 403
    return None


def _own_fingerprint():
    """What a peer has to pin to reach us: our self-signed certificate, or nothing
    when a proxy terminates TLS or the certificate comes from a CA."""
    if effective_reverse_proxy():
        return ''
    from pegaprox.api.auto_install import self_signed_fingerprint
    return self_signed_fingerprint()


def _suggested_url():
    """https://host:port as the browser reached us, trusted-proxy aware."""
    from pegaprox.api.auto_install import _public_base
    try:
        scheme, host, _direct = _public_base()
    except Exception as e:
        logging.debug(f"[HA] no suggested address: {e}")
        return ''
    return f'{scheme}://{host}' if host else ''


def _status_body():
    out = ha.public_status()
    out['suggested_url'] = _suggested_url()
    out['own_fingerprint'] = _own_fingerprint()
    return out


# A standby with the live view on holds real connections to the clusters, and reads
# through them. A console is not a read: keyboard and mouse on a guest, a root shell
# on a node, a SPICE ticket that goes to the node directly. Every console path asks
# this before it looks for a manager - the WebSocket ones too, since the old ?session=
# login reaches them without ever minting a ws token. A standby that serves users
# (ha.serving) opens them itself, as an active instance does: the console is the
# user's, and nothing that acts on its own starts there.
STANDBY_CONSOLE_ERROR = 'Consoles are only available on the active instance.'
# a plugin console on a standby that serves users, for a plugin it does not run as the
# leader does (app.py)
PLUGIN_CONSOLE_ERROR = ('This plugin is not running on this instance - open its console '
                        'on the leader.')


def by_api_token():
    """Whether this request comes with an API token rather than a browser session."""
    return request.headers.get('Authorization', '').startswith('Bearer pgx_')


def no_lease_refusal(known=True):
    """503 HA_NO_LEASE where the leader of an automatic group takes no change right now:
    its lease ran out, it is still taking over (Retry-After says for how long), or less
    than ha_vote.WRITE_LEASE_MARGIN of the lease is left (ha.takes_writes, Q16).
    None everywhere else, a manual group and an instance of its own included. A caller
    nobody has checked (`known` false) hears that changes are paused and nothing else:
    not whether the group has a leader, not how long a takeover still runs."""
    refusal = ha.no_lease()
    if refusal is None:
        return None
    if not known:
        refusal = {'error': ha.NO_LEASE_ANON_ERROR, 'retry_after': None}
    resp = jsonify({'code': 'HA_NO_LEASE', 'error': refusal['error']})
    resp.headers['Retry-After'] = str(refusal['retry_after'] or 10)
    return resp, 503


def write_gate_refusal():
    """What the write gate in app.py answers on an instance that is no standby and may
    not take a write right now. Never None: the gate asked ha.takes_writes() and heard
    no, and whatever the state says a moment later (the lease loop may have stepped the
    instance down in between), this write is not taken. The gate runs before any
    route has looked at the caller, so only a signed-in browser session, or a write a
    member handed over, hears who leads and for how long not."""
    known = request.environ.get(ha.FORWARD_ENVIRON) is not None
    if not known:
        from pegaprox.utils.auth import validate_session
        known = bool(validate_session(request.headers.get('X-Session-ID')
                                      or request.cookies.get('session_id')))
    refused = no_lease_refusal(known)
    if refused is None:
        resp = jsonify({'code': 'HA_NO_LEASE',
                        'error': ha.NO_LEASE_ERROR if known else ha.NO_LEASE_ANON_ERROR})
        resp.headers['Retry-After'] = '10'
        refused = (resp, 503)
    return refused


def guard_refusal():
    """What a request answers once the exit refused one of its writes (ha.guard): this
    leader lost its lease, or no majority confirmed it for that call, and the call did
    not go out. The route behind it took that for a failed cluster call; the caller
    hears what the write gate says instead, with a signed-in user as the one who is
    told who leads (write_gate_refusal)."""
    known = (request.environ.get(ha.FORWARD_ENVIRON) is not None
             or bool((getattr(request, 'session', None) or {}).get('user')))
    refused = no_lease_refusal(known)
    if refused is None:
        resp = jsonify({'code': 'HA_NO_LEASE',
                        'error': ha.NO_LEASE_ERROR if known else ha.NO_LEASE_ANON_ERROR})
        resp.headers['Retry-After'] = '10'
        refused = (resp, 503)
    return refused


def transfer_refusal():
    """503 HA_TRANSFER: the leader hands its lead to another member right now and takes
    no change until that went through or failed (design 7.1). For the write gate in
    app.py and a forwarded write, once ha.handing_over() said so."""
    resp = jsonify({'code': 'HA_TRANSFER', 'error': ha.TRANSFER_ERROR})
    resp.headers['Retry-After'] = '10'
    return resp, 503


def _auto_mode_refusal(error=ha.AUTO_MODE_ERROR):
    """409 HA_AUTO_MODE for what only a manual group does, None in a manual group."""
    if ha.mode() == ha_vote.MODE_MANUAL:
        return None
    return jsonify({'code': 'HA_AUTO_MODE', 'error': error}), 409


def standby_console_refusal():
    """The answer a console route gives where it opens none, None where it opens: on a
    standby that does not serve users, and on one that does for an API token, which
    gets the standby answer there like for any change (scripts use the leader)."""
    if ha.consoles_here() and not (ha.is_standby() and by_api_token()):
        return None
    return jsonify({'code': 'HA_STANDBY', 'error': STANDBY_CONSOLE_ERROR}), 409


# --- forwarded writes, the standby's half ------------------------------------------

def forward_to_active(read=False):
    """The answer for a write the block in app.py would refuse on this standby, when it
    goes to the active instead. None when it does not, and the block refuses it as
    before: not a write method, no browser session behind it (an API token is nobody
    the standby can vouch for), forwarding switched off, or the member it pulls from
    not seen active.

    read: a GET of ha.FORWARDED_READS, the progress of a job the active runs or a view
    only its own tables hold, or a GET of a plugin (ha.PLUGIN_PROXY_RULE). The same way
    there, with a short timeout. When it does not come back whole: None for the progress
    of a job, and the route answers from this instance; None for a plugin as well, which
    app.py refuses; 503 HA_ACTIVE_UNREACHABLE for a view of ha.LEADER_ONLY_READS, whose
    rows here are not the active's - also without an attempt while the leader is known
    to be away.

    The active runs the request as the signed-in user, checked against its own
    accounts, and its status, body and content headers come back as they are. 413
    above ha.FORWARD_MAX_BODY, read no further than that; 503 HA_ACTIVE_UNREACHABLE
    when the active cannot be reached, 504 HA_FORWARD_NO_ANSWER when it took the call
    and did not answer (the change may have happened there); 429 past one user's
    share, 503 HA_FORWARD_BUSY while other large bodies are on their way. A write that
    went through (2xx) starts a pull right away. An account whose password changed on
    the active since our last sync gets 401 and a sync, which ends the session here."""
    if request.environ.get(ha.FORWARD_ENVIRON) is not None:
        # a forwarded call that met an instance which stepped down meanwhile ends here
        return None
    if request.method not in (('GET',) if read else _FORWARD_METHODS):
        return None
    if request.headers.get('Authorization', '').startswith('Bearer pgx_'):
        return None
    from pegaprox.utils.auth import validate_session
    session = validate_session(request.headers.get('X-Session-ID') or request.cookies.get('session_id'))
    if not session:
        return None
    if not ha.forwarding():
        if read and ha.forward_writes() and not ha.leader_reachable():
            # the leader is known to be away: no attempt, but a view only it fills says
            # so instead of showing this instance's own rows
            return _no_leader_read()
        return None
    if not _forward_per_user.allow(session['user']):
        resp = jsonify({'error': 'Too many changes through this standby at once - slow down, or '
                                 'make them on the active instance'})
        resp.headers['Retry-After'] = '60'
        return resp, 429

    if read:
        return _forward_read(session)
    large = request.content_length is None or request.content_length > _FORWARD_LARGE
    if large and not _forward_large_slots.acquire(blocking=False):
        resp = jsonify({'code': 'HA_FORWARD_BUSY',
                        'error': 'This standby is handing other large changes to the active '
                                 'instance - try again in a moment'})
        resp.headers['Retry-After'] = '10'
        return resp, 503
    # a signed-in user's write: its upload may take as long as the link needs (#1052)
    lift_body_deadline(session['user'])
    try:
        return _forward(session)
    finally:
        if large:
            _forward_large_slots.release()


def _forward(session):
    too_large = (jsonify({'code': 'HA_FORWARD_TOO_LARGE',
                          'error': f'Too large to hand to the active instance - at most '
                                   f'{ha.FORWARD_MAX_BODY // (1024 * 1024)} MB. Make this '
                                   f'change on the active instance'}), 413)
    try:
        # werkzeug refuses a Content-Length above the cap before reading a byte, and cuts
        # a body without one at the cap without a word: one byte more tells a cut body
        # from a whole one. Not cached: no route runs here after this
        request.max_content_length = min(request.max_content_length or ha.FORWARD_MAX_BODY + 1,
                                         ha.FORWARD_MAX_BODY + 1)
        body = request.get_data(cache=False)
    except RequestEntityTooLarge:
        return too_large
    if len(body) > ha.FORWARD_MAX_BODY:
        return too_large

    envelope = _envelope_for(session, body)
    del body
    # the path is the browser's: no line breaks of its into our log
    what = sanitize_log_message(f'{request.method} {request.path}')
    try:
        resp = ha.forward_write(envelope)
    except ha.PeerNoAnswer as e:
        logging.warning(f"[HA] forwarded {what}, no answer from the active: {ha._error_text(e)}")
        return jsonify({'code': 'HA_FORWARD_NO_ANSWER', 'error': FORWARD_NO_ANSWER_ERROR}), 504
    except ha.HaError as e:
        logging.warning(f"[HA] could not forward {what}: {ha._error_text(e)}")
        return jsonify({'code': 'HA_ACTIVE_UNREACHABLE', 'error': FORWARD_UNREACHABLE_ERROR}), 503

    if resp.status_code == 200:
        answer = _forwarded_answer(resp)
        if answer is not None:
            status, headers, content = answer
            if 200 <= status < 300:
                ha.pull_soon()
            return Response(content, status=status, headers=headers)
        why = 'The active instance sent an answer this version does not read'
    elif resp.status_code == 403 and _answer_code(resp) == 'HA_FORWARD_STALE_SIGN_IN':
        # the password changed there: the sync ends this session, the browser signs in
        ha.pull_soon()
        return jsonify({'code': 'HA_FORWARD_STALE_SIGN_IN',
                        'error': 'Your password was changed on the active instance - sign in '
                                 'again'}), 401
    elif resp.status_code in (409, 410):
        # not active any more, or it took us out of the group: we refuse as a standby
        logging.warning(f"[HA] the active instance refused a forwarded {what} "
                        f"(HTTP {resp.status_code})")
        return None
    elif resp.status_code == 503 and _answer_code(resp) in ('HA_NO_LEASE', 'HA_TRANSFER'):
        # an automatic group between two leaders, or one handing its lead on: its
        # words, and when to try again
        out = jsonify(resp.json())
        out.headers['Retry-After'] = ha._answer_header(resp, 'Retry-After') or '10'
        return out, 503
    elif resp.status_code == 403 and _answer_code(resp) == 'HA_FORWARD_USER':
        # the account is not there, or disabled, on the active: its words
        return jsonify(resp.json()), 403
    elif resp.status_code == 413:
        # a proxy in front of the active, or its own size cap for requests
        return jsonify({'code': 'HA_FORWARD_TOO_LARGE',
                        'error': 'Too large for the active instance to take - make this '
                                 'change on the active instance'}), 413
    elif resp.status_code in (404, 405):
        why = ('The active instance runs a release that does not take changes from a '
               'standby - update it, or make the change there')
    else:
        why = ha._peer_error(resp, 'The active instance refused the change')
    logging.warning(f"[HA] forwarding {what} failed: {why}")
    return jsonify({'code': 'HA_FORWARD_REFUSED', 'error': why}), 502


def _envelope_for(session, body):
    return {
        'method': request.method,
        'path': request.path,
        'query': request.query_string.decode('latin-1'),
        'content_type': request.headers.get('Content-Type', ''),
        'body_b64': base64.b64encode(body).decode('ascii'),
        'user': session['user'],
        'sign_in': ha.sign_in_digest(session['user']),
        'client_ip': _plain_client_ip(),
    }


LEADER_READ_ERROR = ('The active instance did not answer - this list is kept there. Try '
                     'again in a moment')


def _forward_read(session):
    """The active's answer to a read of ha.FORWARDED_READS. Without one, None for our own
    copy, or the 503 a view of ha.LEADER_ONLY_READS answers instead: its rows here are
    this instance's own, and an ack picked from them would name another row there."""
    try:
        resp = ha.forward_write(_envelope_for(session, b''), timeout=ha.FORWARD_READ_TIMEOUT)
    except ha.HaError as e:
        logging.debug(f"[HA] could not fetch {sanitize_log_message(request.path)} from the "
                      f"active: {ha._error_text(e)}")
        return _no_leader_read()
    answer = _forwarded_answer(resp) if resp.status_code == 200 else None
    if answer is None:
        if resp.status_code == 403 and _answer_code(resp) == 'HA_FORWARD_STALE_SIGN_IN':
            ha.pull_soon()
        return _no_leader_read()
    status, headers, content = answer
    return Response(content, status=status, headers=headers)


def _no_leader_read():
    rule = request.url_rule.rule if request.url_rule is not None else None
    if rule not in ha.LEADER_ONLY_READS:
        return None
    return jsonify({'code': 'HA_ACTIVE_UNREACHABLE', 'error': LEADER_READ_ERROR}), 503


def _plain_client_ip():
    """The client address for the envelope, as the active checks it: a trusted proxy
    may hand on '1.2.3.4:5678', '[v6]:port' or 'unknown'. Anything that is not an
    address after taking the port off is the address the call came from here."""
    raw = (get_client_ip() or '').strip()
    candidates = [raw]
    if raw.startswith('[') and ']' in raw:
        candidates.append(raw[1:raw.index(']')])
    elif raw.count(':') == 1:
        candidates.append(raw.partition(':')[0])
    for value in candidates + [request.remote_addr or '']:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            continue
    return '0.0.0.0'


def _answer_code(resp):
    try:
        data = resp.json()
    except Exception:
        return ''
    return (data.get('code') or '') if isinstance(data, dict) else ''


def _forwarded_answer(resp):
    """(status, headers, body) from the active's answer to a forwarded write, None when
    it is not one."""
    try:
        data = resp.json()
        status, headers = data['status'], data['headers']
        content = base64.b64decode(data['body_b64'], validate=True)
    except Exception:
        return None
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return None
    if not isinstance(headers, dict):
        return None
    out = [(name, value) for name, value in headers.items()
           if name in _FORWARD_HEADERS and isinstance(value, str) and not _CONTROL_RE.search(value)]
    return status, out, content


# --- admin -----------------------------------------------------------------------

@bp.route('/api/ha/status', methods=['GET'])
@require_auth(roles=[ROLE_ADMIN])
def ha_status():
    """Role, epoch, members and last sync of this instance.

    members lists every other instance of the group, is_source marks the one a
    standby pulls from; peer is that one (or the first member) for older readers.
    suggested_url and own_fingerprint are what a pairing code made here would carry,
    so the UI can prefill the form. forward_writes is this instance's switch, forwarding
    whether a standby hands its writes to the active right now. serve_assigned says the
    leader made this standby active, serving that it serves users right now, actives
    and active_limit how many instances do and may; serve on a member is the leader's
    word, serving_seen what the member said. config_version is the cv of the
    configuration here, change_gap what a member was known to hold when this instance
    took the lead without it, and orphans the copies of what a sync did not carry over
    (count, bytes, over_limit, seal, items). An item names two keys. seal is the key the
    copy itself is sealed under: under ('master', derived from the master key of the key
    store, or 'field', the field key on plain SQLite), fp, current, backup and opens,
    whether this instance can open it; a copy under another master key has opens false.
    key is the field key the sealed values inside it are under: fp, current, and backup,
    the key file that still holds it once the key was rotated. seal next to items is
    what this instance seals a copy under now (under, fp). auto, once this release
    offers automatic failover: the mode, the lease and the findings, and pending while
    a switch to automatic failover is pending on this instance (by and by_url, the
    instance that started it, own, since and text), which is why it is not promoted by
    hand until the switch is through or taken back there. site is the label of this
    instance, members[].site the one of each member. split_safety, once this release
    offers automatic failover and on an instance of a group: whether the group survives
    the loss of a site and whether its clusters are ready (voters, majority, tolerates,
    level, sites, unlabeled, clusters, findings), with the very findings the switch goes
    by."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    return jsonify(_status_body())


@bp.route('/api/ha/pairing-code', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_pairing_code():
    """A one-time code for an instance that is to follow this one.

    url is this instance as the standby will reach it, user_password the caller's
    own password (see _refuse_without_reauth). A new code replaces an open one; it is
    good for 15 minutes and for one pairing. An active that has standbys already hands
    out codes too, up to three standbys."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    url = _https_url(_body().get('url'))
    if not url:
        return jsonify({'error': 'Enter the https:// address the standby will use to reach this instance'}), 400
    if ha.is_standby():
        return jsonify({'error': 'A standby cannot hand out pairing codes - promote it first'}), 409
    if ha.group_full():
        return jsonify({'error': ha.GROUP_FULL_ERROR}), 409
    waiting = ha.group_waiting()
    if waiting:
        return jsonify({'error': ha._group_waiting_error(waiting)}), 409
    if ha.mode() == ha_vote.MODE_PENDING:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': ha.AUTO_PENDING_ERROR}), 409
    denied = _refuse_without_reauth('a pairing code')
    if denied:
        return denied
    # an automatic group takes a member only on the instance that holds its lease, and
    # only once a majority said so again just now
    if ha.lease_in_force() and not ha.confirm_step('a pairing code'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    try:
        code, expires = ha.create_pairing_code(url, _own_fingerprint())
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not create a pairing code')}), 500
    log_audit(_user(), 'ha.pairing_code_created', f'pairing code for {url}, valid for 15 minutes')
    return jsonify({'code': code, 'expires_at': expires})


@bp.route('/api/ha/join', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def join_active():
    """Become the standby of the instance that made the code, then restart.

    This instance takes over the active's field key and, with the first sync, its
    configuration, so it wants user_password like the pairing code does. 502 means the
    conversation with the active failed: unreachable, wrong certificate, or it refused
    the code."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    if data.get('confirm') is not True:
        return jsonify({'error': 'Joining replaces the configuration of this instance - confirm it to go ahead'}), 400
    code = _str(data.get('code'), 4096)
    if not code:
        return jsonify({'error': 'Paste the pairing code from the active instance'}), 400
    own_url = _https_url(data.get('own_url'))
    if not own_url:
        return jsonify({'error': 'Enter the https:// address the active instance will use to reach this one'}), 400
    if ha.role() != ha.ROLE_STANDALONE or ha.members():
        return jsonify({'error': 'Only a standalone, unpaired instance can become a standby'}), 409
    try:
        info = ha.decode_code(code)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 400
    if info['instance_id'] == ha.instance_id():
        return jsonify({'error': 'That code was made on this instance'}), 400
    denied = _refuse_without_reauth('joining an active instance')
    if denied:
        return denied

    try:
        p = ha.join(code, own_url, _own_fingerprint())
    except ha.HaError as e:
        logging.warning(f"[HA] joining {info['url']} failed: {e}")
        return jsonify({'error': str(e)}), 502
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Joining the active instance failed')}), 500
    log_audit(_user(), 'ha.joined', f"standby of {p.get('url')} from now on (epoch {ha.epoch()})")
    ha.restart_process('joined as standby')
    return jsonify({'success': True, 'restarting': True})


@bp.route('/api/ha/sync-now', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def sync_now():
    """Pull from the active now instead of at the next interval."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    result = ha.pull_once()
    return jsonify({'result': result, 'status': _status_body()})


@bp.route('/api/ha/promote', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def promote_standby():
    """Make this standby the active instance under a new epoch, then restart.

    Wants user_password. When the instance it follows still answers, one sync from it
    comes first, so the new active starts from the configuration and the member list
    of now; if that sync fails the promotion is refused (409 HA_PROMOTE_SYNC), unless
    force is true. An instance that does not answer at all is the failover this is for.
    A sync that is under way finishes first either way, for up to 20 seconds.
    Every member hears about the new epoch before the restart, if it answers within a
    few seconds: the instance that was active steps down, the other standbys follow
    this one from their next look at the group. A member that does not answer does the
    same as soon as it sees this instance. 409 HA_AUTO_MODE in a group that fails
    over automatically or is switching to it: as this instance holds it, as the
    instance it follows said with the pairing or its last snapshot, or as a member or
    the witness that answers says right now. While a switch is pending here, the error
    names the instance that started it and since when (auto.pending of the status)."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != 'PROMOTE':
        return jsonify({'error': 'Type PROMOTE to confirm'}), 400
    if not ha.is_standby():
        return jsonify({'error': 'Only a standby can be promoted'}), 409
    refused = _auto_mode_refusal(ha.promote_refusal())
    if refused:
        # the group elects its leader, also while the switch to that is pending (the
        # answer then says who started the switch, and since when)
        return refused
    denied = _refuse_without_reauth('promoting this standby')
    if denied:
        return denied
    force = data.get('force') is True
    if not force:
        try:
            ok, why = ha.pull_before_promote()
        except Exception as e:
            ok, why = False, safe_error(e, 'the sync failed')
        if not ok:
            return jsonify({'code': 'HA_PROMOTE_SYNC',
                            'error': f'The instance this standby follows answers, but the sync '
                                     f'before the promotion failed: {why}. Fix that and try '
                                     f'again, or promote with force to take over anyway'}), 409
    old_active = ha.source_id()
    try:
        new_epoch = ha.promote()
    except ha.AutoMode as e:
        # this instance holds no voter config, and a member says the group elects
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Promotion failed')}), 500
    # a reachable old active steps down now, not after our restart and its next watch:
    # until then both would act on the same clusters
    said = {}
    told = ha.tell_members('POST', '/api/ha/peer/step-down', json_body={'epoch': new_epoch},
                           timeout=5, answers=said)
    for mid, err in told.items():
        if err:
            logging.warning(f"[HA] could not tell member {mid} about the promotion: {err}")
    reached = old_active in told and told[old_active] is None
    # its answer says whether it did: an active that refuses (the leader of an automatic
    # group leaves by its lease, not on a member's word) is still active
    theirs = said.get(old_active) or {}
    refused = reached and theirs.get('stepped_down') is False and theirs.get('role') == ha.ROLE_ACTIVE
    others = [mid for mid in told if mid != old_active]
    detail = (f", {sum(1 for mid in others if told[mid] is None)} of {len(others)} other "
              f"member(s) told" if others else '')
    how = 'refused to step down' if refused else 'told to step down' if reached else 'not reached'
    log_audit(_user(), 'ha.promoted', f"promoted to active with epoch {new_epoch}, "
                                      f"old active {how}"
                                      f"{detail}{', without the sync first (force)' if force else ''}")
    ha.restart_process('promoted to active')
    return jsonify({'success': True, 'epoch': new_epoch, 'restarting': True})


@bp.route('/api/ha/unpair', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def unpair_peer():
    """Leave the group. Every member is told first if it answers. Wants user_password.

    A standby leaves on its own: the active drops it, and with the next sync so does
    everybody else. It becomes standalone and restarts, because from then on it acts on
    the configuration it holds. An active leaves the group entirely: every member drops
    it and it becomes standalone; the standbys keep each other and wait for one of them
    to be promoted.

    In a group that fails over automatically a member leaves through the leader, which
    takes it out of the voter config first (left_through names it); without an answering
    leader that is 409 HA_AUTO_MODE, as it is on the leader itself (it hands its lead on
    first), on a member that holds a switch another instance started, and on one whose
    only way out is Force leader (auto.way_out of the status, ha.unpair_refusal)."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if _body().get('confirm') != 'UNPAIR':
        return jsonify({'error': 'Type UNPAIR to confirm'}), 400
    p = ha.peer()
    group = ha.members()
    # a standby or an active without a member (the other side unpaired first, then this
    # one was promoted) must still get out; only a standalone has nothing to undo
    if not group and ha.role() == ha.ROLE_STANDALONE:
        return jsonify({'error': 'This instance is not paired'}), 409
    through, said = None, []
    if ha.unpair_needs_leader():
        denied = _refuse_without_reauth('unpairing')
        if denied:
            return denied
        try:
            through = ha.leave_through_leader()
        except ha.AutoMode as e:
            return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    else:
        why, said = ha.unpair_check()
        if why:
            # before any member is told: nobody leaves an automatic group by hand
            return jsonify({'code': 'HA_AUTO_MODE', 'error': why}), 409
        denied = _refuse_without_reauth('unpairing')
        if denied:
            return denied

    # the leader that took this instance out knows, and holds its tombstone
    others = [m['instance_id'] for m in group if through is None or m['instance_id'] != through['instance_id']]
    told = ha.tell_members('POST', '/api/ha/peer/unpaired', timeout=10, only=others) if others else {}
    for mid, err in told.items():
        if err:
            logging.warning(f"[HA] could not tell member {mid} about the unpairing: {err}")
    if through is not None and len(others) < len(group):
        told[through['instance_id']] = None
    try:
        was = ha.unpair(said=said, leader_agreed=through is not None)
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Unpairing failed')}), 500
    restarting = was == ha.ROLE_STANDBY
    peer_label = (p or {}).get('url') or (p or {}).get('instance_id') or 'no peer'
    if len(group) > 1:
        peer_label += f' and {len(group) - 1} more'
    reached = sum(1 for err in told.values() if err is None)
    if len(group) > 1:
        told_label = f'{reached} of {len(group)} members told'
    else:
        told_label = 'peer told' if reached else 'peer not told'
    if through is not None:
        told_label += (f", taken out of the voter config by the leader "
                       f"{through.get('url') or through['instance_id']}")
    log_audit(_user(), 'ha.unpaired', f"unpaired from {peer_label} (was {was}, {told_label})")
    if restarting:
        ha.restart_process('unpaired, standalone from now on')
    out = {'success': True, 'restarting': restarting}
    if through is not None:
        out['left_through'] = through['instance_id']
    return jsonify(out)


@bp.route('/api/ha/members/<instance_id>/remove', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def remove_member(instance_id):
    """Take a standby out of the group, on the active. Wants user_password.

    Only a member that answered as a standby under the current epoch: anything else
    may be an old active that is merely down, and would act again once it is back.
    shut_down: true is the admin confirming that the instance is shut down for good;
    without it such a member gets 409 HA_REMOVE_UNCONFIRMED. The removed instance
    stays on record as removed, and every remaining member hears so at once: from
    then on its calls get 410 everywhere, and it lets go of the group when it hears
    that. It is told right away if it answers (told), and stays a passive standby
    until an admin unpairs it there. Removing the last standby makes this instance
    standalone.

    In a group that fails over automatically only the instance that holds the lease
    removes a member, once a majority confirmed that again (503 HA_NO_LEASE otherwise),
    and the member leaves the voter config first, one change at a time. 409 HA_AUTO_MODE
    where that would leave fewer than three votes, for the leader itself, and while a
    switch to automatic failover is pending."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != 'REMOVE':
        return jsonify({'error': 'Type REMOVE to confirm'}), 400
    if ha.role() != ha.ROLE_ACTIVE:
        return jsonify({'error': 'Only the active instance removes members'}), 409
    if ha.mode() == ha_vote.MODE_PENDING:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': ha.AUTO_PENDING_ERROR}), 409
    refused = no_lease_refusal()
    if refused:
        return refused
    if not ha.member(instance_id):
        return jsonify({'error': 'That instance is not a member of this group'}), 404
    shut_down = data.get('shut_down') is True
    if not shut_down and not ha.member_confirmed(instance_id):
        # the last tick may predate our epoch: ask the member itself before sending the
        # admin to the shut-down confirmation
        ha.refresh_member(instance_id)
    if not shut_down and not ha.member_confirmed(instance_id):
        return jsonify({'code': 'HA_REMOVE_UNCONFIRMED', 'error': ha.REMOVE_UNCONFIRMED_ERROR}), 409
    denied = _refuse_without_reauth('removing a member')
    if denied:
        return denied
    if ha.lease_in_force() and not ha.confirm_step('removing a member'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    try:
        signer = ha._signer()
        rec = ha.remove_member(instance_id, shut_down=shut_down)
    except ha.RemoveUnconfirmed as e:
        return jsonify({'code': 'HA_REMOVE_UNCONFIRMED', 'error': str(e)}), 409
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Removing the member failed')}), 500
    epoch = ha.epoch()
    # the others first: they drop it and keep its tombstone, so whatever it sends them
    # from now on is answered 410
    others = ha.tell_members('POST', '/api/ha/peer/member-removed',
                             json_body={'instance_id': instance_id, 'epoch': epoch},
                             timeout=10) if ha.members() else {}
    told = False
    try:
        resp = ha.call_member(rec, 'POST', '/api/ha/peer/unpaired',
                              json_body={'removed': True, 'epoch': epoch}, timeout=10, signer=signer)
        # an answer alone is not enough: it has to have let go of the group
        told = resp.status_code == 200 and (resp.json() or {}).get('left_group') is True
    except Exception as e:
        logging.warning(f"[HA] could not tell {rec.get('url') or instance_id} it was removed: {e}")
    reached = sum(1 for err in others.values() if err is None)
    log_audit(_user(), 'ha.member_removed',
              f"removed {rec.get('url') or instance_id} from the group "
              f"({'told' if told else 'not told'}"
              f"{', confirmed as shut down for good' if shut_down else ''}, "
              f"{reached} of {len(others)} other member(s) told, this instance is {ha.role()} now)")
    return jsonify({'success': True, 'told': told, 'members': ha.public_status()['members']})


@bp.route('/api/ha/members/<instance_id>/serve', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_member_serve(instance_id):
    """Make a member one of the group's active instances (serve: true), or a standby
    again (serve: false), on the leader.

    An active member serves users as the leader does: they sign in there, see the
    clusters live and open their consoles there, and every change goes to the leader.
    Its role stays standby, so the leader alone runs the automation. Up to three
    active instances, the leader included; one more is 409 HA_ACTIVE_LIMIT, and serve:
    false always goes through. The member takes it with its next sync, which every
    member is asked for right away. No password: this decides where users are served,
    not which instance acts on the clusters. actives in the answer counts the leader
    and every member it made active."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    serve = _body().get('serve')
    if not isinstance(serve, bool):
        return jsonify({'error': 'serve is true or false'}), 400
    if ha.role() != ha.ROLE_ACTIVE:
        return jsonify({'code': 'HA_STANDBY',
                        'error': 'Which instances are active is set on the leader'}), 409
    refused = no_lease_refusal()
    if refused:
        return refused
    if not ha.member(instance_id):
        return jsonify({'error': 'That instance is not a member of this group'}), 404
    try:
        changed, actives = ha.set_member_serve(instance_id, serve)
    except ha.ActiveLimit as e:
        return jsonify({'code': 'HA_ACTIVE_LIMIT', 'error': str(e)}), 409
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not save which instances are active')}), 500
    if changed:
        rec = ha.member(instance_id) or {}
        log_audit(_user(), 'ha.member_serve_changed',
                  f"{rec.get('url') or instance_id} is {'active' if serve else 'a standby'} from "
                  f"its next sync ({actives} of {ha.ACTIVE_LIMIT} instances active)")
        # the HA routes tell nobody by themselves (app.py): the member list changed
        ha.nudge_members()
    return jsonify({'success': True, 'serve': serve, 'actives': actives})


@bp.route('/api/ha/members/<instance_id>/readmit', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def readmit_member(instance_id):
    """Take a quarantined voter back, on the leader of an automatic group. Wants
    user_password.

    A voter that reports an older state than it reported before (a restored backup, a
    reverted VM snapshot) is quarantined by the leader: it may have forgotten a vote,
    so its votes and acks stop counting, and it still counts in the majority to reach.
    Once an admin has looked at it, this lets it count again, in force when a majority
    holds the change. 409 in a manual group and for a member that is not quarantined,
    503 HA_NO_LEASE on an instance that does not hold the lease."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if not ha.lease_in_force():
        return jsonify({'error': 'This group is in manual mode - nobody is quarantined'}), 409
    denied = _refuse_without_reauth('re-admitting a member')
    if denied:
        return denied
    try:
        ha.readmit_member(instance_id)
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not re-admit the member')}), 500
    rec = ha.member(instance_id) or {}
    log_audit(_user(), 'ha.member_readmitted',
              f"{rec.get('url') or instance_id} re-admitted: its votes count again once a "
              f"majority holds the change")
    return jsonify({'success': True})


# --- the lead of an automatic group (design 7) ----------------------------------------
#
# MK Oct 2026 (#625) - Make leader, Force leader and the VM each member runs as. All three
# are for a group that fails over automatically, which the server refuses until
# ha_vote.AUTO_MODE_SHIPPED is on; anywhere else they answer 409 and change nothing.

_INSTANCE_ID_RE = re.compile(r'[0-9a-f]{32}')


@bp.route('/api/ha/make-leader', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def make_leader():
    """Hand the lead of an automatic group to a data member with a vote. Wants confirm:
    LEADER and user_password.

    On the leader, target names the member. The leader pauses writes (503 HA_TRANSFER),
    the member catches up, and the leader stops acting and hands it its next term; the
    member votes at once and restarts as the leader, the old leader restarts as a
    standby. On a member, without target (or naming itself): it asks the leader to do
    that, and where no leader answers it campaigns at once, with the pre-vote and every
    rule. result: handed (the leader let go, the vote is out), elected (this instance won
    and restarts) or catching up. 409 HA_TRANSFER_REFUSED says why not: the target cannot
    win (no vote, quarantined, does not answer, behind on the voter config), it did not
    catch up within 10 s (writes are open again), the leader holds a majority this member
    is cut off from, or no majority answers at all (Force leader is offered then). 409
    HA_MANUAL in a group in manual mode, HA_AUTO_NOT_SHIPPED while this release does not
    offer automatic failover, 503 HA_NO_LEASE on a leader without its lease."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != ha.LEADER_PHRASE:
        return jsonify({'error': f'Type {ha.LEADER_PHRASE} to confirm'}), 400
    target = data.get('target')
    if target is not None and not (isinstance(target, str) and _INSTANCE_ID_RE.fullmatch(target)):
        return jsonify({'error': 'target is the instance id of a member'}), 400
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if ha.mode() != ha_vote.MODE_AUTO:
        return jsonify({'code': 'HA_MANUAL',
                        'error': 'This group does not fail over automatically - promote a standby instead'}), 409
    denied = _refuse_without_reauth('making a member leader')
    if denied:
        return denied
    who = target or ha.instance_id()
    try:
        result = ha.make_leader(target)
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.TransferRefused as e:
        return jsonify({'code': 'HA_TRANSFER_REFUSED', 'error': str(e)}), 409
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Make leader failed')}), 500
    rec = ha.member(who) or {}
    log_audit(_user(), 'ha.make_leader', f"made {rec.get('url') or who} leader of the group ({result})")
    return jsonify({'success': True, 'result': result, 'target': who})


@bp.route('/api/ha/force-leader', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def force_leader():
    """Force leader: this member of an automatic group that lost its majority for good
    becomes the manual active of its group. Wants confirm: FORCE LEADER, user_password,
    reason (free text) and cut_out, the instance ids of every voter that does not answer,
    each one powered off or destroyed - auto.force_leader of the status lists them, with
    the warning the dialog shows.

    Offered only where no leader was heard for the lease and a half, the last election
    from here found no majority answering, and nothing that answers holds the lease; also
    on a member that holds a pending switch to automatic failover whose maker is gone,
    and on one whose only way out is Force leader (auto.way_out). The members in cut_out
    are out of the group (they hear 410 and go passive when they come back), the voter
    config goes to manual mode at a new epoch, and automatic failover comes back only
    through the switch. After the restart this instance writes its claim (marked forced)
    on every cluster with the claim on, and switches autostart off on the VMs of the
    cut-out members an admin named (agent_vmid). The members that answer hear of the
    new epoch at once. 409 HA_FORCE_REFUSED with the reason where it is not offered or
    cut_out does not name exactly the members that do not answer."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    if data.get('confirm') != ha.FORCE_PHRASE:
        return jsonify({'error': f'Type {ha.FORCE_PHRASE} to confirm', 'warning': ha.FORCE_WARNING}), 400
    cut_out = data.get('cut_out')
    if (not isinstance(cut_out, list) or len(cut_out) > ha.MAX_MEMBERS + 1
            or not all(isinstance(x, str) and _INSTANCE_ID_RE.fullmatch(x) for x in cut_out)):
        return jsonify({'error': 'cut_out is the list of the instance ids that do not answer'}), 400
    reason = data.get('reason')
    if not isinstance(reason, str) or not reason.strip() or len(reason) > ha.FORCE_REASON_MAX:
        return jsonify({'error': f'Say why, in up to {ha.FORCE_REASON_MAX} characters'}), 400
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if not ha.is_standby():
        return jsonify({'code': 'HA_FORCE_REFUSED',
                        'error': 'Only a member that follows is forced to lead'}), 409
    denied = _refuse_without_reauth('forcing this member to lead')
    if denied:
        return denied
    try:
        out = ha.force_leader(cut_out, reason, _user())
    except ha.ForceRefused as e:
        return jsonify({'code': 'HA_FORCE_REFUSED', 'error': str(e)}), 409
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Force leader failed')}), 500
    # an active among the members that answer steps down now, the others follow this
    # instance once they see it
    told = ha.tell_members('POST', '/api/ha/peer/step-down', json_body={'epoch': out['epoch']},
                           timeout=5) if ha.members() else {}
    reached = sum(1 for err in told.values() if err is None)
    log_audit(_user(), 'ha.forced_leader',
              f"forced to lead at epoch {out['epoch']} ({out['case']}), manual mode from now on: "
              f"{sanitize_log_message(reason.strip())}; cut out as powered off or destroyed: "
              f"{', '.join(out['cut_out']) or 'nobody'}; {reached} of {len(told)} member(s) told")
    ha.restart_process('forced to lead')
    return jsonify({'success': True, 'epoch': out['epoch'], 'cut_out': out['cut_out'], 'restarting': True})


@bp.route('/api/ha/members/<instance_id>/agent-vmid', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_member_agent_vmid(instance_id):
    """The VM a member runs as on one cluster, on the leader: cluster_id and vmid (null
    forgets it). instance_id may be the leader itself. Force leader switches autostart off
    on the VMs of the members it cuts out (design 7.3); the members learn it with their
    next sync. No password: it names a VM, it does not act on one. 404 for a cluster this
    instance does not manage, 409 anywhere but on the leader, 409 HA_AUTO_NOT_SHIPPED
    while this release does not offer automatic failover (Force leader is refused then
    too), 503 HA_NO_LEASE on a leader without its lease."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    cluster_id, vmid = data.get('cluster_id'), data.get('vmid')
    if not isinstance(cluster_id, str) or not cluster_id:
        return jsonify({'error': 'cluster_id is the id of a cluster'}), 400
    if vmid is not None and (isinstance(vmid, bool) or not isinstance(vmid, int) or vmid < 100):
        return jsonify({'error': 'vmid is the id of a VM (100 or more), or null'}), 400
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if ha.role() != ha.ROLE_ACTIVE or not ha.members():
        return jsonify({'code': 'HA_STANDBY', 'error': 'The VM of a member is set on the leader of a group'}), 409
    refused = no_lease_refusal()
    if refused:
        return refused
    from pegaprox.globals import cluster_managers
    # forgetting a VM needs no cluster this instance still manages: one deleted since
    # would keep its entry for good
    if vmid is not None and cluster_id not in cluster_managers:
        return jsonify({'error': 'Cluster not found'}), 404
    try:
        changed = ha.set_agent_vmid(instance_id, cluster_id, vmid)
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not save the VM of the member')}), 500
    if changed:
        rec = ha.member(instance_id) or {}
        log_audit(_user(), 'ha.member_agent_vmid',
                  f"{rec.get('url') or instance_id} runs as VM {vmid} on cluster {cluster_id}" if vmid
                  else f"{rec.get('url') or instance_id}: no VM on cluster {cluster_id} any more")
        # the HA routes tell nobody by themselves (app.py): the member list changed
        ha.nudge_members()
    return jsonify({'success': True, 'changed': changed})


# MK Oct 2026 (#625) - what an admin sets per member on the leader (design 3.1, 8): the
# site, a label the split checks go by, and vote and may lead, which in an automatic group
# are a change of the voter config (4.12).

@bp.route('/api/ha/members/<instance_id>/site', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_member_site(instance_id):
    """The site a member runs at, on the leader: site, a label of up to 64 characters
    ('' for none). instance_id may be the leader itself, a member or the witness.

    It decides nothing about who votes, leads or acts: the split checks (status
    split_safety, the switch's checklist) group the votes by it. So a manual group takes
    it as well, and so does a release that does not offer automatic failover yet. The
    members learn it with their next sync, which they are asked for right away. No
    password: it names a place, it does not act. 404 for an instance that is not in the
    group, 409 HA_STANDBY anywhere but on the leader, 409 HA_AUTO_MODE while a switch to
    automatic failover is pending, 503 HA_NO_LEASE on a leader without its lease."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    site = _body().get('site')
    if not isinstance(site, str) or ha._clean_site(site) is None:
        return jsonify({'error': ha.SITE_ERROR}), 400
    if ha.role() != ha.ROLE_ACTIVE or not ha.members():
        return jsonify({'code': 'HA_STANDBY', 'error': ha.SITE_LEADER_ERROR}), 409
    if ha.mode() == ha_vote.MODE_PENDING:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': ha.AUTO_PENDING_ERROR}), 409
    refused = no_lease_refusal()
    if refused:
        return refused
    witness = ha.witness() or {}
    if instance_id != ha.instance_id() and not ha.member(instance_id) and witness.get('instance_id') != instance_id:
        return jsonify({'error': ha.NOT_A_MEMBER_ERROR}), 404
    before = ha._site_of(ha._load(), instance_id)
    try:
        changed = ha.set_member_site(instance_id, site)
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not save the site')}), 500
    label = ha._clean_site(site)
    if changed:
        log_audit(_user(), 'ha.member_site_changed',
                  f"{ha._who(ha._load(), instance_id)} runs at site {sanitize_log_message(label) or '(none)'} "
                  f"(was {sanitize_log_message(before) or '(none)'})")
        # the HA routes tell nobody by themselves (app.py): the member list changed
        ha.nudge_members()
    return jsonify({'success': True, 'site': label, 'changed': changed})


@bp.route('/api/ha/members/<instance_id>/vote', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_member_vote(instance_id):
    """Whether a data member votes and may lead on its own, on the leader: voter and/or
    may_lead (true or false), and user_password. instance_id may be the leader itself
    (may_lead only: the leader keeps its vote).

    In a group that fails over automatically this is a change of the voter config: the
    leader confirms its lease with a majority first, makes one change at a time (409
    HA_VOTE_REFUSED while one waits or is on its way), never leaves fewer than three
    votes, never takes its own vote, gives none to a member that does not answer its
    renewals, and makes no change after which the members that answer would not make a
    majority. It answers once the change is on disk and is in force once a majority
    holds it. In a manual group it is noted for the next switch, which takes it into
    the voter config. 409 HA_VOTE_REFUSED says which rule stands in the way, 409
    HA_STANDBY anywhere but on the leader, HA_AUTO_MODE while a switch is pending,
    HA_AUTO_NOT_SHIPPED while this release does not offer automatic failover, 503
    HA_NO_LEASE on a leader without its lease."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    asked = {k: data[k] for k in ('voter', 'may_lead') if k in data}
    if not asked or not all(isinstance(v, bool) for v in asked.values()):
        return jsonify({'error': 'voter and may_lead are true or false, one of them at least'}), 400
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if ha.role() != ha.ROLE_ACTIVE or not ha.members():
        return jsonify({'code': 'HA_STANDBY', 'error': ha.VOTE_LEADER_ERROR}), 409
    if ha.mode() == ha_vote.MODE_PENDING:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': ha.AUTO_PENDING_ERROR}), 409
    refused = no_lease_refusal()
    if refused:
        return refused
    witness = ha.witness() or {}
    if instance_id != ha.instance_id() and not ha.member(instance_id) and witness.get('instance_id') != instance_id:
        return jsonify({'error': ha.NOT_A_MEMBER_ERROR}), 404
    denied = _refuse_without_reauth('changing the vote of a member')
    if denied:
        return denied
    automatic = ha.lease_in_force()
    try:
        changed = ha.set_member_vote(instance_id, **asked)
    except ha.VoteRefused as e:
        return jsonify({'code': 'HA_VOTE_REFUSED', 'error': str(e)}), 409
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not change the vote of the member')}), 500
    if changed:
        what = ', '.join(f"{'vote' if k == 'voter' else 'may lead'} {'on' if v else 'off'}"
                         for k, v in asked.items())
        log_audit(_user(), 'ha.member_vote_changed',
                  f"{ha._who(ha._load(), instance_id)}: {what} "
                  + ('(a change of the voter config, in force once a majority holds it)' if automatic
                     else '(taken into the voter config at the next switch to automatic failover)'))
        ha.nudge_members()
    return jsonify({'success': True, 'changed': changed, 'automatic': automatic, **asked})


@bp.route('/api/ha/mode', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_mode():
    """Switch the group between manual and automatic failover, on the leader. Wants
    user_password.

    mode: auto starts the switch. It needs at least three votes (data members or the
    witness), every member answering on this release within the last two minutes,
    clocks within 5 s, a time zone for the group (one that has none takes the zone of
    this instance; where that cannot be told, it is set first) and no member that says
    the group is automatic already while this instance holds no voter config of that;
    what stands in the way comes back as 409 HA_AUTO_REFUSED with
    findings [{code, level, text, member}]. A warning (an even number of votes) wants
    its code in accept, else 409 HA_AUTO_CONFIRM with the same list. The voter config
    then goes to every member as pending, and automatic mode is in force once all of
    them hold it (waiting names them); one that does not take it within ten minutes
    takes the group back to manual mode. lease_s is the lease length, 15 to 120 s,
    20 unless given; sent again in automatic mode it changes it.

    mode: manual switches it off, in force once a majority holds the change, or takes a
    pending switch back. The answer's mode is the group's: auto, with result off, while
    the change waits for that majority (the leader still holds its lease then, and one
    that loses it first drops the change); manual once it is through. 409 while it
    waits, HA_AUTO_NOT_SHIPPED while this release does not offer automatic failover,
    503 HA_NO_LEASE on an instance that does not hold the lease, 500 when the change
    could not be written (nothing changed)."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    want = data.get('mode')
    if want not in (ha_vote.MODE_AUTO, ha_vote.MODE_MANUAL):
        return jsonify({'error': 'mode is auto or manual'}), 400
    lease_s = data.get('lease_s', ha_vote.LEASE_DEFAULT)
    if isinstance(lease_s, bool) or not isinstance(lease_s, int) \
            or not ha_vote.LEASE_MIN <= lease_s <= ha_vote.LEASE_MAX:
        return jsonify({'error': ha.LEASE_RANGE_ERROR}), 400
    accept = data.get('accept') if isinstance(data.get('accept'), list) else []
    accept = [code for code in accept if isinstance(code, str)][:32]
    if want == ha_vote.MODE_AUTO and not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if ha.role() != ha.ROLE_ACTIVE:
        return jsonify({'code': 'HA_STANDBY',
                        'error': 'Automatic failover is switched on the leader of a group'}), 409
    now = ha.mode()
    if want == ha_vote.MODE_MANUAL and now == ha_vote.MODE_MANUAL:
        return jsonify({'error': 'This group is in manual mode'}), 409
    denied = _refuse_without_reauth('switching automatic failover')
    if denied:
        return denied
    try:
        if want == ha_vote.MODE_MANUAL:
            done = ha.switch_auto_off()
            log_audit(_user(), 'ha.mode_changed',
                      'automatic failover switched off, in force once a majority of the members '
                      'holds the change' if done == 'off'
                      else 'the pending switch to automatic failover taken back')
            return jsonify({'success': True, 'mode': ha.mode(), 'result': done})
        if now == ha_vote.MODE_AUTO:
            changed = ha.set_lease_seconds(lease_s)
            if changed:
                log_audit(_user(), 'ha.mode_changed', f'lease length set to {lease_s} s')
            return jsonify({'success': True, 'mode': now, 'lease_s': lease_s, 'changed': changed})
        waiting = ha.switch_auto_on(lease_s, accept)
    except ha.AutoRefused as e:
        return jsonify({'code': 'HA_AUTO_CONFIRM' if e.confirm else 'HA_AUTO_REFUSED',
                        'error': str(e), 'findings': e.findings}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.StateNotWritten as e:
        return jsonify({'error': str(e)}), 500
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not switch the mode')}), 500
    log_audit(_user(), 'ha.mode_changed',
              f"switch to automatic failover started (lease {lease_s} s, waiting for "
              f"{len(waiting)} member(s){', accepted: ' + ', '.join(accept) if accept else ''})")
    return jsonify({'success': True, 'mode': ha.mode(), 'lease_s': lease_s, 'waiting': waiting})


@bp.route('/api/ha/timezone', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def set_timezone():
    """The time zone the group's schedules are evaluated in, on the leader.

    Members may run in different zones. Scheduled actions, scheduled tasks, snapshot
    policies and scheduled updates fire by the wall time of this zone on whichever
    member leads, so a failover does not shift them. timezone is an IANA name
    (Europe/Vienna). A group formed on this release starts with the zone of the
    instance that formed it; one formed before has none until it is set here, and each
    instance goes by its own zone until then. The members take it with their next
    sync, which they are asked for right away. The last-run stamps of the schedules
    move to the new zone first; 500 when they could not be moved or the zone not be
    saved, and the zone stays as it was then. 400 for a name this instance does not
    know, or when it has no time zone data at all. No password: it decides when a
    schedule fires, not which instance acts."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    name = _str(_body().get('timezone'), 100)
    if not name:
        return jsonify({'error': 'timezone is the name of a time zone, like Europe/Vienna'}), 400
    if ha.role() != ha.ROLE_ACTIVE:
        return jsonify({'code': 'HA_STANDBY',
                        'error': "The group's time zone is set on the leader of a group"}), 409
    before = ha.group_timezone()
    try:
        changed = ha.set_group_timezone(name)
    except ha.NoLease:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    except ha.StateNotWritten as e:
        return jsonify({'error': str(e)}), 500
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not save the time zone')}), 500
    if changed:
        log_audit(_user(), 'ha.timezone_changed',
                  f"schedules are evaluated in {name} from now on (was {before or 'the zone of each instance'})")
        # the HA routes tell nobody by themselves (app.py)
        ha.nudge_members()
    return jsonify({'success': True, 'timezone': name, 'changed': changed})


@bp.route('/api/ha/settings', methods=['PUT'])
@require_auth(roles=[ROLE_ADMIN])
def update_settings():
    """How often the standby pulls and the active looks at its peer, the live view, and
    whether this instance as a standby forwards writes.

    interval is in seconds. live_view is this instance's own switch: on, a standby
    connects to the clusters read-only; off, it holds no connection at all. A standby
    restarts when live_view changes, because it sets its connections up once per
    process; any other role only keeps the value for when it follows. forward_writes,
    also this instance's own: on, a standby hands the writes of its signed-in users to
    the active; off, it refuses them. It counts from the next write. Any of the three,
    or several. Whether a standby serves users is not its own switch: the leader sets
    it for every member (PUT /api/ha/members/<instance_id>/serve), and serve_users here
    gets 400 HA_SERVE_ON_LEADER."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    if 'serve_users' in data:
        # before anything else in the body is saved: the admin is on the wrong page
        return jsonify({'code': 'HA_SERVE_ON_LEADER',
                        'error': 'Which instances are active is set on the leader'}), 400
    if not any(k in data for k in ('interval', 'live_view', 'forward_writes')):
        return jsonify({'error': 'Nothing to change - send interval, live_view, forward_writes '
                                 'or several of them'}), 400
    interval = data.get('interval')
    if 'interval' in data and (isinstance(interval, bool) or not isinstance(interval, int)
                               or not _MIN_INTERVAL <= interval <= _MAX_INTERVAL):
        return jsonify({'error': f'The interval is a whole number of seconds, '
                                 f'{_MIN_INTERVAL} to {_MAX_INTERVAL}'}), 400
    live = data.get('live_view')
    if 'live_view' in data and not isinstance(live, bool):
        return jsonify({'error': 'live_view is true or false'}), 400
    forward = data.get('forward_writes')
    if 'forward_writes' in data and not isinstance(forward, bool):
        return jsonify({'error': 'forward_writes is true or false'}), 400
    status = ha.public_status()
    if status['broken']:
        # saving now would write the placeholder state over the file that could not be
        # read, and with it the instance id, the epoch and the peer secrets
        return jsonify({'error': 'The HA state file cannot be read - repair or remove '
                                 'config/ha_state.json first'}), 409

    out = {'success': True}
    if 'interval' in data:
        before = status['interval']
        try:
            # instance-local, never part of a snapshot; ha.py has no setter of its own
            ha._update(interval=interval)
        except ha.HaError as e:
            return jsonify({'error': str(e)}), 409
        except Exception as e:
            return jsonify({'error': safe_error(e, 'Could not save the interval')}), 500
        log_audit(_user(), 'ha.settings_changed', f'sync interval {before}s -> {interval}s')
        out['interval'] = interval

    # before the live view, which may restart this standby
    if 'forward_writes' in data:
        try:
            changed = ha.set_forward_writes(forward)
        except ha.HaError as e:
            return jsonify({'error': str(e)}), 409
        except Exception as e:
            return jsonify({'error': safe_error(e, 'Could not save the forwarding switch')}), 500
        if changed:
            log_audit(_user(), 'ha.settings_changed',
                      f"forwarding writes to the active instance {'on' if forward else 'off'}")
        out['forward_writes'] = forward

    if 'live_view' in data:
        was = ha.live_view()
        try:
            ha.set_live_view(live)
        except ha.HaError as e:
            return jsonify({'error': str(e)}), 409
        except Exception as e:
            return jsonify({'error': safe_error(e, 'Could not save the live view')}), 500
        restarting = False
        if live != was:
            standby = ha.is_standby()
            log_audit(_user(), 'ha.live_view_changed',
                      f"live view {'on' if live else 'off'}"
                      f"{', restarting this standby' if standby else ', takes effect as a standby'}")
            if standby:
                restarting = ha.apply_config_now() == 'restart'
        out.update(live_view=live, restarting=restarting)
    return jsonify(out)


@bp.route('/api/ha/apply-config', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def apply_config():
    """Take up a configuration change that is waiting on this standby, now.

    A sync that changes how the clusters are reached leaves a reload of those managers
    waiting, which a standby does by itself once the change holds still; a switched
    live view waits for a restart. This does either at once: reloaded says the
    managers were rebuilt in place, restarting that the process restarts. No password:
    it only decides when, not what."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if not ha.is_standby():
        return jsonify({'error': 'Only a standby takes its configuration from the active instance'}), 409
    sync = ha.public_status().get('sync') or {}
    pending = sync.get('restart_pending') or sync.get('reload_pending') or {}
    try:
        done = ha.apply_config_now()
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not apply the configuration')}), 500
    restarting, reloaded = done == 'restart', done == 'reload'
    if restarting or reloaded:
        reason = pending.get('reason') if isinstance(pending, dict) else ''
        log_audit(_user(), 'ha.config_applied',
                  ('restarting this standby now' if restarting else 'reloaded the managers now')
                  + (f' for the waiting change: {reason}' if reason else ''))
    return jsonify({'success': True, 'restarting': restarting, 'reloaded': reloaded})


# What this instance held and a sync did not carry over (ha.ORPHANS_DIR). The list is
# part of the status; these two hand one out and let go of one. They work on a standby
# as well: that is where the copies are.

@bp.route('/api/ha/orphans/<name>/download', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def download_orphan(name):
    """One copy of changes that were not carried over, as gzip'd JSON: the rows this
    instance held and the snapshot did not carry (sealed values stay sealed), the files
    it replaced, and the journal lines of who wrote them. On disk the copy is sealed
    (under a key derived from the master key, on plain SQLite under the field key) and
    is opened here, after user_password: account rows are in there, as in the config
    backup. 404 for a name that is no copy, 409 with the reason for one that does not
    open: sealed under another master key than this instance runs with (the key store
    changed, or the copy came from another host), under a field key from before a
    rotation whose backup is gone, or a file that was changed."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if not ha.orphan_path(name):
        return jsonify({'error': 'There is no such copy'}), 404
    denied = _refuse_without_reauth('downloading changes that were not carried over')
    if denied:
        return denied
    try:
        data = ha.open_orphan(name)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not read the copy')}), 500
    if data is None:
        return jsonify({'error': 'There is no such copy'}), 404
    log_audit(_user(), 'ha.changes_downloaded', f'{name}, a copy of changes not carried over')
    return Response(data, status=200, mimetype='application/gzip', headers={
        'Content-Disposition': f'attachment; filename="pegaprox-ha-{name}.json.gz"',
        'Cache-Control': 'no-store'})


@bp.route('/api/ha/orphans/<name>/dismiss', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def dismiss_orphan(name):
    """An admin has looked at a copy of changes that were not carried over, and it can
    go: nothing else ever deletes one. Wants confirm: true. 404 for a name that is no
    copy. A copy goes before a sync or after it, never while one looks at what the
    copies hold: this waits a few seconds for a sync that is under way, and answers 409
    HA_SYNC_RUNNING when that one takes longer; the copy is still there then."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if _body().get('confirm') is not True:
        return jsonify({'error': 'Dismissing deletes the copy for good - confirm it to go ahead'}), 400
    try:
        gone = ha.dismiss_orphan(name, _user())
    except ha.SyncRunning as e:
        resp = jsonify({'code': 'HA_SYNC_RUNNING', 'error': str(e)})
        resp.headers['Retry-After'] = '10'
        return resp, 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not dismiss the copy')}), 500
    if not gone:
        return jsonify({'error': 'There is no such copy'}), 404
    return jsonify({'success': True, 'orphans': ha.orphans_summary()})


# --- the witness ------------------------------------------------------------------
#
# MK Oct 2026 (#625) - the third vote of a group, a process of its own that holds no
# configuration (pegaprox/witness.py). It is paired and removed here, on the leader.

@bp.route('/api/ha/witness/pairing-code', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def create_witness_code():
    """A one-time code for the witness of this group, on the leader. Wants user_password.

    url is this instance as the witness reaches it, site where the witness runs (a label,
    for the split checks). The answer spells out one command per way to install the
    witness with the code in it (install: linux, offline, docker, manual, with
    installer_sha256, image, branch, docker_note, placeholder, placeholder_in, note and
    firewall; see witness_install_commands); docker is null with docker_note where no
    image of this release runs the witness. commands is the older form. The code is good for 15 minutes and
    one pairing; a new one replaces an open one. One witness per group: 409 while it has
    one, and 409 HA_AUTO_NOT_SHIPPED while this release does not offer automatic failover,
    which is what a witness votes in. In an automatic group only the instance a majority
    just confirmed makes one (503 HA_NO_LEASE)."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    data = _body()
    url = _https_url(data.get('url'))
    if not url:
        return jsonify({'error': 'Enter the https:// address the witness will use to reach this instance'}), 400
    site = data.get('site', '')
    if not isinstance(site, str) or len(site.strip()) > ha_vote.SITE_MAX:
        return jsonify({'error': f'site is a label of up to {ha_vote.SITE_MAX} characters'}), 400
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    why = ha.witness_refusal()
    if why:
        return jsonify({'error': why}), 409
    denied = _refuse_without_reauth('a witness pairing code')
    if denied:
        return denied
    if ha.lease_in_force() and not ha.confirm_step('a witness pairing code'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    try:
        code, expires = ha.create_witness_code(url, _own_fingerprint(), site)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not create a witness code')}), 500
    log_audit(_user(), 'ha.witness_code_created', f'witness code for {url}, valid for 15 minutes')
    install = witness_install_commands(url, code)
    return jsonify({'code': code, 'expires_at': expires, 'install': install, 'commands': {
        'package': f"pegaprox-witness join '{code}' --url 'https://{WITNESS_HOST}:5005'",
        'docker': install['docker']}})


# --- how a witness gets installed -----------------------------------------------------
#
# MK Oct 2026 (#625) - one command per way, with the code in it. The Linux line fetches
# packaging/witness/install.sh from GitHub, then from its mirror (the order update.sh
# goes by), and runs it only when it matches the SHA-256 of the copy this instance
# ships; where neither has that copy (another release on main, no internet), from this
# instance itself. The installer takes the witness code from this instance too
# (witness_code_bundle), pinned to the fingerprint in the code.

WITNESS_HOST = '<witness-host>'
INSTALLER_REL = 'packaging/witness/install.sh'
# updates.pegaprox.com mirrors the repository, the raw files at their repo path
INSTALLER_SOURCES = (f'{GITHUB_RAW_URL}/{INSTALLER_REL}', f'{MIRROR_RAW_URL}/{INSTALLER_REL}')
WITNESS_IMAGE = 'ghcr.io/pegaprox/pegaprox'
# what .github/workflows/docker-testing.yml publishes from every push to Testing
WITNESS_TESTING_IMAGE = 'ghcr.io/pegaprox/pegaprox-testing:latest'
# the last release whose image has no witness in it: its command `witness` starts a whole
# PegaProx instead
WITNESS_IMAGE_AFTER = '1.2.0'
BRANCH_FILE = '.pegaprox-branch'
_BRANCH_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,99}')


def _git_branch(root):
    """The branch a git checkout at `root` is on, '' for none (a worktree's .git is a file
    that names its git directory)."""
    git = os.path.join(root, '.git')
    try:
        if os.path.isfile(git):
            with open(git, encoding='utf-8') as fh:
                line = fh.read(4096).strip()
            if not line.startswith('gitdir:'):
                return ''
            git = os.path.join(root, line[len('gitdir:'):].strip())
        with open(os.path.join(git, 'HEAD'), encoding='utf-8') as fh:
            head = fh.read(4096).strip()
    except OSError:
        return ''
    return head[len('ref: refs/heads/'):] if head.startswith('ref: refs/heads/') else ''


def update_branch():
    """The branch of the repository this instance follows, 'main' unless its install says
    another: PEGAPROX_BRANCH in its environment (the Testing image carries it, see
    docker-testing.yml), else .pegaprox-branch next to its code (deploy.sh and update.sh
    run with PEGAPROX_BRANCH write it), else the branch of a git checkout it runs from."""
    root = ha.code_root()
    value = (os.environ.get('PEGAPROX_BRANCH') or '').strip()
    if not value:
        try:
            with open(os.path.join(root, BRANCH_FILE), encoding='utf-8') as fh:
                value = fh.read(200).strip()
        except OSError:
            value = ''
    if not value:
        value = _git_branch(root)
    return value if _BRANCH_RE.fullmatch(value) else 'main'


def witness_image(version, branch):
    """(image, note): the image whose command `witness` runs the witness of this code, or
    None and why there is none. A Testing build names the Testing image, a release its own
    image from the first one that ships the witness on; before that there is none."""
    if branch.lower() == 'testing':
        return WITNESS_TESTING_IMAGE, None
    if witness_boot.release_key(version) > witness_boot.release_key(WITNESS_IMAGE_AFTER):
        return f'{WITNESS_IMAGE}:{version}', None
    return None, (f'The Docker image of release {version} has no witness yet, so there is no Docker line: '
                  'use the Linux line, or the line by hand.')


def witness_installer():
    """(bytes, SHA-256) of the witness installer this instance ships, None where it ships
    none (a build without packaging/)."""
    try:
        with open(os.path.join(ha.code_root(), *INSTALLER_REL.split('/')), 'rb') as fh:
            data = fh.read()
    except OSError:
        return None
    return data, hashlib.sha256(data).hexdigest()


def witness_install_commands(url, code, branch=None):
    """The ready commands of "Add witness" for the code `code` of this instance at `url`
    (both shapes the shell takes as they are, see ha_wire): linux, offline, docker and
    manual, and what the UI says around them. linux and offline are None where this
    instance ships no installer, docker where no image runs the witness of this code
    (witness_image, docker_note says why). `branch`, the one this instance follows
    (update_branch)."""
    from pegaprox.constants import PEGAPROX_VERSION
    branch = branch or update_branch()
    # quoted: a placeholder left in reaches the witness, which says what to put there
    # (the shell would take <witness-host> for a redirection)
    own = f"'https://{WITNESS_HOST}:5005'"
    image, image_note = witness_image(PEGAPROX_VERSION, branch)
    out = {
        'version': PEGAPROX_VERSION, 'branch': branch, 'image': image, 'docker_note': image_note, 'port': 5005,
        'installer_sha256': None, 'linux': None, 'offline': None,
        'docker': (f'docker run -d --name pegaprox-witness --restart unless-stopped -p 5005:5005 '
                   f"-v pegaprox-witness:/app/witness {image} witness run --join '{code}' --url {own}"
                   if image else None),
        'manual': f"python3 pegaprox_multi_cluster.py witness run --join '{code}' --url {own}",
        'placeholder': WITNESS_HOST, 'placeholder_in': ['docker', 'manual'] if image else ['manual'],
        'note': (f'Replace {WITNESS_HOST} in the ' + ('Docker and manual commands' if image else 'manual command')
                 + ' with the name or address the members reach the witness at. The Linux installer works '
                 'it out on the witness host (add --url https://...:5005 to choose another). The code is '
                 'good for 15 minutes and one witness.' + (f' {image_note}' if image_note else '')),
        'firewall': ('Open TCP port 5005 on the witness host for the members of the group, and '
                     'nothing else.'),
    }
    inst = witness_installer()
    if inst is None:
        return out
    sha = inst[1]
    check = f"echo '{sha}  install.sh' | sha256sum -c"
    sudo = '$([ "$(id -u)" -eq 0 ] || echo sudo)'
    # the code on stdin (printf is the shell's own): on a command line any user of the
    # witness host reads it in the process list until it is spent
    run = f"printf '%s\\n' '{code}' | {sudo} sh install.sh --code -"
    here = f'{url}/api/ha/witness/installer'
    # curl -k only because the digest is checked before anything runs; straight to this
    # instance, never through a proxy of the environment, which may not reach it (the
    # installer and the witness talk to it the same way). GitHub and the mirror go
    # through one where it is set, and give up in time where the way out is dropped
    from_here = f"curl -fsSLko install.sh --noproxy '*' '{here}'"
    from_public = 'curl -fsSL --connect-timeout 10 --max-time 120 -o install.sh "$u"'
    # the checksum is of this release's installer: once the leader runs another one, the
    # line says where to go instead of a bare FAILED. The installer stays the last word of
    # the line, so --url or --port can be added at its end
    hint = ("echo 'pegaprox-witness: no install.sh that matches this line - it works while the leader runs "
            "the release that made it. Where the witness is installed: sudo sh /opt/pegaprox-witness/install.sh "
            "- else make a new code with Add witness on the leader' >&2")
    checked = f'{{ {check} || {{ {hint}; false; }}; }} && {run}'
    # nothing came from anywhere: not a release that does not match, but the way to this
    # instance (its address, a firewall, its IP allow list answering 403)
    got = (f"{{ [ -f install.sh ] || {{ echo 'pegaprox-witness: could not download install.sh from {here} "
           "(curl says why above; a 403 there is the IP allow list of the leader - add this host in "
           "Settings > Security)' >&2; false; }; }")
    out['installer_sha256'] = sha
    out['linux'] = (f'cd "$(mktemp -d)" && for u in {" ".join(INSTALLER_SOURCES)}; do '
                    f'{from_public} && {check} --status && break; rm -f install.sh; done; '
                    f'[ -f install.sh ] || {from_here}; {got} && {checked}')
    out['offline'] = f'cd "$(mktemp -d)" && {from_here}; {got} && {checked}'
    return out


@bp.route('/api/ha/witness/installer', methods=['GET'])
def witness_installer_file():
    """The witness installer this instance ships (packaging/witness/install.sh), for a
    witness host that reaches neither GitHub nor its mirror.

    No session: it is the file the repository publishes, and the line "Add witness"
    shows checks it against its SHA-256 (X-Checksum-Sha256 here too) before anything of
    it runs. Exactly this one file; 404 where this instance ships none."""
    inst = witness_installer()
    if inst is None:
        return jsonify({'error': 'This instance does not ship the witness installer'}), 404
    resp = Response(inst[0], mimetype='text/x-shellscript')
    resp.headers['Content-Disposition'] = 'attachment; filename="install.sh"'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Checksum-Sha256'] = inst[1]
    return resp


# every try with a code counts, as at the pairing routes; a signed call only when it fails
_bundle_attempts = SlidingWindow(limit=10, window=300, max_keys=2048, name='ha-witness-bundle')


@bp.route('/api/ha/witness/bundle', methods=['POST'])
def witness_code_bundle():
    """The code the witness runs, as one archive signed with this instance's key
    (ha.witness_bundle): {manifest, sig, archive}, the manifest with the release, the
    wire, the archive's size, SHA-256 and files and who signed.

    For two callers and nobody else. The installer on the witness host, with the open
    witness code in the body ({code}; looked at and not spent - only the leader holds
    one): 403 for any other code. The paired witness, by a call signed with its key, for
    its update (any member serves it, the witness takes the signature of any data voter):
    401 for a wrong signature, 401 HA_CLOCK for a good one whose time is off; with
    {check: true} it only asks whether this group still counts it ({witness: true}, no
    code). Nothing else can be fetched here: the bundle is a fixed list of files."""
    try:
        request.max_content_length = _MAX_PEER_BODY
        body = request.get_data(cache=True)
    except Exception:
        body = None
    ip = get_client_ip()
    if body is None or request.query_string:
        return jsonify({'error': 'Bad request'}), 400
    if request.headers.get(ha.PEER_HEADER):
        kind, rec = request_witness()
        if kind == 'skewed':
            return jsonify(ha.clock_refusal(request.headers)), 401
        if kind != 'witness':
            if not _peer_failures.allow(ip):
                resp = jsonify({'error': 'Too many failed peer calls'})
                resp.headers['Retry-After'] = '300'
                return resp, 429
            logging.warning(f"[HA] refused a witness call from {ip} to {request.path}")
            return jsonify({'error': 'Not the witness of this group', 'instance_id': ha.instance_id()}), 401
        if _body().get('check') is True:
            # the installer asks whether this group still counts the witness, not for code
            return jsonify({'witness': True, 'instance_id': ha.instance_id()})
        who = f"the witness {rec.get('url') or rec['instance_id']}"
    else:
        if not _bundle_attempts.allow(ip):
            resp = jsonify({'error': 'Too many attempts - wait a few minutes'})
            resp.headers['Retry-After'] = '300'
            return resp, 429
        if not ha.witness_code_ok(_str(_body().get('code'))):
            logging.warning(f"[HA] witness code bundle for {ip} refused: {ha.PAIRING_CODE_ERROR}")
            return jsonify({'error': ha.PAIRING_CODE_ERROR}), 403
        who = f'the installer at {ip}'
    try:
        out = ha.witness_bundle()
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not put the witness code together')}), 500
    logging.info(f"[HA] witness code {out['manifest']['name']} sent to {who}")
    return jsonify(out)


@bp.route('/api/ha/witness/remove', methods=['POST'])
@require_auth(roles=[ROLE_ADMIN])
def remove_witness():
    """Take the witness out of the group, on the leader. Wants confirm: REMOVE and
    user_password.

    In an automatic group the voter config follows, as a change a majority has to hold;
    409 HA_AUTO_MODE where the group would be left with fewer than three votes (switch
    automatic failover off first), 503 HA_NO_LEASE on an instance that does not hold the
    lease. The witness is told right away if it answers (told), and the members drop it
    with their next sync."""
    denied = _refuse_confined_admin()
    if denied:
        return denied
    if _body().get('confirm') != 'REMOVE':
        return jsonify({'error': 'Type REMOVE to confirm'}), 400
    if ha.role() != ha.ROLE_ACTIVE:
        return jsonify({'error': ha.WITNESS_LEADER_ERROR}), 409
    if ha.witness() is None:
        return jsonify({'error': ha.WITNESS_NONE_ERROR}), 404
    denied = _refuse_without_reauth('removing the witness')
    if denied:
        return denied
    if ha.lease_in_force() and not ha.confirm_step('removing the witness'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    try:
        rec = ha.remove_witness()
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Removing the witness failed')}), 500
    told = False
    try:
        resp = ha.call_witness(rec, 'POST', ha.WITNESS_UNPAIRED_PATH,
                               json_body={'removed': True, 'epoch': ha.epoch()})
        told = resp.status_code == 200 and (resp.json() or {}).get('left_group') is True
    except Exception as e:
        logging.warning(f"[HA] could not tell the witness {rec.get('url')} it was removed: {e}")
    log_audit(_user(), 'ha.witness_removed',
              f"removed the witness {rec.get('url') or rec['instance_id']} ({'told' if told else 'not told'})")
    # the HA routes tell nobody by themselves (app.py): the record goes with the next sync
    ha.nudge_members()
    return jsonify({'success': True, 'told': told})


# --- node agents -----------------------------------------------------------------

_AGENT_CLUSTER = re.compile(r'[A-Za-z0-9_.-]{1,64}')
_AGENT_HEX = re.compile(r'[0-9a-f]+')
AGENT_NOT_LEADER = 'standby'


def _agent_mac(token, text):
    return hmac.new(token.encode(), text.encode(), 'sha256').hexdigest()


@bp.route('/api/ha/agent', methods=['GET'])
def agent_leader_check():
    """What the self-fence agent of a node asks: does this instance lead? (#625)

    No session. The node shows that it belongs to the cluster with sig, an HMAC-SHA256
    under the cluster's agent token over "pegaprox-agent ask <cluster> <nonce>". The
    answer is one line of text: "leader <epoch> <mac>" from the instance that acts on
    the clusters, "standby" from any other. The mac is under the same token, over
    "pegaprox-agent leader <cluster> <nonce> <epoch>". Neither side sends the token, the
    agent does not have to trust the certificate, and an answer fits one nonce only.
    400 for a question that has no shape, 403 for one the token does not sign - an
    unknown cluster answers the same, so the route does not say which clusters exist."""
    cluster = request.args.get('cluster', '')
    nonce = request.args.get('nonce', '')
    sig = request.args.get('sig', '')
    if not (_AGENT_CLUSTER.fullmatch(cluster) and len(nonce) == 32 and _AGENT_HEX.fullmatch(nonce)
            and len(sig) == 64 and _AGENT_HEX.fullmatch(sig)):
        return Response('bad request\n', status=400, mimetype='text/plain')
    from pegaprox.globals import cluster_managers
    cfg = getattr(cluster_managers.get(cluster), 'ha_config', None)
    token = cfg.get('agent_token') if isinstance(cfg, dict) else None
    known = isinstance(token, str) and len(token) == 64 and bool(_AGENT_HEX.fullmatch(token))
    # the same work for a cluster that is not there, so the time it takes says nothing
    signed = hmac.compare_digest(
        _agent_mac(token if known else '0' * 64, f'pegaprox-agent ask {cluster} {nonce}'), sig)
    if not (signed and known):
        return Response('forbidden\n', status=403, mimetype='text/plain')
    if not ha.is_active():
        return Response(f'{AGENT_NOT_LEADER}\n', mimetype='text/plain')
    epoch = ha.epoch()
    mac = _agent_mac(token, f'pegaprox-agent leader {cluster} {nonce} {epoch}')
    return Response(f'leader {epoch} {mac}\n', mimetype='text/plain')


# --- peer ------------------------------------------------------------------------

# where request_peer keeps its verdict: on the request itself. flask.g belongs to the
# app context, and a request served while another one of the same app is still open
# (a test client call from inside a route) shares that one.
_PEER_VERDICT = 'pegaprox.ha_peer'


def request_peer():
    """Who sent this peer call, as ha.peer_verdict says: ('member', record),
    ('removed', tombstone), ('skewed', record) or (None, None). Worked out once per
    request, because a nonce counts once: the IP allow list asks first, the route
    after it.

    No peer call carries a query string. One that does, or whose path holds a '?'
    once decoded, is nobody's: the signature covers the path alone, so the two could
    not be told apart."""
    env = request.environ
    if _PEER_VERDICT in env:
        return env[_PEER_VERDICT]
    verdict = (None, None)
    try:
        plain = not request.query_string and '?' not in request.path
        limit = _peer_body_limit()
        if plain and (request.content_length is None or request.content_length <= limit):
            request.max_content_length = limit
            body = request.get_data(cache=True)
            if len(body) <= limit:
                verdict = ha.peer_verdict(request.headers, request.method, request.path, body)
    except Exception as e:
        logging.warning(f"[HA] could not check a peer call to {request.path}: {e}")
        verdict = (None, None)
    env[_PEER_VERDICT] = verdict
    return verdict


_WITNESS_VERDICT = 'pegaprox.ha_witness'
# the witness's own signed calls: its update and its leaving. The IP allow list lets them
# through as it does a member's signed call (settings.ip_lists_pass)
WITNESS_SIGNED_PATHS = ('/api/ha/witness/bundle', ha.WITNESS_LEAVE_PATH)


def request_witness():
    """Who sent this call in the witness's name, as ha.witness_verdict says: ('witness',
    record), ('skewed', record) or (None, None). Worked out once per request, as
    request_peer is (a nonce counts once): the IP allow list asks first, the route after
    it. Only for the paths the witness signs."""
    env = request.environ
    if _WITNESS_VERDICT in env:
        return env[_WITNESS_VERDICT]
    verdict = (None, None)
    try:
        plain = not request.query_string and '?' not in request.path
        if (plain and request.path in WITNESS_SIGNED_PATHS and request.headers.get(ha.PEER_HEADER)
                and (request.content_length is None or request.content_length <= _MAX_PEER_BODY)):
            request.max_content_length = _MAX_PEER_BODY
            body = request.get_data(cache=True)
            if len(body) <= _MAX_PEER_BODY:
                verdict = ha.witness_verdict(request.headers, request.method, request.path, body)
    except Exception as e:
        logging.warning(f"[HA] could not check a witness call to {request.path}: {e}")
        verdict = (None, None)
    env[_WITNESS_VERDICT] = verdict
    return verdict


def _peer_body_limit():
    """How much of a peer call is read before its sender is known. A forwarded write
    carries an upload, and it comes in chunks (ha._peer_call), past the size check the
    app makes on a Content-Length; its cap is set here, on the active, and only for a
    call whose headers are signed by a member we hold a key of, over the digest of the
    body to come. Everything else is a few bytes."""
    if (request.method == 'POST' and request.path == ha.FORWARD_PATH
            and ha.role() == ha.ROLE_ACTIVE and signed_member_call()):
        return _MAX_FORWARD_ENVELOPE
    return _MAX_PEER_BODY


def signed_member_call():
    """Whether this request's headers carry a good signature of a member, checked
    before its body is read (ha.signed_before_body), once per request. The rate limit
    in app.py and the read limit above go by it; the route still checks the whole
    call."""
    key = 'pegaprox.ha_signed_headers'
    if key not in request.environ:
        request.environ[key] = ha.signed_before_body(request.headers, request.method, request.path)
        if request.environ[key]:
            # a member signed for the body to come: not an anonymous one (#1052)
            lift_body_deadline()
    return request.environ[key]


@bp.after_request
def _say_we_hold_the_key(resp):
    # the caller signed with a key we hold: it can stop sending its old secret
    kind, who = request.environ.get(_PEER_VERDICT) or (None, None)
    if kind == 'member' and who.get('keyed'):
        resp.headers[ha.PEER_KEYED_HEADER] = '1'
    return resp


def _peer_body():
    """The JSON object a peer call carries, {} for anything else. Read whatever the
    Content-Type says: the signature covers the body and not that header, so a
    changed header must not turn a notice into an empty one."""
    data = request.get_json(force=True, silent=True)
    return data if isinstance(data, dict) else {}


def _peer_or_refuse():
    """(peer, None) when the call is from a member, else (None, response): 410
    HA_REMOVED for a member the group took out, 401 HA_CLOCK for a member whose
    signature is good but whose time is not, 401 for anybody else."""
    kind, who = request_peer()
    if kind == 'member':
        return who, None
    if kind == 'removed':
        return None, (jsonify({'code': 'HA_REMOVED', 'epoch': int(who.get('epoch') or 0),
                               'error': 'This instance was removed from the group - unpair it'}), 410)
    if kind == 'skewed':
        # the signature is good, so this is the member itself: no failure to count
        return None, (jsonify(ha.clock_refusal(request.headers)), 401)
    ip = get_client_ip()
    if not _peer_failures.allow(ip):
        logging.debug(f"[HA] peer calls from {ip} over the failure budget")
        resp = jsonify({'error': 'Too many failed peer calls'})
        resp.headers['Retry-After'] = '300'
        return None, (resp, 429)
    logging.warning(f"[HA] refused a peer call from {ip} to {request.path}")
    # who refuses: an active that every member refuses steps aside, and another
    # instance at a member's address (one set up anew there) is not that member
    return None, (jsonify({'error': 'Not the paired instance', 'instance_id': ha.instance_id()}), 401)


@bp.route('/api/ha/peer/pair', methods=['POST'])
def peer_pair():
    """The standby's half of the pairing handshake.

    No session and no peer header: the pairing code in the body authenticates the
    call and is spent by it. The standby sends its Ed25519 public key (public_key).
    The field key, our own public key, the member list and the removed members go
    back sealed with a key derived from that code, and the group's mode when it is
    not manual. The code is looked at first: a wrong one gets 403 on every instance,
    whatever the group does. With the right one, 503 HA_NO_LEASE in an automatic group
    on an instance a majority did not just confirm, and 403 for an instance that holds
    a vote there and would lose it by pairing again."""
    ip = get_client_ip()
    if not _pair_attempts.allow(ip):
        resp = jsonify({'error': 'Too many pairing attempts - wait a few minutes'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    data = _body()
    if not ha.pairing_code_ok(_str(data.get('code'))):
        # first, and the same on every instance: whoever holds no code learns nothing
        # about the group from this route, and costs its leader no round
        logging.warning(f"[HA] pairing attempt from {ip} refused: {ha.PAIRING_CODE_ERROR}")
        return jsonify({'error': ha.PAIRING_CODE_ERROR}), 403
    if ha.lease_in_force() and not ha.confirm_step('pairing a member'):
        # an automatic group: only the instance a majority just confirmed takes a member
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    # not cut here: core refuses an over-long address instead of pairing a shortened one
    standby_url = _str(data.get('url'), 4096)
    try:
        out = ha.accept_pairing(_str(data.get('code')), _str(data.get('instance_id'), 64),
                                standby_url, _str(data.get('fingerprint'), 128),
                                _str(data.get('public_key'), 128))
    except ha.HaError as e:
        logging.warning(f"[HA] pairing attempt from {ip} refused: {e}")
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Pairing failed')}), 500
    log_audit('system', 'ha.paired',
              f"standby {standby_url or data.get('instance_id')} paired, epoch {out['epoch']}",
              ip_address=ip)
    return jsonify(out)


@bp.route('/api/ha/peer/status', methods=['GET'])
def peer_status():
    """Role and epoch, for the watch loop of every other member. group says this
    release takes calls from every member, not only from one peer; serving that this
    standby serves users, which the others show. cv is the configuration it holds
    ([epoch, seq, segment, leader]) and cv_at when that last stepped: what the leader
    is at, and how far each member has pulled."""
    _p, refused = _peer_or_refuse()
    if refused:
        return refused
    out = dict({'instance_id': ha.instance_id(), 'role': ha.role(), 'epoch': ha.epoch(),
                'group': ha.GROUP_MARK, 'serving': ha.serving()}, **ha.peer_cv())
    if ha_vote.AUTO_MODE_SHIPPED:
        out.update(ha.peer_lease_status())
    return jsonify(out)


def _if_none_match():
    """The tags in If-None-Match, unquoted. The standby sends the bare etag it read
    from the last body; a proxy in between may have quoted it."""
    raw = request.headers.get('If-None-Match', '')
    tags = set()
    for part in raw.split(','):
        part = part.strip()
        if part.startswith('W/'):
            part = part[2:]
        tags.add(part.strip('"'))
    tags.discard('')
    return tags


_SNAPSHOT_SEM = None


def _build(meta):
    # runs in the threadpool: no state lock and no logging in here, both are gevent
    # locks a native thread cannot hand back to a waiting greenlet
    stuck, raw = [], []
    snap = ha.build_snapshot(meta, stuck=stuck, raw=raw)
    return snap, raw, stuck


def _one_at_a_time():
    """Hashing and packing every shared table is CPU work, done in gevent's threadpool
    (_pool) while the hub keeps serving the UI and the consoles. One snapshot at a
    time, and the config version steps in the order of the walks it comes from."""
    global _SNAPSHOT_SEM
    try:
        from gevent.lock import BoundedSemaphore
    except Exception:
        return contextlib.nullcontext()
    if _SNAPSHOT_SEM is None:
        _SNAPSHOT_SEM = BoundedSemaphore(1)
    return _SNAPSHOT_SEM


def _pool(fn):
    try:
        from gevent import get_hub
    except Exception:
        return fn()
    return get_hub().threadpool.apply(fn)


def current_etag(meta=None, held=None):
    """The etag a poll of the snapshot gets now, without the body: for the poll, for the
    note the active sends its members after a change (ha.nudge_members) and for the tick
    of an automatic leader (ha.cv_tick). Back on the hub the config version steps when
    the tables and files changed since it last did. `meta` read on the hub, from
    ha.snapshot_meta(); the worker never touches the state. `held` is the config
    version the member that polls says it holds."""
    meta = meta or ha.snapshot_meta()
    raw = []
    with _one_at_a_time():
        upto = ha.journal_mark()
        etag = _pool(lambda: ha.snapshot_etag(meta, raw=raw))
        try:
            ha.note_config_etag(raw[0], upto, data=raw[1], held=held)
        except ha.HaError as e:
            # the snapshot itself is refused until the step can be saved (_snapshot_body)
            logging.warning(f"[HA] {e}")
    return etag


def _snapshot_body(meta, held=None):
    """(snapshot, its gzip'd body, stuck): built in the threadpool, its config version
    put on it on the hub, packed in the threadpool. Raises ha.HaError when the cv
    cannot be saved."""
    with _one_at_a_time():
        upto = ha.journal_mark()
        snap, raw, stuck = _pool(lambda: _build(meta))
        ha.stamp_snapshot(snap, raw[0], upto, data=raw[1], held=held)
        return snap, _pool(lambda: ha.snapshot_bytes(snap)), stuck


@bp.route('/api/ha/peer/snapshot', methods=['GET'])
def peer_snapshot():
    """The shared configuration as gzip-compressed JSON, for the standby.

    304 when If-None-Match carries the current etag. 409 unless this instance is the
    active one: a standby must never serve a snapshot another standby could take. A
    standby names the active it follows in follow {instance_id, url, fingerprint,
    public_key, epoch}, for a member that missed it; that member checks it with the
    active itself before it follows.

    The member sends the config version it holds in X-PegaProx-Peer-Cv, [epoch, seq,
    segment, leader] as JSON. When that is more of this instance's own segment than it
    knows of (its state went back to an earlier one), the snapshot goes out under a
    segment of its own, and the member keeps a copy of what it holds."""
    _p, refused = _peer_or_refuse()
    if refused:
        return refused
    if ha.role() != ha.ROLE_ACTIVE or not ha.holds_lease():
        # in an automatic group only the instance that holds the lease hands out the
        # configuration: what a leader without one holds may be behind
        body = {'error': 'This instance is not active'}
        hint = ha.follow_hint()
        if hint:
            body['follow'] = hint
        return jsonify(body), 409
    started = time.monotonic()
    try:
        # read on the hub, member list included: the worker never touches the state
        meta = ha.snapshot_meta()
        held = ha.held_cv(request.headers.get(ha.PEER_CV_HEADER))
        # the etag alone first: most polls end in a 304 and never build the body
        etag = current_etag(meta, held)
        headers = {'ETag': f'"{etag}"', 'Cache-Control': 'no-store'}
        if etag in _if_none_match():
            return Response(status=304, headers=headers)
        snap, body, stuck = _snapshot_body(meta, held)
        ha.warn_stuck(stuck)
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not build the snapshot')}), 500
    headers['ETag'] = f'"{snap["etag"]}"'
    logging.debug(f"[HA] snapshot {snap['etag']}: {len(body)} bytes in {time.monotonic() - started:.2f}s")
    # Content-Encoding set here keeps flask-compress from compressing it again
    headers['Content-Encoding'] = 'gzip'
    return Response(body, status=200, mimetype='application/json', headers=headers)


@bp.route('/api/ha/peer/step-down', methods=['POST'])
def peer_step_down():
    """A member is active under a newer epoch, or under ours with the higher instance
    id. We become its standby and restart; anything else changes nothing.
    holds_lease: true is the leader of an automatic group, which holds its lease at
    that epoch: an active made by hand next to it steps down at an epoch as high as
    ours too, whatever the instance ids say (a majority renews that leader)."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    data = _peer_body()
    new_epoch = data.get('epoch')
    if ha._epoch_value(new_epoch, low=1) is None:
        return jsonify({'error': 'epoch must be a positive whole number'}), 400
    holds = data.get('holds_lease') is True and ha_vote.AUTO_MODE_SHIPPED
    changed = ha.step_down(new_epoch, p['instance_id'], holds_lease=holds)
    if changed:
        log_audit('system', 'ha.stepped_down',
                  f"peer {p.get('url') or p['instance_id']} is active with epoch {new_epoch}",
                  ip_address=get_client_ip())
        ha.restart_process('stepped down to standby')
    return jsonify({'stepped_down': changed, 'role': ha.role(), 'epoch': ha.epoch()})


@bp.route('/api/ha/peer/unpaired', methods=['POST'])
def peer_unpaired():
    """A member left the group, and we drop it. An active whose last member left
    becomes standalone; a standby stays passive until an admin unpairs or promotes it
    here.

    removed: true is the instance the group follows saying it took this one out of
    the group: we then let go of every member and stay passive until an admin unpairs
    us, an active included. From any other member it is a plain leave. left_group
    says which of the two it was."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    removed = _peer_body().get('removed') is True
    was = ha.role()
    result = ha.forget_peer(p['instance_id'], whole_group=removed)
    if result:
        what = ('removed this instance from the group' if result == 'group'
                else 'unpaired on its side')
        log_audit('system', 'ha.unpaired',
                  f"member {p.get('url') or p['instance_id']} {what}, "
                  f"this instance is {ha.role()} now", ip_address=get_client_ip())
    if was == ha.ROLE_ACTIVE and ha.is_standby():
        ha.restart_process('removed from the group')
    return jsonify({'success': True, 'forgotten': bool(result), 'left_group': result == 'group',
                    'role': ha.role()})


@bp.route('/api/ha/peer/member-removed', methods=['POST'])
def peer_member_removed():
    """The active took another member out of the group: instance_id, and the epoch it
    did so under. We drop that member now rather than with the next member list, and
    keep its tombstone, so its calls get 410 here too. Taken only from the instance
    the group follows."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    data = _peer_body()
    gone = data.get('instance_id')
    dropped = ha.note_member_removed(p['instance_id'], gone, data.get('epoch'))
    if dropped:
        log_audit('system', 'ha.member_removed',
                  f"member {p.get('url') or p['instance_id']} removed member {gone} from the group",
                  ip_address=get_client_ip())
    return jsonify({'success': True, 'dropped': dropped})


@bp.route('/api/ha/peer/tombstones', methods=['POST'])
def peer_tombstones():
    """A member holds tombstones for members this active still lists.

    The removal happened while this instance could not hear about it, and it was
    promoted since. tombstones is the list as the member list carries it. Each one is
    taken only for a member that has not answered as a standby under our epoch, asked
    once more first, and whose credentials it names; taken lists the ones that were.
    Anywhere but on the active nothing changes."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    taken = ha.take_tombstones(p['instance_id'], _peer_body().get('tombstones'))
    for mid in taken:
        log_audit('system', 'ha.member_removed',
                  f"member {p.get('url') or p['instance_id']} holds a tombstone for member {mid}, "
                  f"which is out of the group here too", ip_address=get_client_ip())
    return jsonify({'success': True, 'taken': taken})


@bp.route('/api/ha/peer/changed', methods=['POST'])
def peer_changed():
    """The active changed its configuration (ha.nudge_members): pull now instead of at
    the next poll. Taken from the member this standby pulls from, and the pull is one
    like any other, from that member; from any other member nothing happens. etag is
    the configuration the active holds now: a standby whose last sync was that one has
    nothing to pull. A note without it (an active of an earlier release) is a pull.
    cv and cv_at say where the active's configuration is at; the standby keeps them for
    the day it takes the lead before it has pulled that far. pull says whether the note
    was taken."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    data = _peer_body()
    ours = ha.is_standby() and p['instance_id'] == ha.source_id()
    if ours:
        ha.note_leader_cv(p['instance_id'], data.get('cv'), data.get('cv_at'))
    taken = ours and not ha.holds_etag(data.get('etag'))
    if taken:
        # runs in the background, and asks that come in meanwhile make one more pull
        ha.pull_soon()
    return jsonify({'success': True, 'pull': taken})


# --- automatic failover, between the members -------------------------------------------

def _lease_call(p, kind):
    if not p.get('keyed'):
        # a member that still goes by its old secret signs nothing, and a vote rests
        # on who asked for it
        return jsonify({'code': 'HA_LEASE_UNSIGNED',
                        'error': 'Only a member that signs its calls votes or renews'}), 401
    return jsonify(ha.lease_request(p['instance_id'], kind, _peer_body()))


@bp.route('/api/ha/peer/vote', methods=['POST'])
def peer_vote():
    """A member asks for this instance's vote, or (pre: true) whether it would get it.

    The body is {epoch, candidate, pre, why, cv, cfg_id, lease_s} and, when this voter
    may lack them, the voter configs it is missing (chain). The answer is always 200
    with {granted, ok, reason, epoch, cv, cfg_id, gen}: a real vote is on disk before
    it is granted, a pre-vote changes nothing. reason says why not: MODE_MANUAL (this
    group, or this member, is not in automatic mode; cfg_id [0, 0] and gen 0 from a
    member that holds no voter config at all), NOT_SHIPPED (this release does
    not offer it), NOT_CANDIDATE, TERM, PROMISED (a leader holds this voter's promise),
    HOLD_AFTER_START (this process started less than a lease ago), OLD_CFG, STALE
    (this voter holds a newer configuration, named in fresher), LEADER, GONE.
    These calls have a replay cache of their own, apart from the other peer calls."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    return _lease_call(p, 'vote')


@bp.route('/api/ha/peer/renew', methods=['POST'])
def peer_renew():
    """The leader of an automatic group renews its lease with this member.

    The body is {epoch, leader, lease_s, cv, wall, floor_cv}, the voter configs this
    member lacks (chain), leader_cv and leader_cv_at (where the leader's configuration
    is at), hold_s for a planned restart, and switch: true while a switch to automatic
    mode is pending. The answer is always 200 with {ok, reason, epoch, cv, cfg_id,
    gen}. A member that takes it promises the leader its vote for the length of the
    lease and pulls from it from then on; a higher epoch than its own is on disk
    before the answer. reason says why not: MODE_MANUAL (with cfg_id [0, 0] and gen 0
    from a member that holds no voter config at all), NOT_SHIPPED, OLD_EPOCH, NOT_VOTER
    (the sender is no data voter of the config held here), PROMISED (holder: the
    leader this voter renewed in this very term), MODE_AUTO (a switch round to a
    member that is in automatic mode already), CFG_GAP or BAD_CFG (the voter configs
    do not follow the ones held here), GONE. The answer to a switch round names the
    config held here by its digest (cfg_digest). A switch round with taken_back: true
    comes from a member that started a switch and took it back as it stopped leading:
    a member that holds its pending config takes the manual one, every other answers
    NOT_PENDING and takes nothing."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    return _lease_call(p, 'renew')


@bp.route('/api/ha/peer/fingerprint', methods=['POST'])
def peer_fingerprint():
    """A member says which certificate pin reaches it from now on: fingerprint, the
    SHA-256 fingerprint of its certificate, or '' for one a CA signed.

    Its self-signed certificate was made anew, or it changed between a self-signed and
    a CA certificate; the pin held here would refuse every call to it. Taken only from
    the member itself, on its signature under the key held here. changed says whether
    the pin held here is another one now. Part of automatic failover, whose members
    announce it: 409 HA_AUTO_NOT_SHIPPED while this release does not offer that, and
    the pin stays the one taken at pairing."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    if not p.get('keyed'):
        return jsonify({'code': 'HA_LEASE_UNSIGNED',
                        'error': 'Only a member that signs its calls announces a pin'}), 401
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    try:
        changed = ha.take_fingerprint(p['instance_id'], _peer_body().get('fingerprint'))
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Could not save the pin')}), 500
    if changed:
        log_audit('system', 'ha.fingerprint_changed',
                  f"member {p.get('url') or p['instance_id']} announced a new certificate pin",
                  ip_address=get_client_ip())
    return jsonify({'success': True, 'changed': changed})


@bp.route('/api/ha/peer/campaign', methods=['POST'])
def peer_campaign():
    """The leader of an automatic group handed this member its next term (Make leader,
    design 7.1): {epoch}, the term it leads. This member votes at once, without the
    pre-vote, only while it holds the allowance for exactly the next term from that
    leader's renewal; a late or replayed call does nothing. The answer is 200 with
    {ok, reason}, NO_ALLOWANCE when nothing was handed to it."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    return _lease_call(p, 'campaign')


@bp.route('/api/ha/peer/transfer', methods=['POST'])
def peer_transfer():
    """A member asks this leader to hand it the lead: an admin chose Make leader there
    (design 7.1). Only for the member itself, only from one that signs its calls, only
    on the leader of an automatic group (409 with follow anywhere else). The answer waits
    until the member caught up and the term went out: result handed or catching up; 409
    HA_TRANSFER_REFUSED says why not (it cannot win, it did not catch up in time), 503
    HA_NO_LEASE on a leader without its lease."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    if not p.get('keyed'):
        return jsonify({'code': 'HA_LEASE_UNSIGNED',
                        'error': 'Only a member that signs its calls asks for the lead'}), 401
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if ha.role() != ha.ROLE_ACTIVE or not ha.lease_in_force():
        out = {'error': 'This instance does not lead an automatic group'}
        hint = ha.follow_hint()
        if hint:
            out['follow'] = hint
        return jsonify(out), 409
    try:
        result = ha.hand_over(p['instance_id'])
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.TransferRefused as e:
        return jsonify({'code': 'HA_TRANSFER_REFUSED', 'error': str(e)}), 409
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    log_audit('system', 'ha.make_leader', f"member {p.get('url') or p['instance_id']} asked for the "
                                          f"lead and was handed it ({result})", ip_address=get_client_ip())
    return jsonify({'success': True, 'result': result})


@bp.route('/api/ha/peer/leave', methods=['POST'])
def peer_leave():
    """A member of an automatic group unpairs, and asks this leader first (design 7.4):
    it goes out of the voter config, one change at a time and once a majority confirmed
    the lease again, then out of the member list. left: true once it may go. 409
    HA_AUTO_MODE where that would leave fewer than three votes, 409 with follow on an
    instance that does not lead, 503 HA_NO_LEASE on a leader without its lease."""
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    if not p.get('keyed'):
        return jsonify({'code': 'HA_LEASE_UNSIGNED',
                        'error': 'Only a member that signs its calls leaves this way'}), 401
    if not ha_vote.AUTO_MODE_SHIPPED:
        return jsonify({'code': 'HA_AUTO_NOT_SHIPPED', 'error': ha_vote.NOT_SHIPPED_ERROR}), 409
    if ha.role() != ha.ROLE_ACTIVE or not ha.lease_in_force():
        out = {'error': 'This instance does not lead an automatic group'}
        hint = ha.follow_hint()
        if hint:
            out['follow'] = hint
        return jsonify(out), 409
    if not ha.confirm_step('a member leaving the group'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    try:
        ha.member_leaves(p['instance_id'])
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    log_audit('system', 'ha.member_left', f"member {p.get('url') or p['instance_id']} left the group: "
                                          'out of the voter config and the member list',
              ip_address=get_client_ip())
    ha.nudge_members()
    return jsonify({'success': True, 'left': True})


# --- the witness, between it and the leader ------------------------------------------

@bp.route('/api/ha/peer/pair-witness', methods=['POST'])
def peer_pair_witness():
    """The witness's half of its pairing (`pegaprox-witness join`).

    No session and no peer header: the witness code in the body authenticates the call
    and is spent by it. The witness sends instance_id, url, fingerprint and its Ed25519
    public_key. Its record goes into the group, and back goes, sealed with a key derived
    from the code, this instance's public key, the voter config with the configs before
    it, the epoch, the mode and, in an automatic group, the floor - no field key and no
    snapshot. A wrong code is 403 on every instance; with the right one, 503 HA_NO_LEASE
    in an automatic group on an instance a majority did not just confirm, 403 for
    anything else that is refused."""
    ip = get_client_ip()
    if not _pair_attempts.allow(ip):
        resp = jsonify({'error': 'Too many pairing attempts - wait a few minutes'})
        resp.headers['Retry-After'] = '300'
        return resp, 429
    data = _body()
    if not ha.witness_code_ok(_str(data.get('code'))):
        logging.warning(f"[HA] witness pairing attempt from {ip} refused: {ha.PAIRING_CODE_ERROR}")
        return jsonify({'error': ha.PAIRING_CODE_ERROR}), 403
    if ha.lease_in_force() and not ha.confirm_step('pairing the witness'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    url = _str(data.get('url'), 4096)
    try:
        out = ha.accept_witness(_str(data.get('code')), _str(data.get('instance_id'), 64), url,
                                _str(data.get('fingerprint'), 128), _str(data.get('public_key'), 128))
    except ha.HaError as e:
        logging.warning(f"[HA] witness pairing attempt from {ip} refused: {e}")
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': safe_error(e, 'Pairing the witness failed')}), 500
    log_audit('system', 'ha.witness_paired', f"witness {url} paired, epoch {out['epoch']}", ip_address=ip)
    ha.nudge_members()
    return jsonify(out)


@bp.route('/api/ha/peer/witness-leave', methods=['POST'])
def peer_witness_leave():
    """The witness leaves the group (`pegaprox-witness leave`), signed with its key.

    Taken on the leader, which takes it out as the remove route does: 409 HA_AUTO_MODE
    where an automatic group would be left with fewer than three votes, 503 HA_NO_LEASE
    without the lease. 409 with follow {instance_id, url, fingerprint, public_key, epoch}
    on a standby that knows the leader, for the witness to ask there. 401 HA_CLOCK for a
    good signature whose time is off, 401 for anybody else."""
    try:
        request.max_content_length = _MAX_PEER_BODY
        body = request.get_data(cache=True)
    except Exception:
        body = None
    kind, rec = (None, None) if body is None or request.query_string else request_witness()
    if kind == 'skewed':
        return jsonify(ha.clock_refusal(request.headers)), 401
    if kind != 'witness':
        ip = get_client_ip()
        if not _peer_failures.allow(ip):
            resp = jsonify({'error': 'Too many failed peer calls'})
            resp.headers['Retry-After'] = '300'
            return resp, 429
        logging.warning(f"[HA] refused a witness call from {ip} to {request.path}")
        return jsonify({'error': 'Not the witness of this group', 'instance_id': ha.instance_id()}), 401
    if ha.role() != ha.ROLE_ACTIVE:
        out = {'error': 'This instance does not lead the group'}
        hint = ha.follow_hint()
        if hint:
            out['follow'] = hint
        return jsonify(out), 409
    if ha.lease_in_force() and not ha.confirm_step('the witness leaving'):
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': ha.NO_LEASE_ERROR}), 503)
    try:
        ha.remove_witness()
    except ha.AutoMode as e:
        return jsonify({'code': 'HA_AUTO_MODE', 'error': str(e)}), 409
    except ha.NoLease as e:
        return no_lease_refusal() or (jsonify({'code': 'HA_NO_LEASE', 'error': str(e)}), 503)
    except ha.HaError as e:
        return jsonify({'error': str(e)}), 409
    log_audit('system', 'ha.witness_left', f"the witness {rec.get('url') or rec['instance_id']} left "
                                           'the group', ip_address=get_client_ip())
    ha.nudge_members()
    return jsonify({'success': True})


# --- forwarded writes, the active's half ---------------------------------------------

@bp.route('/api/ha/peer/forward', methods=['POST'])
def peer_forward():
    """A write a standby would have refused, handed to us to run as the user it names.

    The body is {method, path, query, content_type, body_b64, user, sign_in,
    client_ip}, the browser's request as the standby took it, and the peer signature
    covers it like the body of every peer call: neither the request nor the user can
    change on the way. Only on the active (409 anywhere else, which also stops a write
    that would travel on; 503 HA_NO_LEASE on a leader without its lease or with less of
    it left than ha_vote.WRITE_LEASE_MARGIN, said to a member before the body is read,
    and 503 HA_TRANSFER for a write while it hands its lead on), only from a member that
    signs its calls, only a write under
    /api/ and never under /api/ha/ - or a GET of ha.FORWARDED_READS, the progress of a
    job or a view only our tables hold, or of a plugin route that opens no console -
    and only for an account that exists and is enabled here. sign_in is the
    standby's digest of the account's password (ha.sign_in_digest): 403
    HA_FORWARD_STALE_SIGN_IN when ours differs, the password changed here since.
    The request then goes through our routing and every check on the way, CSRF and
    the IP list included, under a session for that user that holds for this one
    request: role, tenant and permissions are ours, whatever the standby thinks of
    them. Its audit lines name the standby and carry the client address the standby
    saw. The answer is {status, headers, body_b64}."""
    if ha.role() == ha.ROLE_ACTIVE and signed_member_call():
        # a leader without its lease, asked by a member (its signature over the headers
        # is good): said before the body is read, however large that is, and no nonce
        # is spent on it
        refused = no_lease_refusal()
        if refused:
            return refused
    p, refused = _peer_or_refuse()
    if refused:
        return refused
    if not p.get('keyed'):
        # a member that still goes by its old secret signs nothing, the body included
        return jsonify({'code': 'HA_FORWARD_UNSIGNED',
                        'error': 'Only a member that signs its calls can hand over a change'}), 401
    if ha.role() != ha.ROLE_ACTIVE:
        return jsonify({'code': 'HA_STANDBY', 'error': 'This instance is not active'}), 409
    refused = no_lease_refusal()
    if refused:
        return refused
    call, bad = _forward_envelope(_peer_body())
    if bad:
        return jsonify({'code': 'HA_FORWARD_INVALID', 'error': bad}), 400
    if call['method'] != 'GET' and ha.handing_over():
        # a write waits while the lead is handed on, as one made here does; reads go on
        return transfer_refusal()
    try:
        from pegaprox.core.db import get_db
        user = get_db().get_user(call['user'])
    except Exception as e:
        logging.warning(f"[HA] could not read the account of {call['user']} for a forwarded write: {e}")
        user = None
    if not isinstance(user, dict) or not user.get('enabled', True):
        return jsonify({'code': 'HA_FORWARD_USER',
                        'error': 'This account does not exist on the active instance, or it is '
                                 'disabled there'}), 403
    if not hmac.compare_digest(call['sign_in'], ha.sign_in_digest(call['user'])):
        # its password changed here since the standby's last sync: the session it
        # vouches for is one that sync ends
        return jsonify({'code': 'HA_FORWARD_STALE_SIGN_IN',
                        'error': 'The password of this account changed on the active instance'}), 403
    via = p.get('url') or p['instance_id']
    status, headers, body = _run_forwarded(call, user, via)
    (logging.debug if call['method'] == 'GET' else logging.info)(
        f"[HA] {call['method']} {call['path']} for {call['user']} via standby {via} "
        f"(client {call['client_ip']}): {status}")
    return jsonify({'status': status, 'headers': headers,
                    'body_b64': base64.b64encode(body).decode('ascii')})


def _text(value, limit):
    return isinstance(value, str) and len(value) <= limit and not _CONTROL_RE.search(value)


def _forward_envelope(data):
    """(the call, None) from a forward body, or (None, what is wrong with it)."""
    method, path = data.get('method'), data.get('path')
    if method not in _FORWARD_METHODS and method != 'GET':
        return None, 'method is POST, PUT, PATCH or DELETE, or GET for a job\'s progress'
    # routing goes by the path as it stands (no dot segments resolved, a double slash
    # redirects), so the prefix is what decides
    if not _text(path, 4096) or not path.startswith('/api/') or path.startswith('/api/ha/'):
        return None, 'path is under /api/, and not under /api/ha/'
    if method == 'GET' and not _forwarded_read(path):
        return None, 'a read is the progress of a job, a view only the active holds or a plugin\'s'
    if method != 'GET' and _opens_a_console(method, path):
        # a standby never hands one on: the browser connects where the console opened
        return None, 'a console opens on the instance the browser is on'
    sign_in = data.get('sign_in')
    if not isinstance(sign_in, str) or not (sign_in == '' or re.fullmatch(r'[0-9a-f]{64}', sign_in)):
        return None, 'sign_in is the digest of the account\'s sign-in'
    query, content_type = data.get('query', ''), data.get('content_type', '')
    if not _text(query, 8192) or not _text(content_type, 1024):
        return None, 'query and content_type are short strings'
    user = data.get('user')
    if not _text(user, 255) or not user:
        return None, 'user names the account'
    try:
        client_ip = str(ipaddress.ip_address(data.get('client_ip')))
    except (TypeError, ValueError):
        return None, 'client_ip is an IP address'
    raw = data.get('body_b64', '')
    if not isinstance(raw, str) or len(raw) > _MAX_FORWARD_ENVELOPE:
        return None, 'body_b64 is the body in base64'
    try:
        body = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None, 'body_b64 is the body in base64'
    if len(body) > ha.FORWARD_MAX_BODY:
        return None, f'the body is larger than {ha.FORWARD_MAX_BODY} bytes'
    if method == 'GET' and body:
        return None, 'a read has no body'
    return {'method': method, 'path': path, 'query': query, 'content_type': content_type,
            'body': body, 'user': user, 'sign_in': sign_in, 'client_ip': client_ip}, None


def _opens_a_console(method, path):
    try:
        rule, args = current_app.url_map.bind('localhost').match(path, method=method, return_rule=True)
    except Exception:
        return False
    if rule.rule == ha.PLUGIN_PROXY_RULE:
        return args.get('subpath') in ha.PLUGIN_CONSOLE_PATHS
    return (method, rule.rule) in ha.CONSOLE_WRITES


def _forwarded_read(path):
    """Whether a standby may hand us a GET of `path`: one of ha.FORWARDED_READS, or a
    plugin route that opens no console. A standby opens a plugin console itself or not
    at all, and one opened here would be no use to the browser there."""
    try:
        rule, args = current_app.url_map.bind('localhost').match(path, method='GET', return_rule=True)
    except Exception:
        return False
    if rule.rule == ha.PLUGIN_PROXY_RULE:
        return args.get('subpath') not in ha.PLUGIN_CONSOLE_PATHS
    return rule.rule in ha.FORWARDED_READS


def _run_forwarded(call, user, via):
    """Run the call through this app as its user: (status, headers, body)."""
    from pegaprox.utils.auth import open_forwarded_session, end_forwarded_session
    outer = request.environ
    sid = open_forwarded_session(call['user'], user.get('role') or 'viewer', call['client_ip'], via)
    environ = {
        'REQUEST_METHOD': call['method'],
        'SCRIPT_NAME': '',
        # WSGI carries the path as the latin-1 text of its UTF-8 bytes
        'PATH_INFO': call['path'].encode('utf-8').decode('latin-1'),
        'QUERY_STRING': call['query'],
        'SERVER_NAME': outer.get('SERVER_NAME') or 'localhost',
        'SERVER_PORT': outer.get('SERVER_PORT') or '443',
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'REMOTE_ADDR': call['client_ip'],
        'HTTP_HOST': request.host,
        # the marker of the UI's own calls, and no foreign Origin: the CSRF gate takes it
        # like any same-origin call. No Origin of ours either, the gate compares an IPv6
        # host with its brackets against one without
        'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest',
        'HTTP_X_SESSION_ID': sid,
        'HTTP_USER_AGENT': f'PegaProx standby {via}'[:200],
        'CONTENT_LENGTH': str(len(call['body'])),
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': outer.get('wsgi.url_scheme') or 'https',
        'wsgi.input': io.BytesIO(call['body']),
        'wsgi.errors': outer.get('wsgi.errors') or sys.stderr,
        'wsgi.multithread': bool(outer.get('wsgi.multithread')),
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
        ha.FORWARD_ENVIRON: {'session': sid, 'via': via, 'client_ip': call['client_ip']},
    }
    if call['content_type']:
        environ['CONTENT_TYPE'] = call['content_type']
    try:
        # a request of its own: flask.g and the contexts of this peer call stay out of it
        return contextvars.Context().run(_dispatch, current_app._get_current_object(), environ)
    finally:
        end_forwarded_session(sid)


def _dispatch(app, environ):
    started, chunks = {}, []

    def start_response(status, headers, exc_info=None):
        started['status'], started['headers'] = status, headers
        return chunks.append

    result = app(environ, start_response)
    size, too_large = 0, False
    try:
        for chunk in result:
            size += len(chunk)
            if size > ha.FORWARD_MAX_BODY:
                too_large = True
                break
            chunks.append(chunk)
    finally:
        close = getattr(result, 'close', None)
        if close:
            close()
    if too_large:
        # done here, but more than the standby takes back
        return 502, {'Content-Type': 'application/json'}, (
            b'{"error":"The change was made, but its answer is too large to pass on - '
            b'fetch it on the active instance"}')
    status = int(str(started.get('status') or '500').split(' ', 1)[0])
    wanted = {name.lower(): name for name in _FORWARD_HEADERS}
    headers = {wanted[k.lower()]: v for k, v in started.get('headers') or () if k.lower() in wanted}
    return status, headers, b''.join(chunks)
