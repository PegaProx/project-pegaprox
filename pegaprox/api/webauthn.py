# -*- coding: utf-8 -*-
"""
WebAuthn / FIDO2 hardware token support.

NS Apr 2026: second-factor only, no passwordless flow (user explicitly asked for
conservative defaults). TOTP stays available in parallel — hardware keys augment,
they don't replace.

Import is lazy: if fido2 isn't installed the blueprint still loads but every
endpoint returns 501 so the dashboard can gracefully hide the Hardware Keys UI.
"""
import os
import time
import secrets
import logging
import sqlite3
from datetime import datetime
from flask import Blueprint, jsonify, request

from pegaprox.core.db import get_db
from pegaprox.constants import DATABASE_FILE
from pegaprox.utils.auth import validate_session, active_sessions, sessions_lock
# MK 2026-06-04 (CWE-117): username comes from a login attempt = attacker-
# controllable. Sanitise before logging.
from pegaprox.utils.sanitization import sanitize_log_message as _sl

try:
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
        AttestedCredentialData, UserVerificationRequirement,
        PublicKeyCredentialDescriptor, PublicKeyCredentialType,
        AuthenticatorSelectionCriteria, ResidentKeyRequirement,
    )
    from fido2.utils import websafe_encode, websafe_decode
    FIDO2_AVAILABLE = True
except Exception as _e:
    FIDO2_AVAILABLE = False
    AttestedCredentialData = None  # keeps name resolution happy when lib missing
    logging.info(f"[WebAuthn] fido2 not available: {_e}")


bp = Blueprint('webauthn', __name__)


# MK: challenges live in memory, keyed by (username, ceremony).
# 5 min TTL. Sweeping on every touch keeps the map small without a cron.
_challenges = {}  # {(user, 'register'|'auth'|'proof'[, nonce]): (state, expiry)}
import threading as _threading
_challenge_lock = _threading.Lock()  # NS Aug 2026 (CodeAnt) — serialize concurrent match/pop of the
#                                      same auth ceremony so two finishes can't reuse one challenge


def _sweep_challenges():
    now = time.time()
    stale = [k for k, (_, exp) in _challenges.items() if exp < now]
    for k in stale:
        _challenges.pop(k, None)


def _is_ip_literal(host):
    """True if host is a raw IPv4/IPv6 literal — WebAuthn forbids those as RP IDs."""
    try:
        import ipaddress
        ipaddress.ip_address(host.strip('[]'))
        return True
    except Exception:
        return False


def _effective_host():
    """Resolve the host the browser thinks it's talking to.

    Reverse-proxy chains rewrite the Host header — nginx with
    `proxy_set_header Host $host` keeps it, HAProxy often replaces it with the
    backend literal. When the request comes from a trusted proxy we prefer
    X-Forwarded-Host (that's what the browser actually saw), falling back to
    the raw Host header otherwise.

    Returns a lowercased hostname without port, or '' if nothing usable.
    """
    try:
        from pegaprox.utils.audit import _is_trusted_proxy
        if request.remote_addr and _is_trusted_proxy(request.remote_addr):
            # Prefer the proxy's X-Forwarded-Host — that's the public hostname
            xfh = (request.headers.get('X-Forwarded-Host') or '').strip()
            if xfh:
                # may be a comma list if chained; take the leftmost
                return xfh.split(',')[0].strip().split(':')[0].lower()
    except Exception:
        pass
    return (request.host or '').split(':')[0].lower()


def _get_rp_or_error():
    """Derive the RP ID from the effective host. Returns (rp_entity, None) on success
    or (None, error_response) when the host is unusable for WebAuthn.

    WebAuthn mandates the RP ID be a registrable domain (or the literal 'localhost').
    Bare IP addresses are rejected by every browser with `SecurityError: invalid domain`,
    so we fail early with a helpful message instead of letting the ceremony reach the
    authenticator and blow up there.
    """
    host = _effective_host()
    if not host:
        return None, (jsonify({'error': 'Cannot determine host from request'}), 400)
    if _is_ip_literal(host):
        return None, (jsonify({
            'error': 'WebAuthn does not support IP addresses as host. '
                     'Open PegaProx via its hostname (e.g. https://pegaprox.local:5000 or '
                     'https://localhost:5000) and try again. If you are behind a reverse '
                     'proxy, make sure it forwards the Host or X-Forwarded-Host header.',
            'code': 'ip_literal_host',
            'current_host': host,
        }), 400)
    return PublicKeyCredentialRpEntity(name="PegaProx", id=host), None


def _get_server_or_error():
    rp, err = _get_rp_or_error()
    if err:
        return None, err
    return Fido2Server(rp), None


def _require_session():
    sid = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
    session = validate_session(sid)
    if not session:
        return None, (jsonify({'error': 'not authenticated'}), 401)
    return session, None


def _not_available():
    return jsonify({'error': 'WebAuthn is not available on this server (fido2 library missing)'}), 501


def _user_row(username):
    from pegaprox.utils.auth import load_users
    users = load_users()
    return users.get(username, {})


def _get_credentials_raw(username):
    """Fetch raw rows for a user. `public_key` blob holds the full serialized
    AttestedCredentialData (aaguid + cred_id + cose pubkey) — that's the
    cheapest format to round-trip with fido2."""
    db = get_db()
    rows = db.query('SELECT credential_id, public_key FROM webauthn_credentials WHERE username = ?', (username,))
    return rows or []


def _load_attested_list(username):
    """Rebuild AttestedCredentialData objects for fido2 server calls."""
    if not FIDO2_AVAILABLE:
        return []
    out = []
    for r in _get_credentials_raw(username):
        try:
            acd = AttestedCredentialData(r['public_key'])
            out.append(acd)
        except Exception as e:
            logging.debug(f"[WebAuthn] ACD rebuild failed: {e}")
    return out


# ────────────────────────────────────────────────────────────
# Registration (authenticated — already logged in)
# ────────────────────────────────────────────────────────────

@bp.route('/api/webauthn/register/begin', methods=['POST'])
def register_begin():
    if not FIDO2_AVAILABLE:
        return _not_available()
    session, err = _require_session()
    if err: return err
    username = session['user']
    _sweep_challenges()

    # Stable user_handle per user — stored separately so a user can have multiple keys
    # all tied to one handle. First-time: generate + persist.
    db = get_db()
    existing_row = db.query_one('SELECT user_handle FROM webauthn_credentials WHERE username = ? LIMIT 1', (username,))
    if existing_row:
        user_handle = existing_row['user_handle']
    else:
        user_handle = secrets.token_bytes(32)

    user_entity = PublicKeyCredentialUserEntity(
        id=user_handle,
        name=username,
        display_name=username,
    )

    # Don't re-register an already-present key
    exclude_list = [
        PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=r['credential_id'])
        for r in _get_credentials_raw(username)
    ]

    srv, err = _get_server_or_error()
    if err: return err
    options, state = srv.register_begin(
        user_entity,
        credentials=_load_attested_list(username),
        user_verification=UserVerificationRequirement.PREFERRED,
        authenticator_attachment=None,  # cross-platform + platform both welcome
    )
    # Stash user_handle in state so /finish can persist it on first use
    _challenges[(username, 'register')] = ({'state': state, 'user_handle': user_handle}, time.time() + 300)

    # fido2 returns dataclasses; .dict() serializes for the browser
    return jsonify(dict(options))


@bp.route('/api/webauthn/register/finish', methods=['POST'])
def register_finish():
    if not FIDO2_AVAILABLE:
        return _not_available()
    session, err = _require_session()
    if err: return err
    username = session['user']
    _sweep_challenges()

    stash = _challenges.pop((username, 'register'), None)
    if not stash:
        return jsonify({'error': 'No registration in progress or challenge expired'}), 400
    state = stash[0]['state']
    user_handle = stash[0]['user_handle']

    data = request.get_json() or {}
    key_name = (data.get('name') or '').strip()[:100] or 'Security Key'

    srv, err = _get_server_or_error()
    if err: return err
    try:
        auth_data = srv.register_complete(state, response=data)
    except Exception as e:
        logging.warning(f"[WebAuthn] register_complete failed for {username}: {e}")
        return jsonify({'error': f'Registration verification failed: {e}'}), 400

    cred_data = auth_data.credential_data  # AttestedCredentialData
    # Persist
    try:
        db = get_db()
        now = datetime.now().isoformat()
        db.execute(
            '''INSERT INTO webauthn_credentials
               (username, credential_id, public_key, sign_count, transports, aaguid, name, user_handle, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                username,
                bytes(cred_data.credential_id),
                bytes(cred_data),  # full AttestedCredentialData blob — easier to rehydrate
                int(auth_data.counter or 0),
                ','.join(data.get('transports') or []),
                cred_data.aaguid.hex() if cred_data.aaguid else '',
                key_name,
                user_handle,
                now,
            )
        )
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Key is already registered'}), 409
    except Exception as e:
        logging.error(f"[WebAuthn] DB insert failed: {e}")
        return jsonify({'error': 'Could not persist credential'}), 500

    from pegaprox.utils.audit import log_audit
    try:
        log_audit(username, 'user.webauthn_register', f"registered hardware key '{key_name}'")
    except Exception:
        pass

    return jsonify({'success': True, 'name': key_name})


# ────────────────────────────────────────────────────────────
# Authentication (during login — 2nd factor)
# The "who is logging in" is passed in the request body; we pull their
# credentials and build the challenge. /finish verifies and, on success,
# returns a ready-to-use session the login endpoint can pick up.
# ────────────────────────────────────────────────────────────

@bp.route('/api/webauthn/auth/begin', methods=['POST'])
def auth_begin():
    if not FIDO2_AVAILABLE:
        return _not_available()
    _sweep_challenges()
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'username required'}), 400

    # sec (audit): a 404 with this message vs a 200 with options told an ANONYMOUS caller
    # whether an account exists and has hardware keys — undoing the deliberate uniform-response
    # hardening on the login endpoint. Give a generic answer, and rate-limit the unbounded
    # per-request DB lookup.
    from pegaprox.utils.ssh import check_auth_action_rate_limit
    from pegaprox.utils.audit import get_client_ip
    if not check_auth_action_rate_limit(f'webauthn_begin:{get_client_ip()}',
                                        max_attempts=20, window=300):
        resp = jsonify({'error': 'Too many attempts'})
        resp.headers['Retry-After'] = '300'
        return resp, 429

    creds = _load_attested_list(username)
    if not creds:
        return jsonify({'error': 'hardware-key authentication is not available for this account'}), 400

    srv, err = _get_server_or_error()
    if err: return err
    options, state = srv.authenticate_begin(
        credentials=creds,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    # NS Aug 2026 (AI-pentest) — key each begin under a unique nonce instead of a single
    # (username,'auth') slot, so a concurrent (unauthenticated) begin for the same username can't
    # clobber a victim's in-flight ceremony (targeted login DoS). auth_finish tries every live
    # ceremony for the user; the matching assertion wins, decoy begins are ignored. Bound per user.
    import secrets as _secrets
    _live = [k for k in list(_challenges) if len(k) == 3 and k[0] == username and k[1] == 'auth']
    while len(_live) >= 5:
        _oldest = min(_live, key=lambda k: _challenges[k][1])
        _challenges.pop(_oldest, None)
        _live.remove(_oldest)
    _challenges[(username, 'auth', _secrets.token_hex(8))] = (state, time.time() + 120)
    return jsonify(dict(options))


@bp.route('/api/webauthn/auth/finish', methods=['POST'])
def auth_finish():
    """Verify the assertion. Caller then uses ?via_webauthn=1 in /api/auth/login
    to skip TOTP. We don't mint the session here — keeps the login endpoint as
    the single source of auth truth."""
    if not FIDO2_AVAILABLE:
        return _not_available()
    _sweep_challenges()
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'username required'}), 400

    # NS Aug 2026 (AI-pentest) — try every in-flight ceremony for this user (keyed by nonce in
    # auth_begin); the matching one wins, so a concurrent attacker begin can't invalidate the victim's.
    _keys = [k for k in list(_challenges) if len(k) == 3 and k[0] == username and k[1] == 'auth']
    if not _keys:
        return jsonify({'error': 'No auth ceremony in progress or challenge expired'}), 400

    creds = _load_attested_list(username)
    if not creds:
        return jsonify({'error': 'no hardware keys registered'}), 404

    srv, err = _get_server_or_error()
    if err: return err
    matched_cred = None
    _last_err = None
    with _challenge_lock:  # one ceremony is matched+consumed atomically per user
        for _k in sorted(_keys, key=lambda k: (_challenges.get(k) or (None, 0))[1], reverse=True):
            _st = _challenges.get(_k)
            if _st is None:
                continue  # already consumed by a racing finish
            try:
                matched_cred = srv.authenticate_complete(_st[0], credentials=creds, response=data)
                _challenges.pop(_k, None)  # consume only the ceremony that actually matched
                break
            except Exception as e:
                _last_err = e
    if matched_cred is None:
        logging.warning(f"[WebAuthn] auth_complete failed for {_sl(username)}: {_sl(str(_last_err))}")
        return jsonify({'error': f'Verification failed: {_last_err}'}), 400

    # Counter lives on the AuthenticatorData in the assertion response. fido2 2.x
    # doesn't expose it on the return value, so we parse it ourselves for our
    # monotonicity tracking (purely informational — we don't block).
    try:
        from fido2.webauthn import AuthenticationResponse
        parsed = AuthenticationResponse.from_dict(data)
        new_counter = parsed.response.authenticator_data.counter or 0
    except Exception:
        new_counter = 0

    try:
        db = get_db()
        db.execute(
            'UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ?, last_used_ip = ? WHERE credential_id = ?',
            (int(new_counter), datetime.now().isoformat(),
             request.remote_addr or '', bytes(matched_cred.credential_id))
        )
    except Exception as e:
        logging.debug(f"[WebAuthn] sign_count update failed: {e}")

    # Issue a short-lived proof token that the login endpoint can verify
    proof = secrets.token_urlsafe(32)
    _challenges[(username, 'proof')] = (proof, time.time() + 120)

    return jsonify({'success': True, 'proof': proof})


def consume_webauthn_proof(username, proof):
    """Called by the login endpoint to consume a just-minted proof."""
    entry = _challenges.pop((username, 'proof'), None)
    if not entry:
        return False
    expected, expiry = entry
    if time.time() > expiry:
        return False
    return secrets.compare_digest(expected, proof or '')


# ────────────────────────────────────────────────────────────
# List / delete (authenticated, caller-owned)
# ────────────────────────────────────────────────────────────

@bp.route('/api/webauthn/credentials', methods=['GET'])
def list_credentials():
    if not FIDO2_AVAILABLE:
        return jsonify({'available': False, 'credentials': []})
    session, err = _require_session()
    if err: return err
    username = session['user']
    db = get_db()
    rows = db.query(
        'SELECT id, name, aaguid, transports, created_at, last_used_at, last_used_ip '
        'FROM webauthn_credentials WHERE username = ? ORDER BY created_at DESC',
        (username,)
    ) or []
    return jsonify({
        'available': True,
        'credentials': [{
            'id': r['id'],
            'name': r['name'],
            'aaguid': r['aaguid'] or None,
            'transports': (r['transports'] or '').split(',') if r['transports'] else [],
            'created_at': r['created_at'],
            'last_used_at': r['last_used_at'],
            'last_used_ip': r['last_used_ip'],
        } for r in rows]
    })


@bp.route('/api/webauthn/credentials/<int:cred_id>', methods=['DELETE'])
def delete_credential(cred_id):
    if not FIDO2_AVAILABLE:
        return _not_available()
    session, err = _require_session()
    if err: return err
    username = session['user']
    db = get_db()
    # only allow owner-delete
    row = db.query_one('SELECT name FROM webauthn_credentials WHERE id = ? AND username = ?', (cred_id, username))
    if not row:
        return jsonify({'error': 'credential not found'}), 404
    db.execute('DELETE FROM webauthn_credentials WHERE id = ? AND username = ?', (cred_id, username))
    try:
        from pegaprox.utils.audit import log_audit
        log_audit(username, 'user.webauthn_delete', f"removed hardware key '{row['name']}'")
    except Exception:
        pass
    return jsonify({'success': True})


@bp.route('/api/webauthn/available', methods=['GET'])
def is_available():
    """Public — login form uses this to decide whether to show the 'Use Security Key' button.
    Also reports whether the current request host is WebAuthn-usable, so the UI can
    show a helpful banner when the user is accessing PegaProx by IP."""
    host = _effective_host()
    host_ok = bool(host) and not _is_ip_literal(host)
    return jsonify({
        'available': FIDO2_AVAILABLE,
        'host': host,
        'host_usable': host_ok,
        'host_reason': None if host_ok else 'ip_literal',
    })
