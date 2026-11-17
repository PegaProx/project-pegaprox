"""Linked mode: working from any site.

An account homed at site H and mirrored at site E signs in at E. E asks H to check the
password, and the second factor when the account has one (at_home here, check_at_home
there). H answers with an assertion it signs: this account signed in at E, for the session
handle `sh` E made for it, first at iat0, good until exp, five minutes on. E keeps it with
the session, renews it while that session works on other sites (principal) and hands it to
every site it relays for the account. A site takes a request for an account homed elsewhere
than at the sending site only with such an assertion, signed by that home, held by the
sender and for the same session handle (refusal).

H keeps no list of them. A renewal checks the account again and ends after a password
change since the first sign-in, a disabled account, or MAX_CHAIN in all: a sign-out at E
(no renewal comes any more), a password change or a disabled account at H end it within
five minutes, and after twelve hours the account signs in again.

H not reachable at sign-in, an account of a directory or with a security key alone: E signs
in as before, from the mirrored password, without an assertion; its own clusters work,
other sites' do not. H refuses the password or the code: E refuses too.

MK Nov 2026
"""
import base64
import json
import logging
import re
import secrets
import threading
import time
from datetime import datetime

from pegaprox.core import federation as fed

ASSERT_DOMAIN = b'pegaprox-fed-assert-1'
ASSERT_SECONDS = 300
RENEW_BEFORE = 60
MAX_CHAIN = 12 * 3600
SKEW = 60
SIGN_IN_PATH = '/api/federation/peer/sign-in'
RENEW_PATH = '/api/federation/peer/assert-renew'
SIGN_IN_TIMEOUT = 8
_HEX32 = re.compile(r'[0-9a-f]{32}')
_TOTP_RE = re.compile(r'[0-9]{6,8}')

# one renewal at a time per home: a home that is slow holds up its own accounts only
_renew_locks = {}
_renew_locks_lock = threading.Lock()


def _renew_lock(home):
    with _renew_locks_lock:
        return _renew_locks.setdefault(home, threading.Lock())


def _windows():
    from pegaprox.utils.ratelimit import SlidingWindow
    return (SlidingWindow(limit=30, window=60, max_keys=64, name='fed-sign-in'),
            SlidingWindow(limit=5, window=900, max_keys=4096, name='fed-sign-in-fail'))


# per sending site, and per (site, account) for refused passwords and codes: a member that
# guesses locks only itself out of that one account, never the account at its home
_sign_in_rate, _sign_in_fails = _windows()


def _failed(key):
    """The refused sign-ins of `key` inside the window, counted without adding one."""
    cutoff = time.time() - _sign_in_fails.window
    with _sign_in_fails._lock:
        return sum(1 for t in _sign_in_fails._hits.get(key, ()) if t > cutoff)


def reset_for_tests():
    global _sign_in_rate, _sign_in_fails
    _sign_in_rate, _sign_in_fails = _windows()


# --- the assertion ---------------------------------------------------------------------------

def issue(user, holder, sh, iat0):
    now = int(time.time())
    text = json.dumps({'v': 1, 'user': user, 'home': fed.instance_id(), 'holder': holder,
                       'sh': sh, 'iat0': int(iat0), 'iat': now, 'exp': now + ASSERT_SECONDS},
                      separators=(',', ':'), sort_keys=True)
    sig = fed.signing_key().sign(ASSERT_DOMAIN + b'\n' + text.encode())
    return {'a': text, 's': base64.b64encode(sig).decode()}


def well_formed(asr):
    return (isinstance(asr, dict) and set(asr) == {'a', 's'}
            and isinstance(asr.get('a'), str) and 0 < len(asr['a']) <= 1024
            and isinstance(asr.get('s'), str) and 0 < len(asr['s']) <= 128)


def read(asr, public_key):
    """The body of an assertion whose signature `public_key` (an Ed25519 key object) checks,
    else None. Its times are the caller's to judge."""
    from cryptography.exceptions import InvalidSignature
    if not well_formed(asr) or public_key is None:
        return None
    try:
        public_key.verify(base64.b64decode(asr['s']), ASSERT_DOMAIN + b'\n' + asr['a'].encode())
        body = json.loads(asr['a'])
    except (InvalidSignature, ValueError, TypeError):
        return None
    if not isinstance(body, dict) or body.get('v') != 1:
        return None
    for k in ('user', 'home', 'holder', 'sh'):
        if not isinstance(body.get(k), str):
            return None
    for k in ('iat0', 'iat', 'exp'):
        if not isinstance(body.get(k), int) or isinstance(body.get(k), bool):
            return None
    return body


def _key_of(iid):
    from pegaprox.core import ha_wire
    if iid == fed.instance_id():
        return fed.signing_key().public_key()
    return ha_wire.public_key((fed.member_record(iid) or {}).get('public_key') or '')


def refusal(sender, call, now=None):
    """None when this site takes `call` (a relayed request's principal, valid_envelope's
    shape) for an account homed elsewhere than at `sender`, else (status, code, sentence)."""
    now = int(time.time()) if now is None else now
    home = call.get('home') or ''
    no = (403, 'FED_RELAY_WRONG_HOME', 'A site acts only for the accounts it homes, or for an '
                                       'account signed in there through its home')
    asr = call.get('asr')
    if not asr or (home != fed.instance_id() and fed.member_record(home) is None):
        return no
    body = read(asr, _key_of(home))
    if body is None or (body['user'], body['home'], body['holder'], body['sh']) != \
            (call.get('user'), home, sender, call.get('sh')):
        return no
    if now > body['exp'] + SKEW or now - body['iat0'] > MAX_CHAIN + SKEW:
        return (403, 'FED_ASSERT_EXPIRED', 'Your sign-in through your home site has run out - '
                                           'sign in again')
    return None


# --- the home ----------------------------------------------------------------------------------

def _no(status, code, error):
    return status, {'code': code, 'error': error}


def check_at_home(sender, site, data):
    """(status, body) for a member's sign-in of one of this instance's accounts. 200
    {assertion} or {requires_2fa: true}; 401 for a refused password or code; 409 for an
    account that signs in here only (FED_SIGN_IN_HERE) or has to change its password here
    (FED_PASSWORD_HOME); 429 when the member asks too often."""
    from pegaprox.core.db import get_db
    from pegaprox.utils.auth import dummy_verify_password, verify_password
    data = data if isinstance(data, dict) else {}
    user, password = data.get('user'), data.get('password')
    totp, sh = data.get('totp'), data.get('sh')
    if not (isinstance(user, str) and 0 < len(user) <= 128 and isinstance(password, str)
            and 0 < len(password) <= 1024 and isinstance(sh, str) and _HEX32.fullmatch(sh)
            and (totp is None or (isinstance(totp, str) and _TOTP_RE.fullmatch(totp)))):
        return _no(400, 'FED_SIGN_IN', 'Not a sign-in')
    if not _sign_in_rate.allow(sender):
        return _no(429, 'FED_BUSY', 'Too many sign-ins from your site')
    key = f'{sender}:{user}'
    if _failed(key) >= _sign_in_fails.limit:
        return _no(429, 'FED_SIGN_IN_LOCKED', 'Too many refused sign-ins of this account from '
                                              'your site - try again later')
    try:
        row = get_db().get_user(user)
    except Exception as e:
        logging.warning(f'[FED] sign-in of {user!r} from {site}: account unreadable ({e})')
        return _no(503, 'FED_UNAVAILABLE', 'The accounts of this site cannot be read')
    refused = _no(401, 'FED_SIGN_IN_REFUSED', 'Invalid credentials')
    if not row or row.get('fed_home') or not row.get('enabled', True):
        dummy_verify_password(password)
        _sign_in_fails.allow(key)
        return refused
    if not row.get('password_hash') or (row.get('auth_source') or 'local') != 'local':
        dummy_verify_password(password)
        return _no(409, 'FED_SIGN_IN_HERE', 'This account signs in through its directory, at '
                                            'its home site')
    if not verify_password(password, row.get('password_salt') or '', row['password_hash']):
        _sign_in_fails.allow(key)
        logging.warning(f'[FED] refused sign-in of {user!r} at site {site}: wrong password')
        return refused
    if row.get('force_password_change'):
        return _no(409, 'FED_PASSWORD_HOME', 'This account has to change its password at its '
                                             'home site first')
    if row.get('portal_only'):
        return _no(409, 'FED_SIGN_IN_HERE', 'This account uses the Client Portal of its home '
                                            'site')
    has_totp = bool(row.get('totp_enabled') and row.get('totp_secret'))
    if not has_totp:
        from pegaprox.api.helpers import load_server_settings
        from pegaprox.utils.auth import MFA_DUE, mfa_enrolment_state
        try:
            passkeys = get_db().query_one('SELECT COUNT(*) AS n FROM webauthn_credentials '
                                          'WHERE username = ?', (user,))
        except Exception:
            return _no(503, 'FED_UNAVAILABLE', 'The second factors of this site cannot be read')
        if passkeys and passkeys['n']:
            # a security key proves itself to the site it was used at only
            return _no(409, 'FED_SIGN_IN_HERE', 'This account signs in with a security key: '
                                                "other sites' clusters open from its home site")
        if mfa_enrolment_state(row, load_server_settings(), user) == MFA_DUE:
            return _no(409, 'FED_SIGN_IN_HERE', 'This site asks every account for a second '
                                                'factor: set one up here first')
    else:
        if totp is None:
            return 200, {'requires_2fa': True}
        import pyotp
        from pegaprox.api.auth import _totp_replayed
        if _totp_replayed(user, totp) or not pyotp.TOTP(row['totp_secret']).verify(
                totp, valid_window=1):
            _sign_in_fails.allow(key)
            return _no(401, 'FED_SIGN_IN_REFUSED', 'Invalid 2FA code')
    from pegaprox.utils.audit import log_audit
    log_audit(user, 'federation.sign_in', f'Signed in at site {site}'
              + (' with the second factor of this site' if has_totp else ''))
    # second_factor: what this site checked, so the asking site skips its own step only then
    return 200, {'assertion': issue(user, sender, sh, time.time()), 'second_factor': has_totp}


def renew_at_home(sender, data):
    """(status, body): a fresh assertion for one this instance issued to `sender`, while
    the account stands as it did at the first sign-in."""
    from pegaprox.core.db import get_db
    asr = (data or {}).get('assertion') if isinstance(data, dict) else None
    body = read(asr, fed.signing_key().public_key())
    if body is None or body['home'] != fed.instance_id() or body['holder'] != sender:
        return _no(403, 'FED_ASSERT_REFUSED', 'Not an assertion of this site for yours')
    now = int(time.time())
    if now - body['iat0'] > MAX_CHAIN:
        return _no(403, 'FED_ASSERT_EXPIRED', 'Signed in too long ago - sign in again')
    try:
        row = get_db().get_user(body['user'])
    except Exception:
        return _no(503, 'FED_UNAVAILABLE', 'The accounts of this site cannot be read')
    if not row or row.get('fed_home') or not row.get('enabled', True) or row.get('portal_only'):
        return _no(403, 'FED_ASSERT_REFUSED', 'The account no longer signs in')
    if row.get('force_password_change'):
        return _no(403, 'FED_ASSERT_REFUSED', 'The account has to change its password here first')
    try:
        from pegaprox.api.helpers import load_server_settings
        from pegaprox.utils.auth import MFA_DUE, mfa_enrolment_state
        if mfa_enrolment_state(row, load_server_settings(), body['user']) == MFA_DUE:
            return _no(403, 'FED_ASSERT_REFUSED', 'This site asks every account for a second '
                                                  'factor: set one up here first')
    except Exception:
        return _no(503, 'FED_UNAVAILABLE', 'The second-factor rule of this site cannot be read')
    changed = row.get('password_changed_at')
    try:
        changed_ts = datetime.fromisoformat(changed).timestamp() if changed else 0
    except (TypeError, ValueError):
        changed_ts = now
    if changed_ts > body['iat0']:
        return _no(403, 'FED_ASSERT_REFUSED', 'The password changed since this sign-in')
    return 200, {'assertion': issue(body['user'], sender, body['sh'], body['iat0'])}


# --- the site the account signs in at ------------------------------------------------------------

def at_home(username, password, totp, user):
    """Ask the home of the mirror `user` to check a sign-in here. {'state': ...}:
    'ok' with the assertion and its session handle (and 'second_factor' when the home
    checked one), 'requires_2fa', 'denied', 'busy' or 'password_home' with the body for the
    browser, and 'none' when the sign-in goes on without one: the home not reachable, the
    switch off, or an account that signs in at its home only."""
    home = (user or {}).get('fed_home') or ''
    if not home or not fed.enabled() or fed.member_record(home) is None:
        return {'state': 'none'}
    sh = secrets.token_hex(16)
    body = {'user': username, 'password': password, 'sh': sh}
    if totp:
        body['totp'] = str(totp).strip()
    status, data, _h = fed.call_peer(home, 'POST', SIGN_IN_PATH, body,
                                     read_timeout=SIGN_IN_TIMEOUT)
    data = data if isinstance(data, dict) else {}
    if status == 200 and data.get('requires_2fa') is True:
        return {'state': 'requires_2fa'}
    if status == 200 and well_formed(data.get('assertion')):
        got = read(data['assertion'], _key_of(home))
        if got and (got['user'], got['holder'], got['sh']) == (username, fed.instance_id(), sh):
            return {'state': 'ok', 'assertion': data['assertion'], 'sh': sh,
                    'second_factor': data.get('second_factor') is True}
        logging.warning(f'[FED] the home of {username!r} answered a sign-in with an assertion '
                        'that is not for it')
        return {'state': 'none'}
    if status == 401:
        return {'state': 'denied',
                'body': {'error': 'Invalid 2FA code' if totp else 'Invalid credentials'}}
    if status == 409 and data.get('code') == 'FED_PASSWORD_HOME':
        return {'state': 'password_home',
                'body': {'code': 'FED_PASSWORD_HOME', 'home': home,
                         'error': 'This account has to change its password at its home '
                                  'instance first'}}
    if status == 429:
        return {'state': 'busy', 'body': {'error': 'Too many sign-ins - try again later'}}
    return {'state': 'none'}


def keep(session_id, verdict):
    """Put an 'ok' verdict of at_home with the session it opened."""
    from pegaprox.utils.auth import active_sessions, save_sessions, sessions_lock
    with sessions_lock:
        sess = active_sessions.get(session_id)
        if sess is None:
            return
        sess['fed_assert'], sess['fed_sh'] = verdict['assertion'], verdict['sh']
    save_sessions()


def principal(session_id, username, ip):
    """The relay principal of a mirror's session here: its assertion, renewed at its home
    when it is about to run out. None when the session holds none (or no longer one)."""
    from pegaprox.utils.auth import active_sessions, save_sessions, sessions_lock
    with sessions_lock:
        sess = active_sessions.get(session_id or '') or {}
        asr, sh = sess.get('fed_assert'), sess.get('fed_sh')
    if not asr or not sh or sess.get('user') != username:
        return None
    try:
        body = json.loads(asr['a'])
    except Exception:
        return None
    home = body.get('home') or ''
    if int(time.time()) >= int(body.get('exp') or 0) - RENEW_BEFORE:
        with _renew_lock(home):
            with sessions_lock:
                held = (active_sessions.get(session_id) or {}).get('fed_assert')
            if held is asr or held == asr:
                status, data, _h = fed.call_peer(home, 'POST', RENEW_PATH, {'assertion': asr},
                                                 read_timeout=SIGN_IN_TIMEOUT)
                fresh = (data or {}).get('assertion') if isinstance(data, dict) else None
                got = read(fresh, _key_of(home)) if status == 200 else None
                with sessions_lock:
                    live = active_sessions.get(session_id)
                    if live is not None:
                        if got and (got['user'], got['holder'], got['sh']) == \
                                (username, fed.instance_id(), sh):
                            live['fed_assert'] = fresh
                        elif status in (401, 403):
                            # the home said no: the account works here, on this site only
                            live.pop('fed_assert', None)
                save_sessions()
            with sessions_lock:
                asr = (active_sessions.get(session_id) or {}).get('fed_assert')
        if not asr:
            return None
        try:
            if int(time.time()) > int(json.loads(asr['a']).get('exp') or 0) + SKEW:
                return None
        except Exception:
            return None
    return {'user': username, 'home': home, 'sh': sh, 'ip': ip or '', 'asr': asr}
