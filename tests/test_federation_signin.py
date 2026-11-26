"""Linked mode: working from any site.

An account signs in at another site than its home; the home checks the password and the
second factor and signs an assertion for that site and session, five minutes at a time.
With it the account works on every site's clusters from where it signed in. Held here:
the home signs only for the site that asked and only after its own checks, a site that
guesses locks only itself out of that account, a renewal ends with a password change, and
a third site takes the account only with its home's assertion, for the sending site and
the same session.

MK Nov 2026
"""
import time

import pytest

from pegaprox.core import federation
from pegaprox.core import federation_relay as relay
from pegaprox.core import federation_signin as fsign
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _add_local_user, _code, _db_of, _defaults_out_of_the_config_dir, _fresh_budgets, _join,
    _map, _settled, _wire, at, iid)
from tests.test_federation_relay import (  # noqa: F401
    CID, _fresh_relay, _get, _relay_side, _session, linked)

PASSWORD = 'C0rrect!horse9'
# 160 bits: pyotp 2.12 refuses a secret under 112
SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'


@pytest.fixture(autouse=True)
def _fresh_sign_ins():
    fsign.reset_for_tests()
    from pegaprox.api import auth as api_auth
    api_auth._totp_used.clear()
    yield
    fsign.reset_for_tests()


def _password(side, user, totp=False):
    from pegaprox.utils.auth import hash_password
    salt, h = hash_password(PASSWORD)
    db = _db_of(side)
    db.conn.execute('UPDATE users SET password_salt = ?, password_hash = ?, auth_source = '
                    "'local' WHERE username = ?", (salt, h, user))
    if totp:
        db.conn.execute('UPDATE users SET totp_enabled = 1, totp_secret_encrypted = ? '
                        'WHERE username = ?', (db._encrypt(SECRET), user))
    db.conn.commit()


def _check(home, asker, **body):
    data = {'user': 'alice', 'password': PASSWORD, 'sh': 'a' * 32}
    data.update(body)
    with at(home):
        return fsign.check_at_home(iid(asker), 'site-b', data)


def _code_now():
    import pyotp
    return pyotp.TOTP(SECRET).now()


# --- the home ------------------------------------------------------------------------------------

def test_the_home_checks_password_and_code_and_signs_for_the_asking_site(linked):
    a, b = linked
    _password(a, 'alice', totp=True)
    assert _check(a, b) == (200, {'requires_2fa': True})
    status, body = _check(a, b, totp='000000')
    assert (status, body['code']) == (401, 'FED_SIGN_IN_REFUSED')
    code = _code_now()
    status, body = _check(a, b, totp=code)
    assert status == 200, body
    with at(a):
        got = fsign.read(body['assertion'], federation.signing_key().public_key())
    assert (got['user'], got['home'], got['holder'], got['sh']) == ('alice', iid(a), iid(b),
                                                                    'a' * 32)
    assert got['exp'] - got['iat'] == fsign.ASSERT_SECONDS
    # the code counts once
    assert _check(a, b, totp=code)[0] == 401
    status, _b = _check(a, b, password='wrong-one!', totp=_code_now())
    assert status == 401


def test_a_refused_code_is_not_spent(linked):
    """Only an accepted code is remembered: one typed ahead of its time, refused then, goes
    through once it is due (and then only once)."""
    import pyotp
    a, b = linked
    _password(a, 'alice', totp=True)
    code = pyotp.TOTP(SECRET).at(int(time.time()) + 300)
    assert _check(a, b, totp=code)[0] == 401
    real = pyotp.TOTP.verify
    try:
        pyotp.TOTP.verify = lambda self, otp, **kw: otp == code
        assert _check(a, b, totp=code)[0] == 200
        assert _check(a, b, totp=code)[0] == 401
    finally:
        pyotp.TOTP.verify = real


def test_a_site_that_guesses_locks_only_itself_out_of_the_account(linked):
    a, b = linked
    from pegaprox.globals import login_attempts_by_user
    _password(a, 'alice')
    for _ in range(5):
        assert _check(a, b, password='nope-nope-1')[0] == 401
    status, body = _check(a, b)
    assert (status, body['code']) == (429, 'FED_SIGN_IN_LOCKED')
    # the account itself is not locked at its home, nor for another site
    assert 'alice' not in login_attempts_by_user
    with at(a):
        status, body = fsign.check_at_home('c' * 32, 'site-c', {'user': 'alice', 'password': PASSWORD,
                                                                'sh': 'b' * 32})
    assert status == 200 and 'assertion' in body


def test_accounts_that_sign_in_at_their_home_only_get_no_assertion(linked):
    a, b = linked
    _password(a, 'alice')
    db = _db_of(a)
    db.conn.execute("INSERT INTO webauthn_credentials (username, credential_id, public_key, "
                    "transports, aaguid, name, user_handle, created_at) VALUES "
                    "('alice', 'k1', 'p', '', '', 'key', 'h', '2026')")
    db.conn.commit()
    status, body = _check(a, b)
    assert (status, body['code']) == (409, 'FED_SIGN_IN_HERE')
    db.conn.execute("DELETE FROM webauthn_credentials")
    db.conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    db.conn.commit()
    assert _check(a, b)[0] == 401
    db.conn.execute("UPDATE users SET enabled = 1, fed_home = ? WHERE username = 'alice'",
                    ('e' * 32,))
    db.conn.commit()
    # a mirror at this site is not this site's to vouch for
    assert _check(a, b)[0] == 401


def test_a_renewal_ends_with_a_password_change(linked):
    a, b = linked
    _password(a, 'alice')
    _s, body = _check(a, b)
    first = body['assertion']
    with at(a):
        status, out = fsign.renew_at_home(iid(b), {'assertion': first})
        assert status == 200
        renewed = fsign.read(out['assertion'], federation.signing_key().public_key())
        assert renewed['iat0'] == fsign.read(first, federation.signing_key().public_key())['iat0']
        # held by another site: not renewed for it
        assert fsign.renew_at_home('c' * 32, {'assertion': first})[0] == 403
    from datetime import datetime, timedelta
    _db_of(a).conn.execute("UPDATE users SET password_changed_at = ? WHERE username = 'alice'",
                           ((datetime.now() + timedelta(seconds=5)).isoformat(),))
    _db_of(a).conn.commit()
    with at(a):
        status, out = fsign.renew_at_home(iid(b), {'assertion': first})
    assert (status, out['code']) == (403, 'FED_ASSERT_REFUSED')


def test_a_renewal_ends_when_the_home_asks_for_a_new_password(linked):
    a, b = linked
    _password(a, 'alice')
    _s, body = _check(a, b)
    _db_of(a).conn.execute("UPDATE users SET force_password_change = 1 WHERE username = 'alice'")
    _db_of(a).conn.commit()
    with at(a):
        status, out = fsign.renew_at_home(iid(b), {'assertion': body['assertion']})
    assert (status, out['code']) == (403, 'FED_ASSERT_REFUSED')


def test_the_home_says_which_second_factor_it_checked(linked):
    a, b = linked
    _password(a, 'alice')
    assert _check(a, b, totp='123456')[1]['second_factor'] is False
    _password(a, 'alice', totp=True)
    assert _check(a, b, totp=_code_now())[1]['second_factor'] is True


# --- three sites -----------------------------------------------------------------------------------

@pytest.fixture
def three(tmp_path):
    """a homes alice; b is where she signs in; c leads the cluster. Both map a's tenant."""
    a, b, c = (_relay_side(tmp_path, n) for n in ('a', 'b', 'c'))
    calls = []
    _wire([a, b, c], calls)
    _add_local_user(a, 'alice', role='admin')
    _join(b, _code(a))
    _join(c, _code(a))
    for s in (a, b, c):
        _settled(s)
    for s in (b, c):
        assert _map(s, a, 'tenant', 'default', 'default')['pulled']
    _password(a, 'alice')
    b.calls = calls
    return a, b, c


def _signed_in_at(b, user='alice'):
    """alice signs in at b through her home: the session and the verdict kept with it."""
    from pegaprox.core.db import get_db
    with at(b):
        verdict = fsign.at_home(user, PASSWORD, None, get_db().get_user(user))
    assert verdict['state'] == 'ok', verdict
    sid = _session(b, user)
    with at(b):
        fsign.keep(sid, verdict)
    return sid


def test_an_account_signed_in_through_its_home_works_on_a_third_site(three):
    a, b, c = three
    sid = _signed_in_at(b)
    r = _get(b, f'/api/clusters/{CID}~{iid(c)}/status', sid)
    assert r.status_code == 200 and r.get_json()['user'] == 'alice', r.data
    # and on its home's own clusters, as the account it is there
    r = _get(b, f'/api/clusters/{CID}~{iid(a)}/status', sid)
    assert r.status_code == 200 and r.get_json()['user'] == 'alice', r.data
    # counterproof: signed in at b without its home, b's own clusters only
    plain = _session(b, 'alice')
    r = _get(b, f'/api/clusters/{CID}~{iid(c)}/status', plain)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_HOME_ELSEWHERE'


def _as(b, c, principal):
    with at(b):
        kind, status, _h, body = relay.relay_call(iid(c), 'GET', f'/api/clusters/{CID}/status',
                                                  principal=principal)
    import json
    return status, json.loads(body or b'{}')


def test_an_assertion_holds_for_its_holder_and_session_only(three):
    a, b, c = three
    sid = _signed_in_at(b)
    with at(b):
        good = fsign.principal(sid, 'alice', '')
    assert _as(b, c, good)[0] == 200
    # another session of the same site
    status, body = _as(b, c, dict(good, sh='f' * 32))
    assert (status, body['code']) == (403, 'FED_RELAY_WRONG_HOME')
    # another account under it
    _add_local_user(a, 'bob', role='admin')
    assert _map(c, a, 'tenant', 'default', 'default')['pulled']
    status, body = _as(b, c, dict(good, user='bob'))
    assert (status, body['code']) == (403, 'FED_RELAY_WRONG_HOME')
    # c, sending b's assertion to the home: held by b, not by c
    status, body = _as(c, a, good)
    assert (status, body['code']) == (403, 'FED_RELAY_WRONG_HOME')
    # the home itself speaks for its account without one, as ever
    assert _as(a, c, {k: v for k, v in good.items() if k != 'asr'})[0] == 200
    # without one
    status, body = _as(b, c, {k: v for k, v in good.items() if k != 'asr'})
    assert (status, body['code']) == (403, 'FED_RELAY_WRONG_HOME')


def test_an_assertion_runs_out_and_its_renewal_ends_with_a_password_change(three, monkeypatch):
    a, b, c = three
    sid = _signed_in_at(b)
    from pegaprox.utils.auth import active_sessions
    first = active_sessions[sid]['fed_assert']
    with at(c):
        call = {'user': 'alice', 'home': iid(a), 'sh': active_sessions[sid]['fed_sh'],
                'asr': first}
        exp = __import__('json').loads(first['a'])['exp']
        assert fsign.refusal(iid(b), call, now=exp + fsign.SKEW + 1)[1] == 'FED_ASSERT_EXPIRED'
        assert fsign.refusal(iid(b), call, now=exp) is None
    # due for renewal: a fresh one from the home, for the same session
    monkeypatch.setattr(fsign, 'RENEW_BEFORE', fsign.ASSERT_SECONDS + 5)
    time.sleep(1.1)
    with at(b):
        got = fsign.principal(sid, 'alice', '')
    assert got['asr'] != first and active_sessions[sid]['fed_assert'] == got['asr']
    # a password change at the home since the sign-in: the renewal is refused, and the
    # session works on this site alone
    from datetime import datetime, timedelta
    _db_of(a).conn.execute("UPDATE users SET password_changed_at = ? WHERE username = 'alice'",
                           ((datetime.now() + timedelta(seconds=5)).isoformat(),))
    _db_of(a).conn.commit()
    with at(b):
        assert fsign.principal(sid, 'alice', '') is None
    assert 'fed_assert' not in active_sessions[sid]
    r = _get(b, f'/api/clusters/{CID}~{iid(c)}/status', sid)
    assert r.status_code == 403 and r.get_json()['code'] == 'FED_HOME_ELSEWHERE'


def test_the_home_answers_only_a_sign_in_of_its_own_accounts(three):
    """b cannot have c vouch for alice: c is not her home and holds only a mirror."""
    a, b, c = three
    _password(c, 'alice')
    with at(c):
        status, body = fsign.check_at_home(iid(b), 'b', {'user': 'alice', 'password': PASSWORD,
                                                         'sh': 'a' * 32})
    assert status == 401
