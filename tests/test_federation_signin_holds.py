"""Sign-in at any site: what the client sends does not decide whether the home is asked,
and one account does not use up its home's answers to a site.

A totp_code that could not be a code made the home refuse the request as malformed, and
the site went on from its mirrored password; any webauthn_proof left the home out as well.
An account whose password the home had changed, or that the home had disabled, signed in
with what the mirror still held. And the home answered 30 sign-ins a minute per site, one
account's included: one account signing in every two seconds kept every other account of
its home from signing in there. MK Nov 2026
"""
import pytest

from pegaprox.core import federation_signin as fsign
from tests.test_federation import (  # noqa: F401 - fixtures by name
    _add_local_user, _code, _db_of, _defaults_out_of_the_config_dir, _fresh_budgets, _join,
    _map, _pull, _settled, _wire, at)
from tests.test_federation_relay import _fresh_relay, _relay_side  # noqa: F401

PASSWORD = 'C0rrect!horse9'


@pytest.fixture(autouse=True)
def _fresh_sign_ins():
    from pegaprox.api import auth as api_auth
    from pegaprox.globals import login_attempts_by_ip, login_attempts_by_user
    fsign.reset_for_tests()
    api_auth._totp_used.clear()
    login_attempts_by_ip.clear()
    login_attempts_by_user.clear()
    yield
    fsign.reset_for_tests()
    login_attempts_by_ip.clear()
    login_attempts_by_user.clear()


def _password(side, user, password=PASSWORD):
    from pegaprox.utils.auth import hash_password
    salt, h = hash_password(password)
    db = _db_of(side)
    db.conn.execute('UPDATE users SET password_salt = ?, password_hash = ?, auth_source = '
                    "'local', enabled = 1 WHERE username = ?", (salt, h, user))
    db.conn.commit()


@pytest.fixture
def sites(tmp_path, monkeypatch):
    """a homes alice (admin) and vic (viewer), both mirrored and mapped at b; b serves the
    real /api/auth/login."""
    from pegaprox.api import auth as api_auth
    from pegaprox.utils import auth as auth_utils
    a, b = _relay_side(tmp_path, 'a'), _relay_side(tmp_path, 'b')
    _wire([a, b], [])
    _add_local_user(a, 'alice', role='admin')
    _add_local_user(a, 'vic', role='viewer')
    _password(a, 'alice')
    _password(a, 'vic')
    _join(b, _code(a))
    for s in (a, b):
        _settled(s)
    assert _map(b, a, 'tenant', 'default', 'default')['pulled']
    _pull(b, a)
    b.app.register_blueprint(api_auth.bp)
    b.client = b.app.test_client()
    monkeypatch.setattr(api_auth, 'initialization_state', lambda: auth_utils.INIT_INITIALIZED)
    return a, b


def login(side, user, password=PASSWORD, **extra):
    with at(side):
        return side.client.post('/api/auth/login',
                                json=dict(username=user, password=password, **extra))


def _forget_failures():
    from pegaprox.globals import login_attempts_by_ip, login_attempts_by_user
    login_attempts_by_ip.clear()
    login_attempts_by_user.clear()


def _signed_in(r):
    return r.status_code == 200 and bool((r.get_json() or {}).get('session_id'))


def test_one_account_does_not_use_up_its_homes_sign_ins_at_a_site(sites):
    a, b = sites
    # one account signs in at b with its own password, again and again
    for _ in range(30):
        login(b, 'vic')
    # its own budget runs out, the others of its home still sign in there
    assert login(b, 'vic').status_code == 429
    r = login(b, 'alice')
    assert _signed_in(r), r.data


@pytest.mark.parametrize('extra', [{'totp_code': 'x'}, {'totp_code': '12ab56'},
                                   {'webauthn_proof': 'x'}], ids=['letters', 'mixed', 'proof'])
def test_a_junk_second_factor_does_not_leave_the_home_out(sites, extra):
    a, b = sites
    # alice's home changed her password; b's mirror still holds the old one
    _password(a, 'alice', 'N3w!password-only-a-knows')
    r = login(b, 'alice', **extra)
    assert r.status_code == 401 and not _signed_in(r), r.data
    # counterproof: with nothing sent along, the home refuses the old password as well
    _forget_failures()
    assert login(b, 'alice').status_code == 401


def test_a_junk_code_does_not_sign_in_an_account_its_home_disabled(sites):
    a, b = sites
    _db_of(a).conn.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    _db_of(a).conn.commit()
    r = login(b, 'alice', totp_code='x')
    assert r.status_code == 401 and not _signed_in(r), r.data
    # and the account at its home is fine otherwise: enabled again, it signs in at b
    _db_of(a).conn.execute("UPDATE users SET enabled = 1 WHERE username = 'alice'")
    _db_of(a).conn.commit()
    _forget_failures()
    assert _signed_in(login(b, 'alice'))


def test_a_code_that_cannot_be_one_is_refused_without_asking_the_home(sites, monkeypatch):
    a, b = sites
    from pegaprox.core import federation
    asked = []
    monkeypatch.setattr(federation, 'call_peer', lambda *x, **kw: asked.append(x) or (0, None, {}))
    with at(b):
        user = _db_of(b).get_user('alice')
        got = fsign.at_home('alice', PASSWORD, 'x', user)
    assert got['state'] == 'denied' and asked == []


def test_a_home_that_takes_it_for_no_sign_in_refuses_it(sites, monkeypatch):
    """The home's 400 is no reason to go on from the mirror without its word."""
    a, b = sites
    from pegaprox.core import federation
    monkeypatch.setattr(federation, 'call_peer',
                        lambda *x, **kw: (400, {'code': 'FED_SIGN_IN', 'error': 'Not a sign-in'}, {}))
    with at(b):
        user = _db_of(b).get_user('alice')
        assert fsign.at_home('alice', PASSWORD, None, user)['state'] == 'denied'
