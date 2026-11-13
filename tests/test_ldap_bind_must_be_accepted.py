"""An LDAP bind counts only when the directory accepted it.

ldap3 raises on a refused bind such as a wrong password (49), but a few answers come back
from bind() as False instead: a SASL step in progress (14), compare false and true (5, 6),
a size or time limit (4, 3) and a referral that is not followed (10). Nobody looked at the
return value, so a user bind answered that way signed the user in with any password, a
service bind answered that way ran the search unbound, and the group search went on after
a bind that did not take. Each of them counts only when bind() says True now: the login,
its group search, the test button, and the two re-authentication routes that asked
ldap_authenticate for "no error" instead of a success. MK Nov 2026
"""
import pytest

from test_ldap_ca_certificate import (ADMINS, BASE_DN, SVC_DN, directory, ldap_settings,  # noqa: F401
                                      pki)

NOT_RAISED = [14, 5, 6, 4, 3]
USER_DN = f'CN=jdoe,OU=Users,{BASE_DN}'


@pytest.mark.parametrize('verify', [True, False], ids=['check on', 'check off'])
@pytest.mark.parametrize('code', NOT_RAISED + [49])
def test_a_user_bind_that_was_not_accepted_signs_nobody_in(db, directory, pki, code, verify):
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(False, bind_answers={1: code})      # 0 is the service account, 1 the user
    ldap_settings(db, d, ca=pki['ca'], verify=verify)
    assert ldap_authenticate('jdoe', 'wrong-pw') == {'error': 'Invalid LDAP credentials'}


def test_a_user_bind_answered_with_a_referral_is_not_a_sign_in_with_the_check_on(db, directory, pki):
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(False, bind_answers={1: 10})
    ldap_settings(db, d, ca=pki['ca'])
    assert ldap_authenticate('jdoe', 'wrong-pw') == {'error': 'Invalid LDAP credentials'}
    assert len(d.binds) == 2


@pytest.mark.parametrize('code', NOT_RAISED)
def test_a_service_bind_that_was_not_accepted_stops_the_login(db, directory, pki, code, caplog):
    import logging
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(False, bind_answers={0: code})
    ldap_settings(db, d, ca=pki['ca'])
    with caplog.at_level(logging.WARNING):
        assert ldap_authenticate('jdoe', 'user-pw') == {'error': 'LDAP authentication failed'}
    assert len(d.binds) == 1      # no search, no user bind after it
    assert [r for r in caplog.records if 'did not accept the service account bind' in r.getMessage()]


def test_the_group_search_does_not_run_on_a_bind_that_did_not_take(db, directory, pki):
    """No memberOf on the user: the groups come from a search of their own, on a connection
    of the service account. Its bind is answered 14; what that search would find (the
    directory answers it with the user's own DN, mapped to admin here) must not count."""
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(False, groups=(), bind_answers={2: 14}, nested=False)
    ldap_settings(db, d, ca=pki['ca'])
    db.save_server_setting('ldap_group_base_dn', BASE_DN)
    db.save_server_setting('ldap_admin_group', USER_DN)
    res = ldap_authenticate('jdoe', 'user-pw')
    assert res.get('success') and res['role'] == 'viewer' and res['groups'] == [], res


def test_without_any_odd_answer_the_group_search_still_works(db, directory, pki):
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(False, groups=(), nested=False)
    ldap_settings(db, d, ca=pki['ca'])
    db.save_server_setting('ldap_group_base_dn', BASE_DN)
    db.save_server_setting('ldap_admin_group', USER_DN)
    res = ldap_authenticate('jdoe', 'user-pw')
    assert res.get('success') and res['role'] == 'admin', res


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


@pytest.mark.parametrize('code', [14, 4])
def test_the_test_button_says_the_bind_was_not_accepted(admin, seed, directory, pki, code):
    d = directory(False, bind_answers={0: code})
    ldap_settings(seed.db, d, ca=pki['ca'])
    res = admin.post('/api/settings/ldap/test', json={'ldap_bind_password': '********',
                                                      'test_username': 'jdoe'}).get_json()
    assert res['success'] is False, res
    assert res['steps'][-1]['step'] == 'Bind' and res['steps'][-1]['status'] == 'error'
    assert 'did not accept the bind' in res['error'] and str(code) in res['error']
    assert not [s for s in res['steps'] if s['step'] == 'Service account bind']


# --- the re-authentication routes ------------------------------------------------------------

@pytest.fixture
def directory_user(api, seed):
    seed.db.save_user('jdoe', {'password_salt': '', 'password_hash': '', 'role': 'admin',
                               'auth_source': 'ldap', 'enabled': True})
    return api.as_user({'username': 'jdoe', 'role': 'admin'})


def test_verify_password_takes_only_a_confirmed_sign_in(directory_user, seed, directory, pki):
    """The re-check before a sensitive action, against a directory that answers the user
    bind with 14: that is no confirmation of the password."""
    d = directory(False, bind_answers={1: 14})
    ldap_settings(seed.db, d, ca=pki['ca'])
    r = directory_user.post('/api/auth/verify-password', json={'password': 'wrong-pw'})
    assert r.status_code == 401, r.get_data(as_text=True)


@pytest.mark.parametrize('answer', [{}, {'success': False}])
def test_no_error_is_not_a_success_for_the_re_checks(api, directory_user, monkeypatch, answer):
    import pegaprox.utils.ldap as ldap_mod
    monkeypatch.setattr(ldap_mod, 'ldap_authenticate', lambda u, p: dict(answer))
    r = directory_user.post('/api/auth/verify-password', json={'password': 'any'})
    assert r.status_code == 401, r.get_data(as_text=True)
    api.set_manager('c1', api.make_fake_manager('c1'))
    r = directory_user.post('/api/clusters/c1/reconfigure', json={'current_password': 'any'})
    assert r.status_code == 401 and 'LDAP' in r.get_json()['error'], r.get_data(as_text=True)
