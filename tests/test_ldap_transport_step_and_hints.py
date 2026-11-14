"""The LDAP test says what the passwords travel over, and a refused certificate points to the CA field.

The test button lists its steps. A Transport step joins them once the connection and its
TLS are up, read off the connection: plain text and TLS without a certificate check are
warnings, TLS with a checked certificate is ok and says what it was checked against.

ldap3 goes by a scheme in the server field (ldap://, ldaps://) over the LDAPS toggle, so a
step and a tab note built from the toggles could call a plain bind checked. The save and
the test take the scheme apart into the toggles, and the settings read says what a stored
server with a scheme still runs over.

When the TLS handshake failed, the login answered 'Disable "Verify TLS Certificate" for
self-signed/internal CA certificates', the one change that lets a machine on the path
answer for the directory. Both the login and the test point to the CA certificate field
now and name switching the check off as the last resort. A host name that does not match
during STARTTLS came as an error of ldap3's own, not as an ssl error, and read as a failed
login; it gets the TLS answer as well, with what to enter instead. MK Nov 2026
"""
import pytest

from test_ldap_ca_certificate import BASE_DN, SVC_DN, directory, ldap_settings, pki, system_store  # noqa: F401 (fixtures)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _test(admin, d, **form):
    body = {'ldap_server': 'localhost', 'ldap_port': d.port, 'ldap_bind_dn': SVC_DN,
            'ldap_bind_password': 'svc-pw', 'ldap_base_dn': BASE_DN, 'ldap_verify_tls': True,
            'ldap_use_ssl': d.ldaps, 'ldap_use_starttls': not d.ldaps, 'test_username': 'jdoe'}
    body.update(form)
    r = admin.post('/api/settings/ldap/test', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _step(result, name):
    found = [s for s in result['steps'] if s['step'] == name]
    assert len(found) == 1, result['steps']
    return found[0]


def test_plain_text_is_a_warning(admin, directory):
    d = directory(False)
    res = _test(admin, d, ldap_use_starttls=False)
    assert res['success'], res
    step = _step(res, 'Transport')
    assert step['status'] == 'warning' and 'plain text' in step['detail']
    # the step comes before the bind it is about
    names = [s['step'] for s in res['steps']]
    assert names.index('Transport') < names.index('Service account bind')
    assert d.plain_binds


@pytest.mark.parametrize('ldaps,kind', [(True, 'LDAPS'), (False, 'STARTTLS')])
def test_tls_without_the_check_is_a_warning(admin, directory, ldaps, kind):
    d = directory(ldaps, impostor=True)     # nobody checks whose certificate it is
    res = _test(admin, d, ldap_verify_tls=False)
    assert res['success'], res
    step = _step(res, 'Transport')
    assert step['status'] == 'warning'
    assert step['detail'].startswith(kind) and 'without certificate check' in step['detail']


@pytest.mark.parametrize('ldaps,kind', [(True, 'LDAPS'), (False, 'STARTTLS')])
def test_a_checked_certificate_is_ok(admin, directory, pki, ldaps, kind):
    d = directory(ldaps)
    res = _test(admin, d, ldap_ca_cert=pki['ca'])
    assert res['success'], res
    step = _step(res, 'Transport')
    assert step['status'] == 'ok'
    assert step['detail'] == f'{kind}, certificate checked against the CA certificate in the settings'
    assert not d.plain_binds and 'hint' not in res


def test_the_saved_ca_counts_for_the_test_too(admin, seed, directory, pki):
    d = directory(False)
    ldap_settings(seed.db, d, ca=pki['ca'])
    res = _test(admin, d, ldap_bind_password='********')
    assert res['success'], res
    assert _step(res, 'Transport')['status'] == 'ok'


def test_without_a_ca_it_says_the_system_trust_store():
    """The ok wording for the trust store, without a directory that has a public certificate."""
    import pegaprox.api.settings as settings_api
    step = settings_api._ldap_transport_step('ldaps', True, '')
    assert step == {'step': 'Transport', 'status': 'ok',
                    'detail': 'LDAPS, certificate checked against the system trust store'}


@pytest.mark.parametrize('ldaps,failed', [(True, 'Server connection'), (False, 'STARTTLS')])
def test_a_refused_certificate_points_to_the_ca_field(admin, directory, pki, ldaps, failed):
    d = directory(ldaps, impostor=True)
    res = _test(admin, d, ldap_ca_cert=pki['ca'])
    assert res['success'] is False
    assert [s['step'] for s in res['steps']][-1] == failed
    assert 'Transport' not in [s['step'] for s in res['steps']]
    hint = res['hint']
    assert 'CA Certificate' in hint and 'last resort' in hint
    assert hint.index('CA Certificate') < hint.index('Verify TLS')
    assert d.binds == []


def test_a_server_that_is_not_there_gets_no_certificate_hint(admin):
    import socket
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    res = admin.post('/api/settings/ldap/test', json={'ldap_server': '127.0.0.1', 'ldap_port': port,
                                                      'ldap_use_starttls': True}).get_json()
    assert res['success'] is False and 'hint' not in res


@pytest.mark.parametrize('ldaps', [True, False], ids=['ldaps', 'starttls'])
def test_the_login_error_names_the_ca_field_first(db, directory, pki, ldaps):
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(ldaps, impostor=True)
    ldap_settings(db, d, ca=pki['ca'])
    err = ldap_authenticate('jdoe', 'user-pw')['error']
    assert 'TLS/certificate error' in err
    assert 'CA Certificate' in err and err.index('CA Certificate') < err.index('Verify TLS')
    assert 'Disable "Verify TLS Certificate"' not in err


def test_a_directory_only_user_sees_it_on_the_login_page(api, seed, directory, pki, tmp_path, monkeypatch):
    """auth.py hands the TLS error to an account that only exists in the directory, so what
    to do about the certificate reaches the login page."""
    import pegaprox.utils.auth as authmod
    marker = tmp_path / '.admin_initialized'
    marker.write_text('x')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', str(marker))
    d = directory(False, impostor=True)
    ldap_settings(seed.db, d, ca=pki['ca'])
    seed.db.save_user('jdoe', {'password_salt': '', 'password_hash': '', 'role': 'viewer',
                               'auth_source': 'ldap', 'enabled': True})
    assert seed.db.get_user('jdoe')['auth_source'] == 'ldap'
    r = api.anon().post('/api/auth/login', json={'username': 'jdoe', 'password': 'user-pw'})
    assert r.status_code == 401
    assert 'CA Certificate' in r.get_json()['error'], r.get_json()
    assert d.binds == []


# --- a host name that does not match -----------------------------------------------------------

@pytest.mark.parametrize('ldaps', [True, False], ids=['ldaps', 'starttls'])
def test_an_ip_address_that_fails_the_name_check_says_to_enter_the_dns_name(db, directory, system_store, ldaps):
    """The certificate names localhost, the server field holds 127.0.0.1. During STARTTLS
    ldap3 raised that as its own error, which the login took for a failed login. (The CA
    is in the system trust store here, so the handshake itself checks out.)"""
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(ldaps)
    ldap_settings(db, d)
    db.save_server_setting('ldap_server', '127.0.0.1')
    err = ldap_authenticate('jdoe', 'user-pw')['error']
    assert 'TLS/certificate error' in err and 'DNS name' in err and 'IP address' in err, err
    assert d.binds == []


def test_a_name_that_does_not_match_says_to_enter_the_one_in_the_certificate():
    from pegaprox.utils.ldap import ldap_tls_hint
    from ldap3.core.exceptions import LDAPCertificateError
    e = LDAPCertificateError("certificate {} doesn't match any name in ['dc1.corp.example'] ")
    assert 'DNS name the certificate was issued for' in ldap_tls_hint(e, 'dc1.corp.example')
    assert 'IP address' in ldap_tls_hint(e, '10.0.0.5')
    assert 'IP address' in ldap_tls_hint(e, 'ldaps://[fd00::5]:636')


# --- a scheme in the server field ------------------------------------------------------------

def test_the_server_field_is_read_the_way_ldap3_reads_it():
    from pegaprox.utils.ldap import ldap_split_server
    assert ldap_split_server('dc1.corp.example') == ('dc1.corp.example', None, None)
    assert ldap_split_server('LDAPS://dc1.corp.example:3269/') == ('dc1.corp.example', True, 3269)
    assert ldap_split_server('ldap://dc1.corp.example') == ('dc1.corp.example', False, None)
    assert ldap_split_server('ldaps://[fd00::5]:636') == ('fd00::5', True, 636)
    assert ldap_split_server(None) == ('', None, None)


@pytest.mark.parametrize('stored,kind,checked', [
    ({'ldap_server': 'ldap://dc1', 'ldap_use_ssl': True, 'ldap_verify_tls': True}, 'plain', False),
    ({'ldap_server': 'ldap://dc1', 'ldap_use_starttls': True, 'ldap_verify_tls': True}, 'starttls', True),
    ({'ldap_server': 'ldaps://dc1', 'ldap_use_ssl': False, 'ldap_use_starttls': False,
      'ldap_verify_tls': True}, 'ldaps', False),
    ({'ldap_server': 'dc1', 'ldap_use_ssl': True, 'ldap_verify_tls': True}, 'ldaps', True),
    ({'ldap_server': 'dc1', 'ldap_use_ssl': True, 'ldap_use_starttls': True, 'ldap_verify_tls': False},
     'ldaps', False),
])
def test_the_settings_read_says_what_a_stored_server_runs_over(admin, seed, stored, kind, checked):
    """A server stored with a scheme before the save took it apart: LDAPS through the scheme
    alone runs on ldap3's own TLS, which checks nothing."""
    seed.db.save_server_settings(dict({'ldap_use_ssl': False, 'ldap_use_starttls': False}, **stored))
    got = admin.get('/api/settings/server').get_json()['ldap_transport']
    assert got == {'kind': kind, 'checked': checked}


def test_a_stored_scheme_is_tested_as_what_it_runs(admin, seed, directory, pki):
    """ldap:// with LDAPS ticked binds in plain text in ldap3, and the test says so now."""
    d = directory(False)
    ldap_settings(seed.db, d, ca=pki['ca'], ldaps=True, starttls=False)
    seed.db.save_server_setting('ldap_server', 'ldap://localhost')
    res = admin.post('/api/settings/ldap/test', json={'ldap_bind_password': '********',
                                                      'test_username': 'jdoe'}).get_json()
    assert res['success'], res
    step = _step(res, 'Transport')
    assert step['status'] == 'warning' and 'plain text' in step['detail'], step
    assert d.plain_binds


@pytest.mark.parametrize('server,before,after', [
    ('ldaps://dc1.corp.example:3269', {'ldap_use_ssl': False, 'ldap_use_starttls': True},
     {'ldap_server': 'dc1.corp.example', 'ldap_use_ssl': True, 'ldap_use_starttls': False, 'ldap_port': 3269}),
    ('ldap://dc1.corp.example/', {'ldap_use_ssl': True, 'ldap_use_starttls': True},
     {'ldap_server': 'dc1.corp.example', 'ldap_use_ssl': False, 'ldap_use_starttls': True, 'ldap_port': 389}),
    ('dc1.corp.example', {'ldap_use_ssl': True, 'ldap_use_starttls': False},
     {'ldap_server': 'dc1.corp.example', 'ldap_use_ssl': True, 'ldap_use_starttls': False, 'ldap_port': 389}),
])
def test_the_save_takes_the_scheme_apart(admin, seed, server, before, after):
    body = dict(before, ldap_server=server, ldap_port=389)
    assert admin.post('/api/settings/server', json=body).status_code == 200
    stored = {k: seed.db.get_server_setting(k) for k in after}
    assert stored == after


def test_taking_the_scheme_apart_needs_no_password_again(admin, seed):
    """The form sends back the stored ldap://dc1 with the masked password: the same server."""
    seed.db.save_server_settings({'ldap_server': 'ldaps://dc1.corp.example', 'ldap_port': 636,
                                  'ldap_bind_dn': 'CN=svc,DC=corp,DC=example',
                                  'ldap_bind_password': seed.db._encrypt('svc-pw')})
    r = admin.post('/api/settings/server', json={'ldap_server': 'ldaps://dc1.corp.example', 'ldap_port': 636,
                                                 'ldap_bind_password': '********'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert seed.db.get_server_setting('ldap_server') == 'dc1.corp.example'
    assert seed.db._decrypt(seed.db.get_server_setting('ldap_bind_password')) == 'svc-pw'
    # and the next save of the same server is no move either
    r = admin.post('/api/settings/server', json={'ldap_server': 'dc1.corp.example', 'ldap_port': 636,
                                                 'ldap_bind_password': '********'})
    assert r.status_code == 200, r.get_data(as_text=True)
