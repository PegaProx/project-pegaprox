"""A stored SMTP or LDAP password goes to the server it was typed for.

The settings save kept the stored password whenever the form sent the mask, also when
the same save pointed smtp_host or ldap_server (or the port) somewhere else, so the next
alert mail or LDAP login handed it to the new address. The LDAP test did the same on the
spot, and the SMTP test checked the host but not the port. Moving the server now needs
the password typed again (CREDENTIAL_REQUIRED), as PBS and the clusters do. Without a
user or bind DN nothing is sent, so that save goes through. MK Nov 2026
"""
import pytest

STORED = {'smtp_enabled': True, 'smtp_host': 'mail.corp.example', 'smtp_port': 587,
          'smtp_user': 'alerts', 'smtp_from_email': 'pp@corp.example',
          'ldap_enabled': True, 'ldap_server': 'dc1.corp.example', 'ldap_port': 636,
          'ldap_bind_dn': 'CN=svc,DC=corp,DC=example', 'ldap_base_dn': 'DC=corp,DC=example'}


@pytest.fixture
def admin(api, seed):
    seed.db.save_server_settings(dict(STORED, smtp_password=seed.db._encrypt('smtp-pw-1'),
                                      ldap_bind_password=seed.db._encrypt('ldap-pw-1')))
    a = api.as_user(seed.user('root', role='admin'))
    a.db = seed.db
    return a


def _stored(admin):
    from pegaprox.api.helpers import load_server_settings
    return load_server_settings()


@pytest.mark.parametrize('body, field', [
    ({'smtp_host': 'mx.elsewhere.example', 'smtp_password': '********'}, 'smtp_password'),
    ({'smtp_host': 'mx.elsewhere.example'}, 'smtp_password'),
    ({'smtp_host': 'mail.corp.example', 'smtp_port': 2525, 'smtp_password': ''}, 'smtp_password'),
    ({'ldap_server': 'ldap.elsewhere.example', 'ldap_bind_password': '********'}, 'ldap_bind_password'),
    ({'ldap_server': 'dc1.corp.example', 'ldap_port': 389}, 'ldap_bind_password'),
])
def test_moving_the_server_keeps_nothing_without_the_password(admin, body, field):
    r = admin.post('/api/settings/server', json=body)
    assert r.status_code == 400, r.get_data(as_text=True)
    assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED' and r.get_json()['fields'] == [field]
    s = _stored(admin)
    assert (s['smtp_host'], s['smtp_port'], s['ldap_server'], s['ldap_port']) == (
        'mail.corp.example', 587, 'dc1.corp.example', 636)


def test_the_form_saved_as_it_came_goes_through(admin):
    form = dict(STORED, smtp_password='********', ldap_bind_password='********',
                smtp_host='MAIL.corp.example.', smtp_from_name='PegaProx 2')
    r = admin.post('/api/settings/server', json=form)
    assert r.status_code == 200, r.get_data(as_text=True)
    s = _stored(admin)
    assert s['smtp_from_name'] == 'PegaProx 2'
    assert admin.db._decrypt(s['smtp_password']) == 'smtp-pw-1'
    assert admin.db._decrypt(s['ldap_bind_password']) == 'ldap-pw-1'


def test_a_move_with_the_password_typed_again_is_taken(admin):
    r = admin.post('/api/settings/server', json={'smtp_host': 'mx.elsewhere.example', 'smtp_password': 'smtp-pw-2',
                                                 'ldap_server': 'ldap.elsewhere.example', 'ldap_bind_password': 'ldap-pw-2'})
    assert r.status_code == 200, r.get_data(as_text=True)
    s = _stored(admin)
    assert s['smtp_host'] == 'mx.elsewhere.example' and admin.db._decrypt(s['smtp_password']) == 'smtp-pw-2'
    assert s['ldap_server'] == 'ldap.elsewhere.example' and admin.db._decrypt(s['ldap_bind_password']) == 'ldap-pw-2'


def test_a_move_that_sends_no_login_is_taken(admin):
    r = admin.post('/api/settings/server', json={'smtp_host': 'relay.open.example', 'smtp_user': ''})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _stored(admin)['smtp_host'] == 'relay.open.example'


def test_the_ldap_test_uses_the_stored_password_only_for_the_saved_server(admin):
    r = admin.post('/api/settings/ldap/test', json={'ldap_server': 'ldap.elsewhere.example', 'ldap_port': 636,
                                                    'ldap_bind_dn': STORED['ldap_bind_dn'],
                                                    'ldap_bind_password': '********'})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    r = admin.post('/api/settings/ldap/test', json={'ldap_server': 'dc1.corp.example', 'ldap_port': 389,
                                                    'ldap_bind_dn': STORED['ldap_bind_dn']})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED'


def test_the_smtp_test_asks_for_the_password_on_another_port(admin):
    r = admin.post('/api/settings/smtp/test', json={'email': 'ops@corp.example', 'smtp_host': 'mail.corp.example',
                                                    'smtp_port': 2525, 'smtp_user': 'alerts',
                                                    'smtp_password': '********', 'smtp_from_email': 'pp@corp.example'})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
