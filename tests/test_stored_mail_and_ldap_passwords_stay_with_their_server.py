"""A stored SMTP or LDAP password goes to the server it was typed for.

The settings save kept the stored password whenever the form sent the mask, also when
the same save pointed smtp_host or ldap_server (or the port) somewhere else, so the next
alert mail or LDAP login handed it to the new address. The LDAP test did the same on the
spot, and the SMTP test checked the host but not the port. Moving the server now needs
the password typed again (CREDENTIAL_REQUIRED), as PBS and the clusters do. A save
without a user or bind DN is held the same way: the next save could set one on the moved
server and the stored password would go along. Such a server takes any value typed into
the password field, it is not sent without a user. MK Nov 2026
"""
import smtplib

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


def test_a_move_without_a_login_needs_a_value_in_the_password_field(admin):
    r = admin.post('/api/settings/server', json={'smtp_host': 'relay.open.example', 'smtp_user': ''})
    assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
    assert 'without a login takes any value' in r.get_json()['error']
    assert _stored(admin)['smtp_host'] == 'mail.corp.example'
    r = admin.post('/api/settings/server', json={'smtp_host': 'relay.open.example', 'smtp_user': '',
                                                 'smtp_password': 'none'})
    assert r.status_code == 200, r.get_data(as_text=True)
    s = _stored(admin)
    assert s['smtp_host'] == 'relay.open.example' and admin.db._decrypt(s['smtp_password']) == 'none'


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


class _Relay:
    """smtplib.SMTP as far as send_email uses it, writing down where each login goes."""
    logins = []

    def __init__(self, host, port, timeout=None, **kw):
        self.where = (host, port)

    def ehlo(self):
        pass

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        self.logins.append((self.where, user, password))

    def sendmail(self, *a):
        return {}

    def quit(self):
        pass


@pytest.fixture
def relay(monkeypatch):
    monkeypatch.setattr(_Relay, 'logins', [])
    monkeypatch.setattr(smtplib, 'SMTP', _Relay)
    return _Relay


# the user or bind DN cleared in the move itself, or in a save of its own before it, and set
# again once the server is the other one
SMTP_STEPS = {
    'with_the_move': [{'smtp_host': 'mx.elsewhere.example', 'smtp_user': ''}, {'smtp_user': 'svc'}],
    'before_the_move': [{'smtp_user': ''}, {'smtp_host': 'mx.elsewhere.example'}, {'smtp_user': 'svc'}],
}
LDAP_STEPS = {
    'with_the_move': [{'ldap_server': 'ldap.elsewhere.example', 'ldap_bind_dn': ''},
                      {'ldap_bind_dn': STORED['ldap_bind_dn']}],
    'before_the_move': [{'ldap_bind_dn': ''}, {'ldap_server': 'ldap.elsewhere.example', 'ldap_port': 636},
                        {'ldap_bind_dn': STORED['ldap_bind_dn']}],
}


@pytest.mark.parametrize('order', sorted(SMTP_STEPS))
def test_clearing_the_user_on_the_way_does_not_carry_the_smtp_password_along(admin, relay, order):
    codes = [admin.post('/api/settings/server', json=body) for body in SMTP_STEPS[order]]
    # the test mail from the saved settings, and one for the host the saves were after
    sent = [admin.post('/api/settings/smtp/test', json={'email': 'ops@corp.example'}),
            admin.post('/api/settings/smtp/test', json={'email': 'ops@corp.example',
                                                        'smtp_host': 'mx.elsewhere.example', 'smtp_user': 'svc',
                                                        'smtp_password': '********',
                                                        'smtp_from_email': 'pp@corp.example'})]
    assert relay.logins == [(('mail.corp.example', 587), 'svc', 'smtp-pw-1')]
    moved = codes[-2]
    assert moved.status_code == 400 and moved.get_json()['fields'] == ['smtp_password'], moved.get_data(as_text=True)
    assert [r.status_code for r in codes if r is not moved] == [200] * (len(codes) - 1)
    s = _stored(admin)
    assert (s['smtp_host'], s['smtp_user']) == ('mail.corp.example', 'svc')
    assert sent[0].status_code == 200, sent[0].get_data(as_text=True)
    assert sent[1].status_code == 400 and sent[1].get_json()['code'] == 'CREDENTIAL_REQUIRED'


@pytest.mark.parametrize('order', sorted(LDAP_STEPS))
def test_clearing_the_bind_dn_on_the_way_does_not_carry_the_bind_password_along(admin, monkeypatch, order):
    import ldap3
    binds = []

    class Server:
        def __init__(self, host, port=None, **kw):
            self.where = (host, port)

    class Connection:
        def __init__(self, server, user=None, password=None, **kw):
            binds.append((server.where, user, password))

        def open(self):
            raise ldap3.core.exceptions.LDAPSocketOpenError('no directory in this test')

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, 'Server', Server)
    monkeypatch.setattr(ldap3, 'Connection', Connection)
    dn = STORED['ldap_bind_dn']
    codes = [admin.post('/api/settings/server', json=body) for body in LDAP_STEPS[order]]
    tested = [admin.post('/api/settings/ldap/test', json={}),
              admin.post('/api/settings/ldap/test', json={'ldap_server': 'ldap.elsewhere.example', 'ldap_port': 636,
                                                          'ldap_bind_dn': dn, 'ldap_bind_password': '********'})]
    assert binds == [(('dc1.corp.example', 636), dn, 'ldap-pw-1')]
    moved = codes[-2]
    assert moved.status_code == 400 and moved.get_json()['fields'] == ['ldap_bind_password'], \
        moved.get_data(as_text=True)
    assert [r.status_code for r in codes if r is not moved] == [200] * (len(codes) - 1)
    s = _stored(admin)
    assert (s['ldap_server'], s['ldap_port'], s['ldap_bind_dn']) == ('dc1.corp.example', 636, dn)
    assert tested[0].status_code == 200
    assert tested[1].status_code == 400 and tested[1].get_json()['code'] == 'CREDENTIAL_REQUIRED'


def test_a_null_host_is_saved_as_the_empty_host_the_check_compared(admin):
    s = _stored(admin)
    admin.db.save_server_settings(dict(s, smtp_host='', smtp_password=admin.db._encrypt('smtp-pw-1'),
                                       ldap_bind_password=admin.db._encrypt('ldap-pw-1')))
    assert admin.post('/api/settings/server', json={'smtp_host': None}).status_code == 200
    assert _stored(admin)['smtp_host'] == ''
