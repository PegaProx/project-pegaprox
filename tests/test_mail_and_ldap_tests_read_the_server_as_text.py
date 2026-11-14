"""The SMTP and LDAP test buttons read the server field as text.

smtp_host and ldap_server went straight into .strip() and .lower() when the form sent the
masked password, so a JSON null, a number or a list ended in an AttributeError and a 500.
They are read as text now, a null as no server: an empty LDAP server is the 400 it was, an
empty SMTP host tests the saved settings, and anything else is a host like any other one,
held to the saved host before the stored password goes along. MK Nov 2026
"""
import smtplib

import pytest

STORED = {'smtp_enabled': True, 'smtp_host': 'mail.corp.example', 'smtp_port': 587,
          'smtp_user': 'alerts', 'smtp_from_email': 'pp@corp.example',
          'ldap_enabled': True, 'ldap_server': 'dc1.corp.example', 'ldap_port': 636,
          'ldap_bind_dn': 'CN=svc,DC=corp,DC=example', 'ldap_base_dn': 'DC=corp,DC=example'}
ODD = [None, 0, 25, 2.5, True, ['mail.corp.example'], {'host': 'mail.corp.example'}]


@pytest.fixture
def admin(api, seed):
    seed.db.save_server_settings(dict(STORED, smtp_password=seed.db._encrypt('smtp-pw-1'),
                                      ldap_bind_password=seed.db._encrypt('ldap-pw-1')))
    return api.as_user(seed.user('root', role='admin'))


@pytest.fixture
def wire(monkeypatch):
    """Where a login would have gone, without a relay or a directory on the other end."""
    import ldap3
    seen = []

    class Relay:
        def __init__(self, host, port, timeout=None, **kw):
            self.where = (host, port)

        def ehlo(self):
            pass

        def starttls(self, context=None):
            pass

        def login(self, user, password):
            seen.append(('smtp', self.where, password))

        def sendmail(self, *a):
            return {}

        def quit(self):
            pass

    class Server:
        def __init__(self, host, port=None, **kw):
            self.where = (host, port)

    class Connection:
        def __init__(self, server, user=None, password=None, **kw):
            seen.append(('ldap', server.where, password))

        def open(self):
            raise ldap3.core.exceptions.LDAPSocketOpenError('no directory in this test')

        def unbind(self):
            pass

    monkeypatch.setattr(smtplib, 'SMTP', Relay)
    monkeypatch.setattr(ldap3, 'Server', Server)
    monkeypatch.setattr(ldap3, 'Connection', Connection)
    return seen


def _smtp(admin, host, password='********'):
    return admin.post('/api/settings/smtp/test', json={'email': 'ops@corp.example', 'smtp_host': host,
                                                       'smtp_user': 'alerts', 'smtp_password': password,
                                                       'smtp_from_email': 'pp@corp.example'})


def _ldap(admin, server, password='********'):
    return admin.post('/api/settings/ldap/test', json={'ldap_server': server, 'ldap_port': 636,
                                                       'ldap_bind_dn': STORED['ldap_bind_dn'],
                                                       'ldap_bind_password': password})


@pytest.mark.parametrize('host', ODD, ids=repr)
def test_the_smtp_test_answers_a_host_that_is_no_text(admin, wire, host):
    r = _smtp(admin, host)
    assert r.status_code != 500, r.get_data(as_text=True)
    if host in (None, 0):
        # no host: the saved settings, with their stored password
        assert r.status_code == 200, r.get_data(as_text=True)
        assert wire == [('smtp', ('mail.corp.example', 587), 'smtp-pw-1')]
    else:
        assert r.status_code == 400 and r.get_json()['code'] == 'CREDENTIAL_REQUIRED', r.get_data(as_text=True)
        assert wire == []


@pytest.mark.parametrize('server', ODD, ids=repr)
def test_the_ldap_test_answers_a_server_that_is_no_text(admin, wire, server):
    r = _ldap(admin, server)
    assert r.status_code == 400, r.get_data(as_text=True)
    if server in (None, 0):
        assert r.get_json()['error'] == 'LDAP server is required'
    else:
        assert r.get_json()['code'] == 'CREDENTIAL_REQUIRED'
    assert wire == []


def test_an_empty_ldap_server_is_turned_down_as_such(admin, wire):
    # blanks are no server either, with the password typed or the stored one
    for server in ('', None, '   ', '\t '):
        for password in ('typed-pw', '********'):
            r = _ldap(admin, server, password=password)
            assert r.status_code == 400 and r.get_json()['error'] == 'LDAP server is required', (server, password)
    assert wire == []


def test_a_host_written_as_a_number_is_tested_with_the_password_typed_for_it(admin, wire):
    assert _smtp(admin, 25, password='typed-pw').status_code == 200
    r = _ldap(admin, 25, password='typed-pw')
    assert r.status_code == 200 and r.get_json()['success'] is False
    assert wire == [('smtp', ('25', 587), 'typed-pw'), ('ldap', ('25', 636), 'typed-pw')]
