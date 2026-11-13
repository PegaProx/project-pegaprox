"""A new LDAP setup starts on STARTTLS with the certificate checked; an existing one keeps what it runs on.

Both ldap_use_starttls and ldap_verify_tls defaulted to off, so a directory configured by
filling in a server and a bind DN sent the service account password and every user password
in plain text. The defaults are on now, for setups that start after the change only:

(a) a fresh install that never configured LDAP reads both as on,
(b) an install whose LDAP was set up in the tab (every ldap_* key stored, TLS off) reads
    what it stored,
(c) one that stored a server but never the TLS keys (a save through the API with a few
    fields) reads them as off, the way it ran before,
(d) one that saved other settings but never set up LDAP gets the new defaults once someone
    does. Every save writes back all keys it read, so such an install holds the old
    defaults for both keys without anyone having chosen them, and they only count once
    there is a server.

A plain bind is still possible: an admin who turns STARTTLS off on purpose keeps it off.
MK Nov 2026
"""
import pytest

from pegaprox.api.helpers import load_server_settings

TLS_KEYS = ('ldap_use_ssl', 'ldap_use_starttls', 'ldap_verify_tls')
# what every save of an older version wrote back with whatever it saved: its defaults,
# among them the two TLS toggles (ldap_verify_tls was never one of them)
OLD_DEFAULTS = {'domain': '', 'port': 5000, 'ldap_enabled': False, 'ldap_server': '', 'ldap_port': 389,
                'ldap_use_ssl': False, 'ldap_use_starttls': False, 'ldap_bind_dn': '',
                'ldap_bind_password': '', 'ldap_base_dn': '', 'smtp_enabled': False}
# what the LDAP tab of an older version saved: every field of the form
OLD_TAB_SAVE = {'ldap_enabled': True, 'ldap_server': 'dc1.corp.example', 'ldap_port': 389,
                'ldap_use_ssl': False, 'ldap_use_starttls': False, 'ldap_verify_tls': False,
                'ldap_bind_dn': 'CN=svc,DC=corp,DC=example', 'ldap_base_dn': 'DC=corp,DC=example',
                'ldap_default_role': 'viewer', 'ldap_auto_create_users': True}


def _tls(settings):
    # what get_ldap_settings makes of them, also where a key is missing
    return {k: settings.get(k, False) for k in TLS_KEYS}


ON = {'ldap_use_ssl': False, 'ldap_use_starttls': True, 'ldap_verify_tls': True}
OFF = {'ldap_use_ssl': False, 'ldap_use_starttls': False, 'ldap_verify_tls': False}


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _read(admin):
    r = admin.get('/api/settings/server')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


# (a)
def test_a_fresh_install_starts_on_starttls_with_the_check(db, admin):
    assert db.get_server_settings() == {}
    assert _tls(load_server_settings()) == ON
    got = _read(admin)
    assert _tls(got) == ON and got['ldap_ca_cert'] == ''


def test_what_a_fresh_install_writes_on_its_first_save_keeps_the_defaults(db, admin):
    # any save writes every key it read: the new defaults are what lands
    assert admin.post('/api/settings/server', json={'domain': 'pp.corp.example'}).status_code == 200
    assert db.get_server_setting('ldap_use_starttls') is True
    assert db.get_server_setting('ldap_verify_tls') is True
    assert admin.post('/api/settings/server', json={'ldap_enabled': True, 'ldap_server': 'dc1.corp.example',
                                                    'ldap_base_dn': 'DC=corp,DC=example'}).status_code == 200
    assert _tls(load_server_settings()) == ON


# (b)
def test_an_ldap_set_up_in_the_tab_keeps_its_plain_transport(db, admin):
    db.save_server_settings(dict(OLD_DEFAULTS, **OLD_TAB_SAVE))
    assert _tls(load_server_settings()) == OFF
    assert _tls(_read(admin)) == OFF
    from pegaprox.utils.ldap import get_ldap_settings
    cfg = get_ldap_settings()
    assert (cfg['use_ssl'], cfg['use_starttls'], cfg['verify_tls']) == (False, False, False)
    # a save of something else changes nothing of it
    assert admin.post('/api/settings/server', json={'domain': 'pp.corp.example'}).status_code == 200
    assert _tls(load_server_settings()) == OFF


def test_an_ldaps_set_up_without_the_check_keeps_it_off(db, admin):
    db.save_server_settings({**OLD_DEFAULTS, **OLD_TAB_SAVE, 'ldap_use_ssl': True, 'ldap_port': 636})
    assert _tls(_read(admin)) == {'ldap_use_ssl': True, 'ldap_use_starttls': False, 'ldap_verify_tls': False}


# (c)
def test_a_server_stored_without_the_tls_keys_stays_plain(db, admin):
    db.save_server_settings({'ldap_enabled': True, 'ldap_server': 'dc1.corp.example',
                             'ldap_base_dn': 'DC=corp,DC=example'})
    assert _tls(load_server_settings()) == OFF
    assert _tls(_read(admin)) == OFF
    # and a later save of a few LDAP fields writes that down, not the new defaults
    assert admin.post('/api/settings/server', json={'ldap_bind_dn': 'CN=svc,DC=corp,DC=example'}).status_code == 200
    assert db.get_server_setting('ldap_use_starttls') is False
    assert db.get_server_setting('ldap_verify_tls') in (False, None)
    assert _tls(load_server_settings()) == OFF


def test_a_server_stored_with_only_one_tls_key_keeps_both_as_they_ran(db):
    db.save_server_settings({'ldap_server': 'dc1.corp.example', 'ldap_use_ssl': True})
    assert _tls(load_server_settings()) == {'ldap_use_ssl': True, 'ldap_use_starttls': False,
                                            'ldap_verify_tls': False}


# (d)
def test_an_install_that_never_set_up_ldap_reads_the_new_defaults(db, admin):
    db.save_server_settings(OLD_DEFAULTS)
    assert db.get_server_setting('ldap_use_starttls') is False
    assert _tls(load_server_settings()) == ON
    assert _tls(_read(admin)) == ON


def test_setting_it_up_through_the_api_lands_on_the_new_defaults(db, admin):
    db.save_server_settings(OLD_DEFAULTS)
    r = admin.post('/api/settings/server', json={'ldap_enabled': True, 'ldap_server': 'dc1.corp.example',
                                                 'ldap_base_dn': 'DC=corp,DC=example'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_server_setting('ldap_use_starttls') is True
    assert db.get_server_setting('ldap_verify_tls') is True
    assert _tls(load_server_settings()) == ON


def test_setting_it_up_in_the_tab_lands_on_the_new_defaults(db, admin):
    # the tab sends back what it read, with the server typed in
    db.save_server_settings(OLD_DEFAULTS)
    form = {k: v for k, v in _read(admin).items() if k.startswith('ldap_')}
    form.update(ldap_enabled=True, ldap_server='dc1.corp.example', ldap_base_dn='DC=corp,DC=example')
    assert admin.post('/api/settings/server', json=form).status_code == 200
    assert _tls(load_server_settings()) == ON


def test_ldaps_chosen_before_a_server_is_typed_is_kept(db):
    db.save_server_settings(dict(OLD_DEFAULTS, ldap_use_ssl=True, ldap_port=636))
    assert _tls(load_server_settings()) == {'ldap_use_ssl': True, 'ldap_use_starttls': False,
                                            'ldap_verify_tls': True}


# a plain bind is still the admin's call
def test_an_admin_can_still_turn_tls_off(db, admin):
    r = admin.post('/api/settings/server', json={'ldap_enabled': True, 'ldap_server': 'dc1.corp.example',
                                                 'ldap_use_starttls': False, 'ldap_verify_tls': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert _tls(load_server_settings()) == OFF
    from pegaprox.utils.ldap import get_ldap_settings
    assert get_ldap_settings()['use_starttls'] is False


def test_a_backup_of_an_older_install_restores_to_what_it_ran(db):
    # the export is load_server_settings(); restored, the same rules read it
    db.save_server_settings(dict(OLD_DEFAULTS, **OLD_TAB_SAVE))
    exported = load_server_settings()
    assert _tls(exported) == OFF
    db.conn.execute('DELETE FROM server_settings')
    db.conn.commit()
    db.save_server_settings(exported)
    assert _tls(load_server_settings()) == OFF
