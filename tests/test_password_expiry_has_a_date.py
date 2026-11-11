"""Password expiry counts from a date the database actually keeps.

Every place that sets a password wrote password_changed_at into the user dict: the own
change, the admin reset, a new account, the reset-all button. The users table had no
column for it and save_user() writes only the columns it names, so the value was gone
with the next read. With expiry switched on that meant two things:

  * the warning mails never went out - the job skips a user without a date
  * the banner said "expired" for every local account, and changing the password did
    not clear it, because the new date was dropped as well

Pinned here: the column survives a reopen of the database, an older database gets it
with the time of the upgrade (nobody is expired by the upgrade itself, and an HA standby
does not take it for a change made there), the users.enc import keeps its own value, a
password change clears the banner, the mail goes out, and only to local accounts. The
stamps the database writes itself are UTC, so both checks have to read an offset as an
offset.

MK
"""
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

import pegaprox.api.auth as authapi
import pegaprox.background.password_expiry as pe
import pegaprox.core.db as dbmod
from pegaprox.core import ha
from pegaprox.utils.auth import hash_password
from test_ha_core import env, _wire, B  # noqa: F401  (env is a fixture)
from test_ha_api import _audit
from test_ha_orphans import _leader, _member, _next_from_leader, _moves_on, _copies

OLD_PW = 'OldPassw0rd!x1'
NEW_PW = 'NewPassw0rd!x9Zq'


def _reopen():
    """A new connection to the same file - a round trip through one connection proves
    nothing about what is stored."""
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    return dbmod.get_db()


def _row(**extra):
    row = {'password_salt': 'x', 'password_hash': 'x', 'role': 'user', 'enabled': True,
           'auth_source': 'local'}
    row.update(extra)
    return row


def _ago(days, tz=None):
    # a few minutes more than whole days, so a stamp cut to the second still counts them
    return (datetime.now(tz) - timedelta(days=days, minutes=5)).isoformat()


def _recent(stamp):
    parsed = datetime.fromisoformat(stamp)
    assert parsed.utcoffset() == timedelta(0), stamp
    return abs(datetime.now(timezone.utc) - parsed) < timedelta(minutes=5)


@pytest.fixture
def behind_utc():
    """Twelve hours behind UTC (POSIX sign: Etc/GMT+12 is UTC-12), so a UTC stamp read
    as local time is half a day off."""
    saved = os.environ.get('TZ')
    os.environ['TZ'] = 'Etc/GMT+12'
    time.tzset()
    assert time.timezone == 12 * 3600, 'no tz database here'
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = saved
        time.tzset()


# --- the column ------------------------------------------------------------------------

def test_the_date_survives_a_reopen(db):
    stamp = _ago(10)
    db.save_user('alice', _row(password_changed_at=stamp))

    reopened = _reopen()

    assert reopened.get_user('alice')['password_changed_at'] == stamp
    assert reopened.get_all_users()['alice']['password_changed_at'] == stamp


def test_a_save_without_the_date_keeps_the_stored_one(db):
    """A backup from before the column carries no date; restoring it must not reset
    or clear the clock of an account that has one."""
    stamp = _ago(30)
    db.save_user('bob', _row(password_changed_at=stamp))
    db.save_user('bob', _row(display_name='Bob'))

    assert _reopen().get_user('bob')['password_changed_at'] == stamp


def test_an_older_database_gets_the_column_with_the_upgrade_time(db):
    cols = [r[1] for r in db.conn.execute('PRAGMA table_info(users)').fetchall()]
    if 'password_changed_at' in cols:
        db.conn.execute('ALTER TABLE users DROP COLUMN password_changed_at')
    db.conn.execute("INSERT INTO users (username, password_salt, password_hash, role) "
                    "VALUES ('olduser', 'x', 'x', 'user')")
    db.conn.commit()

    stamp = _reopen().get_user('olduser').get('password_changed_at')

    assert stamp and _recent(stamp), stamp


def test_the_upgrade_is_no_change_made_on_an_ha_standby(env, db, seed):
    """A standby in step is upgraded before its active. HA takes a value other than the
    column default for a change made here, so a migration that wrote the date into every
    row had the next sync keep a sealed copy of the whole users table, with the orphan
    banner and an audit entry. The upgrade time is the column default instead."""
    for name in ('alice', 'bob', 'carol'):
        seed.user(name)
    cols = [r[1] for r in db.conn.execute('PRAGMA table_info(users)').fetchall()]
    if 'password_changed_at' in cols:
        db.conn.execute('ALTER TABLE users DROP COLUMN password_changed_at')
        db.conn.commit()
    _leader(env)
    one = _wire(ha.build_snapshot())
    _member(env, B)
    ha.apply_snapshot(one)
    assert ha.apply_snapshot(one)['captured'] is None

    # the new release starts on the standby and its migration runs
    stamp = _reopen().get_user('alice').get('password_changed_at')
    assert stamp and _recent(stamp), stamp

    two = _next_from_leader(one, _moves_on)
    assert ha.apply_snapshot(two)['captured'] is None
    assert _copies() == [] and 'orphans' not in ha.banner()
    assert _audit('ha.changes_not_carried_over') == []


def test_the_legacy_import_keeps_its_own_date(db, monkeypatch):
    stamp = _ago(40)
    monkeypatch.setattr(db, '_read_legacy_users', lambda: {
        'kept': {'password_salt': 'x', 'password_hash': 'x', 'role': 'user',
                 'password_changed_at': stamp},
        'undated': {'password_salt': 'x', 'password_hash': 'x', 'role': 'user'},
    })

    assert db._migrate_users()
    db.conn.commit()
    reopened = _reopen()

    assert reopened.get_user('kept')['password_changed_at'] == stamp
    assert _recent(reopened.get_user('undated')['password_changed_at'])


# --- the banner ------------------------------------------------------------------------

@pytest.fixture
def expiry_on(monkeypatch):
    real = authapi.load_server_settings

    def patched(*a, **k):
        s = dict(real(*a, **k))
        s.update({'password_expiry_enabled': True, 'password_expiry_days': 90,
                  'password_expiry_warning_days': 14})
        return s
    monkeypatch.setattr(authapi, 'load_server_settings', patched)


def _banner(api, name):
    _reopen()
    r = api.as_user({'username': name, 'role': 'user'}).get('/api/auth/check')
    assert r.status_code == 200, r.get_json()
    return r.get_json()['password_expiry']


def test_a_password_change_clears_the_expired_banner(api, db, expiry_on):
    salt, h = hash_password(OLD_PW)
    db.save_user('carol', _row(password_salt=salt, password_hash=h,
                               password_changed_at=_ago(200)))
    assert _banner(api, 'carol')['expired'] is True

    r = api.as_user({'username': 'carol', 'role': 'user'}).post(
        '/api/auth/change-password', json={'current_password': OLD_PW, 'new_password': NEW_PW})
    assert r.status_code == 200, r.get_json()

    banner = _banner(api, 'carol')
    assert banner['expired'] is False, banner
    assert banner['days_until_expiry'] == 90, banner


def test_reset_all_makes_the_passwords_expire(api, db, seed, expiry_on):
    db.save_user('dana', _row(password_changed_at=_ago(1)))
    assert _banner(api, 'dana')['expired'] is False

    admin = seed.user('root', role='admin')
    r = api.as_user(admin).post('/api/security/password-expiry/reset-all', json={})
    assert r.status_code == 200, r.get_json()

    assert _banner(api, 'dana')['expired'] is True


def test_the_banner_reads_a_utc_date_as_utc(api, db, expiry_on, behind_utc):
    db.save_user('erin', _row(password_changed_at=_ago(76, timezone.utc)))

    banner = _banner(api, 'erin')

    assert banner['days_until_expiry'] == 14, banner
    assert banner['warning'] is True, banner


def test_an_admin_reset_clears_the_expired_banner(api, db, seed, expiry_on):
    db.save_user('hank', _row(password_changed_at=_ago(200)))
    assert _banner(api, 'hank')['expired'] is True

    admin = seed.user('root', role='admin')
    r = api.as_user(admin).put('/api/users/hank/password', json={'password': NEW_PW})
    assert r.status_code == 200, r.get_json()

    assert _banner(api, 'hank')['expired'] is False


def test_a_new_account_starts_with_a_fresh_password(api, db, seed, expiry_on):
    admin = seed.user('root', role='admin')
    r = api.as_user(admin).post('/api/users', json={'username': 'ivan', 'password': NEW_PW,
                                                    'role': 'user'})
    assert r.status_code in (200, 201), r.get_json()

    banner = _banner(api, 'ivan')

    assert banner['expired'] is False and banner['days_until_expiry'] == 90, banner


# --- the mail --------------------------------------------------------------------------

@pytest.fixture
def mails(monkeypatch):
    monkeypatch.setattr(pe, 'load_server_settings', lambda *a, **k: {
        'password_expiry_enabled': True, 'password_expiry_email_enabled': True,
        'smtp_enabled': True, 'password_expiry_days': 90, 'password_expiry_warning_days': 14})
    sent = []
    monkeypatch.setattr(pe, 'send_email',
                        lambda to, subject, body: sent.append((to[0], subject)) or (True, None))
    pe._password_expiry_last_check.clear()
    yield sent
    pe._password_expiry_last_check.clear()


def test_a_password_seven_days_from_expiry_gets_its_mail(db, mails):
    db.save_user('frank', _row(email='frank@example.com', password_changed_at=_ago(83)))
    _reopen()

    pe.check_password_expiry()

    assert [to for to, _ in mails] == ['frank@example.com']
    assert 'expires in 7 days' in mails[0][1]


@pytest.mark.parametrize('source', ['ldap', 'oidc', 'entra'])
def test_a_directory_account_gets_no_mail(mails, monkeypatch, source):
    """Its password lives in the directory or the IdP, as the banner already knows."""
    stamp = _ago(83)
    monkeypatch.setattr(pe, 'load_users', lambda: {
        'local': {'role': 'user', 'enabled': True, 'auth_source': 'local',
                  'email': 'local@example.com', 'password_changed_at': stamp},
        'remote': {'role': 'user', 'enabled': True, 'auth_source': source,
                   'email': 'remote@example.com', 'password_changed_at': stamp},
    })

    pe.check_password_expiry()

    assert [to for to, _ in mails] == ['local@example.com']


def test_the_mail_reads_a_utc_date_as_utc(mails, monkeypatch, behind_utc):
    monkeypatch.setattr(pe, 'load_users', lambda: {
        'gina': {'role': 'user', 'enabled': True, 'auth_source': 'local',
                 'email': 'gina@example.com', 'password_changed_at': _ago(83, timezone.utc)},
    })

    pe.check_password_expiry()

    assert [s for _, s in mails] and 'expires in 7 days' in mails[0][1], mails
