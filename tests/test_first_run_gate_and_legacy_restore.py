"""First-run gate and legacy user import - the paths that decide who owns an install.

Five findings from the September 2026 pentest sweep, all in the same corner of the
code and all with the same shape: a state the server could not determine was read as
the *permissive* one.

  * an unreadable user store answered "fresh install", which re-opens the setup
    wizard on a production deployment while login refuses everyone
  * the setup endpoint checked "not initialised" and wrote the administrator as two
    separate steps, with a body read and an argon2 hash in between
  * the legacy user import ran whenever no cluster happened to be configured, and
    wrote the old file over the live accounts
  * a failing re-migration could commit the DELETE and not the refill
  * a WebAuthn enrolment probe that errored dropped the second factor

MK / NS
"""
import os
import json

import pytest

import pegaprox.core.db as dbmod
import pegaprox.utils.auth as authmod


# --------------------------------------------------------------------------
# the legacy import must never write over accounts that are already there
# --------------------------------------------------------------------------

@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """Throwaway DB with the module globals - including the legacy file - repointed."""
    saved = (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
             dbmod._db, dbmod.PegaProxDB._instance)
    dbmod.CONFIG_DIR = str(tmp_path)
    dbmod.DATABASE_FILE = str(tmp_path / 'pegaprox.db')
    dbmod.KEY_FILE = str(tmp_path / '.pegaprox.key')
    dbmod._db = None
    dbmod.PegaProxDB._instance = None
    monkeypatch.setattr(dbmod, 'USERS_FILE_ENCRYPTED', str(tmp_path / 'users.enc'))
    import pegaprox.core.config as cfgmod
    monkeypatch.setattr(cfgmod, 'CONFIG_DIR', str(tmp_path), raising=False)
    monkeypatch.setattr(cfgmod, 'KEY_FILE', str(tmp_path / '.pegaprox.key'), raising=False)
    try:
        yield dbmod.PegaProxDB()
    finally:
        (dbmod.CONFIG_DIR, dbmod.DATABASE_FILE, dbmod.KEY_FILE,
         dbmod._db, dbmod.PegaProxDB._instance) = saved


def _write_legacy(db, users):
    from pegaprox.core.config import get_fernet
    with open(dbmod.USERS_FILE_ENCRYPTED, 'wb') as f:
        f.write(get_fernet().encrypt(json.dumps(users).encode()))


def _row(db, username):
    cur = db.conn.cursor()
    cur.execute("SELECT role, enabled, password_hash FROM users WHERE username = ?", (username,))
    r = cur.fetchone()
    return None if r is None else (r[0], bool(r[1]), r[2])


def test_clusterless_restart_keeps_a_rotated_password(fresh):
    """The trigger was "no clusters configured", which is an ordinary state: a fresh
    install has none, and so does one whose last cluster was removed."""
    _write_legacy(fresh, {'pegaprox': {'password_salt': 'argon2',
                                       'password_hash': 'LEGACY-DEFAULT',
                                       'role': 'admin'}})
    fresh.save_user('pegaprox', {'password_salt': 'argon2',
                                 'password_hash': 'ROTATED-STRONG',
                                 'role': 'admin', 'enabled': True})

    fresh._migrate_from_legacy()   # runs from __init__, so: every start-up

    assert _row(fresh, 'pegaprox')[2] == 'ROTATED-STRONG'


def test_clusterless_restart_does_not_re_promote_a_demoted_account(fresh):
    _write_legacy(fresh, {'ops': {'password_salt': 's', 'password_hash': 'h', 'role': 'admin'}})
    fresh.save_user('ops', {'password_salt': 's', 'password_hash': 'h',
                            'role': 'viewer', 'enabled': True})

    fresh._migrate_from_legacy()

    assert _row(fresh, 'ops')[0] == 'viewer'


def test_clusterless_restart_does_not_re_enable_a_disabled_account(fresh):
    _write_legacy(fresh, {'ops': {'password_salt': 's', 'password_hash': 'h', 'role': 'admin'}})
    fresh.save_user('ops', {'password_salt': 's', 'password_hash': 'h',
                            'role': 'viewer', 'enabled': False})

    fresh._migrate_from_legacy()

    assert _row(fresh, 'ops')[1] is False


def test_clusterless_restart_does_not_resurrect_a_deleted_account(fresh):
    """The account is gone from the table on purpose; the legacy file still lists it."""
    _write_legacy(fresh, {'fired': {'password_salt': 's', 'password_hash': 'h', 'role': 'admin'},
                          'kept': {'password_salt': 's', 'password_hash': 'h', 'role': 'user'}})
    fresh.save_user('kept', {'password_salt': 's', 'password_hash': 'h',
                             'role': 'user', 'enabled': True})

    fresh._migrate_from_legacy()

    assert _row(fresh, 'fired') is None


def test_a_genuinely_empty_table_still_imports_the_legacy_users(fresh):
    """The behaviour we must not lose: on a real first migration the file is the source."""
    _write_legacy(fresh, {'ops': {'password_salt': 's', 'password_hash': 'h', 'role': 'admin'}})

    fresh._migrate_from_legacy()

    assert _row(fresh, 'ops') == ('admin', True, 'h')


def test_a_disabled_legacy_account_does_not_arrive_enabled(fresh):
    """`enabled` was missing from the INSERT column list, so it took the column
    default of 1 and a deactivated account came back active."""
    _write_legacy(fresh, {'ops': {'password_salt': 's', 'password_hash': 'h',
                                  'role': 'admin', 'enabled': False}})

    fresh._migrate_from_legacy()

    assert _row(fresh, 'ops')[1] is False


@pytest.mark.parametrize('stored', [False, 0])
def test_a_disabled_legacy_account_stays_disabled_however_it_was_written(fresh, stored):
    """The JSON store wrote this flag as 0/1 as often as true/false, so the check has
    to be truthiness - `is False` let the integer form through as enabled."""
    _write_legacy(fresh, {'ops': {'password_salt': 's', 'password_hash': 'h',
                                  'role': 'admin', 'enabled': stored}})

    fresh._migrate_from_legacy()

    assert _row(fresh, 'ops')[1] is False


def test_an_import_that_writes_nothing_reports_failure(fresh, monkeypatch):
    """_migrate_users() returned True whenever the legacy file merely parsed, so the
    re-migration path above it could not tell a real refill from one where every
    single insert had failed - and that path clears the table first."""
    # a value SQLite cannot bind, so every per-user execute() raises and is swallowed
    # by the per-user handler exactly as a disk or schema error would be
    monkeypatch.setattr(fresh, '_read_legacy_users',
                        lambda: {'ops': {'password_salt': 's', 'password_hash': object(),
                                         'role': 'admin'}})

    assert fresh._migrate_users() is False


def test_an_import_that_writes_something_reports_success(fresh):
    _write_legacy(fresh, {'ops': {'password_salt': 's', 'password_hash': 'h', 'role': 'admin'}})

    assert fresh._migrate_users() is True


# --------------------------------------------------------------------------
# an unreadable user store is not a fresh install
# --------------------------------------------------------------------------

class _UnreadableStore:
    def get_all_users(self):
        raise RuntimeError('file is not a database')


@pytest.fixture
def no_marker(tmp_path, monkeypatch):
    """No marker file on disk - the state a pre-setup-wizard upgrade leaves behind
    when backfill_initialized_marker() hit the same unreadable store."""
    marker = str(tmp_path / '.admin_initialized')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', marker)
    return marker


def test_an_unreadable_store_is_reported_as_unknown(no_marker, monkeypatch):
    monkeypatch.setattr(authmod, 'get_db', lambda: _UnreadableStore())
    assert authmod.initialization_state() == authmod.INIT_UNKNOWN


def test_is_initialized_fails_closed_when_the_store_is_unreadable(no_marker, monkeypatch):
    """This is the whole point: False here re-opens /api/auth/setup on a live install."""
    monkeypatch.setattr(authmod, 'get_db', lambda: _UnreadableStore())
    assert authmod.is_initialized() is True


def test_an_empty_store_is_still_reported_as_a_fresh_install(no_marker, monkeypatch):
    class _Empty:
        def get_all_users(self):
            return {}
    monkeypatch.setattr(authmod, 'get_db', lambda: _Empty())
    assert authmod.initialization_state() == authmod.INIT_UNINITIALIZED
    assert authmod.is_initialized() is False


def test_a_marker_we_cannot_stat_is_not_read_as_absent(no_marker, monkeypatch):
    """os.path.exists() answers False for a file it may not stat, so an unreadable
    config/ looked exactly like a fresh install."""
    import errno
    real_stat = os.stat

    def _denied(path, *a, **k):
        if str(path) == no_marker:
            raise PermissionError(errno.EACCES, 'Permission denied', str(path))
        return real_stat(path, *a, **k)
    monkeypatch.setattr(os, 'stat', _denied)

    assert authmod.initialization_state() == authmod.INIT_UNKNOWN


def test_the_marker_short_circuits_the_store_entirely(no_marker, monkeypatch):
    with open(no_marker, 'w') as f:
        f.write('x')
    monkeypatch.setattr(authmod, 'get_db', lambda: _UnreadableStore())
    assert authmod.initialization_state() == authmod.INIT_INITIALIZED


# --------------------------------------------------------------------------
# claiming the install is atomic
# --------------------------------------------------------------------------

def test_only_one_claim_wins(no_marker):
    """O_EXCL is the mutual exclusion; without it both racers created an admin.

    Run concurrently rather than in sequence - the sequential version only proves
    that a second create is refused, which is not the property under test. The
    end-to-end half of this (two administrators before the fix, one after, over
    real HTTPS with a deliberately slow request body) does not belong in the unit
    suite; it lives in the commit message.
    """
    import gevent

    results = [g.get() for g in
               [gevent.spawn(authmod.claim_admin_initialization) for _ in range(8)]]

    assert results.count(True) == 1, results
    assert os.path.exists(no_marker)


def test_a_second_claim_after_the_first_is_still_refused(no_marker):
    """The sequential half, kept separately so the concurrent one keeps its name."""
    assert authmod.claim_admin_initialization() is True
    assert authmod.claim_admin_initialization() is False


def test_a_released_claim_can_be_taken_again(no_marker):
    """A setup that failed to write the account must not brick the install."""
    assert authmod.claim_admin_initialization() is True
    authmod.release_admin_initialization()
    assert authmod.claim_admin_initialization() is True


def test_releasing_a_claim_that_was_never_taken_is_harmless(no_marker):
    authmod.release_admin_initialization()   # must not raise
    assert not os.path.exists(no_marker)


# --------------------------------------------------------------------------
# the endpoints, through the real app
# --------------------------------------------------------------------------

@pytest.fixture
def marker(tmp_path, monkeypatch):
    """Point both the helper module and the API module at a per-test marker path."""
    import pegaprox.api.auth as apiauth
    path = str(tmp_path / '.admin_initialized')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', path)
    # a fresh counter per test (it is a bounded SlidingWindow since Sep 2026, not a dict)
    from pegaprox.utils.ratelimit import SlidingWindow
    monkeypatch.setattr(apiauth, '_setup_attempts_by_ip',
                        SlidingWindow(limit=5, window=60, max_keys=2048))
    return path


def test_setup_refuses_when_the_store_cannot_be_read(api, marker, monkeypatch):
    """Before this, an install whose DB had gone unreadable served the setup wizard
    to anyone who asked, while its own operator could not log in."""
    monkeypatch.setattr(authmod, 'get_db', lambda: _UnreadableStore())

    r = api.anon().post('/api/auth/setup',
                        json={'username': 'attacker', 'password': 'Str0ng!passw0rd'})

    assert r.status_code == 503
    assert r.get_json()['code'] == 'USER_STORE_UNAVAILABLE'
    assert not os.path.exists(marker)


def test_setup_refuses_once_the_install_is_claimed(api, marker):
    """The claim, not the user table, is what closes the window."""
    assert authmod.claim_admin_initialization() is True

    r = api.anon().post('/api/auth/setup',
                        json={'username': 'second', 'password': 'Str0ng!passw0rd'})

    assert r.status_code == 409
    assert r.get_json()['code'] == 'ALREADY_INITIALIZED'


def test_a_failed_admin_write_hands_the_claim_back(api, marker, monkeypatch):
    """Otherwise the install is bricked: setup says "already initialised" and there
    is no account to log in with."""
    import pegaprox.api.auth as apiauth

    # how this actually fails in production: save_users() catches its own exception,
    # logs it and returns normally. A try/except around the call therefore never fires -
    # the handler has to read the account back to know anything was written.
    monkeypatch.setattr(apiauth, 'save_users', lambda *a, **k: None)

    r = api.anon().post('/api/auth/setup',
                        json={'username': 'ops', 'password': 'Str0ng!passw0rd'})

    assert r.status_code == 500, "a silently failed write was reported as success"
    assert not os.path.exists(marker), "the claim outlived the failure"


def test_login_names_the_unreadable_store_instead_of_offering_setup(api, marker, monkeypatch):
    """NOT_INITIALIZED tells the operator to run the wizard. On a live install with a
    broken DB that is both wrong and an invitation."""
    monkeypatch.setattr(authmod, 'get_db', lambda: _UnreadableStore())

    r = api.anon().post('/api/auth/login', json={'username': 'ops', 'password': 'x'})

    assert r.status_code == 503
    assert r.get_json()['code'] == 'USER_STORE_UNAVAILABLE'


def test_login_still_reports_a_genuinely_fresh_install(api, marker, monkeypatch):
    class _Empty:
        def get_all_users(self):
            return {}
    monkeypatch.setattr(authmod, 'get_db', lambda: _Empty())

    r = api.anon().post('/api/auth/login', json={'username': 'ops', 'password': 'x'})

    assert r.status_code == 503
    assert r.get_json()['code'] == 'NOT_INITIALIZED'


def test_a_key_only_account_is_not_let_through_when_the_probe_fails(api, db, marker,
                                                                    monkeypatch):
    """The probe used to swallow its error into "no key enrolled". For an account whose
    ONLY second factor is a security key that dropped the factor and the password alone
    was enough."""
    import pegaprox.api.auth as apiauth
    from pegaprox.utils.auth import hash_password

    salt, pw_hash = hash_password('C0rrect!horse9')
    db.save_user('keyuser', {'password_salt': salt, 'password_hash': pw_hash,
                             'role': 'admin', 'enabled': True, 'auth_source': 'local'})
    with open(marker, 'w') as f:     # install is initialised
        f.write('x')

    class _ProbeFails:
        def query_one(self, *a, **k):
            raise RuntimeError('no such table: webauthn_credentials')
        def __getattr__(self, name):
            return getattr(db, name)
    monkeypatch.setattr(apiauth, 'get_db', lambda: _ProbeFails())

    r = api.anon().post('/api/auth/login',
                        json={'username': 'keyuser', 'password': 'C0rrect!horse9'})

    assert r.status_code == 503, f"password alone got through: {r.status_code}"
    assert r.get_json()['code'] == 'MFA_STATE_UNAVAILABLE'
