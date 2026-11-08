"""First-run setup opens on a fresh install, not on one that lost its accounts.

initialization_state() took a missing marker plus an empty users table for a fresh
install. An install whose accounts were gone - the marker lost with them, a restore
without the users table - still held its clusters, their credentials and the tokens it
had issued, and /api/auth/setup made whoever reached the port first its administrator.
Such an install now stays shut until the operator reopens setup on the server itself.
A fresh install sets up exactly as before. (#991) MK
"""
import os

import pytest

import pegaprox.api.auth as apiauth
import pegaprox.utils.auth as authmod
from pegaprox.utils.ratelimit import SlidingWindow

SETUP = '/api/auth/setup'
ADMIN = {'username': 'ops', 'password': 'Str0ng!passw0rd'}


@pytest.fixture
def files(tmp_path, monkeypatch):
    """The marker and the reopen file, per test; and a fresh setup rate limit."""
    marker = str(tmp_path / '.admin_initialized')
    reopen = str(tmp_path / 'reopen_setup')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', marker)
    monkeypatch.setattr(authmod, 'SETUP_REOPEN_FILE', reopen, raising=False)
    monkeypatch.setattr(apiauth, '_setup_attempts_by_ip',
                        SlidingWindow(limit=5, window=60, max_keys=2048))
    return marker, reopen


def _a_cluster(db):
    db.save_cluster('c1', {'name': 'prod', 'host': '192.0.2.10', 'user': 'root@pam',
                           'pass': 'secret'})


def _a_token(db):
    authmod.ensure_api_tokens_table()
    db.conn.execute("INSERT INTO api_tokens (token_hash, token_prefix, username, name, role, "
                    "created_at) VALUES ('h', 'abcd', 'gone', 'ci', 'admin', '2026-01-01')")
    db.conn.commit()


def _a_pbs(db):
    db.conn.execute("INSERT INTO pbs_servers (id, name, host, user) "
                    "VALUES ('p1', 'backup', '192.0.2.20', 'root@pam')")
    db.conn.commit()


# --- the finding -------------------------------------------------------------------------

@pytest.mark.parametrize('holding', [_a_cluster, _a_token, _a_pbs])
def test_setup_stays_shut_on_an_install_that_lost_its_accounts(api, db, files, holding):
    marker, _ = files
    holding(db)

    r = api.anon().post(SETUP, json=ADMIN)

    assert db.get_all_users() == {}, 'setup made the caller administrator of a live install'
    assert r.status_code == 409
    assert r.get_json()['code'] == 'NO_ACCOUNTS'
    assert not os.path.exists(marker)


def test_the_state_says_what_it_is(api, db, files):
    _a_cluster(db)

    assert authmod.is_initialized() is True, 'an install with clusters read as fresh'
    assert authmod.initialization_state() == 'no_accounts'
    r = api.anon().post('/api/auth/login', json=ADMIN)
    assert r.status_code == 503 and r.get_json()['code'] == 'NO_ACCOUNTS'
    check = api.anon().get('/api/auth/check')
    assert check.status_code == 401 and check.get_json()['initialized'] is True


def test_a_store_that_cannot_say_what_it_holds_keeps_setup_shut(api, db, files, monkeypatch):
    def unreadable():
        raise RuntimeError('database disk image is malformed')
    monkeypatch.setattr(db, 'holds_configuration', unreadable, raising=False)

    r = api.anon().post(SETUP, json=ADMIN)

    assert r.status_code == 503 and r.get_json()['code'] == 'USER_STORE_UNAVAILABLE'
    assert db.get_all_users() == {}


# --- the ways that stay open -------------------------------------------------------------

def test_a_fresh_install_sets_up_as_before(api, db, files):
    """What an install fills before its setup: server settings, the default tenant, the
    rate tables. None of it closes the wizard."""
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    s = load_server_settings()
    s['port'] = 5100
    save_server_settings(s)
    db.save_tenant('default', {'name': 'Default', 'clusters': []})
    marker, _ = files

    assert authmod.initialization_state() == authmod.INIT_UNINITIALIZED
    r = api.anon().post(SETUP, json=ADMIN)

    assert r.status_code == 200, r.data
    assert db.get_user('ops')['role'] == 'admin'
    assert os.path.exists(marker)


def test_the_operator_reopens_it_on_the_server_once(api, db, files):
    marker, reopen = files
    _a_cluster(db)
    with open(reopen, 'w') as f:
        f.write('')

    assert authmod.initialization_state() == authmod.INIT_UNINITIALIZED
    r = api.anon().post(SETUP, json=ADMIN)

    assert r.status_code == 200, r.data
    assert db.get_user('ops')['role'] == 'admin'
    assert not os.path.exists(reopen), 'the reopen file outlived the setup it was made for'
    assert api.anon().post(SETUP, json={'username': 'late', 'password': 'Str0ng!passw0rd'}
                           ).status_code == 409


def test_an_install_with_accounts_is_initialised_whatever_else_it_holds(api, db, files, seed):
    seed.user('ops', role='admin')
    _a_cluster(db)

    assert authmod.initialization_state() == authmod.INIT_INITIALIZED
