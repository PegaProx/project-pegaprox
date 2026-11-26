"""The sign-in and the session check say whether the federation runs (#1372).

With the federation switched off, every signed-in browser asked /api/federation/linked
every five minutes and got 404 FED_DISABLED back: a failed request in the browser's
console each time. /api/federation/status is for admins only, so the flag comes with what
every account reads already, the login answer and /api/auth/check. The dashboard asks for
the linked sites only while it is true (the browser half is in test_federation_linked_ui).

The flag is the switch the federation routes ask themselves. Off, every one of them still
answers 404 FED_DISABLED, the flag says false and nothing else of the federation is asked;
on, the flag says true and the route answers. The anonymous answer of /api/auth/check
does not carry it.

MK Nov 2026
"""
from pegaprox.core import federation

from test_federation_off_is_inert import calls  # noqa: F401

PASSWORD = 'C0rrect!horse9'


def _local_account(db, username='nora'):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user(username, {'password_salt': salt, 'password_hash': pw_hash, 'role': 'viewer',
                            'enabled': True, 'auth_source': 'local'})


def _sign_in(api, username='nora'):
    r = api.anon().post('/api/auth/login', json={'username': username, 'password': PASSWORD})
    body = r.get_json() or {}
    assert r.status_code == 200 and body.get('session_id'), (r.status_code, body)
    return body


def test_off_the_session_check_says_so_and_the_route_stays_shut(api, seed, calls):
    """A viewer, who cannot read the status route, learns it from the session check. The
    linked route keeps answering 404 FED_DISABLED, so the flag only spares the request."""
    viewer = api.as_user(seed.user('vera', role='viewer'))
    r = viewer.get('/api/auth/check')
    assert r.status_code == 200
    assert r.get_json().get('federation_enabled') is False
    linked = viewer.get('/api/federation/linked')
    assert linked.status_code == 404 and linked.get_json()['code'] == 'FED_DISABLED'
    assert viewer.get('/api/federation/status').status_code == 403
    assert calls == []


def test_off_the_login_answer_says_so(api, db, calls):
    _local_account(db)
    assert _sign_in(api).get('federation_enabled') is False
    assert calls == []


def test_on_both_say_so_and_the_route_answers(api, seed, db, monkeypatch):
    monkeypatch.setenv(federation.ENV_SWITCH, '1')
    # no identity of its own yet: the route answers with no sites rather than asking any
    monkeypatch.setattr(federation, 'instance_id', lambda: '')
    viewer = api.as_user(seed.user('vera', role='viewer'))
    r = viewer.get('/api/auth/check')
    assert r.status_code == 200 and r.get_json().get('federation_enabled') is True
    linked = viewer.get('/api/federation/linked')
    assert linked.status_code == 200 and linked.get_json()['sites'] == []
    _local_account(db)
    assert _sign_in(api).get('federation_enabled') is True


def test_the_flag_follows_the_switch_in_the_settings(api, seed, db, monkeypatch):
    """Switched on by an admin while the page is open: the next session check says so, and
    off again it says false. That check is what the dashboard reads every five minutes."""
    monkeypatch.delenv(federation.ENV_SWITCH, raising=False)
    monkeypatch.setattr(federation, 'start_workers', lambda: None)
    monkeypatch.setattr(federation, 'stop_workers', lambda: None)
    viewer = api.as_user(seed.user('vera', role='viewer'))
    assert viewer.get('/api/auth/check').get_json().get('federation_enabled') is False
    for value in (True, False):
        db.save_server_setting(federation.SETTING_KEY, value)
        federation._runtime['switch'] = None
        assert viewer.get('/api/auth/check').get_json().get('federation_enabled') is value


def test_the_anonymous_answer_does_not_carry_it(api):
    r = api.anon().get('/api/auth/check')
    assert r.status_code == 401
    assert 'federation_enabled' not in (r.get_json() or {})
