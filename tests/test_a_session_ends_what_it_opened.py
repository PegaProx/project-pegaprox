"""What a session opened ends with it: console tokens, SSE tokens, streams, sockets.

Signing out, revoking a session and a password change dropped the session (and the SSE
token, and API tokens on a password change), but not what had been minted or opened under
it. A console ws token kept working for its 60 s after a password reset (#1038), an open
live-update socket and an open SSE stream kept getting frames, and the stream's 30 s
re-check asked only whether the account still existed. Someone holding a hijacked session
kept live frames and a console after the victim had locked them out.

Every ws and SSE token now records the session (or API token) it was minted under, and
ending a session ends those, the SSE streams opened with them and the WebSockets on the
main port opened under it. The re-checks of the live-update socket and of an SSE stream
ask for that session or API token as well. A password change from the client portal
keeps the session that made it, and what it opened.

Consoles on the dedicated VNC and SSH ports are not reached by this.

NS Oct 2026
"""
import json
import time

import gevent
import pytest
import websocket
from gevent.pool import Pool
from gevent.pywsgi import WSGIHandler, WSGIServer

import pegaprox.api.realtime as rt
import pegaprox.app as app_mod
import pegaprox.globals as ppglobals
import pegaprox.utils.auth as authmod
import pegaprox.utils.realtime as rtu

NEW_PASSWORD = 'Another-Str0ng-Passw0rd!'


def _ws_token(client):
    r = client.post('/api/ws/token', json={})
    assert r.status_code == 200, r.get_json()
    return r.get_json()['token']


def _sse_token(client, headers=None):
    r = client.post('/api/sse/token', json={}, headers=headers)
    assert r.status_code == 200, r.get_json()
    return r.get_json()['token']


def _still_valid(token):
    """validate_ws_token consumes, so look without consuming."""
    with ppglobals.ws_tokens_lock:
        return token in ppglobals.ws_tokens


@pytest.fixture
def people(api, seed):
    ppglobals.ws_tokens.clear()
    ppglobals.sse_tokens.clear()
    ppglobals.sse_clients.clear()
    seed.user('root', role='admin')
    seed.user('alice', role='user')
    seed.user('bob', role='user')
    yield {
        'root': api.as_user({'username': 'root', 'role': 'admin'}),
        'alice': api.as_user({'username': 'alice', 'role': 'user'}),
        'alice_phone': api.as_user({'username': 'alice', 'role': 'user'}),
        'bob': api.as_user({'username': 'bob', 'role': 'user'}),
    }
    ppglobals.ws_tokens.clear()
    ppglobals.sse_tokens.clear()
    ppglobals.sse_clients.clear()


# --- console tokens (#1038) -------------------------------------------------------------

def test_an_admin_password_reset_takes_the_console_tokens_with_it(people):
    """The finding: a ws token minted with a session the reset ends kept opening a console."""
    token = _ws_token(people['alice'])

    r = people['root'].put('/api/users/alice/password', json={'password': NEW_PASSWORD})
    assert r.status_code == 200, r.get_json()

    assert not _still_valid(token), 'a console token outlived the password reset'


def test_an_own_password_change_takes_them_too(people, db):
    salt, pw_hash = authmod.hash_password('Old-Str0ng-Passw0rd!')
    db.save_user('alice', {**db.get_user('alice'), 'password_salt': salt, 'password_hash': pw_hash})
    token = _ws_token(people['alice_phone'])

    r = people['alice'].post('/api/auth/change-password',
                             json={'current_password': 'Old-Str0ng-Passw0rd!',
                                   'new_password': NEW_PASSWORD})
    assert r.status_code == 200, r.get_json()

    assert not _still_valid(token)


def test_revoking_one_session_takes_its_tokens_and_leaves_the_others(people):
    lost = _ws_token(people['alice_phone'])
    kept = _ws_token(people['alice'])
    sessions = people['alice'].get('/api/user/sessions').get_json()['sessions']
    other = next(s for s in sessions if not s['is_current'])

    r = people['alice'].delete(f"/api/user/sessions/{other['revoke_token']}")
    assert r.status_code == 200, r.get_json()

    assert not _still_valid(lost), 'the revoked session kept its console token'
    assert _still_valid(kept), 'the session that revoked the other one lost its token'


def test_a_password_change_that_keeps_the_current_session_keeps_its_tokens(people):
    """The client portal changes the password and stays signed in."""
    kept = _ws_token(people['alice'])
    lost = _ws_token(people['alice_phone'])

    authmod.invalidate_all_user_sessions('alice', except_session=people['alice'].session_id)

    assert _still_valid(kept)
    assert not _still_valid(lost)


def test_another_accounts_tokens_are_untouched(people):
    theirs = _ws_token(people['bob'])
    people['root'].put('/api/users/alice/password', json={'password': NEW_PASSWORD})
    assert _still_valid(theirs)


# --- open SSE streams -------------------------------------------------------------------

def _open_stream(app, token):
    """(generator, its queue), iterated outside the request context like the server does."""
    with app.test_request_context(f'/api/sse/updates?token={token}'):
        resp = rt.sse_updates()
    assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
    client_id = next(iter(ppglobals.sse_clients))
    gen = resp.response
    next(gen)                                   # connect envelope
    return gen, ppglobals.sse_clients[client_id]['queue']


def _closes(gen, q, frames=3):
    """Feed heartbeats as broadcast.py does and see whether the stream lets go."""
    try:
        for _ in range(frames):
            q.put_nowait('{"type":"heartbeat"}')
            next(gen)
    except StopIteration:
        return True
    return False


def test_signing_out_ends_an_open_stream(api, people, monkeypatch):
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    gen, q = _open_stream(api.app, _sse_token(people['alice_phone']))
    try:
        authmod.invalidate_session(people['alice_phone'].session_id)
        assert _closes(gen, q), 'the stream kept running after its session ended'
    finally:
        gen.close()


def test_a_stream_of_another_session_keeps_running(api, people, monkeypatch):
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    gen, q = _open_stream(api.app, _sse_token(people['alice']))
    try:
        authmod.invalidate_session(people['alice_phone'].session_id)
        assert not _closes(gen, q)
    finally:
        gen.close()


def test_a_revoked_api_token_ends_the_stream_it_opened(api, people, db, monkeypatch):
    """No session to end here: the re-check asks for the token."""
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    res = authmod.create_api_token('alice', 'ci', role='user')
    gen, q = _open_stream(
        api.app, _sse_token(api.anon(), headers={'Authorization': f"Bearer {res['token']}"}))
    try:
        db.conn.execute('UPDATE api_tokens SET revoked = 1 WHERE id = ?', (res['token_id'],))
        db.conn.commit()
        assert _closes(gen, q), 'the stream outlived the API token it was opened with'
    finally:
        gen.close()


def test_a_standing_api_token_keeps_its_stream(api, people, monkeypatch):
    monkeypatch.setattr(rt, 'SSE_REAUTHZ_INTERVAL', 0, raising=False)
    res = authmod.create_api_token('alice', 'ci', role='user')
    gen, q = _open_stream(
        api.app, _sse_token(api.anon(), headers={'Authorization': f"Bearer {res['token']}"}))
    try:
        assert not _closes(gen, q)
    finally:
        gen.close()


# --- the live-update socket, over a real server -------------------------------------------

@pytest.fixture
def serve(api, monkeypatch):
    monkeypatch.setattr(rtu, '_held_ws', {}, raising=False)
    ppglobals.ws_clients.clear()
    handler = type('Handler', (app_mod._IdleTimeoutMixin, WSGIHandler), {})
    srv = WSGIServer(('127.0.0.1', 0), api.app, handler_class=handler, spawn=Pool(8),
                     log=None, error_log=None)
    srv.start()
    opened = []

    def connect(sid):
        ws = websocket.create_connection(f'ws://127.0.0.1:{srv.server_port}/api/ws/updates',
                                         timeout=5)
        opened.append(ws)
        ws.send(json.dumps({'session_id': sid}))
        assert json.loads(ws.recv())['type'] == 'connected'
        return ws

    yield connect
    for ws in opened:
        try:
            ws.close()
        except Exception:
            pass
    srv.stop(timeout=2)
    ppglobals.ws_clients.clear()


def _hung_up(ws, within=3):
    ws.settimeout(within)
    end = time.monotonic() + within
    try:
        while time.monotonic() < end:
            if not ws.recv():
                return True
    except Exception as e:
        return not isinstance(e, websocket.WebSocketTimeoutException)
    return False


def test_ending_the_session_hangs_up_its_live_socket(serve, people):
    ws = serve(people['alice_phone'].session_id)

    authmod.invalidate_session(people['alice_phone'].session_id)

    assert _hung_up(ws), 'the live-update socket stayed open after its session ended'


def test_the_socket_of_the_session_that_stays_is_not_touched(serve, people):
    ws = serve(people['alice'].session_id)

    authmod.invalidate_session(people['alice_phone'].session_id)
    gevent.sleep(0.1)

    ws.settimeout(3)
    ws.send(json.dumps({'type': 'ping'}))
    assert json.loads(ws.recv()).get('type') == 'pong'


# --- the handshake reads the account by its own row (#1037) -------------------------------

class _OneShotWs:
    def __init__(self, sid):
        self.sent = []
        self._msgs = [json.dumps({'session_id': sid})]

    def receive(self, timeout=None):
        return self._msgs.pop(0) if self._msgs else None

    def send(self, data):
        self.sent.append(json.loads(data))


def test_an_unreadable_account_gets_no_live_socket(api, people, monkeypatch):
    """The row read failing fell back to load_users().get(name, {}), and {} is a
    default-tenant viewer: every cluster when that tenant has no list."""
    import pegaprox.core.db as dbmod

    real = dbmod.PegaProxDB.get_user

    def boom(self, username):
        if username == 'alice':
            raise RuntimeError('database is locked')
        return real(self, username)

    sid = people['alice'].session_id
    with authmod.sessions_lock:
        # its second factor already judged, so the session itself still validates
        authmod.active_sessions[sid].update(mfa_due=False, mfa_checked_at=time.time())
    monkeypatch.setattr(dbmod.PegaProxDB, 'get_user', boom)
    # the whole-table read of a failing store comes back empty
    monkeypatch.setattr(rt, 'load_users', lambda: {}, raising=False)
    ws = _OneShotWs(sid)
    with api.app.test_request_context('/api/ws/updates'):
        api.app.view_functions['__flask_sock.ws_live_updates'].__wrapped__(ws)

    assert ws.sent and ws.sent[0].get('type') == 'error', ws.sent
    assert not any(m.get('type') == 'connected' for m in ws.sent)
