"""Forwarded writes (#625 v3): a standby hands a write it would refuse to the active,
and the active runs it as the user the standby vouches for.

Runs on the in-process group of tests/test_ha_members.py: a is active, b its standby.
A write sent while the state file is b's reaches a through the real peer route, as a
signed call answered in a context of its own, and a runs it through its own routing
in a context of its own again. The two share the one test database and the one
session store, as everywhere in these tests, so a change is visible at once; what
shows it went through the active is the call in g.calls, the session it ran under and
the audit line it left.

ha._peer_call sends the forward call in chunks, without a Content-Length, and it is
served that way here too.

MK Sep 2026
"""
import base64
import io
import json
import types

import pytest
from flask import Response
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from test_ha_members import (group, _built, _post, _send, _watch, IDS, URLS,  # noqa: F401
                             V2_ACTIVE, V2_STANDBY, V2_STANDBY_PRESENTS)
from test_ha_signed_peers import _sign_as
from test_ha_api import ha_env, _admin, _audit, _Wire, ADMIN_PW  # noqa: F401

FORWARD = '/api/ha/peer/forward'
SNAPSHOT = '/api/ha/peer/snapshot'
CLIENT = '198.51.100.23'
FROM_CLIENT = {'X-Forwarded-For': CLIENT}      # the test client is loopback, a trusted proxy
MB = 1024 * 1024


@pytest.fixture
def fwd(group, monkeypatch):
    """The group with the forward call served in chunks, as ha._peer_call sends it, and
    the pull after a forwarded write run in place: the harness takes turns on one state
    file, so it cannot run beside the request. g.pulls names the instance each run
    started on."""
    g = group
    ha = g.ha
    plain = g._serve

    def serve(to, method, path, body, headers):
        if path != ha.FORWARD_PATH or not body:
            return plain(to, method, path, body, headers)
        with g.at(to):
            env = EnvironBuilder(path=path, method=method, headers=headers, data=body,
                                 base_url='http://localhost').get_environ()
            del env['CONTENT_LENGTH']
            env.update({'HTTP_TRANSFER_ENCODING': 'chunked', 'wsgi.input_terminated': True})
            resp = g.client.open(Request(env))
        return _Wire(resp)
    monkeypatch.setattr(g, '_serve', serve)
    g.pulls = []

    def in_place(fn, name):
        g.pulls.append(g.name())
        fn()
    monkeypatch.setattr(ha, '_in_background', in_place)
    monkeypatch.setattr(ha, '_soon', {'wanted': False, 'running': False})
    return g


@pytest.fixture
def probe(monkeypatch):
    """A loaded plugin whose routes note what reaches them: the request as the route
    sees it, and a file and a plain text answer."""
    import pegaprox.api.plugins as plugins
    seen = []

    def record():
        from flask import g, request
        from pegaprox.core import ha
        seen.append({
            'role': ha.role(), 'method': request.method, 'path': request.path,
            'args': request.args.to_dict(), 'body': request.get_data(),
            'content_type': request.content_type, 'remote_addr': request.remote_addr,
            'origin': request.headers.get('Origin'), 'xhr': request.headers.get('X-Requested-With'),
            'host': request.host, 'user': request.session.get('user'),
            'sid': request.headers.get('X-Session-ID'),
            'mark': request.environ.get(ha.FORWARD_ENVIRON),
            'files': {k: (f.filename, f.read()) for k, f in request.files.items()},
            'form': request.form.to_dict(),
            'outer_g': getattr(g, 'outer_marker', None),
        })
        return {'written': True}

    def download():
        resp = Response(PAYLOAD, mimetype='application/octet-stream')
        resp.headers['Content-Disposition'] = 'attachment; filename="probe.bin"'
        resp.headers['Set-Cookie'] = 'session_id=from-the-active; Path=/'
        resp.headers['X-Probe'] = 'not passed on'
        return resp

    def words():
        return Response('plain words, no JSON', status=202, mimetype='text/plain')

    monkeypatch.setitem(plugins._loaded_plugins, 'probe', types.SimpleNamespace())
    monkeypatch.setitem(plugins._plugin_routes, 'probe',
                        {'record': record, 'download': download, 'words': words})
    return seen


PAYLOAD = bytes(range(256)) * 1024 + b'\r\n--\x00the end'


class _Stream(io.RawIOBase):
    """A request body of `size` zero bytes that counts what was read of it."""

    def __init__(self, size):
        self.left, self.read_bytes = size, 0

    def readable(self):
        return True

    def readinto(self, buf):
        n = min(len(buf), self.left)
        buf[:n] = b'\0' * n
        self.left -= n
        self.read_bytes += n
        return n


def _streamed(g, to, path, headers, stream, length=None):
    """A POST whose body is `stream`: with a Content-Length of `length`, or in chunks."""
    env = EnvironBuilder(path=path, method='POST', base_url='http://localhost',
                         headers=headers).get_environ()
    env['wsgi.input'] = stream
    if length is None:
        env.pop('CONTENT_LENGTH', None)
        env.update({'HTTP_TRANSFER_ENCODING': 'chunked', 'wsgi.input_terminated': True})
    else:
        env['CONTENT_LENGTH'] = str(length)
    with g.at(to):
        return g.client.open(Request(env))


def _forward_calls(g):
    return [c for c in g.calls if c[3] == FORWARD]


def _audit_rows(action):
    from pegaprox.core.db import get_db
    return [dict(r) for r in get_db().conn.cursor().execute(
        'SELECT user, action, details, ip_address FROM audit_log WHERE action = ?', (action,)).fetchall()]


def _forward_sessions():
    import pegaprox.utils.auth as authmod
    return [s for s in authmod.active_sessions.values() if s.get('ha_forward')]


def _envelope(**over):
    from pegaprox.core import ha
    env = {'method': 'PUT', 'path': '/api/user/preferences', 'query': '',
           'content_type': 'application/json',
           'body_b64': base64.b64encode(b'{"theme":"nord"}').decode(),
           'user': 'root', 'client_ip': CLIENT}
    env.update(over)
    if 'sign_in' not in over:
        env['sign_in'] = ha.sign_in_digest(env['user'])
    return env


def _forward_as(g, n, envelope, to='a', headers=None):
    """A forward call `n` signs by hand for `to`, sent with a Content-Length."""
    body = g.ha._wire_body(envelope)
    h = headers or _sign_as(g, n, to, 'POST', FORWARD, body)
    return _send(g, to, h, method='POST', path=FORWARD, body=body)


# --- the way through --------------------------------------------------------------------

def test_a_write_on_the_standby_runs_on_the_active_as_its_user(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    g.calls.clear()
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'}, headers=FROM_CLIENT)
    assert r.status_code == 200, r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    from pegaprox.core.db import get_db
    assert get_db().get_user('root')['theme'] == 'nord'

    # the audit line on the active says where the write came from, and from whom
    row = _audit_rows('user.preferences_updated')[-1]
    assert row['user'] == 'root' and row['ip_address'] == CLIENT
    assert row['details'].endswith(f"(via standby {URLS['b']})"), row['details']
    # the standby syncs at once, after the write and not before it
    assert g.pulls == ['b']
    assert g.calls.index(('b', 'a', 'GET', SNAPSHOT)) > g.calls.index(('b', 'a', 'POST', FORWARD))
    # the session the active ran it under is gone
    assert _forward_sessions() == []


def test_the_active_sees_a_same_origin_browser_call(fwd, seed, probe):
    """The inner call passes the CSRF gate the way the UI's own calls do: with their
    marker and no foreign Origin. The route sees the user, the client address, the
    query and the body the browser sent to the standby."""
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('b'):
        r = admin.post('/api/plugins/probe/api/record?x=1&y=%C3%A4', json={'k': 'v'},
                       headers=FROM_CLIENT)
    assert r.status_code == 200 and r.get_json() == {'written': True}, r.data
    seen = probe[-1]
    assert seen['role'] == 'active'
    assert seen['method'] == 'POST' and seen['path'] == '/api/plugins/probe/api/record'
    assert seen['args'] == {'x': '1', 'y': 'ä'}
    assert json.loads(seen['body']) == {'k': 'v'} and seen['content_type'] == 'application/json'
    assert seen['user'] == 'root' and seen['remote_addr'] == CLIENT
    assert seen['xhr'] == 'XMLHttpRequest' and seen['origin'] is None
    assert seen['mark'] == {'session': seen['sid'], 'via': URLS['b'], 'client_ip': CLIENT}
    # that session is not the browser's, and it is gone once the call is done
    assert seen['sid'] != admin.session_id
    import pegaprox.utils.auth as authmod
    assert seen['sid'] not in authmod.active_sessions

    # counterproof: CSRF is still on for every other call on the active
    with g.at('a'):
        r = g.client.post('/api/plugins/probe/api/record', json={}, base_url='http://localhost',
                          headers={'X-Session-ID': admin.session_id})
    assert r.status_code == 403 and 'CSRF' in r.get_json()['error']
    # and on the peer route itself
    body = g.ha._wire_body(_envelope())
    h = dict(_sign_as(g, 'b', 'a', 'POST', FORWARD, body), **{'Content-Type': 'application/json'})
    with g.at('a'):
        r = g.client.post(FORWARD, data=body, headers=h, base_url='http://localhost')
    assert r.status_code == 403 and 'CSRF' in r.get_json()['error']
    assert len(probe) == 1


def test_a_multipart_upload_over_the_request_cap_reaches_the_route(fwd, seed, probe):
    """12 MB: past the 10 MB the app takes with a Content-Length on any route but an
    upload, and its envelope (16 MB of base64) past it as well. The standby takes it on
    the upload route; the envelope goes in chunks and meets the forward route's cap."""
    g = fwd
    admin = _built(g, seed, 'b')
    mgr = g.api.make_fake_manager('c1', cluster_type='xcpng')
    mgr.is_connected = True
    got = {}

    def upload(node, storage, filename, stream, content):
        got.update(node=node, storage=storage, filename=filename, data=stream.read(), content=content)
        return {'success': True, 'upid': 'UPID:n1:1'}
    mgr.upload_to_storage.side_effect = upload
    g.api.set_manager('c1', mgr)
    payload = bytes(range(256)) * (48 * 1024) + b'tail'
    assert len(payload) > 12 * MB
    with g.at('b'):
        r = admin.post('/api/clusters/c1/datastores/local/upload', content_type='multipart/form-data',
                       data={'file': (io.BytesIO(payload), 'small.iso'), 'content': 'iso', 'node': 'n1'})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'upid': 'UPID:n1:1'}
    assert got['data'] == payload
    assert (got['node'], got['storage'], got['filename'], got['content']) == ('n1', 'local', 'small.iso', 'iso')
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]


def test_with_a_content_length_the_envelope_meets_the_app_cap(fwd, seed):
    """Why the forward call goes in chunks: the same envelope with a Content-Length is
    stopped by the app's size check before any route has seen it."""
    g = fwd
    _built(g, seed, 'b')
    big = _envelope(body_b64=base64.b64encode(b'{"theme":"nord"}' + b' ' * (9 * MB)).decode())
    r = _forward_as(g, 'b', big)
    assert r.status_code == 413, r.data


def test_the_forward_call_goes_out_in_chunks(monkeypatch):
    import requests
    import pegaprox.utils.url_security as urlsec
    from pegaprox.core import ha
    monkeypatch.setattr(urlsec, 'is_safe_outbound_url', lambda *a, **k: (True, ''))
    sent = []

    def capture(self, method, url, **kw):
        sent.append(kw)
        return types.SimpleNamespace(status_code=200, headers={})
    monkeypatch.setattr(requests.Session, 'request', capture)
    envelope = _envelope(body_b64='A' * (3 * MB))
    ha._peer_call('POST', 'https://10.0.0.5:5000', '', ha.FORWARD_PATH, json_body=envelope)
    data = sent[0]['data']
    assert not isinstance(data, (bytes, bytearray, str))
    assert b''.join(data) == ha._wire_body(envelope)
    # every other peer call keeps its Content-Length
    ha._peer_call('POST', 'https://10.0.0.5:5000', '', '/api/ha/peer/step-down', json_body={'epoch': 1})
    assert sent[1]['data'] == b'{"epoch":1}'


def test_a_file_and_a_plain_answer_come_back_as_they_were(fwd, seed, probe):
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('b'):
        r = admin.post('/api/plugins/probe/api/download', json={})
    assert r.status_code == 200, r.data
    assert r.get_data() == PAYLOAD
    assert r.headers['Content-Type'] == 'application/octet-stream'
    assert r.headers['Content-Disposition'] == 'attachment; filename="probe.bin"'
    # nothing else of the active's answer: no cookie of its session, no header of its own
    assert 'Set-Cookie' not in r.headers and 'X-Probe' not in r.headers

    with g.at('b'):
        r = admin.post('/api/plugins/probe/api/words', json={})
    assert r.status_code == 202 and r.get_data() == b'plain words, no JSON'
    assert r.headers['Content-Type'].startswith('text/plain')


def test_a_route_that_asks_for_the_password_gets_it_from_the_body(fwd, seed):
    """The config backup checks the account password again, on the active against its
    own users table, and answers with a file."""
    g = fwd
    admin = _built(g, seed, 'b')
    g.pulls.clear()
    with g.at('b'):
        r = admin.post('/api/config/backup', json={'user_password': 'wrong', 'backup_password': 'long-enough'})
    assert r.status_code == 401 and r.get_json()['error'] == 'Incorrect password'
    assert g.pulls == []          # nothing went through, nothing to pull
    assert _audit_rows('config.backup_failed')[-1]['details'].endswith(f"(via standby {URLS['b']})")

    with g.at('b'):
        r = admin.post('/api/config/backup', json={'user_password': ADMIN_PW, 'backup_password': 'long-enough'})
    assert r.status_code == 200, r.data
    assert r.headers['Content-Type'] == 'application/octet-stream'
    assert r.headers['Content-Disposition'].startswith('attachment; filename=pegaprox-backup-')
    assert len(r.get_data()) > 100
    assert g.pulls == ['b']


# --- who decides --------------------------------------------------------------------------

def test_the_rights_are_the_actives(fwd, seed):
    """The envelope names the user and nothing about their rights. A viewer stays a
    viewer, whatever the standby's session says or an envelope adds."""
    g = fwd
    _built(g, seed, 'b')
    seed.user('vic', role='viewer')
    vic = g.api.as_user({'username': 'vic', 'role': 'admin'})     # the standby's session says admin
    from pegaprox.core.db import get_db
    with g.at('b'):
        r = vic.post('/api/users', json={'username': 'newbie', 'password': 'Longer-Pa55word!', 'role': 'admin'})
    assert r.status_code == 403, r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert get_db().get_user('newbie') is None

    body = base64.b64encode(json.dumps({'username': 'newbie', 'password': 'Longer-Pa55word!',
                                        'role': 'admin'}).encode()).decode()
    r = _forward_as(g, 'b', _envelope(method='POST', path='/api/users', body_b64=body, user='vic',
                                      role='admin', permissions=['admin.users']))
    assert r.status_code == 200, r.data
    assert r.get_json()['status'] == 403
    assert get_db().get_user('newbie') is None


def test_an_account_the_active_does_not_know_or_has_disabled_is_refused(fwd, seed):
    g = fwd
    _built(g, seed, 'b')
    seed.user('eve', role='admin')
    eve = g.api.as_user({'username': 'eve', 'role': 'admin'})
    from pegaprox.core.db import get_db
    db = get_db()
    row = db.get_user('eve')
    row['enabled'] = False
    db.save_user('eve', row)
    # the standby still holds her session; the active says no
    with g.at('b'):
        r = eve.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_FORWARD_USER', r.data
    assert db.get_user('eve').get('theme') != 'nord'

    r = _forward_as(g, 'b', _envelope(user='nobody'))
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_FORWARD_USER'
    assert _forward_sessions() == []


@pytest.mark.parametrize('change,why', [
    ({'path': '/api/ha/promote'}, 'path'),
    ({'path': '/api/ha/peer/step-down', 'method': 'POST'}, 'path'),
    ({'path': '/api/ha/../users'}, 'path'),
    ({'path': '/login'}, 'path'),
    ({'path': '/api/users\r\nX-Evil: 1'}, 'path'),
    ({'method': 'GET', 'body_b64': ''}, 'progress of a job'),
    ({'method': 'OPTIONS'}, 'method'),
    ({'sign_in': 'x' * 64}, 'sign_in'),
    ({'sign_in': None}, 'sign_in'),
    ({'client_ip': 'somewhere'}, 'client_ip'),
    ({'body_b64': 'not base64!'}, 'body_b64'),
    ({'user': ''}, 'user'),
    ({'user': ['root']}, 'user'),
    ({'content_type': 'application/json\r\nX-Evil: 1'}, 'content_type'),
])
def test_the_active_refuses_what_is_not_a_forwardable_write(fwd, seed, change, why):
    g = fwd
    _built(g, seed, 'b')
    r = _forward_as(g, 'b', _envelope(**change))
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_FORWARD_INVALID', r.data
    assert why in r.get_json()['error']
    assert _forward_sessions() == []


def test_the_envelope_is_covered_by_the_signature(fwd, seed):
    g = fwd
    _built(g, seed, 'b')
    seed.user('mallory', role='admin')
    body = g.ha._wire_body(_envelope(user='vic'))
    headers = _sign_as(g, 'b', 'a', 'POST', FORWARD, body)
    # another user, or another request, under the same signature: nobody's call
    for other in (_envelope(user='mallory'), _envelope(path='/api/users/vic')):
        r = _send(g, 'a', headers, method='POST', path=FORWARD, body=g.ha._wire_body(other))
        assert r.status_code == 401 and r.get_json()['error'] == 'Not the paired instance'
    # the call as signed is taken once (vic is unknown here), and not a second time
    r = _send(g, 'a', headers, method='POST', path=FORWARD, body=body)
    assert r.status_code == 403 and r.get_json()['code'] == 'HA_FORWARD_USER'
    r = _send(g, 'a', headers, method='POST', path=FORWARD, body=body)
    assert r.status_code == 401
    # nobody at all
    assert _send(g, 'a', {}, method='POST', path=FORWARD, body=body).status_code == 401


def test_a_removed_member_and_an_unsigned_one_are_refused(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'bc')
    with g.at('a'):
        r = _post(admin, f"/api/ha/members/{IDS['c']}/remove", {'confirm': 'REMOVE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    r = _forward_as(g, 'c', _envelope())
    assert r.status_code == 410 and r.get_json()['code'] == 'HA_REMOVED'

    # a pair from before the keys: the old secret alone signs nothing, the body included
    g.write('a', json.loads(json.dumps(V2_ACTIVE)))
    g.write('b', json.loads(json.dumps(V2_STANDBY)))
    r = _forward_as(g, 'b', _envelope(), headers={g.ha.PEER_HEADER: f"{IDS['b']}:{V2_STANDBY_PRESENTS}"})
    assert r.status_code == 401 and r.get_json()['code'] == 'HA_FORWARD_UNSIGNED', r.data
    assert _forward_sessions() == []


def test_a_pair_from_before_the_keys_forwards_once_the_key_travels(fwd, seed):
    """The standby of a v2 pair sends its key along with the secret and signs the call;
    the active takes the key from its pair partner, and the write goes through."""
    g = fwd
    admin = _admin(g.api, seed)
    g.write('a', json.loads(json.dumps(V2_ACTIVE)))
    g.write('b', json.loads(json.dumps(V2_STANDBY)))
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 200, r.data
    assert g.state('a')['members'][IDS['b']]['public_key']


# --- when it does not go ---------------------------------------------------------------------

def test_an_api_token_write_stays_refused(fwd, seed):
    from pegaprox.utils.auth import create_api_token
    g = fwd
    admin = _built(g, seed, 'b')
    res = create_api_token('root', 'automation', role='admin')
    assert res.get('success'), res
    token = {'Authorization': f"Bearer {res['token']}"}
    g.calls.clear()
    with g.at('b'):
        r = g.api.anon().put('/api/user/preferences', json={'theme': 'nord'}, headers=token)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
        # a session beside the token does not make it the session's call
        r = admin.put('/api/user/preferences', json={'theme': 'nord'}, headers=token)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
        # and no session at all is nobody to vouch for
        r = g.api.anon().put('/api/user/preferences', json={'theme': 'nord'})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert _forward_calls(g) == [] and g.pulls == []


def test_with_forwarding_off_the_standby_refuses_as_before(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('b') as ha:
        assert admin.get('/api/ha/status').get_json()['forwarding'] is True
        assert admin.get('/api/auth/check').get_json()['ha']['forwarding'] is True
        r = admin.put('/api/ha/settings', json={'forward_writes': 'no'})
        assert r.status_code == 400
        r = admin.put('/api/ha/settings', json={'forward_writes': False})
        assert r.status_code == 200 and r.get_json() == {'success': True, 'forward_writes': False}
        assert ha.forward_writes() is False
    assert g.file('b')['forward_writes'] is False
    assert _audit('ha.settings_changed')[-1]['details'] == 'forwarding writes to the active instance off'
    g.calls.clear()
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        status = admin.get('/api/ha/status').get_json()
        assert status['forwarding'] is False and status['forward_writes'] is False
        assert admin.get('/api/auth/check').get_json()['ha']['forwarding'] is False
    assert _forward_calls(g) == []

    # on again, and a source that has not answered as active is not written to either
    with g.at('b') as ha:
        assert admin.put('/api/ha/settings', json={'forward_writes': True}).status_code == 200
        assert admin.put('/api/user/preferences', json={'theme': 'dracula'}).status_code == 200
        ms = ha._load()['members']
        ha._update(members=dict(ms, **{IDS['a']: dict(ms[IDS['a']], role_seen='standby')}))
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        assert admin.get('/api/ha/status').get_json()['forwarding'] is False
    assert len(_forward_calls(g)) == 1


def test_an_active_says_it_forwards_nothing(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('a'):
        status = admin.get('/api/ha/status').get_json()
        assert status['forwarding'] is False and status['forward_writes'] is True
        assert admin.get('/api/auth/check').get_json()['ha'] == {'role': 'active'}


def test_the_console_token_is_not_forwarded(fwd, seed):
    from pegaprox.globals import ws_tokens
    g = fwd
    admin = _built(g, seed, 'b')
    before = set(ws_tokens)
    g.calls.clear()
    with g.at('b'):
        r = admin.post('/api/ws/token', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert _forward_calls(g) == [] and set(ws_tokens) == before


def test_a_plugin_is_read_on_the_active(fwd, seed, probe):
    """A plugin handler serves every method from one function, so a GET of a plugin may
    write as well: a forwarding standby runs none of it, it reads it from the active."""
    g = fwd
    admin = _built(g, seed, 'b')
    g.calls.clear()
    with g.at('b'):
        r = admin.get('/api/plugins/probe/api/record?x=1', headers=FROM_CLIENT)
    assert r.status_code == 200 and r.get_json() == {'written': True}, r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert len(probe) == 1
    seen = probe[0]
    assert (seen['role'], seen['method'], seen['args'], seen['body']) == ('active', 'GET', {'x': '1'}, b'')
    assert seen['mark']['via'] == URLS['b'] and seen['remote_addr'] == CLIENT
    # a read: no sync after it
    assert g.pulls == []
    # counterproof: on the active the same call runs in place, nothing is forwarded
    g.calls.clear()
    with g.at('a'):
        assert admin.get('/api/plugins/probe/api/record').status_code == 200
    assert _forward_calls(g) == [] and probe[-1]['role'] == 'active' and probe[-1]['mark'] is None


def test_a_plugin_read_the_active_does_not_answer_is_refused(fwd, seed, probe):
    """Forwarding off, the active gone, an API token or HEAD: 409 as before, and the
    plugin does not run here instead."""
    from pegaprox.utils.auth import create_api_token
    g = fwd
    admin = _built(g, seed, 'b')
    token = {'Authorization': f"Bearer {create_api_token('root', 'automation', role='admin')['token']}"}
    g.calls.clear()
    with g.at('b') as ha:
        for call in (lambda: g.api.anon().get('/api/plugins/probe/api/record', headers=token),
                     lambda: admin._call('head', '/api/plugins/probe/api/record', False)):
            r = call()
            assert r.status_code == 409, r.data
        ha.set_forward_writes(False)
        r = admin.get('/api/plugins/probe/api/record')
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        ha.set_forward_writes(True)
    assert _forward_calls(g) == [] and probe == []
    g.down.add('a')
    with g.at('b'):
        r = admin.get('/api/plugins/probe/api/record')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert probe == []
    # counterproof: back, and it is read there again
    g.down.discard('a')
    _watch(g, 'b')
    with g.at('b'):
        assert admin.get('/api/plugins/probe/api/record').status_code == 200
    assert [s['role'] for s in probe] == ['active']


def test_the_active_reads_a_plugin_but_opens_no_console_for_a_standby(fwd, seed, probe, monkeypatch):
    import pegaprox.api.plugins as plugins
    g = fwd
    admin = _built(g, seed, 'b')
    opened = []
    monkeypatch.setitem(plugins._plugin_routes, 'probe', dict(
        plugins._plugin_routes['probe'], **{'vm/console': lambda: opened.append(1) or {'ticket': 'x'}}))
    r = _forward_as(g, 'b', _envelope(method='GET', path='/api/plugins/probe/api/vm/console', body_b64=''))
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_FORWARD_INVALID', r.data
    assert opened == []
    # counterproof: the plugin's other routes are read there, and the console opens on
    # the active for its own browsers
    r = _forward_as(g, 'b', _envelope(method='GET', path='/api/plugins/probe/api/record', body_b64=''))
    assert r.status_code == 200 and r.get_json()['status'] == 200
    assert probe[-1]['role'] == 'active'
    with g.at('a'):
        assert admin.get('/api/plugins/probe/api/vm/console').status_code == 200
    assert opened == [1]


def test_when_the_active_cannot_be_reached(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    g.down.add('a')
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 503
    assert r.get_json() == {'code': 'HA_ACTIVE_UNREACHABLE',
                            'error': 'The active instance cannot be reached - act again once it is '
                                     'back, or promote this standby'}
    assert g.pulls == []

    # until the active answers again the standby is read-only, and says so: a write does
    # not wait for the network, the banner and the status say forwarding is off
    g.calls.clear()
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        assert admin.get('/api/auth/check').get_json()['ha']['forwarding'] is False
        status = admin.get('/api/ha/status').get_json()
        assert status['forwarding'] is False and status['forward_writes'] is True
    assert _forward_calls(g) == []
    # a watch that still cannot reach it changes nothing; one that does, ends it
    assert _watch(g, 'b') is not None
    with g.at('b') as ha:
        assert ha.forwarding() is False
    g.down.discard('a')
    _watch(g, 'b')
    with g.at('b') as ha:
        assert ha.forwarding() is True
        assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200


def test_a_pull_that_reaches_the_active_resumes_forwarding(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    g.down.add('a')
    with g.at('b') as ha:
        assert ha.pull_once() == 'failed'
        assert ha.forwarding() is False
    g.down.discard('a')
    with g.at('b') as ha:
        assert ha.pull_once() in ('applied', 'unchanged')
        assert ha.forwarding() is True
    # counterproof: an answer that refuses is still an answer
    with g.at('b') as ha:
        ha._note_source_heard(IDS['a'], False)
        assert ha.forwarding() is False


def test_no_answer_after_the_call_went_out_is_not_unreachable(fwd, seed, monkeypatch):
    """The active took the call and sent nothing back in time: the write may have
    happened there. The browser hears that, not 'act again or promote', and the
    standby keeps forwarding - the active is not gone."""
    g = fwd
    admin = _built(g, seed, 'b')
    plain = g.call

    def call(method, base_url, fingerprint, path, *a, **kw):
        if path == FORWARD:
            raise g.ha.PeerNoAnswer('The peer took the call but sent no answer: ReadTimeout')
        return plain(method, base_url, fingerprint, path, *a, **kw)
    monkeypatch.setattr(g.ha, '_peer_call', call)
    with g.at('b') as ha:
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
        assert r.status_code == 504, r.data
        assert r.get_json() == {'code': 'HA_FORWARD_NO_ANSWER',
                                'error': 'The active instance took the change but did not answer '
                                         'in time - it may still be carrying it out. Check there '
                                         'before you try again'}
        assert ha.forwarding() is True
    assert g.pulls == []


def test_the_forward_call_waits_long_for_the_answer_and_briefly_for_the_connection(fwd, seed, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    seen = []
    plain = g.call

    def call(method, base_url, fingerprint, path, *a, **kw):
        if path == FORWARD:
            seen.append(kw.get('timeout'))
        return plain(method, base_url, fingerprint, path, *a, **kw)
    monkeypatch.setattr(g.ha, '_peer_call', call)
    with g.at('b'):
        assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
    assert seen == [(15, 900)]


@pytest.mark.parametrize('raised,expect', [
    ('read_timeout', 'no_answer'),
    ('chunked', 'no_answer'),
    ('aborted', 'no_answer'),
    ('refused', 'unreachable'),
    ('connect_timeout', 'unreachable'),
])
def test_what_the_transport_says_decides_unreachable_or_no_answer(monkeypatch, raised, expect):
    import requests
    import urllib3
    from pegaprox.core import ha
    errors = {
        'read_timeout': requests.exceptions.ReadTimeout('read timed out'),
        'chunked': requests.exceptions.ChunkedEncodingError('broken'),
        'aborted': requests.exceptions.ConnectionError(
            urllib3.exceptions.ProtocolError('Connection aborted.', ConnectionResetError())),
        'refused': requests.exceptions.ConnectionError(
            urllib3.exceptions.MaxRetryError(None, '/', 'Failed to establish a new connection')),
        'connect_timeout': requests.exceptions.ConnectTimeout('connect timed out'),
    }

    def boom(self, *a, **kw):
        raise errors[raised]
    monkeypatch.setattr(requests.Session, 'request', boom)
    with pytest.raises(ha.PeerUnreachable) as e:
        ha._peer_call('POST', 'https://127.0.0.1:9', '', FORWARD, json_body={'x': 1})
    assert isinstance(e.value, ha.PeerNoAnswer) is (expect == 'no_answer')


def test_one_user_gets_a_share_of_the_forwarding(fwd, seed, monkeypatch):
    import pegaprox.api.ha as ha_api
    from pegaprox.utils.ratelimit import SlidingWindow
    g = fwd
    admin = _built(g, seed, 'b')
    monkeypatch.setattr(ha_api, '_forward_per_user', SlidingWindow(limit=2, window=60, name='t'))
    seed.user('ops', role='admin')
    ops = g.api.as_user({'username': 'ops', 'role': 'admin'})
    g.calls.clear()
    with g.at('b'):
        for _ in range(2):
            assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
        assert r.status_code == 429 and r.headers['Retry-After'] == '60'
        # another user has a share of their own
        assert ops.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
    assert len(_forward_calls(g)) == 3


def test_large_bodies_wait_for_a_slot(fwd, seed, probe, monkeypatch):
    import threading
    import pegaprox.api.ha as ha_api
    g = fwd
    admin = _built(g, seed, 'b')
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(ha_api, '_forward_large_slots', slots)
    big = json.dumps({'blob': 'x' * (2 * MB)})
    with g.at('b'):
        assert slots.acquire(blocking=False)     # another large one is on its way
        r = admin.post('/api/plugins/probe/api/record', data=big, content_type='application/json')
        assert r.status_code == 503 and r.get_json()['code'] == 'HA_FORWARD_BUSY', r.data
        assert r.headers['Retry-After'] == '10'
        # a small one does not need a slot
        r = admin.post('/api/plugins/probe/api/record', json={'small': True})
        assert r.status_code == 200, r.data
        slots.release()
        # and a slot is given back after use
        for _ in range(2):
            r = admin.post('/api/plugins/probe/api/record', data=big, content_type='application/json')
            assert r.status_code == 200, r.data
    assert [len(x['body']) for x in probe] == [len(b'{"small": true}'), len(big), len(big)]


@pytest.mark.parametrize('xff,want', [
    ('198.51.100.23:5555', '198.51.100.23'),
    ('[2001:db8::1]:443', '2001:db8::1'),
    ('2001:db8::7', '2001:db8::7'),
    ('unknown', '127.0.0.1'),
])
def test_the_client_address_travels_as_an_address(fwd, seed, probe, xff, want):
    """A trusted proxy may hand on a port with the address, or no address at all; the
    active takes only an address. What cannot be read as one is the address the
    call came from."""
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('b'):
        r = admin.post('/api/plugins/probe/api/record', json={}, headers={'X-Forwarded-For': xff})
    assert r.status_code == 200, r.data
    assert probe[-1]['remote_addr'] == want


def test_a_path_no_route_serves_is_not_forwarded(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    g.calls.clear()
    with g.at('b'):
        r = admin.post('/api/nothing/here', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert _forward_calls(g) == []


def test_a_forwarded_session_rotates_no_session_out_and_is_never_saved(ha_env, seed, monkeypatch):
    import pegaprox.utils.auth as authmod
    from pegaprox.utils.auth import open_forwarded_session, end_forwarded_session, create_session
    api = ha_env.api
    seed.user('root', role='admin')
    own = [api.as_user({'username': 'root', 'role': 'admin'}).session_id for _ in range(2)]
    sid = open_forwarded_session('root', 'admin', CLIENT, URLS['b'])
    saved = {}
    monkeypatch.setattr(authmod, 'get_db', lambda: types.SimpleNamespace(save_all_sessions=saved.update))
    try:
        with api.app.test_request_context('/'):
            new = create_session('root', 'admin')
        # a sign-in on the active while a forwarded write runs keeps both own sessions
        assert all(s in authmod.active_sessions for s in own + [new])
        authmod._real_save_sessions()
        assert sid not in saved and new in saved
    finally:
        end_forwarded_session(sid)


def test_a_body_over_50_mb_is_refused_on_the_standby_unread(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')

    def upload(stream, length):
        return _streamed(g, 'b', '/api/clusters/c1/datastores/local/upload',
                         {'X-Session-ID': admin.session_id, 'Origin': 'http://localhost',
                          'X-Requested-With': 'XMLHttpRequest',
                          'Content-Type': 'multipart/form-data; boundary=x'}, stream, length)

    size = 60 * MB
    stream = _Stream(size)
    r = upload(stream, size)
    assert r.status_code == 413 and r.get_json()['code'] == 'HA_FORWARD_TOO_LARGE', r.data
    assert stream.read_bytes == 0
    # without a length it is read up to the cap and no further
    stream = _Stream(size)
    r = upload(stream, None)
    assert r.status_code == 413 and r.get_json()['code'] == 'HA_FORWARD_TOO_LARGE', r.data
    assert stream.read_bytes <= 50 * MB + 64 * 1024
    assert _forward_calls(g) == []

    # counterproof: with forwarding off it is the block's answer, as before
    with g.at('b') as ha:
        ha.set_forward_writes(False)
    stream = _Stream(size)
    r = upload(stream, size)
    assert r.status_code == 409 and stream.read_bytes == 0


# --- no loops ---------------------------------------------------------------------------------

def _stepped_down(g, name='a', follows='b'):
    """`name` is a standby now that follows `follows`, and would forward to it."""
    with g.at(name) as ha:
        st = ha._load()
        ms = dict(st['members'])
        ms[IDS[follows]] = dict(ms[IDS[follows]], role_seen='active')
        ha._update(role='standby', source=IDS[follows], members=ms)


def test_an_instance_that_stepped_down_answers_409(fwd, seed):
    g = fwd
    admin = _built(g, seed, 'b')
    _stepped_down(g)
    g.calls.clear()
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert g.pulls == []
    # the route says no by itself: a standby would run what it lets through locally
    r = _forward_as(g, 'b', _envelope(method='POST', path='/api/sse/token',
                                      body_b64=base64.b64encode(b'{}').decode()))
    assert r.status_code == 409, r.data
    assert r.get_json() == {'code': 'HA_STANDBY', 'error': 'This instance is not active'}
    assert _forward_sessions() == []


def test_a_forwarded_write_goes_no_further(fwd, seed, monkeypatch):
    """a steps down between taking the call and running it: the call meets the write
    block of a standby, which answers it as a standby and hands it on to nobody."""
    import pegaprox.api.ha as ha_api
    g = fwd
    admin = _built(g, seed, 'b')
    real = ha_api._run_forwarded

    def step_down_first(*a, **kw):
        _stepped_down(g)
        with g.at('a') as ha:
            assert ha.forwarding()          # it would forward, if the call were anybody's
        return real(*a, **kw)
    monkeypatch.setattr(ha_api, '_run_forwarded', step_down_first)
    g.calls.clear()
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert _forward_sessions() == []


# --- the pull and the session ------------------------------------------------------------------

def test_writes_close_together_share_the_pulls(monkeypatch):
    from pegaprox.core import ha
    runs, pulls = [], []
    monkeypatch.setattr(ha, '_in_background', lambda fn, name: runs.append(fn))
    monkeypatch.setattr(ha, '_soon', {'wanted': False, 'running': False})
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'peer', lambda: {'instance_id': 'a' * 32})
    monkeypatch.setattr(ha, 'pull_once', lambda timeout: pulls.append(timeout) or 'applied')

    assert ha.pull_soon() is True
    assert ha.pull_soon() is False and ha.pull_soon() is False
    assert len(runs) == 1
    runs[0]()
    assert pulls == [ha.PULL_TIMEOUT_FLOOR]

    # a write while the pull runs gets one more pull after it
    def pull(timeout):
        pulls.append(timeout)
        if len(pulls) == 2:
            assert ha.pull_soon() is False
        return 'applied'
    monkeypatch.setattr(ha, 'pull_once', pull)
    assert ha.pull_soon() is True
    runs[-1]()
    assert len(pulls) == 3 and len(runs) == 2
    # the run is over: the next write starts a new one
    assert ha.pull_soon() is True and len(runs) == 3

    # a run that dies halfway does not keep the next ones from starting
    monkeypatch.setattr(ha, '_soon', {'wanted': False, 'running': False})

    def killed(timeout):
        raise KeyboardInterrupt
    monkeypatch.setattr(ha, 'pull_once', killed)
    assert ha.pull_soon() is True
    with pytest.raises(KeyboardInterrupt):
        runs[-1]()
    assert ha.pull_soon() is True


def test_the_forwarded_session_holds_inside_its_request_only(ha_env, seed):
    import pegaprox.utils.auth as authmod
    from pegaprox.core import ha
    from pegaprox.utils.auth import open_forwarded_session, end_forwarded_session, validate_session
    api = ha_env.api
    seed.user('root', role='admin')
    own = [api.as_user({'username': 'root', 'role': 'admin'}).session_id for _ in range(3)]
    sid = open_forwarded_session('root', 'admin', CLIENT, URLS['b'])
    # the user's own sessions are all still there: it rotates none of them out
    assert all(s in authmod.active_sessions for s in own)
    base = {'REMOTE_ADDR': CLIENT}
    with api.app.test_request_context('/', environ_base=base):
        assert validate_session(sid) is None
    with api.app.test_request_context('/', environ_base=dict(base, **{ha.FORWARD_ENVIRON: {'session': 'other'}})):
        assert validate_session(sid) is None
    with api.app.test_request_context('/', environ_base=dict(base, **{ha.FORWARD_ENVIRON: {'session': sid}})):
        assert validate_session(sid)['user'] == 'root'
        # the user's own session is still an ordinary one there
        assert validate_session(own[0])['user'] == 'root'
    end_forwarded_session(sid)
    assert sid not in authmod.active_sessions
    with api.app.test_request_context('/', environ_base=dict(base, **{ha.FORWARD_ENVIRON: {'session': sid}})):
        assert validate_session(sid) is None


def test_the_audit_says_nothing_extra_elsewhere(ha_env, seed):
    """Counterproof to the via-standby note: an ordinary write logs as it did."""
    admin = ha_env.api.as_user(seed.user('root', role='admin'))
    r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 200, r.data
    assert 'via standby' not in _audit_rows('user.preferences_updated')[-1]['details']


# --- the edges of the way through --------------------------------------------------------

def test_the_inner_call_has_a_context_of_its_own(fwd, seed, probe, monkeypatch):
    """flask.g of the peer call does not reach the route the call runs."""
    import pegaprox.api.ha as ha_api
    from flask import g as flask_g
    g = fwd
    admin = _built(g, seed, 'b')
    real = ha_api._run_forwarded

    def marked(*a, **kw):
        flask_g.outer_marker = 'from the peer call'
        return real(*a, **kw)
    monkeypatch.setattr(ha_api, '_run_forwarded', marked)
    with g.at('b'):
        assert admin.post('/api/plugins/probe/api/record', json={}).status_code == 200
    assert probe[-1]['outer_g'] is None and probe[-1]['user'] == 'root'


def test_the_active_hands_back_only_the_content_headers(fwd, seed, probe):
    g = fwd
    _built(g, seed, 'b')
    r = _forward_as(g, 'b', _envelope(method='POST', path='/api/plugins/probe/api/download',
                                      body_b64=base64.b64encode(b'{}').decode()))
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['status'] == 200
    assert body['headers'] == {'Content-Type': 'application/octet-stream',
                               'Content-Disposition': 'attachment; filename="probe.bin"'}
    assert base64.b64decode(body['body_b64']) == PAYLOAD


def test_the_standby_reads_only_a_well_formed_answer():
    import pegaprox.api.ha as ha_api

    def answer(data):
        return types.SimpleNamespace(json=lambda: data)
    good = {'status': 201, 'body_b64': base64.b64encode(b'a,b').decode(),
            'headers': {'Content-Type': 'text/csv', 'Set-Cookie': 'session_id=x',
                        'Content-Disposition': 'attachment\r\nX-Evil: 1', 'Retry-After': '5'}}
    assert ha_api._forwarded_answer(answer(good)) == (
        201, [('Content-Type', 'text/csv'), ('Retry-After', '5')], b'a,b')
    for bad in (None, [], {}, dict(good, status='201'), dict(good, status=True),
                dict(good, status=99), dict(good, headers=[]), dict(good, body_b64='%%')):
        assert ha_api._forwarded_answer(answer(bad)) is None, bad


def test_an_answer_too_large_to_hand_back(fwd, seed, probe, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    monkeypatch.setattr(g.ha, 'FORWARD_MAX_BODY', 64 * 1024)
    assert len(PAYLOAD) > 64 * 1024
    with g.at('b'):
        r = admin.post('/api/plugins/probe/api/download', json={})
    assert r.status_code == 502 and 'answer is too large' in r.get_json()['error'], r.data


def test_a_413_from_the_active_reaches_the_browser(fwd, seed, monkeypatch):
    """A proxy in front of the active that buffers the chunks sends them on with a
    Content-Length, and the active's size check stops a large one. The browser hears
    413, not a gateway error."""
    g = fwd
    admin = _built(g, seed, 'b')
    monkeypatch.setattr(g, '_serve', types.MethodType(type(g)._serve, g))
    mgr = g.api.make_fake_manager('c1', cluster_type='xcpng')
    mgr.is_connected = True
    g.api.set_manager('c1', mgr)
    with g.at('b'):
        r = admin.post('/api/clusters/c1/datastores/local/upload', content_type='multipart/form-data',
                       data={'file': (io.BytesIO(b'\0' * (11 * MB)), 'small.iso'), 'node': 'n1'})
    assert r.status_code == 413 and r.get_json()['code'] == 'HA_FORWARD_TOO_LARGE', r.data
    assert not mgr.upload_to_storage.called


def test_an_active_that_refuses_the_call_is_a_gateway_error(fwd, seed, monkeypatch):
    g = fwd
    admin = _built(g, seed, 'b')
    # an active on a release without the route
    monkeypatch.setattr(g.ha, 'FORWARD_PATH', '/api/ha/peer/forward-of-a-later-release')
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 502 and r.get_json()['code'] == 'HA_FORWARD_REFUSED', r.data
    assert 'release' in r.get_json()['error']
    monkeypatch.setattr(g.ha, 'FORWARD_PATH', FORWARD)
    # an active that does not know our key: its refusal, as a gateway error and not as
    # a 401 the browser would take for its own session
    with g.at('a') as ha:
        ms = ha._load()['members']
        ha._update(members=dict(ms, **{IDS['b']: {k: v for k, v in ms[IDS['b']].items() if k != 'public_key'}}))
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 502 and r.get_json() == {'code': 'HA_FORWARD_REFUSED',
                                                     'error': 'Not the paired instance'}, r.data
    assert g.pulls == []


def test_an_answer_the_standby_cannot_read_is_a_gateway_error(fwd, seed, monkeypatch):
    import pegaprox.api.ha as ha_api
    g = fwd
    admin = _built(g, seed, 'b')
    monkeypatch.setattr(ha_api, '_forwarded_answer', lambda resp: None)
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 502 and r.get_json()['code'] == 'HA_FORWARD_REFUSED', r.data
    assert 'does not read' in r.get_json()['error'] and g.pulls == []


def _signed_for_body(g, n, to, body, **kw):
    """_sign_as with the digest header a member sends along, over `body`."""
    import hashlib
    h = _sign_as(g, n, to, 'POST', FORWARD, body, **kw)
    h[g.ha.PEER_BODY_HEADER] = hashlib.sha256(body).hexdigest()
    return h


def test_a_large_body_is_read_only_behind_a_signed_header(fwd, seed):
    """The forward route reads an upload's worth only once the headers carry a good
    signature of a member, over the digest of the body to come. A member id is easy
    to learn (a refused peer call names the instance), so naming one is not enough."""
    g = fwd
    _built(g, seed, 'b')
    h = {'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/json'}
    zeros = b'\0' * (5 * MB)

    def read(headers, to='a'):
        stream = _Stream(5 * MB)
        r = _streamed(g, to, FORWARD, dict(h, **headers), stream)
        return r, stream.read_bytes

    # a stranger, a member's id without a signature over a digest, a digest signed with
    # another key, a digest from outside the window: a peer call's worth, then 401
    for headers in ({g.ha.PEER_HEADER: 'e' * 32},
                    {g.ha.PEER_HEADER: IDS['b']},
                    _sign_as(g, 'b', 'a', 'POST', FORWARD, zeros),
                    _signed_for_body(g, 'b', 'a', zeros, key_of='a'),
                    _signed_for_body(g, 'b', 'a', zeros, ts=1)):
        r, got = read(headers)
        assert r.status_code == 401 and got <= 64 * 1024, (headers, r.status_code, got)

    # the member's own signature over this body: read whole, and taken (it is no
    # envelope, so the route says so)
    r, got = read(_signed_for_body(g, 'b', 'a', zeros))
    assert got == 5 * MB and r.status_code == 400, r.data
    # signed over another body: read, and then refused like any bad signature
    r, got = read(_signed_for_body(g, 'b', 'a', b'{}'))
    assert got == 5 * MB and r.status_code == 401
    # a standby takes no forwarded write, so it reads none either
    r, got = read(_signed_for_body(g, 'a', 'b', zeros), to='b')
    assert got <= 64 * 1024 and r.status_code == 401


def test_the_signed_headers_carry_the_body_digest(fwd, seed):
    import hashlib
    g = fwd
    admin = _built(g, seed, 'b')
    with g.at('b'):
        assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
    sent = [x for x in g.sent if x[3] == FORWARD]
    assert len(sent) == 1
    body, headers = sent[0][4], sent[0][5]
    assert headers[g.ha.PEER_BODY_HEADER] == hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize('path', ['/api//ha/peer/step-down', '/api/x/../ha/peer/step-down',
                                  '/api/./ha/promote'])
def test_a_path_that_only_looks_like_ha_runs_nothing_there(fwd, seed, path):
    """Routing takes the path as it stands: none of these reaches an /api/ha/ route."""
    g = fwd
    _built(g, seed, 'b')
    r = _forward_as(g, 'b', _envelope(method='POST', path=path,
                                      body_b64=base64.b64encode(b'{"epoch": 99}').decode()))
    assert r.status_code == 200, r.data
    assert r.get_json()['status'] in (308, 404, 405), r.get_json()
    a = g.state('a')
    assert a['role'] == 'active' and a['epoch'] == 1


# --- what a standby keeps refusing ------------------------------------------------------

def _hook_lists(app):
    """The lists the standby block in app.py goes by, from the hook itself."""
    hook = next(f for f in app.before_request_funcs[None] if f.__name__ == 'refuse_writes_on_standby')
    return dict(zip(hook.__code__.co_freevars, (c.cell_contents for c in hook.__closure__)))


def _concrete(rule):
    """A path the rule serves, with a stand-in for every part it takes."""
    import re
    return re.sub(r'<(?:(\w+):)?(\w+)>', lambda m: '100' if m.group(1) == 'int' else 'x' + m.group(2), rule)


def test_every_route_kept_from_forwarding_exists(api):
    """A typo in the list would forward the route it meant to keep. The consoles have a
    list of their own: a standby that serves users opens them (tests/test_ha_serving.py)."""
    lists = _hook_lists(api.app)
    served = {(m, r.rule) for r in api.app.url_map.iter_rules() for m in r.methods}
    kept = lists['_STANDBY_NOT_FORWARDED'] | lists['_STANDBY_CONSOLES']
    missing = [e for e in kept if e not in served]
    assert missing == []
    assert len(lists['_STANDBY_NOT_FORWARDED']) >= 19 and len(lists['_STANDBY_CONSOLES']) == 5


def test_a_standby_forwards_none_of_them(fwd, seed):
    """Consoles, this instance's own settings, its code and plugins, security keys and
    rows of its own tables: refused as before, and nothing reaches the active. The
    consoles on a standby that does not serve users, which is every standby here."""
    g = fwd
    admin = _built(g, seed, 'b')
    lists = _hook_lists(g.api.app)
    entries = sorted(lists['_STANDBY_NOT_FORWARDED'] | lists['_STANDBY_CONSOLES'])
    g.calls.clear()
    with g.at('b'):
        for method, rule in entries:
            r = getattr(admin, method.lower())(_concrete(rule), json={})
            assert r.status_code == 409 and r.get_json().get('code') == 'HA_STANDBY', (method, rule, r.data)
    assert _forward_calls(g) == []
    # counterproof: the same client and the same kind of call is forwarded elsewhere
    with g.at('b'):
        assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200
    assert len(_forward_calls(g)) == 1


def test_the_server_settings_of_the_standby_do_not_reach_the_active(fwd, seed):
    """The server form sends this instance's port, domain and certificate settings with
    every save. On the active they would replace its own."""
    from pegaprox.api.helpers import load_server_settings
    g = fwd
    admin = _built(g, seed, 'b')
    before = {k: load_server_settings().get(k) for k in ('domain', 'port', 'proxy_bind_address')}
    with g.at('b'):
        r = admin.post('/api/settings/server', content_type='multipart/form-data',
                       data={'domain': 'standby.example', 'port': '5999', 'ssl_enabled': 'false',
                             'proxy_bind_address': '10.9.9.9', 'default_theme': 'nord'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert {k: load_server_settings().get(k) for k in before} == before
    assert _forward_calls(g) == []


def test_a_plugin_console_is_not_forwarded_but_its_other_writes_are(fwd, seed, probe, monkeypatch):
    import pegaprox.api.plugins as plugins
    g = fwd
    admin = _built(g, seed, 'b')
    monkeypatch.setitem(plugins._plugin_routes, 'probe', dict(plugins._plugin_routes['probe'],
                                                               **{'vm/console': lambda: {'ticket': 'x'}}))
    g.calls.clear()
    with g.at('b'):
        r = admin.post('/api/plugins/probe/api/vm/console', json={})
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
        assert _forward_calls(g) == []
        assert admin.post('/api/plugins/probe/api/record', json={}).status_code == 200
    assert len(_forward_calls(g)) == 1 and len(probe) == 1


# --- the progress of a job the active runs -------------------------------------------------

@pytest.fixture
def v2p_list(fwd, monkeypatch):
    """GET /api/vmware/migrations noting where it ran and under which session."""
    from flask import request
    app = fwd.api.app
    endpoint = next(r.endpoint for r in app.url_map.iter_rules()
                    if r.rule == '/api/vmware/migrations' and 'GET' in r.methods)
    seen = []

    def view(*a, **kw):
        from pegaprox.core import ha
        seen.append({'role': ha.role(), 'mark': request.environ.get(ha.FORWARD_ENVIRON),
                     'args': request.args.to_dict()})
        return {'migrations': [{'id': 'm1', 'on': ha.role()}]}
    monkeypatch.setitem(app.view_functions, endpoint, view)
    return seen


def test_every_forwarded_read_is_a_get_route(api):
    from pegaprox.core import ha
    served = {r.rule for r in api.app.url_map.iter_rules() if 'GET' in r.methods}
    assert sorted(ha.FORWARDED_READS - served) == []


def test_a_forwarding_standby_shows_the_progress_the_active_holds(fwd, seed, v2p_list):
    g = fwd
    admin = _built(g, seed, 'b')
    g.calls.clear()
    with g.at('b'):
        r = admin.get('/api/vmware/migrations?all=1')
    assert r.status_code == 200 and r.get_json() == {'migrations': [{'id': 'm1', 'on': 'active'}]}
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)]
    assert v2p_list[-1]['role'] == 'active' and v2p_list[-1]['mark']['via'] == URLS['b']
    assert v2p_list[-1]['args'] == {'all': '1'}
    # a read changes nothing: no sync after it, and no audit line
    assert g.pulls == []


def test_a_read_falls_back_to_the_standbys_own_answer(fwd, seed, v2p_list):
    """Forwarding off, the active gone, an API token, a read not on the list: the route
    answers here, and nothing is sent."""
    from pegaprox.utils.auth import create_api_token
    g = fwd
    admin = _built(g, seed, 'b')
    token = {'Authorization': f"Bearer {create_api_token('root', 'automation', role='admin')['token']}"}
    g.calls.clear()
    with g.at('b') as ha:
        assert g.api.anon().get('/api/vmware/migrations', headers=token).get_json()['migrations'][0]['on'] == 'standby'
        assert admin.get('/api/ha/status').status_code == 200
        ha.set_forward_writes(False)
        assert admin.get('/api/vmware/migrations').get_json()['migrations'][0]['on'] == 'standby'
        ha.set_forward_writes(True)
    assert _forward_calls(g) == []
    g.down.add('a')
    with g.at('b'):
        r = admin.get('/api/vmware/migrations')
    assert r.status_code == 200 and r.get_json()['migrations'][0]['on'] == 'standby'
    # counterproof: back, and it goes to the active again
    g.down.discard('a')
    _watch(g, 'b')
    with g.at('b'):
        assert admin.get('/api/vmware/migrations').get_json()['migrations'][0]['on'] == 'active'


def test_the_active_serves_no_other_read(fwd, seed):
    g = fwd
    _built(g, seed, 'b')
    for path in ('/api/clusters', '/api/users', '/api/ha/status', '/api/nothing'):
        r = _forward_as(g, 'b', _envelope(method='GET', path=path, body_b64=''))
        assert r.status_code == 400 and r.get_json()['code'] == 'HA_FORWARD_INVALID', (path, r.data)
    r = _forward_as(g, 'b', _envelope(method='GET', path='/api/vmware/migrations'))
    assert r.status_code == 400, 'a read with a body'
    r = _forward_as(g, 'b', _envelope(method='GET', path='/api/vmware/migrations', body_b64=''))
    assert r.status_code == 200 and r.get_json()['status'] == 200


# --- a password changed on the active --------------------------------------------------

def test_a_session_older_than_a_password_change_on_the_active_is_refused(fwd, seed, monkeypatch):
    """The two instances share one database here, so the standby's older copy of the
    account is played by its digest."""
    g = fwd
    admin = _built(g, seed, 'b')
    real = g.ha.sign_in_digest
    monkeypatch.setattr(g.ha, 'sign_in_digest',
                        lambda u: real(u) if g.name() == 'a' else '0' * 64)
    with g.at('b'):
        r = admin.put('/api/user/preferences', json={'theme': 'nord'})
    assert r.status_code == 401 and r.get_json() == {
        'code': 'HA_FORWARD_STALE_SIGN_IN',
        'error': 'Your password was changed on the active instance - sign in again'}
    # the standby syncs at once, which ends the session there
    assert g.pulls == ['b']
    from pegaprox.core.db import get_db
    assert get_db().get_user('root').get('theme') != 'nord'
    # counterproof: the same digest on both, and it goes through
    monkeypatch.setattr(g.ha, 'sign_in_digest', real)
    with g.at('b'):
        assert admin.put('/api/user/preferences', json={'theme': 'nord'}).status_code == 200


def test_the_sign_in_digest_follows_the_password(ha_env, seed):
    from pegaprox.core import ha
    from pegaprox.core.db import get_db
    seed.user('root', role='admin')
    before = ha.sign_in_digest('root')
    assert len(before) == 64 and ha.sign_in_digest('nobody') == ''
    conn = get_db().conn
    conn.execute("UPDATE users SET password_hash = 'changed' WHERE username = 'root'")
    conn.commit()
    assert ha.sign_in_digest('root') not in (before, '')


def test_an_envelope_without_the_digest_is_refused(fwd, seed):
    g = fwd
    _built(g, seed, 'b')
    env = _envelope()
    del env['sign_in']
    r = _forward_as(g, 'b', env)
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_FORWARD_INVALID'


# --- the per-address limit ----------------------------------------------------------------

def test_signed_member_calls_do_not_count_against_the_address(fwd, seed, monkeypatch):
    """Every write a standby forwards comes from its one address, next to its sync. A
    signed member call is not charged to that address; anything else is."""
    import pegaprox.app as app_mod
    g = fwd
    admin = _built(g, seed, 'b')
    charged = []

    def limit(ip):
        charged.append(ip)
        # the members all call from the loopback test client: that address is over its
        # budget, the browser's is not
        return ip != '127.0.0.1'
    monkeypatch.setattr(app_mod, '_check_api_rate_limit', limit)
    with g.at('b') as ha:
        assert ha.pull_once() in ('applied', 'unchanged')
        r = admin.put('/api/user/preferences', json={'theme': 'nord'}, headers=FROM_CLIENT)
    assert r.status_code == 200, r.data
    assert _forward_calls(g) and '127.0.0.1' not in charged
    # the forwarded request inside counts against the client, on both instances
    assert charged == [CLIENT, CLIENT]
    # counterproof: an unsigned peer call is charged, and refused
    charged.clear()
    r = _send(g, 'a', {g.ha.PEER_HEADER: IDS['b']})
    assert r.status_code == 429 and charged == ['127.0.0.1']


@pytest.mark.parametrize('path', ['/api/ws/token', '/api/clusters/c1/nodes/n1/shell',
                                  '/api/clusters/c1/vms/n1/qemu/100/termproxy',
                                  '/api/clusters/c1/vms/n1/qemu/100/vnc-poll',
                                  '/api/vmware/v1/vms/vm-1/console',
                                  '/api/plugins/probe/api/vm/console'])
def test_the_active_opens_no_console_for_a_standby(fwd, seed, path):
    """A standby never hands a console on - the browser connects where it opened - and
    the active does not take one either, whoever signs the envelope."""
    from pegaprox.globals import ws_tokens
    g = fwd
    _built(g, seed, 'b')
    before = set(ws_tokens)
    r = _forward_as(g, 'b', _envelope(method='POST', path=path,
                                      body_b64=base64.b64encode(b'{}').decode()))
    assert r.status_code == 400 and r.get_json()['code'] == 'HA_FORWARD_INVALID', (path, r.data)
    assert 'console' in r.get_json()['error'] and set(ws_tokens) == before
    # counterproof: another write of the same envelope goes through
    r = _forward_as(g, 'b', _envelope())
    assert r.status_code == 200 and r.get_json()['status'] == 200
