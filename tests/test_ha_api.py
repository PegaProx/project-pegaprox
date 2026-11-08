"""Warm standby routes (#625): the admin page, the peer calls, and the write block
on a standby.

Everything drives the real Flask app. Peer calls go through a RAW test client with
only what the other instance really sends (X-Requested-With and the peer header, no
Origin). The harness client adds Origin to every write, and with it these tests
would pass even if the CSRF gate turned every peer away.

Two instances in one process: each side has its own state file, and ha.STATE_FILE
points at whichever side is answering. Both share the one test database, which is
what a pair looks like right after a sync anyway.
"""
import ast
import base64
import contextvars
import gzip
import inspect
import json
import os
import re
import time
import types

import pytest

A_ID = 'a' * 32          # the active
B_ID = 'b' * 32          # the standby
PEER_SECRET = 'what-the-standby-presents-' + 'x' * 24
ACTIVE_URL = 'https://active.example:5000'
STANDBY_URL = 'https://standby.example:5000'
# what _admin's account signs in with; pairing, join, promote and unpair want it again
ADMIN_PW = 'Adm1n-at-the-keyboard!'
# the name of a copy of changes that were not carried over; none is kept under it
ORPHAN = '1-4-20261001T100158Z-0123456789ab'

ADMIN_ROUTES = [
    ('get', '/api/ha/status', None),
    ('post', '/api/ha/pairing-code', {'url': ACTIVE_URL, 'user_password': ADMIN_PW}),
    ('post', '/api/ha/join', {'code': 'pgxha1_x', 'own_url': STANDBY_URL, 'confirm': True,
                              'user_password': ADMIN_PW}),
    ('post', '/api/ha/sync-now', None),
    ('post', '/api/ha/promote', {'confirm': 'PROMOTE', 'user_password': ADMIN_PW}),
    ('post', '/api/ha/unpair', {'confirm': 'UNPAIR', 'user_password': ADMIN_PW}),
    ('put', '/api/ha/settings', {'interval': 60}),
    ('post', '/api/ha/apply-config', None),
    ('post', f'/api/ha/members/{B_ID}/remove', {'confirm': 'REMOVE', 'user_password': ADMIN_PW}),
    ('put', f'/api/ha/members/{B_ID}/serve', {'serve': True}),
    ('post', f'/api/ha/orphans/{ORPHAN}/download', {'user_password': ADMIN_PW}),
    ('post', f'/api/ha/orphans/{ORPHAN}/dismiss', {'confirm': True}),
    # automatic failover and the group's time zone (tests/test_ha_lease_routes.py)
    ('put', '/api/ha/mode', {'mode': 'auto', 'user_password': ADMIN_PW}),
    ('post', f'/api/ha/members/{B_ID}/readmit', {'user_password': ADMIN_PW}),
    ('put', '/api/ha/timezone', {'timezone': 'Europe/Vienna'}),
    # the witness (tests/test_ha_witness.py)
    ('post', '/api/ha/witness/pairing-code', {'url': ACTIVE_URL, 'user_password': ADMIN_PW}),
    ('post', '/api/ha/witness/remove', {'confirm': 'REMOVE', 'user_password': ADMIN_PW}),
    # the lead of an automatic group (tests/test_ha_make_leader.py, test_ha_force_leader.py)
    ('post', '/api/ha/make-leader', {'confirm': 'LEADER', 'user_password': ADMIN_PW}),
    ('post', '/api/ha/force-leader', {'confirm': 'FORCE LEADER', 'cut_out': [], 'reason': 'test',
                                      'user_password': ADMIN_PW}),
    ('put', f'/api/ha/members/{B_ID}/agent-vmid', {'cluster_id': 'c1', 'vmid': 101}),
    # what an admin sets per member (tests/test_ha_member_settings.py)
    ('put', f'/api/ha/members/{B_ID}/site', {'site': 'dc1'}),
    ('put', f'/api/ha/members/{B_ID}/vote', {'voter': False, 'user_password': ADMIN_PW}),
]
PEER_ROUTES = [
    ('POST', '/api/ha/peer/pair'),
    ('GET', '/api/ha/peer/status'),
    ('GET', '/api/ha/peer/snapshot'),
    ('POST', '/api/ha/peer/step-down'),
    ('POST', '/api/ha/peer/unpaired'),
    ('POST', '/api/ha/peer/member-removed'),
    ('POST', '/api/ha/peer/tombstones'),
    ('POST', '/api/ha/peer/forward'),
    ('POST', '/api/ha/peer/changed'),
    ('POST', '/api/ha/peer/vote'),
    ('POST', '/api/ha/peer/renew'),
    ('POST', '/api/ha/peer/fingerprint'),
    ('POST', '/api/ha/peer/pair-witness'),
    ('POST', '/api/ha/peer/witness-leave'),
    ('POST', '/api/ha/peer/campaign'),
    ('POST', '/api/ha/peer/transfer'),
    ('POST', '/api/ha/peer/leave'),
]
# what the self-fence agent of a node asks; no session, keyed with the cluster's agent
# token (tests/test_ha_agent_script.py)
AGENT_ROUTES = [
    ('GET', '/api/ha/agent'),
]
# what a witness host fetches: the installer the repository publishes, and the witness
# code for the open code or the paired witness's signature (tests/test_ha_witness_delivery.py)
WITNESS_DELIVERY_ROUTES = [
    ('GET', '/api/ha/witness/installer'),
    ('POST', '/api/ha/witness/bundle'),
]


_URL_SHAPE = re.compile(r'https://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?(/[A-Za-z0-9._~\-/]*)?')


def _url_stand_in(url):
    """The rule the routes had before ha.valid_https_url, for a core without it."""
    url = (url or '').strip().rstrip('/') if isinstance(url, str) else ''
    return url if _URL_SHAPE.fullmatch(url) else ''


@pytest.fixture
def ha_env(api, tmp_path, monkeypatch):
    from pegaprox.core import ha
    import pegaprox.api.ha as ha_api
    monkeypatch.setattr(ha, 'STATE_FILE', str(tmp_path / 'ha_state.json'))
    monkeypatch.setattr(ha, 'AES_KEY_FILE', str(tmp_path / '.pegaprox_aes256.key'))
    monkeypatch.setattr(ha, 'KNOWN_HOSTS_FILE', str(tmp_path / '.ssh_known_hosts'))
    monkeypatch.setattr(ha, 'BRANDING_DIR', str(tmp_path / 'branding'))
    if not hasattr(ha, 'valid_https_url'):
        monkeypatch.setattr(ha, 'valid_https_url', _url_stand_in, raising=False)
    env = types.SimpleNamespace(ha=ha, api=api, tmp=tmp_path, restarts=[], installed=[], calls=[])
    monkeypatch.setattr(ha, 'restart_process', env.restarts.append)
    monkeypatch.setattr(ha, '_install_field_key', env.installed.append)
    ha.reset_for_tests()
    ha.forget_seen_nonces()
    for window in (ha_api._pair_attempts, ha_api._peer_failures, ha_api._reauth_attempts):
        window.reset()
    yield env
    ha.reset_for_tests()
    for window in (ha_api._pair_attempts, ha_api._peer_failures, ha_api._reauth_attempts):
        window.reset()


# --- helpers -----------------------------------------------------------------------

def _write_state(path, role, instance_id=A_ID, epoch=1, peer=None, **extra):
    st = {'role': role, 'epoch': epoch, 'instance_id': instance_id, 'interval': 30,
          'peer': peer, 'pairing': None, 'sync': {}}
    st.update(extra)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)


def _be(env, role, **kw):
    _write_state(env.ha.STATE_FILE, role, **kw)
    env.ha.reset_for_tests()


def _peer_record(instance_id=B_ID, url=STANDBY_URL, role_seen='standby'):
    """The peer of a v1/v2 pair state file, which _load reads as a group of two: we
    present 'y' * 43 to every member, and the member presents PEER_SECRET."""
    from pegaprox.core import ha
    return {'instance_id': instance_id, 'url': url, 'fingerprint': '',
            'secret_out': 'y' * 43, 'secret_in_hash': ha._hash_secret(PEER_SECRET),
            'paired_at': '2026-09-29T10:00:00+00:00', 'role_seen': role_seen, 'epoch_seen': 1}


def _active_with_standby(env, epoch=1):
    _be(env, 'active', epoch=epoch, peer=_peer_record())


def _standby_of_active(env, **kw):
    """A standby whose active answers. Its writes are refused, as they were before v3:
    these tests are about that block, and nothing here answers a forwarded write.
    tests/test_ha_forward.py covers forward_writes on."""
    kw.setdefault('forward_writes', False)
    _be(env, 'standby', instance_id=B_ID, peer=_peer_record(A_ID, ACTIVE_URL, 'active'), **kw)


GOOD = f'{B_ID}:{PEER_SECRET}'


def _peer(api, method, path, peer_header, headers=None, **kw):
    """What the other instance sends: X-Requested-With, the peer header, no Origin."""
    h = {'X-Requested-With': 'XMLHttpRequest'}
    if peer_header is not None:
        h['X-PegaProx-Peer'] = peer_header
    h.update(headers or {})
    return api.app.test_client().open(path, method=method, headers=h,
                                      base_url='http://localhost', **kw)


_ADMIN_HASH = []


def _admin(api, seed, name='root', **kw):
    """An admin with a real password, ADMIN_PW, so the routes that re-check it can."""
    from pegaprox.utils.auth import hash_password
    user = seed.user(name, role=kw.pop('role', 'admin'), **kw)
    if not _ADMIN_HASH:
        _ADMIN_HASH.append(hash_password(ADMIN_PW))     # argon2 is slow, once is enough
    salt, pw_hash = _ADMIN_HASH[0]
    row = seed.db.get_user(name)
    row.update(password_salt=salt, password_hash=pw_hash)
    seed.db.save_user(name, row)
    return api.as_user(user)


def _send(client, method, path, body, **kw):
    if body is not None:
        kw['json'] = body
    return getattr(client, method)(path, **kw)


def _join(client, code, own_url=STANDBY_URL, **extra):
    body = {'code': code, 'own_url': own_url, 'confirm': True, 'user_password': ADMIN_PW}
    body.update(extra)
    return client.post('/api/ha/join', json=body)


def _audit(action):
    from pegaprox.core.db import get_db
    return [dict(r) for r in get_db().conn.cursor().execute(
        'SELECT user, action, details FROM audit_log WHERE action = ?', (action,)).fetchall()]


def _file(path):
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)


class _Wire:
    """The part of a requests.Response that ha.py reads."""

    def __init__(self, resp):
        self.status_code = resp.status_code
        self.headers = resp.headers
        data = resp.get_data()
        if resp.headers.get('Content-Encoding') == 'gzip':
            data = gzip.decompress(data)      # requests undoes it the same way
        self.content = data

    def json(self):
        return json.loads(self.content)


def _switch(env, path):
    env.ha.STATE_FILE = path                  # monkeypatch restores it at teardown
    env.ha.reset_for_tests()


def _wire_to(env, monkeypatch, other_side, down=False):
    """ha._peer_call, answered by the same app with `other_side` as its state."""
    ha = env.ha
    client = env.api.app.test_client()

    def call(method, base_url, fingerprint, path, json_body=None, auth=None,
             headers=None, timeout=15):
        env.calls.append((method, base_url, path))
        if down:
            raise ha.PeerUnreachable('Cannot reach the peer: ConnectTimeout')
        body = ha._wire_body(json_body)
        h = {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
        if body:
            h['Content-Type'] = 'application/json'
        if auth is not None:
            h.update(auth(method, path, body))
        h.update(headers or {})
        home = ha.STATE_FILE
        _switch(env, other_side)
        try:
            # a request of its own, as between two processes: not in the app context
            # (and flask.g) of a route it is made from
            resp = contextvars.Context().run(client.open, path, method=method, data=body or None,
                                             headers=h, base_url='http://localhost')
        finally:
            _switch(env, home)
        return _Wire(resp)

    monkeypatch.setattr(ha, '_peer_call', call)


def _two_sides(env):
    active, standby = str(env.tmp / 'active.json'), str(env.tmp / 'standby.json')
    _write_state(active, 'standalone', instance_id=A_ID, epoch=0)
    _write_state(standby, 'standalone', instance_id=B_ID, epoch=0)
    return active, standby


def _joined(env, seed, monkeypatch):
    """A real pairing: the code from the active's route, the join through the
    standby's route, the handshake through the active's pair route."""
    admin = _admin(env.api, seed)
    active, standby = _two_sides(env)
    _switch(env, active)
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    code = r.get_json()['code']
    _switch(env, standby)
    _wire_to(env, monkeypatch, active)
    r = _join(admin, code)
    assert r.status_code == 200, r.data
    return admin, active, standby, r


# --- every route, every caller ------------------------------------------------------

def test_the_route_lists_are_every_ha_route(api):
    listed = {(m.upper(), p) for m, p, _b in ADMIN_ROUTES} | set(PEER_ROUTES) | set(AGENT_ROUTES) | \
        set(WITNESS_DELIVERY_ROUTES)
    served = set()
    for rule in api.app.url_map.iter_rules():
        if rule.rule.startswith('/api/ha/'):
            for m in rule.methods - {'HEAD', 'OPTIONS'}:
                # the list names one member for the route that takes any
                served.add((m, rule.rule.replace('<instance_id>', B_ID).replace('<name>', ORPHAN)))
    assert served == listed


def test_no_admin_route_answers_without_a_login(ha_env):
    for method, path, body in ADMIN_ROUTES:
        r = _send(ha_env.api.anon(), method, path, body)
        assert r.status_code == 401, (method, path, r.status_code)
    assert not os.path.exists(ha_env.ha.STATE_FILE)
    assert ha_env.restarts == []


@pytest.mark.parametrize('kind', ['user', 'viewer', 'capped_admin', 'capped_default_admin',
                                  'admins_viewer_token'])
def test_below_an_unconfined_admin_nothing_changes(ha_env, seed, kind):
    api = ha_env.api
    headers = None
    if kind == 'user':
        # every permission a settings page could ask for, still not an admin
        c = api.as_user(seed.user('ops', role='user', permissions=[
            'admin.users', 'admin.settings', 'security.settings.manage']))
    elif kind == 'viewer':
        c = api.as_user(seed.user('watcher', role='viewer'))
    elif kind == 'capped_admin':
        # an admin that an LDAP tenant mapping has lowered where they live
        seed.tenant('globex', ['cluster_globex'])
        c = api.as_user(seed.user('gx', role='admin', tenant_id='globex',
                                  tenant_permissions={'globex': {'role': 'user'}}))
    elif kind == 'capped_default_admin':
        # the same in the default tenant, whose empty cluster list reads as "all
        # clusters": the scope check alone lets this one through. The right password
        # too, so nothing but the tenant gate stands in the way.
        c = _admin(api, seed, 'lowered', tenant_id='default',
                   tenant_permissions={'default': {'role': 'viewer'}})
    else:
        from pegaprox.utils.auth import create_api_token
        seed.user('root', role='admin')
        res = create_api_token('root', 'ci', role='viewer')
        assert res.get('success'), res
        c, headers = api.anon(), {'Authorization': f"Bearer {res['token']}"}
    for method, path, body in ADMIN_ROUTES:
        r = _send(c, method, path, body, headers=headers)
        assert r.status_code == 403, (kind, method, path, r.status_code, r.data)
        if kind in ('capped_admin', 'capped_default_admin'):
            assert b'tenant' in r.data, r.data     # our gate, not the role check
    assert not os.path.exists(ha_env.ha.STATE_FILE)
    assert ha_env.restarts == []


def test_an_override_that_restates_admin_is_no_cap(ha_env, seed):
    """Counterproof for the tenant gate: an override in the admin's own tenant that
    says admin again lowers nothing, and neither does one for another tenant."""
    for name, tp in (('restated', {'default': {'role': 'admin'}}),
                     ('elsewhere', {'globex': {'role': 'viewer'}})):
        c = _admin(ha_env.api, seed, name, tenant_id='default', tenant_permissions=tp)
        assert c.get('/api/ha/status').status_code == 200, name
        r = c.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
        assert r.status_code == 200, (name, r.data)


def test_an_admin_reaches_every_route(ha_env, seed):
    c = _admin(ha_env.api, seed)
    expected = {
        '/api/ha/status': 200,
        '/api/ha/pairing-code': 200,
        '/api/ha/join': 400,          # the code in the list is not a real one
        '/api/ha/sync-now': 200,
        '/api/ha/promote': 409,       # not a standby
        '/api/ha/unpair': 409,        # not paired
        '/api/ha/settings': 200,
        '/api/ha/apply-config': 409,  # not a standby
        f'/api/ha/members/{B_ID}/remove': 409,  # not active
        f'/api/ha/members/{B_ID}/serve': 409,   # not the leader
        f'/api/ha/orphans/{ORPHAN}/download': 404,  # no such copy
        f'/api/ha/orphans/{ORPHAN}/dismiss': 404,
        '/api/ha/mode': 409,                        # not the leader of a group
        f'/api/ha/members/{B_ID}/readmit': 409,     # a manual group quarantines nobody
        '/api/ha/timezone': 409,                    # not the leader of a group
        '/api/ha/witness/pairing-code': 409,        # not the leader of a group
        '/api/ha/witness/remove': 409,              # not the leader of a group
        '/api/ha/make-leader': 409,                 # not an automatic group
        '/api/ha/force-leader': 409,                # not a member that follows
        f'/api/ha/members/{B_ID}/agent-vmid': 409,  # not the leader of a group
        f'/api/ha/members/{B_ID}/site': 409,        # not the leader of a group
        f'/api/ha/members/{B_ID}/vote': 409,        # not the leader of a group
    }
    for method, path, body in ADMIN_ROUTES:
        r = _send(c, method, path, body)
        assert r.status_code == expected[path], (method, path, r.status_code, r.data)
        if r.status_code >= 400:
            assert r.get_json()['error']


def test_an_admin_api_token_reaches_the_page(ha_env, seed):
    from pegaprox.utils.auth import create_api_token
    seed.user('root', role='admin')
    res = create_api_token('root', 'automation', role='admin')
    assert res.get('success'), res
    r = ha_env.api.anon().get('/api/ha/status', headers={'Authorization': f"Bearer {res['token']}"})
    assert r.status_code == 200, r.data
    assert r.get_json()['role'] == 'standalone'


def test_peer_routes_want_the_peer_header(ha_env):
    import pegaprox.api.ha as ha_api
    ha, api = ha_env.ha, ha_env.api
    _active_with_standby(ha_env, epoch=2)
    wrong = [None, '', PEER_SECRET, f'{B_ID}:', f'{B_ID}:wrong-secret',
             f'{A_ID}:{PEER_SECRET}', f'{B_ID}:{PEER_SECRET}x',
             f'{B_ID}:{ha._hash_secret(PEER_SECRET)}']
    for method, path in PEER_ROUTES:
        if path in ('/api/ha/peer/pair', '/api/ha/peer/pair-witness'):
            continue                               # the code authenticates those
        ha_api._peer_failures.reset()
        for header in wrong:
            r = _peer(api, method, path, header, json={'epoch': 99})
            assert r.status_code == 401, (path, header, r.status_code)
    assert ha.role() == 'active' and ha.epoch() == 2 and ha.peer()['instance_id'] == B_ID
    assert ha_env.restarts == []

    r = _peer(api, 'GET', '/api/ha/peer/status', GOOD)
    assert r.status_code == 200
    # this release offers automatic failover: what the watch reads about it comes along,
    # and nothing else (the wall clock moved on between the two reads)
    said, lease = r.get_json(), ha.peer_lease_status()
    assert abs(said.pop('wall') - lease.pop('wall')) < 5
    assert said == dict({'instance_id': A_ID, 'role': 'active', 'epoch': 2, 'group': 1,
                         'serving': False}, **lease)
    assert said['mode'] == 'manual'
    assert _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD).status_code == 200
    r = _peer(api, 'POST', '/api/ha/peer/step-down', GOOD, json={'epoch': 1})
    assert r.status_code == 200 and r.get_json()['stepped_down'] is False
    r = _peer(api, 'POST', '/api/ha/peer/unpaired', GOOD)
    assert r.status_code == 200 and r.get_json()['forgotten'] is True
    assert ha.role() == 'standalone' and ha.peer() is None
    assert _audit('ha.unpaired')
    # forgotten means forgotten
    assert _peer(api, 'GET', '/api/ha/peer/status', GOOD).status_code == 401


def test_failed_peer_calls_are_rate_limited_per_address(ha_env):
    api = ha_env.api
    _active_with_standby(ha_env)
    flood = {'X-Forwarded-For': '203.0.113.7'}
    for _ in range(10):
        assert _peer(api, 'GET', '/api/ha/peer/status', 'nope', flood).status_code == 401
    assert _peer(api, 'GET', '/api/ha/peer/status', 'nope', flood).status_code == 429
    assert _peer(api, 'GET', '/api/ha/peer/status', 'nope',
                 {'X-Forwarded-For': '203.0.113.8'}).status_code == 401
    # only failures count: the real peer behind the same address still gets in
    assert _peer(api, 'GET', '/api/ha/peer/status', GOOD, flood).status_code == 200


# --- pairing ------------------------------------------------------------------------

def _code(admin, url=ACTIVE_URL):
    r = admin.post('/api/ha/pairing-code', json={'url': url, 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    return r.get_json()


# the key pair the standby of these tests pairs with; only the public half is sent
STANDBY_KEY = base64.b64encode(bytes(range(32))).decode()


def _standby_public():
    from pegaprox.core import ha
    return ha._public_of(ha._private_key(STANDBY_KEY))


def _as_standby(to, method, path, body=b''):
    """The peer headers of a call the standby of STANDBY_KEY signs for `to`."""
    from pegaprox.core import ha
    signer = ha._Signer(B_ID, ha._private_key(STANDBY_KEY))
    return ha._auth_for(signer, to)(method, path, body)


def _pair_body(secret, instance_id=B_ID):
    return {'code': secret, 'instance_id': instance_id, 'url': STANDBY_URL,
            'fingerprint': '', 'public_key': _standby_public()}


def test_the_pairing_handshake_through_the_routes(ha_env, seed):
    from pegaprox.core.db import get_db
    ha, api = ha_env.ha, ha_env.api
    admin = _admin(api, seed)
    made = _code(admin, ACTIVE_URL + '/')
    code = made['code']
    assert code.startswith('pgxha1_')
    assert time.time() < made['expires_at'] <= time.time() + 15 * 60 + 5
    info = ha.decode_code(code)
    assert info['url'] == ACTIVE_URL and info['instance_id'] == ha.instance_id()
    status = admin.get('/api/ha/status')
    assert status.get_json()['pairing_open_until'] == made['expires_at']
    assert info['secret'] not in status.get_data(as_text=True)

    r = _peer(api, 'POST', '/api/ha/peer/pair', None, json=_pair_body(info['secret']))
    assert r.status_code == 200, r.data
    out = r.get_json()
    assert out['instance_id'] == ha.instance_id() and out['epoch'] == 1
    assert out['key_fp'] == ha.key_fingerprint()
    field_key = get_db().aes_key
    assert base64.b64encode(field_key).decode() not in r.get_data(as_text=True)

    opened = ha._unseal(info['secret'], out['sealed'], aad=B_ID)
    assert base64.b64decode(opened['field_key']) == field_key
    # sealed to that code and that standby, nothing else opens it
    for secret, aad in (('not-the-code', B_ID), (info['secret'], 'c' * 32)):
        with pytest.raises(Exception):
            ha._unseal(secret, out['sealed'], aad=aad)

    assert ha.role() == 'active' and ha.epoch() == 1
    assert ha.peer()['instance_id'] == B_ID and ha.peer()['url'] == STANDBY_URL
    assert ha.peer()['public_key'] == _standby_public()
    # our public key, and the member list with both of us in it
    assert opened['public_key'] == ha.own_public_key() and 'secret_hash' not in opened
    assert {e['instance_id'] for e in opened['members']} == {ha.instance_id(), B_ID}
    assert ha._load()['signing_key'] not in json.dumps(opened)
    # the standby signs with its own key from now on, which never left it
    assert STANDBY_KEY not in json.dumps(_file(ha.STATE_FILE))
    r = _peer(api, 'GET', '/api/ha/peer/status', None,
              headers=_as_standby(ha.instance_id(), 'GET', '/api/ha/peer/status'))
    assert r.status_code == 200 and r.get_json()['role'] == 'active'

    # single use
    again = _peer(api, 'POST', '/api/ha/peer/pair', None,
                  json=_pair_body(info['secret'], instance_id='c' * 32))
    assert again.status_code == 403
    assert 'sealed' not in again.get_json()
    assert ha.peer()['instance_id'] == B_ID

    assert _audit('ha.pairing_code_created')[0]['user'] == 'root'
    assert len(_audit('ha.paired')) == 1


def test_an_expired_code_does_not_pair(ha_env, seed):
    ha = ha_env.ha
    info = ha.decode_code(_code(_admin(ha_env.api, seed))['code'])
    st = _file(ha.STATE_FILE)
    st['pairing']['expires'] = int(time.time()) - 1
    with open(ha.STATE_FILE, 'w', encoding='utf-8') as fh:
        json.dump(st, fh)
    ha.reset_for_tests()
    r = _peer(ha_env.api, 'POST', '/api/ha/peer/pair', None, json=_pair_body(info['secret']))
    assert r.status_code == 403 and 'expired' in r.get_json()['error']
    assert ha.role() == 'standalone' and ha.peer() is None
    assert _audit('ha.paired') == []


def test_a_wrong_code_does_not_pair_and_does_not_spend_the_right_one(ha_env, seed):
    ha = ha_env.ha
    info = ha.decode_code(_code(_admin(ha_env.api, seed))['code'])
    for guess in ('', 'x' * 43, info['secret'][:-1], 42):
        r = _peer(ha_env.api, 'POST', '/api/ha/peer/pair', None, json=_pair_body(guess))
        assert r.status_code == 403, (guess, r.status_code)
    assert ha.peer() is None
    r = _peer(ha_env.api, 'POST', '/api/ha/peer/pair', None, json=_pair_body(info['secret']))
    assert r.status_code == 200, r.data


def test_pairing_attempts_are_rate_limited_per_address(ha_env, seed):
    ha, api = ha_env.ha, ha_env.api
    info = ha.decode_code(_code(_admin(api, seed))['code'])
    here = {'X-Forwarded-For': '198.51.100.4'}
    for _ in range(5):
        r = _peer(api, 'POST', '/api/ha/peer/pair', None, here, json=_pair_body('guess'))
        assert r.status_code == 403
    # the sixth is refused before the code is even looked at, the right one too
    r = _peer(api, 'POST', '/api/ha/peer/pair', None, here, json=_pair_body(info['secret']))
    assert r.status_code == 429 and ha.peer() is None
    r = _peer(api, 'POST', '/api/ha/peer/pair', None, {'X-Forwarded-For': '198.51.100.5'},
              json=_pair_body(info['secret']))
    assert r.status_code == 200, r.data


def test_a_pairing_code_needs_https_and_a_free_instance(ha_env, seed):
    admin = _admin(ha_env.api, seed)
    for bad in ('http://active.example:5000', 'active.example', 'https://', 'https://a b',
                'https://x.example/%0a', 'javascript:alert(1)', None, 42, ['https://x.example']):
        r = admin.post('/api/ha/pairing-code', json={'url': bad})
        assert r.status_code == 400, (bad, r.status_code)
    assert not os.path.exists(ha_env.ha.STATE_FILE)

    # an active with a standby takes more, up to three - once that standby has
    # answered as a member of a group: the pair release takes calls from its one peer only
    _active_with_standby(ha_env)
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
    assert r.status_code == 409 and STANDBY_URL in r.get_json()['error']
    assert 'update it' in r.get_json()['error']
    ha_env.ha._note_members({B_ID: {'group_seen': True}})
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    full = {mid: {'url': f'https://{mid[:4]}.example', 'fingerprint': '',
                  'secret_hash': ha_env.ha._hash_secret(mid)} for mid in ('1' * 32, '2' * 32, '3' * 32)}
    _be(ha_env, 'active', members=full, member_secret='y' * 43)
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
    assert r.status_code == 409
    assert r.get_json() == {'error': 'This group already has 3 standbys - remove one first'}
    _standby_of_active(ha_env)
    r = admin.post('/api/ha/pairing-code', json={'url': ACTIVE_URL, 'user_password': ADMIN_PW})
    assert r.status_code == 409 and 'standby' in r.get_json()['error']


def test_the_admin_routes_take_urls_through_the_core_rule(ha_env, seed, monkeypatch):
    """Both addresses an admin types go through ha.valid_https_url, whole: the same rule
    the other side applies, and no cut to 512 characters first."""
    ha = ha_env.ha
    seen = []

    def rule(url):
        seen.append(url)
        return '' if 'refused' in url else url
    monkeypatch.setattr(ha, 'valid_https_url', rule, raising=False)
    admin = _admin(ha_env.api, seed)
    long_url = 'https://x.example/' + 'p' * 600

    r = admin.post('/api/ha/pairing-code', json={'url': ' https://refused.example ',
                                                  'user_password': ADMIN_PW})
    assert r.status_code == 400
    r = admin.post('/api/ha/pairing-code', json={'url': long_url + '/', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    # the code carries what the rule returned, whole, without the trailing slash
    raw = r.get_json()['code'][len(ha.CODE_PREFIX):]
    carried = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))['u']
    assert carried == long_url
    assert seen == ['https://refused.example', long_url + '/']

    _be(ha_env, 'standalone')
    code = ha.encode_code(ACTIVE_URL, '', 'f' * 43, A_ID)
    r = _join(admin, code, own_url='https://refused.example')
    assert r.status_code == 400 and 'address' in r.get_json()['error']
    assert seen[-1] == 'https://refused.example'
    assert ha_env.calls == [] and ha_env.restarts == []


def test_status_and_code_carry_what_a_peer_needs_to_reach_us(ha_env, seed, monkeypatch):
    import pegaprox.api.auto_install as ai
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    fp = ':'.join(['AB'] * 32)
    monkeypatch.setattr(ai, 'self_signed_fingerprint', lambda: fp)
    monkeypatch.delenv('PEGAPROX_BEHIND_PROXY', raising=False)

    body = admin.get('/api/ha/status').get_json()
    assert body['role'] == 'standalone' and body['peer'] is None
    assert body['suggested_url'] == 'http://localhost'
    assert body['own_fingerprint'] == fp
    assert ha.decode_code(_code(admin)['code'])['fingerprint'] == fp

    # the address as a trusted proxy forwarded it (the harness talks from loopback)
    fwd = admin.get('/api/ha/status', headers={'X-Forwarded-Host': 'pegaprox.example.com:8443',
                                                'X-Forwarded-Proto': 'https'}).get_json()
    assert fwd['suggested_url'] == 'https://pegaprox.example.com:8443'

    # behind a reverse proxy the certificate on the wire is not ours: pin nothing
    monkeypatch.setenv('PEGAPROX_BEHIND_PROXY', '1')
    assert admin.get('/api/ha/status').get_json()['own_fingerprint'] == ''
    ha.reset_for_tests()
    os.remove(ha.STATE_FILE)
    ha.reset_for_tests()
    assert ha.decode_code(_code(admin)['code'])['fingerprint'] == ''


def test_status_does_not_show_the_secrets(ha_env, seed):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    _active_with_standby(ha_env)
    text = admin.get('/api/ha/status').get_data(as_text=True)
    assert json.loads(text)['peer']['instance_id'] == B_ID
    assert 'y' * 43 not in text and ha._hash_secret(PEER_SECRET) not in text

    # no field named after one, however deep; the checks of automatic failover may say
    # the word in a sentence (a member that still signs by the secret of an old pairing)
    def names(value):
        if isinstance(value, dict):
            for k, v in value.items():
                yield k
                yield from names(v)
        elif isinstance(value, list):
            for v in value:
                yield from names(v)
    assert not [k for k in names(json.loads(text)) if 'secret' in k.lower()]


# --- join -------------------------------------------------------------------------

def test_join_pairs_through_the_real_pair_route(ha_env, seed, monkeypatch):
    from pegaprox.core.db import get_db
    ha = ha_env.ha
    _admin_c, active, _standby, r = _joined(ha_env, seed, monkeypatch)
    assert r.get_json() == {'success': True, 'restarting': True}
    assert ha_env.restarts == ['joined as standby']
    assert ha_env.installed == [get_db().aes_key]
    assert ha_env.calls == [('POST', ACTIVE_URL, '/api/ha/peer/pair')]

    mine = ha.peer()
    assert ha.role() == 'standby' and ha.epoch() == 1 and ha.instance_id() == B_ID
    assert mine['instance_id'] == A_ID and mine['url'] == ACTIVE_URL
    theirs = _file(active)
    assert theirs['role'] == 'active' and theirs['epoch'] == 1
    assert list(theirs['members']) == [B_ID] and theirs['members'][B_ID]['url'] == STANDBY_URL
    # each side holds the other's public key, and nothing private of it
    assert theirs['members'][B_ID]['public_key'] == ha.own_public_key()
    assert mine['public_key'] == ha._public_of(ha._private_key(theirs['signing_key']))
    assert ha._load()['signing_key'] not in json.dumps(theirs)
    assert theirs['signing_key'] not in json.dumps(ha._load())
    assert theirs['member_secret'] is None and ha._load()['member_secret'] is None
    assert len(_audit('ha.joined')) == 1 and len(_audit('ha.paired')) == 1


def test_join_says_so_when_the_active_cannot_be_reached(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    active, standby = _two_sides(ha_env)
    _switch(ha_env, active)
    code = _code(admin)['code']
    _switch(ha_env, standby)
    _wire_to(ha_env, monkeypatch, active, down=True)
    r = _join(admin, code)
    assert r.status_code == 502 and 'reach' in r.get_json()['error']
    assert ha.role() == 'standalone' and ha.peer() is None
    assert ha_env.restarts == [] and ha_env.installed == []
    assert _file(active)['role'] == 'standalone' and _file(active)['members'] == {}


def test_join_passes_on_the_actives_refusal(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    active, standby = _two_sides(ha_env)
    _switch(ha_env, active)
    info = ha.decode_code(_code(admin)['code'])
    # a code with the right address and id but a secret the active never issued
    forged = ha.encode_code(info['url'], '', 'f' * 43, info['instance_id'])
    _switch(ha_env, standby)
    _wire_to(ha_env, monkeypatch, active)
    r = _join(admin, forged)
    assert r.status_code == 502 and 'wrong or has expired' in r.get_json()['error']
    assert ha.role() == 'standalone' and ha_env.installed == [] and ha_env.restarts == []


def test_join_checks_its_input_before_calling_anyone(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    _wire_to(ha_env, monkeypatch, str(ha_env.tmp / 'nobody.json'), down=True)
    own_code = ha.encode_code(ACTIVE_URL, '', 'f' * 43, ha.instance_id())
    good_code = ha.encode_code(ACTIVE_URL, '', 'f' * 43, A_ID)
    cases = [
        ({'code': good_code, 'own_url': STANDBY_URL}, 400),                  # no confirm
        ({'code': '', 'own_url': STANDBY_URL, 'confirm': True}, 400),
        ({'code': 'pgxha1_%%%', 'own_url': STANDBY_URL, 'confirm': True}, 400),
        ({'code': good_code, 'own_url': 'http://standby.example', 'confirm': True}, 400),
        ({'code': good_code, 'confirm': True}, 400),
        ({'code': own_code, 'own_url': STANDBY_URL, 'confirm': True}, 400),
    ]
    for body, status in cases:
        r = admin.post('/api/ha/join', json=body)
        assert r.status_code == status, (body, r.status_code, r.data)
    _active_with_standby(ha_env)
    r = _join(admin, good_code)
    assert r.status_code == 409
    assert ha_env.calls == [] and ha_env.restarts == [] and ha_env.installed == []


# --- sync -------------------------------------------------------------------------

def test_sync_now_pulls_once_and_then_finds_nothing_new(ha_env, seed, monkeypatch):
    admin, _active, _standby, _r = _joined(ha_env, seed, monkeypatch)
    r = admin.post('/api/ha/sync-now')
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['result'] == 'applied', body['status']['sync']
    assert body['status']['role'] == 'standby'
    assert body['status']['sync']['last_ok_at'] and body['status']['sync']['tables'] > 0
    assert body['status']['sync']['etag'] is None           # not the UI's business
    assert body['status']['peer']['last_contact']

    r = admin.post('/api/ha/sync-now')
    assert r.get_json()['result'] == 'unchanged', r.get_json()['status']['sync']
    assert ha_env.calls[-2:] == [('GET', ACTIVE_URL, '/api/ha/peer/snapshot')] * 2


def test_sync_now_on_an_instance_that_is_not_a_standby(ha_env, seed):
    body = _admin(ha_env.api, seed).post('/api/ha/sync-now').get_json()
    assert body['result'] == 'not a standby'
    assert body['status']['role'] == 'standalone'


def test_the_snapshot_route(ha_env):
    api = ha_env.api
    _active_with_standby(ha_env)
    r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD)
    assert r.status_code == 200
    assert r.headers['Content-Encoding'] == 'gzip'
    assert r.headers['Content-Type'].startswith('application/json')
    assert r.headers['Cache-Control'] == 'no-store'
    snap = json.loads(gzip.decompress(r.get_data()))
    etag = r.headers['ETag'].strip('"')
    assert snap['etag'] == etag
    assert snap['role'] == 'active' and snap['instance_id'] == A_ID and snap['epoch'] == 1
    assert 'users' in snap['tables'] and 'sessions' not in snap['tables']

    # the bare etag is what pull_once sends; a proxy may have quoted it
    for inm in (etag, f'"{etag}"', f'"other", W/"{etag}"'):
        r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD, {'If-None-Match': inm})
        assert r.status_code == 304, inm
        assert r.get_data() == b''
    r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD, {'If-None-Match': 'stale'})
    assert r.status_code == 200

    assert _peer(api, 'GET', '/api/ha/peer/snapshot', None).status_code == 401
    assert _peer(api, 'GET', '/api/ha/peer/snapshot', f'{B_ID}:wrong').status_code == 401

    # a standby never serves one, whoever asks
    _be(ha_env, 'standby', peer=_peer_record())
    r = _peer(api, 'GET', '/api/ha/peer/snapshot', GOOD)
    assert r.status_code == 409 and 'not active' in r.get_json()['error']


# --- promotion and stepping down ---------------------------------------------------

def test_step_down_only_for_a_newer_epoch(ha_env):
    ha, api = ha_env.ha, ha_env.api
    _active_with_standby(ha_env, epoch=3)
    # the same epoch goes to the higher instance id, and B is higher than us: see
    # tests/test_ha_members.py for the tie
    for older in (1, 2):
        r = _peer(api, 'POST', '/api/ha/peer/step-down', GOOD, json={'epoch': older})
        assert r.status_code == 200
        assert r.get_json() == {'stepped_down': False, 'role': 'active', 'epoch': 3}
    for bad in ('4', 4.5, True, 0, -1, None, 2 ** 40):
        r = _peer(api, 'POST', '/api/ha/peer/step-down', GOOD, json={'epoch': bad})
        assert r.status_code == 400, bad
    assert ha.role() == 'active' and ha_env.restarts == []

    r = _peer(api, 'POST', '/api/ha/peer/step-down', GOOD, json={'epoch': 4})
    assert r.get_json() == {'stepped_down': True, 'role': 'standby', 'epoch': 4}
    assert ha_env.restarts == ['stepped down to standby']
    assert len(_audit('ha.stepped_down')) == 1
    assert ha.peer()['role_seen'] == 'active' and ha.peer()['epoch_seen'] == 4

    # only an active steps down
    r = _peer(api, 'POST', '/api/ha/peer/step-down', GOOD, json={'epoch': 5})
    assert r.get_json()['stepped_down'] is False and ha.epoch() == 4
    assert ha_env.restarts == ['stepped down to standby']


def test_promote(ha_env, seed):
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    _standby_of_active(ha_env, epoch=2)
    r = admin.post('/api/ha/promote', json={'confirm': 'PROMOTE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'epoch': 3, 'restarting': True}
    assert ha.role() == 'active' and ha.epoch() == 3
    assert ha_env.restarts == ['promoted to active']
    assert _audit('ha.promoted')[0]['user'] == 'root'
    r = admin.post('/api/ha/promote', json={'confirm': 'PROMOTE', 'user_password': ADMIN_PW})
    assert r.status_code == 409 and ha.epoch() == 3


def test_promote_tells_the_old_active_to_step_down(ha_env, seed, monkeypatch):
    """A reachable old active steps down before the promoted side restarts, not only
    when one of the two watch loops gets round to it."""
    ha = ha_env.ha
    admin, active, standby, _r = _joined(ha_env, seed, monkeypatch)
    assert _file(active)['role'] == 'active'
    r = admin.post('/api/ha/promote', json={'confirm': 'PROMOTE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'epoch': 2, 'restarting': True}
    assert ha_env.calls[-1] == ('POST', ACTIVE_URL, '/api/ha/peer/step-down')
    theirs = _file(active)
    assert theirs['role'] == 'standby' and theirs['epoch'] == 2
    # the old active restarts into its new role before we do
    assert ha_env.restarts[-2:] == ['stepped down to standby', 'promoted to active']
    assert ha.role() == 'active' and ha.epoch() == 2
    assert 'told to step down' in _audit('ha.promoted')[-1]['details']


def test_promote_goes_ahead_when_the_old_active_is_gone(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env, epoch=2)
    _wire_to(ha_env, monkeypatch, str(ha_env.tmp / 'gone.json'), down=True)
    r = admin.post('/api/ha/promote', json={'confirm': 'PROMOTE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    # the sync first finds nobody, which is the failover this is for; then the members are
    # asked whether the group fails over automatically (nobody answers that either)
    assert ha_env.calls == [('GET', ACTIVE_URL, '/api/ha/peer/snapshot'),
                            ('GET', ACTIVE_URL, '/api/ha/peer/status'),
                            ('POST', ACTIVE_URL, '/api/ha/peer/step-down')]
    assert ha.role() == 'active' and ha.epoch() == 3
    assert ha_env.restarts == ['promoted to active']
    assert 'not reached' in _audit('ha.promoted')[-1]['details']


def test_the_irreversible_ones_want_their_confirmation(ha_env, seed):
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    for route, word in (('/api/ha/promote', 'PROMOTE'), ('/api/ha/unpair', 'UNPAIR')):
        for body in (None, {}, {'confirm': word.lower()}, {'confirm': True},
                     {'confirm': word + ' '}, {'confirm': [word]}):
            r = _send(admin, 'post', route, body)
            assert r.status_code == 400, (route, body, r.status_code)
    assert ha.role() == 'standby' and ha.peer()['instance_id'] == A_ID and ha.epoch() == 1

    _be(ha_env, 'standalone')
    code = ha.encode_code(ACTIVE_URL, '', 'f' * 43, 'c' * 32)
    for confirm in (None, False, 'true', 1, 'yes'):
        body = {'code': code, 'own_url': STANDBY_URL}
        if confirm is not None:
            body['confirm'] = confirm
        r = admin.post('/api/ha/join', json=body)
        assert r.status_code == 400 and 'confirm' in r.get_json()['error'], confirm
    assert ha.role() == 'standalone' and ha.peer() is None
    assert ha_env.restarts == [] and ha_env.installed == []


# --- unpairing -----------------------------------------------------------------------

def test_unpairing_a_standby_tells_the_active_and_restarts(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin, active, _standby, _r = _joined(ha_env, seed, monkeypatch)
    r = admin.post('/api/ha/unpair', json={'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'restarting': True}
    assert ha_env.calls[-1] == ('POST', ACTIVE_URL, '/api/ha/peer/unpaired')
    assert ha_env.restarts == ['joined as standby', 'unpaired, standalone from now on']
    assert ha.role() == 'standalone' and ha.peer() is None
    theirs = _file(active)
    assert theirs['role'] == 'standalone' and theirs['members'] == {}
    # one line from each side
    assert len(_audit('ha.unpaired')) == 2


def test_unpairing_the_active_needs_no_restart_nor_a_reachable_peer(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    _active_with_standby(ha_env)
    _wire_to(ha_env, monkeypatch, str(ha_env.tmp / 'gone.json'), down=True)
    r = admin.post('/api/ha/unpair', json={'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'restarting': False}
    assert ha_env.calls == [('POST', STANDBY_URL, '/api/ha/peer/unpaired')]
    assert ha.role() == 'standalone' and ha.peer() is None and ha_env.restarts == []
    assert 'not told' in _audit('ha.unpaired')[0]['details']

    r = admin.post('/api/ha/unpair', json={'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 409


def test_a_standby_the_active_let_go_of_can_still_be_unpaired(ha_env, seed):
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    _be(ha_env, 'standby', instance_id=B_ID)          # the active forgot us first
    r = admin.post('/api/ha/unpair', json={'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200 and r.get_json()['restarting'] is True
    assert ha.role() == 'standalone'


def test_an_active_without_a_peer_can_be_unpaired(ha_env, seed, monkeypatch):
    """The standby the active let go of, promoted afterwards: active, no peer. Unpair
    is its way back to standalone (and from there to joining a rebuilt instance)."""
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    _wire_to(ha_env, monkeypatch, str(ha_env.tmp / 'nobody.json'), down=True)
    _be(ha_env, 'active', instance_id=B_ID, epoch=2)
    r = admin.post('/api/ha/unpair', json={'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    # active and standalone both act, so there is nothing to restart for
    assert r.get_json() == {'success': True, 'restarting': False}
    assert ha.role() == 'standalone' and ha.peer() is None
    assert ha_env.calls == [] and ha_env.restarts == []
    assert 'was active' in _audit('ha.unpaired')[-1]['details']
    # a standalone still has nothing to unpair
    r = admin.post('/api/ha/unpair', json={'confirm': 'UNPAIR', 'user_password': ADMIN_PW})
    assert r.status_code == 409 and 'not paired' in r.get_json()['error']


# --- settings ------------------------------------------------------------------------

def test_the_interval(ha_env, seed):
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    for bad in (4, 3601, '60', 60.0, True, None, [60]):
        r = admin.put('/api/ha/settings', json={'interval': bad})
        assert r.status_code == 400, bad
    assert not os.path.exists(ha.STATE_FILE)
    for good in (5, 3600, 60):
        r = admin.put('/api/ha/settings', json={'interval': good})
        assert r.status_code == 200 and r.get_json() == {'success': True, 'interval': good}
    assert _file(ha.STATE_FILE)['interval'] == 60
    ha.reset_for_tests()
    assert ha.public_status()['interval'] == 60
    assert '3600s -> 60s' in _audit('ha.settings_changed')[-1]['details']


def test_the_interval_leaves_an_unreadable_state_file_alone(ha_env, seed):
    """The placeholder _load builds for a file it cannot read has a new instance id, no
    peer and epoch 0. Saving the interval would write that over the original bytes."""
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    _standby_of_active(ha_env, epoch=7)
    with open(ha.STATE_FILE, 'rb') as fh:
        good = fh.read()
    broken = good[:-40]                                  # a write cut short
    with open(ha.STATE_FILE, 'wb') as fh:
        fh.write(broken)
    ha.reset_for_tests()
    assert ha.public_status()['broken'] and ha.is_standby()

    r = admin.put('/api/ha/settings', json={'interval': 60})
    assert r.status_code == 409 and 'cannot be read' in r.get_json()['error']
    with open(ha.STATE_FILE, 'rb') as fh:
        assert fh.read() == broken
    assert _audit('ha.settings_changed') == []

    # counterproof: the same file, readable, takes the interval and keeps the rest
    with open(ha.STATE_FILE, 'wb') as fh:
        fh.write(good)
    ha.reset_for_tests()
    r = admin.put('/api/ha/settings', json={'interval': 60})
    assert r.status_code == 200, r.data
    st = _file(ha.STATE_FILE)
    assert st['interval'] == 60 and st['epoch'] == 7 and st['instance_id'] == B_ID
    # written in the member form now, the pairing kept
    assert list(st['members']) == [A_ID] and st['source'] == A_ID and 'peer' not in st


# --- the write block on a standby -------------------------------------------------------

def test_a_standby_refuses_config_writes(ha_env, seed):
    from pegaprox.core.db import get_db
    api = ha_env.api
    admin = _admin(api, seed)
    seed.user('someone', role='user')
    _standby_of_active(ha_env)
    probes = [
        ('post', '/api/users', {'username': 'newbie', 'password': 'Longer-Pa55word!', 'role': 'user'}),
        ('delete', '/api/users/someone', None),
        ('post', '/api/settings/server', {'app_name': 'renamed'}),
        ('post', '/api/auth/tokens', {'name': 'ci'}),
        ('post', '/api/auth/change-password', {'current_password': 'x', 'new_password': 'y'}),
        ('put', '/api/user/preferences', {'theme': 'light'}),
        ('post', '/api/auth/2fa/verify', {'code': '123456'}),
        ('post', '/api/no-such-route', {}),
    ]
    for method, path, body in probes:
        r = _send(admin, method, path, body)
        assert r.status_code == 409, (method, path, r.status_code, r.data)
        assert r.get_json()['code'] == 'HA_STANDBY'
        assert 'active instance' in r.get_json()['error']
    # the first-run wizard too, which needs no session at all
    r = api.anon().post('/api/auth/setup', json={'username': 'x', 'password': 'y'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert get_db().get_user('newbie') is None and get_db().get_user('someone') is not None

    # the open /api/ha/ prefix is no way around it
    for sneaky in ('/api/ha/../users', '/api/ha/%2e%2e/users', '/api/ha/..%2fusers', '//api/users'):
        r = admin.post(sneaky, json={'username': 'sneaky', 'password': 'Longer-Pa55word!'})
        assert r.status_code in (308, 404, 405, 409), (sneaky, r.status_code, r.data)
    assert get_db().get_user('sneaky') is None

    # reading goes on
    assert admin.get('/api/users').status_code == 200
    assert admin.get('/api/ha/status').get_json()['role'] == 'standby'
    # the block sits behind the CSRF gate, not in front of it
    r = api.app.test_client().post('/api/users', json={}, base_url='http://localhost',
                                   headers={'X-Session-ID': admin.session_id})
    assert r.status_code == 403 and 'CSRF' in r.get_json()['error']
    # and /api/ha/ stays open: promotion is how a standby gets out
    r = admin.post('/api/ha/promote', json={'confirm': 'PROMOTE', 'user_password': ADMIN_PW})
    assert r.status_code == 200, r.data
    assert ha_env.restarts == ['promoted to active']


def test_the_block_is_the_standbys_alone(ha_env, seed):
    admin = _admin(ha_env.api, seed)
    for role in ('standalone', 'active'):
        _be(ha_env, role, peer=_peer_record() if role == 'active' else None)
        r = admin.put('/api/user/preferences', json={'theme': 'light'})
        assert r.status_code != 409, (role, r.data)


@pytest.fixture
def probe_plugin(monkeypatch):
    """A loaded plugin with one route that writes whatever method reaches it, like the
    bundled status_page generate-key does."""
    import pegaprox.api.plugins as plugins
    hits = []

    def handler():
        from flask import request
        hits.append(request.method)
        return {'success': True, 'written': True}
    monkeypatch.setitem(plugins._loaded_plugins, 'probe', types.SimpleNamespace())
    monkeypatch.setitem(plugins._plugin_routes, 'probe', {'generate-key': handler})
    return hits


def test_a_standby_shuts_the_plugin_proxy_for_every_method(ha_env, seed, probe_plugin):
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    for method in ('get', 'post', 'put', 'delete'):
        r = getattr(admin, method)('/api/plugins/probe/api/generate-key')
        assert r.status_code == 409, (method, r.status_code, r.data)
        assert r.get_json()['code'] == 'HA_STANDBY'
    # the cookie-only link on the plugins page, no Origin and no marker
    r = ha_env.api.app.test_client().get('/api/plugins/probe/api/generate-key',
                                         base_url='http://localhost',
                                         headers={'Cookie': f'session_id={admin.session_id}'})
    assert r.status_code == 409
    assert probe_plugin == []
    # the plugin management pages are not the proxy and still read
    assert admin.get('/api/plugins').status_code == 200

    # counterproof: anywhere else the same call reaches the plugin
    for role, peer in (('standalone', None), ('active', _peer_record())):
        _be(ha_env, role, peer=peer)
        r = admin.get('/api/plugins/probe/api/generate-key')
        assert r.status_code == 200, (role, r.data)
    assert probe_plugin == ['GET', 'GET']


def test_the_rule_the_block_matches_is_the_plugin_proxy(api):
    from pegaprox.core import ha
    rule = next(r for r in api.app.url_map.iter_rules() if r.endpoint == 'plugins.plugin_proxy')
    assert ha.PLUGIN_PROXY_RULE == rule.rule
    # and it is the one the block in app.py goes by
    hook = next(f for f in api.app.before_request_funcs[None] if f.__name__ == 'refuse_writes_on_standby')
    held = dict(zip(hook.__code__.co_freevars, (c.cell_contents for c in hook.__closure__)))
    assert held['_PLUGIN_PROXY_RULE'] == rule.rule
    assert held['_PLUGIN_CONSOLE_PATHS'] is ha.PLUGIN_CONSOLE_PATHS


def _local_writes():
    """_STANDBY_LOCAL_WRITES as create_app holds it."""
    from pegaprox import app as app_mod
    fn = ast.parse(inspect.getsource(app_mod.create_app)).body[0]
    for node in ast.walk(fn):
        target = getattr(node, 'targets', [None])[0]
        if isinstance(node, ast.Assign) and getattr(target, 'id', '') == '_STANDBY_LOCAL_WRITES':
            return set(ast.literal_eval(node.value.args[0]))
    raise AssertionError('no _STANDBY_LOCAL_WRITES in create_app')


def test_every_local_write_names_a_real_route(api):
    served = {(m, r.rule) for r in api.app.url_map.iter_rules() for m in r.methods}
    listed = _local_writes()
    assert listed and listed <= served, listed - served
    # the mixed settings form stays out
    assert not any(rule == '/api/settings/server' for _m, rule in listed)
    # and so does the console token: every caller of it opens a console (v2)
    assert ('POST', '/api/ws/token') not in listed


def test_a_standby_lets_instance_local_writes_through(ha_env, seed, monkeypatch):
    """What changes only this instance - its own sessions, stream tokens, lockouts,
    a restart - is not the active's to make."""
    import pegaprox.api.settings as settings_mod
    from pegaprox.api.helpers import load_server_settings
    from pegaprox.globals import login_attempts_by_ip, login_attempts_by_user
    api = ha_env.api
    admin = _admin(api, seed)
    other = api.as_user({'username': 'root', 'role': 'admin'})    # root's second session
    _standby_of_active(ha_env)
    # /api/auth/check below reports the live view of a standby (v2)
    monkeypatch.setattr(ha_env.ha, 'live_view', lambda: True, raising=False)

    # the caller's own session, by its revocation token
    listing = admin.get('/api/user/sessions').get_json()['sessions']
    token = next(s['revoke_token'] for s in listing if not s['is_current'])
    r = admin.delete(f'/api/user/sessions/{token}')
    assert r.status_code == 200 and r.get_json()['success'], r.data
    assert other.get('/api/auth/check').status_code == 401
    assert admin.get('/api/auth/check').status_code == 200

    r = admin.post('/api/sse/token', json={})
    assert r.status_code == 200 and r.get_json()['token'], r.data
    # v2: the console token is not local any more, a standby opens no console
    r = admin.post('/api/ws/token', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    # and the two reads the live UI sends as POST
    r = admin.post('/api/sse/subscribe', json={'client_id': 'gone-already'})
    assert r.status_code == 200 and r.get_json() == {'ok': False, 'reason': 'client_not_found'}, r.data
    r = admin.post('/api/snapshots/overview', json={})
    assert r.status_code == 200 and r.get_json() == {'snapshots': []}, r.data

    monkeypatch.setitem(login_attempts_by_ip, '198.51.100.9', {'attempts': [], 'locked_until': 9e9})
    monkeypatch.setitem(login_attempts_by_user, 'someone', {'attempts': [], 'locked_until': 9e9})
    assert admin.delete('/api/security/locked-ips/198.51.100.9').status_code == 200
    assert admin.delete('/api/security/locked-users/someone').status_code == 200
    assert admin.delete('/api/security/locked-ips').status_code == 200
    assert admin.delete('/api/security/locked-users').status_code == 200

    # these mean a local change but save back the whole settings dict they loaded; a
    # sync landing in between would be overwritten with the older copy (second review)
    before = load_server_settings().get('hardware_monitoring')
    for path, body in (('/api/hardware-monitoring/consent', {'enabled': False}),
                       ('/api/settings/acme/request', {'domain': ''}),
                       ('/api/settings/acme/dns/complete', {})):
        r = admin.post(path, json=body)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (path, r.data)
    assert load_server_settings().get('hardware_monitoring') == before

    started = []
    monkeypatch.setattr(settings_mod, 'threading', types.SimpleNamespace(
        Thread=lambda target=None, **kw: types.SimpleNamespace(start=lambda: started.append(target),
                                                               daemon=True)))
    r = admin.post('/api/settings/server/restart', json={})
    assert r.status_code == 200 and len(started) == 1, r.data

    # counterproof: a synced write next to them is still refused, and a local route
    # under the wrong method does not borrow the entry
    r = admin.post('/api/settings/server', json={'trusted_proxies': '192.0.2.7'})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    r = admin.post(f'/api/user/sessions/{token}', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


def _local_user(db, tmp_path, monkeypatch, username='ops', role='admin'):
    import pegaprox.utils.auth as authmod
    from pegaprox.utils.auth import hash_password
    marker = tmp_path / '.admin_initialized'
    marker.write_text('x')
    monkeypatch.setattr(authmod, 'ADMIN_INITIALIZED_FILE', str(marker))
    salt, pw_hash = hash_password('C0rrect!horse9')
    db.save_user(username, {'password_salt': salt, 'password_hash': pw_hash, 'role': role,
                            'enabled': True, 'auth_source': 'local'})
    return {'username': username, 'password': 'C0rrect!horse9'}


def test_a_standby_still_signs_people_in_and_out(ha_env, db, tmp_path, monkeypatch):
    api = ha_env.api
    creds = _local_user(db, tmp_path, monkeypatch)
    _standby_of_active(ha_env, sync={'last_ok_at': '2026-09-29T10:00:00+00:00'})
    monkeypatch.setattr(ha_env.ha, 'live_view', lambda: True, raising=False)

    r = api.anon().post('/api/auth/login', json=creds)
    assert r.status_code == 200, r.data
    body = r.get_json()
    banner = {'role': 'standby', 'peer_url': ACTIVE_URL, 'last_sync_at': '2026-09-29T10:00:00+00:00',
              'live_view': True, 'forwarding': False, 'serving': False, 'leader_reachable': True,
              'removed': False}
    assert body['ha'] == banner
    sid = {'X-Session-ID': body['session_id']}
    check = api.anon().get('/api/auth/check', headers=sid)
    assert check.status_code == 200 and check.get_json()['ha'] == banner

    # the hardware-key steps are part of signing in; whatever they answer, it is not the block
    for path in ('/api/webauthn/auth/begin', '/api/webauthn/auth/finish'):
        r = api.anon().post(path, json={'username': 'ops'})
        assert r.status_code != 409, (path, r.data)
    r = api.anon().post('/api/auth/oidc/callback', json={'code': 'x', 'state': 'y'})
    assert r.status_code != 409, r.data

    assert api.anon().post('/api/auth/logout', headers=sid).status_code == 200
    assert api.anon().get('/api/auth/check', headers=sid).status_code == 401


def test_the_login_answer_and_the_check_carry_the_role(ha_env, db, tmp_path, monkeypatch):
    api = ha_env.api
    creds = _local_user(db, tmp_path, monkeypatch)
    for role, peer in (('standalone', None), ('active', _peer_record())):
        _be(ha_env, role, peer=peer)
        body = api.anon().post('/api/auth/login', json=creds).get_json()
        # an active says what it is, not where its standby lives
        assert body['ha'] == {'role': role}, body.get('ha')
        sid = {'X-Session-ID': body['session_id']}
        assert api.anon().get('/api/auth/check', headers=sid).get_json()['ha'] == {'role': role}


def test_the_login_page_learns_the_role_and_nothing_more(ha_env):
    api = ha_env.api
    r = api.anon().get('/api/auth/check')
    assert r.status_code == 401
    assert r.get_json()['ha_role'] == 'standalone' and 'ha' not in r.get_json()
    _standby_of_active(ha_env)
    r = api.anon().get('/api/auth/check')
    assert r.status_code == 401 and r.get_json()['ha_role'] == 'standby'
    assert 'ha' not in r.get_json() and ACTIVE_URL not in r.get_data(as_text=True)


# --- CSRF and the real client -----------------------------------------------------------

def test_what_the_real_client_sends_passes_the_csrf_gate(ha_env, monkeypatch):
    """Take the headers ha._peer_call really builds and replay them against the app:
    no CSRF exemption is needed, and none was added."""
    import requests
    import pegaprox.utils.url_security as urlsec
    ha, api = ha_env.ha, ha_env.api
    # epoch 2: the replayed epoch 1 is older, so the call is answered and changes nothing
    _active_with_standby(ha_env, epoch=2)
    monkeypatch.setattr(urlsec, 'is_safe_outbound_url', lambda *a, **k: (True, ''))
    sent = {}

    def capture(self, method, url, **kw):
        sent.update(kw.get('headers') or {})
        sent['body'] = kw.get('data')
        return types.SimpleNamespace(status_code=200, headers={})
    monkeypatch.setattr(requests.Session, 'request', capture)
    # what call_member sends the standby: signed for it, and while the standby may not
    # hold our key yet, the secret from the pair state file and the key along with it
    ha.call_member(dict(ha.peer(), instance_id=B_ID), 'POST', '/api/ha/peer/step-down',
                   json_body={'epoch': 1})
    body = sent.pop('body')
    assert body == b'{"epoch":1}' and sent['Content-Type'] == 'application/json'
    assert sent['X-Requested-With'] == 'XMLHttpRequest'
    assert 'Origin' not in sent and 'Referer' not in sent
    assert sent[ha.PEER_HEADER] == f"{A_ID}:{'y' * 43}"
    assert sent[ha.PEER_KEY_HEADER] == ha.own_public_key()
    assert sent[ha.PEER_SIG_HEADER] and sent[ha.PEER_NONCE_HEADER] and sent[ha.PEER_TS_HEADER]

    # the same shape from the standby's side (it goes by its secret), and the gate
    # lets it through
    replay = {k: v for k, v in sent.items() if not k.startswith('X-PegaProx-Peer')}
    replay[ha.PEER_HEADER] = GOOD
    client = api.app.test_client()
    r = client.post('/api/ha/peer/step-down', data=body, headers=replay,
                    base_url='http://localhost')
    assert r.status_code == 200, r.data
    # the gate is on for these paths: without the marker, or from a foreign page, no
    no_marker = {k: v for k, v in replay.items() if k != 'X-Requested-With'}
    r = client.post('/api/ha/peer/step-down', data=body, headers=no_marker,
                    base_url='http://localhost')
    assert r.status_code == 403 and 'CSRF' in r.get_json()['error']
    r = client.post('/api/ha/peer/step-down', data=body,
                    headers=dict(replay, Origin='https://evil.example'), base_url='http://localhost')
    assert r.status_code == 403
    assert ha.role() == 'active'


# --- the published description ------------------------------------------------------------

def test_the_spec_says_what_the_peer_routes_take(api):
    from pegaprox.cli.gen_openapi import build
    paths = build(api.app)
    for method, path in PEER_ROUTES:
        op = paths[path][method.lower()]
        assert op['x-pegaprox-auth'] == 'inline', path
        if path in ('/api/ha/peer/pair', '/api/ha/peer/pair-witness'):
            assert op['security'] == [], 'the code in the body is the credential'
        else:
            assert op['security'] == [{'haPeer': []}], path
    for method, path, _b in ADMIN_ROUTES:
        op = paths[path.replace(B_ID, '{instance_id}').replace(ORPHAN, '{name}')][method]
        assert op['x-pegaprox-roles'] == ['admin'], path


# --- boot wiring ------------------------------------------------------------------------------

def _calls_in(nodes):
    names = set()
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                names.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', ''))
    return names


def test_a_standby_boots_without_managers_and_acting_starters():
    """main() cannot run in a test (it binds a port), so read it: everything that
    rewrites run state sits behind the standby check, and the peer loop starts in
    every role. The managers go by managers_wanted() since the live view, see
    tests/test_ha_v2_managers.py."""
    from pegaprox import app as app_mod
    fn = ast.parse(inspect.getsource(app_mod.main)).body[0]
    guarded = set()
    for node in fn.body:
        if isinstance(node, ast.If) and 'standby' in ast.unparse(node.test):
            acting = node.orelse if ast.unparse(node.test) == 'standby' else node.body
            guarded |= _calls_in(acting)
    for starter in ('start_heartbeat', 'start_plugin_backgrounds'):
        assert starter in guarded, starter
    top_level = _calls_in([n for n in fn.body if not isinstance(n, ast.If)])
    assert 'start_loop' in top_level
    assert 'start_loop' not in guarded


def _call_lines(fn, name):
    def callee(f):
        return getattr(f, 'attr', None) or getattr(f, 'id', None)
    return [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call) and callee(n.func) == name]


def test_an_old_active_asks_its_peer_before_anything_can_act():
    """A crashed active whose standby got promoted still reads "active" from its file.
    main() asks the peer before create_app(), whose imports start the first loops, and
    so before every manager and acting loop - and before it reads the role."""
    from pegaprox import app as app_mod
    fn = ast.parse(inspect.getsource(app_mod.main)).body[0]
    boot = _call_lines(fn, 'check_peer_at_boot')
    assert len(boot) == 1, 'main() asks the peer exactly once'
    call = next(n for n in ast.walk(fn) if isinstance(n, ast.Call)
                and getattr(n.func, 'attr', None) == 'check_peer_at_boot')
    assert [(k.arg, getattr(k.value, 'value', None)) for k in call.keywords] == [('timeout', 5)]
    for later in ('create_app', 'is_standby', 'managers_wanted', 'boot_pull', '_start_managers',
                  'start_alert_thread', 'start_scheduler_thread', 'start_actions_scheduler',
                  'start_password_expiry_thread', 'start_cross_cluster_lb_thread',
                  'start_cross_cluster_replication_thread', 'start_heartbeat',
                  'start_plugin_backgrounds', 'start_loop'):
        lines = _call_lines(fn, later)
        assert lines and boot[0] < min(lines), later


def test_nothing_before_the_boot_check_starts_a_thread():
    """The boot check sits before create_app() because importing pegaprox.app itself
    starts nothing: the first loops come with the blueprint imports inside create_app()."""
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run([sys.executable, '-c',
                          'import threading, pegaprox.app, pegaprox.core.ha, sys; '
                          'print(len(threading.enumerate()), "pegaprox.api.storage" in sys.modules)'],
                         cwd=root, capture_output=True, text=True, timeout=120,
                         env=dict(os.environ, PEGAPROX_NO_GEVENT='1'))
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.split()[-2:] == ['1', 'False'], out.stdout
