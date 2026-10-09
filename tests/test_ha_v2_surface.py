"""Warm standby v2 (#625): what a standby with live cluster connections may do over HTTP.

v1 was safe because a standby had no managers: nothing it served could reach a
cluster. In v2 it connects read-only, so everything that is not a read is closed in
the handler itself, not only by the write block, which never sees a GET or a
WebSocket upgrade:

  * every console path - the GET routes, the three VNC WebSocket handlers, the node
    shell, the SSH server's validate and cluster-creds calls - answers the standby
    refusal before it looks for a manager, with a ws token and with the old ?session=;
  * POST /api/ws/token is shut (every caller opens a console), the two POST reads the
    live UI needs are open;
  * GETs with a side effect: the efficient-snapshot refresh is ignored, the VAPID key
    is read and never generated or rewritten;
  * the live view switch and "apply now" under /api/ha/, and the banner field.

Every refusal has its counterproof: the same call on an active instance gets past the
gate and does look the cluster up. The managers are fakes and the cluster registry
records every lookup, so "before any cluster_managers lookup" is checked as such.
"""
import ast
import asyncio
import inspect
import json
import textwrap
import types

import pytest

from test_ha_api import (  # noqa: F401  (ha_env is a fixture)
    ha_env, _admin, _audit, _be, _file, _peer_record, _standby_of_active,
    _active_with_standby, _local_user, ACTIVE_URL,
)

CID = 'c1'
VM = f'/api/clusters/{CID}/vms/n1/qemu/100'
STANDBY_ANSWER = {'code': 'HA_STANDBY', 'error': 'Consoles are only available on the active instance.'}


class _Lookups(dict):
    """cluster_managers that notes every key anyone asks it about."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.asked = []

    def __contains__(self, key):
        self.asked.append(key)
        return super().__contains__(key)

    def __getitem__(self, key):
        self.asked.append(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.asked.append(key)
        return super().get(key, default)


def _registry(monkeypatch, **managers):
    """One recording registry behind every name the console paths read it through."""
    import pegaprox.globals as ppglobals
    import pegaprox.api.vms as vms
    import pegaprox.api.auth as auth_api
    reg = _Lookups(managers)
    for mod in (ppglobals, vms, auth_api):
        monkeypatch.setattr(mod, 'cluster_managers', reg)
    return reg


def _fake_manager(api):
    m = api.make_fake_manager(CID)
    m.config.name = CID
    m.host, m.api_port = '192.0.2.10', 8006
    m.is_connected = True
    return m


def _roles(env):
    """(role, set it) for the two roles that act, as counterproof to the standby."""
    return (('active', lambda: _active_with_standby(env)),
            ('standalone', lambda: _be(env, 'standalone')))


# --- the console GET routes ------------------------------------------------------------

def _console_calls(monkeypatch):
    from pegaprox.utils import vnc_grab
    import pegaprox.api.vms as vms
    monkeypatch.setattr(vnc_grab, 'screendump_to_png', lambda *a, **k: b'\x89PNG-frame', raising=False)
    monkeypatch.setattr(vms, '_vm_screenshot_cache', {})
    return {
        f'{VM}/console': ('get_vnc_ticket', {'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'}),
        f'{VM}/vnc': ('get_vnc_ticket', {'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'}),
        f'{VM}/spice': ('get_spice_ticket', {'success': True, 'data': {'type': 'spice', 'host': 'pve'}}),
        f'{VM}/screenshot?fresh=1': (None, None),
    }


def test_the_console_routes_refuse_on_a_standby_before_the_cluster_lookup(ha_env, seed, monkeypatch):
    api = ha_env.api
    admin = _admin(api, seed)
    mgr = _fake_manager(api)
    reg = _registry(monkeypatch, **{CID: mgr})
    calls = _console_calls(monkeypatch)
    _standby_of_active(ha_env)
    for path in calls:
        r = admin.get(path)
        assert r.status_code == 409, (path, r.status_code, r.data)
        assert r.get_json() == STANDBY_ANSWER, path
    assert reg.asked == []
    assert mgr.get_vnc_ticket.call_count == 0 and mgr.get_spice_ticket.call_count == 0


def test_the_console_routes_work_as_before_where_the_instance_acts(ha_env, seed, monkeypatch):
    api = ha_env.api
    admin = _admin(api, seed)
    mgr = _fake_manager(api)
    reg = _registry(monkeypatch, **{CID: mgr})
    calls = _console_calls(monkeypatch)
    for method, ret in calls.values():
        if method:
            getattr(mgr, method).return_value = ret
    for role, be in _roles(ha_env):
        be()
        for path, (method, _ret) in calls.items():
            reg.asked.clear()
            r = admin.get(path)
            assert r.status_code == 200, (role, path, r.status_code, r.data)
            assert CID in reg.asked, (role, path)
    assert mgr.get_vnc_ticket.call_count == 4 and mgr.get_spice_ticket.call_count == 2


# --- the WebSocket paths ------------------------------------------------------------------

class _SyncWS:
    """What flask-sock and geventwebsocket hand a handler, as far as they are used."""

    def __init__(self):
        self.sent, self.closed = [], None

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        raise ConnectionError('the test does not talk back')

    def close(self, *args, **kwargs):
        self.closed = (args, kwargs)


class _AsyncWS:
    """The websockets server connection the standalone handlers get."""

    def __init__(self, path):
        self.request = types.SimpleNamespace(path=path)
        self.sent, self.closed = [], None

    async def send(self, data):
        self.sent.append(data)

    async def recv(self):
        raise ConnectionError('the test does not talk back')

    async def close(self, code=1000, reason=''):
        self.closed = (code, reason)


def _sock_handler(app, rule):
    """The function behind a flask-sock route. Sock.route returns None, so the module
    attribute is gone; the view keeps the original as __wrapped__."""
    for r in app.url_map.iter_rules():
        if r.rule == rule and getattr(r, 'websocket', False):
            return app.view_functions[r.endpoint].__wrapped__
    raise AssertionError(f'no websocket route {rule}')


def _auth_query(kind, admin):
    if kind == 'session':
        return f'session={admin.session_id}'
    from pegaprox.utils.realtime import create_ws_token
    return f'token={create_ws_token("root", "admin")}'


@pytest.mark.parametrize('auth', ['token', 'session'])
def test_the_main_port_vnc_socket(ha_env, seed, monkeypatch, auth):
    api = ha_env.api
    admin = _admin(api, seed)
    reg = _registry(monkeypatch)
    handler = _sock_handler(api.app, '/api/clusters/<cluster_id>/vms/<node>/<vm_type>/<int:vmid>/vncwebsocket')
    path = f'{VM}/vncwebsocket'

    _standby_of_active(ha_env)
    ws = _SyncWS()
    with api.app.test_request_context(f'{path}?{_auth_query(auth, admin)}'):
        handler(ws, CID, 'n1', 'qemu', 100)
    assert ws.sent == [STANDBY_ANSWER['error']]
    assert ws.closed == ((), {'reason': 1008, 'message': STANDBY_ANSWER['error']})
    assert reg.asked == []

    for role, be in _roles(ha_env):
        be()
        ws = _SyncWS()
        with api.app.test_request_context(f'{path}?{_auth_query(auth, admin)}'):
            handler(ws, CID, 'n1', 'qemu', 100)
        assert reg.asked and reg.asked[-1] == CID, role     # it went looking: not found
        assert STANDBY_ANSWER['error'] not in ws.sent


def test_the_gevent_vnc_socket(ha_env, seed, monkeypatch):
    """The HTTP route in front of handle_vnc_websocket, with the upgraded socket in the
    environ the way geventwebsocket puts it there. It takes only ?session=."""
    api = ha_env.api
    admin = _admin(api, seed)
    reg = _registry(monkeypatch)
    client = api.app.test_client()
    url = f'{VM}/vncwebsocket?session={admin.session_id}'

    _standby_of_active(ha_env)
    ws = _SyncWS()
    r = client.get(url, base_url='http://localhost', environ_base={'wsgi.websocket': ws})
    assert r.status_code == 200
    assert ws.closed == ((1008, STANDBY_ANSWER['error']), {})
    assert reg.asked == []

    for role, be in _roles(ha_env):
        be()
        ws = _SyncWS()
        client.get(url, base_url='http://localhost', environ_base={'wsgi.websocket': ws})
        assert reg.asked and reg.asked[-1] == CID, role
        assert ws.closed is None, role


def _standalone_vnc_handler(reg):
    """vnc_handler lives inside start_vnc_websocket_server, which binds a port. Compile
    the nested coroutine on its own against the module's names instead; the paths
    tested here return before anything from the enclosing function is read."""
    import pegaprox.api.vms as vms
    outer = ast.parse(textwrap.dedent(inspect.getsource(vms.start_vnc_websocket_server))).body[0]
    inner = next(n for n in ast.walk(outer)
                 if isinstance(n, ast.AsyncFunctionDef) and n.name == 'vnc_handler')
    ns = dict(vms.__dict__, cluster_managers=reg)
    exec(compile(ast.Module(body=[inner], type_ignores=[]), vms.__file__, 'exec'), ns)
    return ns['vnc_handler']


@pytest.mark.parametrize('auth', ['token', 'session'])
def test_the_standalone_vnc_server(ha_env, seed, monkeypatch, auth):
    api = ha_env.api
    admin = _admin(api, seed)
    reg = _registry(monkeypatch)
    handler = _standalone_vnc_handler(reg)
    path = f'{VM}/vncwebsocket'

    _standby_of_active(ha_env)
    ws = _AsyncWS(f'{path}?{_auth_query(auth, admin)}')
    asyncio.run(handler(ws))
    assert ws.closed == (1008, STANDBY_ANSWER['error'])
    assert reg.asked == []

    for role, be in _roles(ha_env):
        be()
        ws = _AsyncWS(f'{path}?{_auth_query(auth, admin)}')
        asyncio.run(handler(ws))
        assert ws.closed == (1002, 'Cluster not found'), (role, ws.closed)
        assert reg.asked and reg.asked[-1] == CID, role


def test_the_legacy_node_shell_socket(ha_env, seed, monkeypatch):
    """/shellws on the main port, here with ?session= (it takes ?token= first, #1143)."""
    api = ha_env.api
    admin = _admin(api, seed)
    reg = _registry(monkeypatch)
    handler = _sock_handler(api.app, '/api/clusters/<cluster_id>/nodes/<node>/shellws')
    url = f'/api/clusters/{CID}/nodes/n1/shellws?session={admin.session_id}'

    _standby_of_active(ha_env)
    ws = _SyncWS()
    with api.app.test_request_context(url):
        handler(ws, CID, 'n1')
    assert [json.loads(m) for m in ws.sent] == [{'status': 'error', 'message': STANDBY_ANSWER['error']}]
    assert reg.asked == []
    # the page's ws token alike, and a standby does not spend it
    from pegaprox.utils.realtime import ws_tokens
    token_query = _auth_query('token', admin)
    ws = _SyncWS()
    with api.app.test_request_context(f'/api/clusters/{CID}/nodes/n1/shellws?{token_query}'):
        handler(ws, CID, 'n1')
    assert [json.loads(m) for m in ws.sent] == [{'status': 'error', 'message': STANDBY_ANSWER['error']}]
    assert token_query[len('token='):] in ws_tokens and reg.asked == []

    pytest.importorskip('paramiko')
    for role, be in _roles(ha_env):
        be()
        for query in (f'session={admin.session_id}', _auth_query('token', admin)):
            ws = _SyncWS()
            with api.app.test_request_context(f'/api/clusters/{CID}/nodes/n1/shellws?{query}'):
                handler(ws, CID, 'n1')
            assert [json.loads(m)['message'] for m in ws.sent] == ['Cluster not found'], (role, query)
            assert reg.asked and reg.asked[-1] == CID, role


def test_the_ws_token_validation_the_ssh_server_asks(ha_env, seed, monkeypatch):
    """GET /api/ws/token/validate: the node shell and the VM terminal of the SSH server."""
    from pegaprox.utils.realtime import create_ws_token
    api = ha_env.api
    _admin(api, seed)
    reg = _registry(monkeypatch)
    client = api.app.test_client()

    def validate():
        token = create_ws_token('root', 'admin')
        return client.get(f'/api/ws/token/validate?token={token}&cluster_id={CID}&node=n1&shell=node',
                          base_url='http://localhost')

    _standby_of_active(ha_env)
    r = validate()
    assert r.status_code == 409 and r.get_json() == STANDBY_ANSWER
    assert reg.asked == []

    for role, be in _roles(ha_env):
        be()
        r = validate()
        assert r.status_code == 200 and r.get_json()['valid'] is True, (role, r.data)
        assert reg.asked and reg.asked[-1] == CID, role


def test_the_cluster_creds_route_of_the_legacy_shell(ha_env, seed, monkeypatch):
    """GET /api/internal/cluster-creds: node addresses and a PVE ticket for a shell."""
    api = ha_env.api
    admin = _admin(api, seed)
    reg = _registry(monkeypatch)
    client = api.app.test_client()
    # the SSH server sends the browser's session as the cookie `session`
    client.set_cookie('session', admin.session_id, domain='localhost')

    def creds():
        return client.get(f'/api/internal/cluster-creds/{CID}', base_url='http://localhost')

    _standby_of_active(ha_env)
    r = creds()
    assert r.status_code == 409 and r.get_json() == STANDBY_ANSWER
    assert reg.asked == []

    for role, be in _roles(ha_env):
        be()
        r = creds()
        assert r.status_code == 404 and r.get_json()['error'] == 'Cluster not found', (role, r.data)
        assert reg.asked == [CID], role
        reg.asked.clear()


# --- the SSH server subprocess ------------------------------------------------------------

class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body if body is not None else {}

    def json(self):
        return self._body


def _ssh_server(answers):
    """The script start_ssh_websocket_server writes and runs, loaded without running
    its server, with requests answering from `answers` (URL fragment -> _Resp)."""
    import pegaprox.api.vms as vms
    fn = ast.parse(textwrap.dedent(inspect.getsource(vms.start_ssh_websocket_server))).body[0]
    script = next(n.value.value for n in ast.walk(fn) if isinstance(n, ast.Assign)
                  and getattr(n.targets[0], 'id', '') == 'server_script')
    ns = {'__name__': 'ssh_ws_server_under_test'}
    exec(compile(script, '.ssh_ws_server.py', 'exec'), ns)
    asked = []

    def get(url, **kw):
        asked.append(url)
        for part, resp in answers.items():
            if part in url:
                return resp
        raise AssertionError(f'unexpected call {url}')
    ns['requests'] = types.SimpleNamespace(get=get, exceptions=ns['requests'].exceptions)
    return ns, asked


STANDBY_409 = _Resp(409, dict(STANDBY_ANSWER))
SHELL = f'/api/clusters/{CID}/nodes/n1/shellws'
TERM = f'{VM}/termwebsocket'


@pytest.mark.parametrize('path, answers', [
    (f'{SHELL}?token=t', {'/api/ws/token/validate': STANDBY_409}),
    (f'{SHELL}?session=s', {'/api/auth/validate': _Resp(200, {'valid': True}),
                            '/api/internal/cluster-creds/': STANDBY_409}),
    (f'{TERM}?token=t&ticket=x&port=5900&host=h&user=u', {'/api/ws/token/validate': STANDBY_409}),
    (f'{TERM}?session=s&ticket=x&port=5900&host=h&user=u',
     {'/api/auth/validate': _Resp(200, {'valid': True}), '/api/internal/cluster-creds/': STANDBY_409}),
])
def test_the_ssh_server_passes_the_standby_answer_on(path, answers):
    pytest.importorskip('paramiko')
    pytest.importorskip('websockets')
    ns, asked = _ssh_server(answers)
    ws = _AsyncWS(path)
    asyncio.run(ns['ssh_handler'](ws))
    assert [json.loads(m) for m in ws.sent] == [{'status': 'error', 'message': STANDBY_ANSWER['error']}]
    assert ws.closed == (1008, 'standby')
    assert len(asked) == len(answers)


def test_the_ssh_server_keeps_its_other_answers():
    """Counterproof: a refused token and a 409 that is not the standby's still end the
    way they did."""
    pytest.importorskip('paramiko')
    pytest.importorskip('websockets')
    for resp in (_Resp(401, {'error': 'Invalid or expired token'}), _Resp(409, {'error': 'something else'})):
        ns, _asked = _ssh_server({'/api/ws/token/validate': resp})
        ws = _AsyncWS(f'{SHELL}?token=t')
        asyncio.run(ns['ssh_handler'](ws))
        assert ws.closed == (1008, 'Invalid auth'), resp.status_code
        assert STANDBY_ANSWER['error'] not in ws.sent[0]


# --- tokens and the two reads -------------------------------------------------------------

def test_a_standby_mints_no_console_token(ha_env, seed):
    from pegaprox.globals import ws_tokens
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    before = set(ws_tokens)
    r = admin.post('/api/ws/token', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert set(ws_tokens) == before
    # the stream token beside it stays open
    r = admin.post('/api/sse/token', json={})
    assert r.status_code == 200 and r.get_json()['token']

    for role, be in _roles(ha_env):
        be()
        r = admin.post('/api/ws/token', json={})
        assert r.status_code == 200 and r.get_json()['token'], (role, r.data)


def test_a_standby_serves_the_two_reads_that_come_as_post(ha_env, seed, monkeypatch):
    """The SSE subscription change and the snapshot overview. Neither writes: the first
    changes which clusters this instance's stream carries, the second only calls the
    manager's read methods."""
    from pegaprox.globals import sse_clients
    api = ha_env.api
    admin = _admin(api, seed)
    mgr = _fake_manager(api)
    mgr.get_vm_resources.return_value = [{'vmid': 100, 'node': 'n1', 'type': 'qemu', 'name': 'web'}]
    mgr.get_snapshots.return_value = [{'name': 'before-upgrade', 'snaptime': 1_700_000_000}]
    api.set_manager(CID, mgr)
    monkeypatch.setitem(sse_clients, 'client-1', {'user': 'root', 'clusters': []})
    _standby_of_active(ha_env)

    r = admin.post('/api/sse/subscribe', json={'client_id': 'client-1', 'clusters': [CID]})
    assert r.status_code == 200 and r.get_json() == {'ok': True, 'clusters': [CID]}, r.data
    assert sse_clients['client-1']['clusters'] == [CID]

    r = admin.post('/api/snapshots/overview', json={'cluster_id': CID})
    assert r.status_code == 200, r.data
    assert [s['snapshot_name'] for s in r.get_json()['snapshots']] == ['before-upgrade']
    # refresh_ip_cache: the subscribe route kicks it for a newly watched cluster, and it
    # only reads guest-agent addresses into memory
    called = {c[0].split('.')[0] for c in mgr.method_calls}
    assert called <= {'get_vm_resources', 'get_snapshots', 'refresh_ip_cache'}, called

    # a write beside them stays shut
    r = admin.post('/api/snapshots/delete', json={'snapshots': []})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'


def test_the_write_block_names_actions_too(ha_env, seed):
    api = ha_env.api
    admin = _admin(api, seed)
    mgr = api.set_manager(CID, _fake_manager(api))
    _standby_of_active(ha_env)
    r = admin.post(f'{VM}/start', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert 'act on the active instance' in r.get_json()['error']
    assert mgr.method_calls == []


# --- GETs with a side effect ------------------------------------------------------------------

def test_a_standby_does_not_refresh_efficient_snapshots(ha_env, seed):
    api = ha_env.api
    admin = _admin(api, seed)
    mgr = api.set_manager(CID, _fake_manager(api))
    mgr.get_efficient_snapshots.return_value = []
    url = f'{VM}/efficient-snapshots?refresh=true'

    _standby_of_active(ha_env)
    assert admin.get(url).status_code == 200
    assert mgr.get_efficient_snapshots.call_args.kwargs['refresh_usage'] is False

    for role, be in _roles(ha_env):
        be()
        assert admin.get(url).status_code == 200
        assert mgr.get_efficient_snapshots.call_args.kwargs['refresh_usage'] is True, role
        # and nobody refreshes when nobody asked
        assert admin.get(f'{VM}/efficient-snapshots').status_code == 200
        assert mgr.get_efficient_snapshots.call_args.kwargs['refresh_usage'] is False, role


def _vapid_row():
    from pegaprox.core.db import get_db
    r = get_db().conn.cursor().execute(
        "SELECT value FROM server_settings WHERE key = 'webpush_vapid_keypair'").fetchone()
    return r['value'] if r else None


def _store_vapid(value):
    from pegaprox.core.db import get_db
    db = get_db()
    db.conn.cursor().execute('INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)',
                             ('webpush_vapid_keypair', json.dumps(value)))
    db.conn.commit()


def test_a_standby_hands_out_the_synced_vapid_key_and_writes_nothing(ha_env, seed):
    import pegaprox.api.push as push
    from pegaprox.core.db import get_db
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)

    # nothing synced yet: no keypair of its own
    r = admin.get('/api/push/vapid-key')
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.data
    assert _vapid_row() is None

    # the active's key, as the sync delivers it
    kp = push._generate_vapid_keypair()
    _store_vapid({'private_pem': get_db()._encrypt(kp['private_pem']), 'public_b64': kp['public_b64']})
    row = _vapid_row()
    r = admin.get('/api/push/vapid-key')
    assert r.status_code == 200 and r.get_json() == {'public_key': kp['public_b64']}
    assert _vapid_row() == row

    # a legacy plaintext row is the active's to migrate, and one this instance cannot
    # decrypt is no reason to make a new one
    for stored in ({'private_pem': kp['private_pem'], 'public_b64': kp['public_b64']},
                   {'private_pem': 'aes256:not-for-this-key', 'public_b64': kp['public_b64']}):
        _store_vapid(stored)
        row = _vapid_row()
        r = admin.get('/api/push/vapid-key')
        assert r.status_code == 200 and r.get_json() == {'public_key': kp['public_b64']}
        assert _vapid_row() == row


def test_an_acting_instance_still_makes_and_migrates_its_vapid_key(ha_env, seed):
    import pegaprox.api.push as push
    admin = _admin(ha_env.api, seed)
    for role, be in _roles(ha_env):
        be()
        _store_vapid({})
        r = admin.get('/api/push/vapid-key')
        assert r.status_code == 200, (role, r.data)
        stored = json.loads(_vapid_row())
        assert stored['public_b64'] == r.get_json()['public_key']
        assert stored['private_pem'].startswith(('aes256:', 'enc:')), role
    kp = push._generate_vapid_keypair()
    _store_vapid({'private_pem': kp['private_pem'], 'public_b64': kp['public_b64']})
    assert ha_env.api.as_user({'username': 'root', 'role': 'admin'}).get('/api/push/vapid-key').status_code == 200
    assert json.loads(_vapid_row())['private_pem'].startswith(('aes256:', 'enc:'))


# --- live view and apply-config -------------------------------------------------------------

@pytest.fixture
def live(ha_env, monkeypatch):
    """The core half of the contract, as the routes see it. apply_config_now says what it
    did: 'restart', 'reload' (the managers rebuilt in place) or False."""
    box = types.SimpleNamespace(value=True, sets=[], applied=[], apply_result='restart')

    def set_live_view(value):
        box.sets.append(value)
        box.value = bool(value)

    def apply_config_now():
        box.applied.append(ha_env.ha.role())
        return box.apply_result

    monkeypatch.setattr(ha_env.ha, 'live_view', lambda: box.value, raising=False)
    monkeypatch.setattr(ha_env.ha, 'set_live_view', set_live_view, raising=False)
    monkeypatch.setattr(ha_env.ha, 'apply_config_now', apply_config_now, raising=False)
    return box


def test_switching_the_live_view_restarts_a_standby(ha_env, seed, live):
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    r = admin.put('/api/ha/settings', json={'live_view': False})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'live_view': False, 'restarting': True}
    assert live.sets == [False] and live.applied == ['standby']
    assert 'live view off, restarting' in _audit('ha.live_view_changed')[-1]['details']

    # the same value again changes nothing and restarts nothing
    r = admin.put('/api/ha/settings', json={'live_view': False})
    assert r.get_json() == {'success': True, 'live_view': False, 'restarting': False}
    assert live.applied == ['standby'] and len(_audit('ha.live_view_changed')) == 1

    r = admin.put('/api/ha/settings', json={'live_view': True})
    assert r.get_json()['restarting'] is True and live.applied == ['standby', 'standby']
    assert 'live view on' in _audit('ha.live_view_changed')[-1]['details']


def test_elsewhere_the_live_view_is_only_saved(ha_env, seed, live):
    admin = _admin(ha_env.api, seed)
    for role, be in _roles(ha_env):
        be()
        live.value = True
        r = admin.put('/api/ha/settings', json={'live_view': False})
        assert r.status_code == 200, (role, r.data)
        assert r.get_json() == {'success': True, 'live_view': False, 'restarting': False}
    assert live.sets == [False, False] and live.applied == []
    assert ha_env.restarts == []


def test_the_live_view_takes_a_boolean_only(ha_env, seed, live):
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    for bad in ('false', 0, 1, None, [], {}):
        r = admin.put('/api/ha/settings', json={'live_view': bad})
        assert r.status_code == 400, bad
    r = admin.put('/api/ha/settings', json={})
    assert r.status_code == 400
    # a bad interval next to a good live view saves neither
    r = admin.put('/api/ha/settings', json={'live_view': False, 'interval': 2})
    assert r.status_code == 400
    assert live.sets == [] and live.applied == []


def test_interval_and_live_view_in_one_call(ha_env, seed, live):
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    r = admin.put('/api/ha/settings', json={'interval': 90, 'live_view': False})
    assert r.get_json() == {'success': True, 'interval': 90, 'live_view': False, 'restarting': True}
    assert _file(ha_env.ha.STATE_FILE)['interval'] == 90
    assert live.sets == [False] and live.applied == ['standby']


def test_the_live_view_leaves_an_unreadable_state_file_alone(ha_env, seed, live):
    ha, admin = ha_env.ha, _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    with open(ha.STATE_FILE, 'r+', encoding='utf-8') as fh:
        good = fh.read()
        fh.seek(0)
        fh.write(good[:-40])
        fh.truncate()
    ha.reset_for_tests()
    r = admin.put('/api/ha/settings', json={'live_view': False})
    assert r.status_code == 409 and 'cannot be read' in r.get_json()['error']
    assert live.sets == [] and live.applied == []


def test_apply_config_on_a_standby(ha_env, seed, live, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    real = ha.public_status
    pending = {'since': '2026-09-30T08:00:00+00:00', 'reason': 'the live view was switched off'}
    monkeypatch.setattr(ha, 'public_status',
                        lambda: dict(real(), sync=dict(real()['sync'], restart_pending=pending)))
    # no password: it only moves the restart forward
    r = admin.post('/api/ha/apply-config', json={})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'success': True, 'restarting': True, 'reloaded': False}
    assert live.applied == ['standby']
    assert _audit('ha.config_applied')[-1]['details'] == (
        'restarting this standby now for the waiting change: the live view was switched off')

    # an admin API token may do it too
    from pegaprox.utils.auth import create_api_token
    tok = create_api_token('root', 'ops', role='admin')['token']
    r = ha_env.api.anon().post('/api/ha/apply-config', json={}, headers={'Authorization': f'Bearer {tok}'})
    assert r.status_code == 200, r.data

    # a changed connection: the managers reloaded in place, no restart
    pending = {'since': '2026-09-30T08:00:00+00:00', 'reason': '1 cluster changed'}
    monkeypatch.setattr(ha, 'public_status',
                        lambda: dict(real(), sync=dict(real()['sync'], reload_pending=pending)))
    live.apply_result = 'reload'
    r = admin.post('/api/ha/apply-config', json={})
    assert r.get_json() == {'success': True, 'restarting': False, 'reloaded': True}
    assert _audit('ha.config_applied')[-1]['details'] == (
        'reloaded the managers now for the waiting change: 1 cluster changed')

    # nothing to apply: no restart, no audit line claiming one
    live.apply_result = False
    r = admin.post('/api/ha/apply-config', json={})
    assert r.get_json() == {'success': True, 'restarting': False, 'reloaded': False}
    assert len(_audit('ha.config_applied')) == 3


def test_apply_config_is_a_standbys_alone(ha_env, seed, live):
    admin = _admin(ha_env.api, seed)
    for role, be in _roles(ha_env):
        be()
        r = admin.post('/api/ha/apply-config', json={})
        assert r.status_code == 409, (role, r.data)
    assert live.applied == [] and _audit('ha.config_applied') == []


def test_the_status_carries_the_new_fields(ha_env, seed, monkeypatch):
    ha = ha_env.ha
    admin = _admin(ha_env.api, seed)
    _standby_of_active(ha_env)
    real = ha.public_status
    monkeypatch.setattr(ha, 'public_status', lambda: dict(
        real(), live_view=False, managers_running=False,
        sync=dict(real()['sync'], restart_pending={'since': 'x', 'reason': 'y'})))
    body = admin.get('/api/ha/status').get_json()
    assert body['live_view'] is False and body['managers_running'] is False
    assert body['sync']['restart_pending'] == {'since': 'x', 'reason': 'y'}


# --- the banner ---------------------------------------------------------------------------------

@pytest.mark.parametrize('on', [True, False])
def test_the_standby_banner_says_whether_the_view_is_live(ha_env, db, tmp_path, monkeypatch, live, on):
    api = ha_env.api
    creds = _local_user(db, tmp_path, monkeypatch)
    _standby_of_active(ha_env, sync={'last_ok_at': '2026-09-30T08:00:00+00:00'})
    live.value = on
    body = api.anon().post('/api/auth/login', json=creds).get_json()
    want = {'role': 'standby', 'peer_url': ACTIVE_URL,
            'last_sync_at': '2026-09-30T08:00:00+00:00', 'live_view': on, 'forwarding': False,
            'serving': False, 'leader_reachable': True, 'removed': False}
    assert body['ha'] == want
    check = api.anon().get('/api/auth/check', headers={'X-Session-ID': body['session_id']})
    assert check.get_json()['ha'] == want


def test_an_acting_banner_has_no_live_view(ha_env, db, tmp_path, monkeypatch, live):
    api = ha_env.api
    creds = _local_user(db, tmp_path, monkeypatch)
    for role, be in _roles(ha_env):
        be()
        body = api.anon().post('/api/auth/login', json=creds).get_json()
        assert body['ha'] == {'role': role}
