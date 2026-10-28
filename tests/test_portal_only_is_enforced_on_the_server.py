"""portal_only held on the server.

An account an admin marks portal_only was kept to the Client Portal by the browser alone:
web/src/contexts.js sends it to /portal, and nothing on the server read the flag. Such an
account with role `user` in the default tenant called the main API directly and stopped
guests on a cluster where no ACL row named it.

Now the flag decides on the server too. The account reaches what the portal needs
(utils/auth.PORTAL_ONLY_ENDPOINTS and the client_portal plugin API) and every other route
answers 403 PORTAL_ONLY before its body runs: require_auth holds the routes behind it, the
hook hold_portal_only_accounts (app.py) the ones that find their caller themselves. The
portal's own routes and the console keep it to the guests an ACL row or a pool grant
names. An administrator is never held (rbac.portal_only_holds).

The sweeps below send one request per route and method of the URL map; the counter-sweep
sends the same with the same account without the flag. The runtime part drives
portal.html and web/index.html in headless Chromium against the real app.

MK Oct 2026
"""
import json
import re
import socket

import gevent.socket
import pytest

from test_ha_ui import BASE, browser  # noqa: F401  (browser is a fixture)
from test_forced_2fa_ui import _RealBackend

PASSWORD = 'C0rrect!horse9'
HOME, FOREIGN = 'c-home', 'c-foreign'
PORTAL_CFG = {'allowed_actions': ['vm.view', 'vm.start', 'vm.stop', 'vm.console'],
              'show_resource_usage': True, 'show_ip_addresses': False}
WS_HEADERS = {'Upgrade': 'websocket', 'Connection': 'Upgrade',
              'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Version': '13'}
REFUSED = (403, 'PORTAL_ONLY')
# left alone by the hook (auth.PORTAL_ONLY_UNREAD), and the route outside the rate limit
# that reads no API token, where the hook does not look one up
UNREAD = {'auth.health_check', 'settings.get_interface_lock'}
TOKENLESS_UNCOUNTED = {'realtime.sse_updates'}


# ── accounts, clusters, the plugin ───────────────────────────────────────────

def _account(db, name, role='user', portal_only=False):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password(PASSWORD)
    db.save_user(name, {'password_salt': salt, 'password_hash': pw_hash, 'role': role,
                        'enabled': True, 'auth_source': 'local', 'language': 'en',
                        'layout_chosen': True, 'portal_only': portal_only,
                        'tenant_id': 'default'})
    user = db.get_user(name)
    user['username'] = name
    return user


def _token(name):
    from pegaprox.utils.auth import create_api_token
    out = create_api_token(name, 'ci')
    assert out.get('token', '').startswith('pgx_'), out
    return out['token']


def _manager(api, cid, guests):
    m = api.make_fake_manager(cid)
    m.is_connected = True
    m.host = f'{cid}.example'
    m.config.name = cid
    m.get_vm_resources.return_value = [dict(g) for g in guests]
    m.vm_action.return_value = {'success': True, 'data': 'UPID:n1:0001'}
    m._api_post.return_value.status_code = 200
    m.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'}
    return api.set_manager(cid, m)


def _guest(vmid, name):
    return {'vmid': vmid, 'name': name, 'type': 'qemu', 'status': 'stopped', 'node': 'n1'}


@pytest.fixture
def world(api, seed):
    """cust (portal_only, role user, default tenant) owns guest 100 on HOME through an ACL
    row; FOREIGN has guest 300 and no row for it. other is cust without the flag."""
    _manager(api, HOME, [_guest(100, 'cust-web'), _guest(101, 'not-cust')])
    _manager(api, FOREIGN, [_guest(300, 'someone-elses')])
    seed.vm_acl(HOME, 100, ['cust'])
    return api


@pytest.fixture
def portal(api, monkeypatch):
    """The client_portal plugin, loaded into the app for this test only."""
    import pegaprox.api.plugins as plugins
    monkeypatch.setattr(plugins, '_loaded_plugins', dict(plugins._loaded_plugins))
    monkeypatch.setattr(plugins, '_plugin_routes', dict(plugins._plugin_routes))
    ok, err = plugins.load_plugin(api.app, 'client_portal')
    assert ok, err
    mod = plugins._loaded_plugins['client_portal']
    monkeypatch.setattr(mod, '_load_config', lambda: json.loads(json.dumps(PORTAL_CFG)))
    return mod


def _code(resp):
    try:
        return (resp.get_json(silent=True) or {}).get('code')
    except Exception:
        return None


# ── the sweep over the URL map ───────────────────────────────────────────────

_ARG = re.compile(r'<(?:(?P<conv>\w+)(?:\((?P<args>[^)]*)\))?:)?(?P<name>\w+)>')
_DUMMY = {'int': '4242', 'float': '1.5', 'path': 'pp-x/pp-y',
          'uuid': '12345678-1234-5678-1234-567812345678'}


def _fill(rule):
    def one(m):
        conv = m.group('conv') or 'default'
        if conv == 'any':
            return re.findall(r"[\w-]+", m.group('args'))[0]
        return _DUMMY.get(conv, 'pp-x')
    return _ARG.sub(one, rule.rule)


def _allowed(rule, path):
    from pegaprox.utils.auth import PORTAL_ONLY_ENDPOINTS, PORTAL_ONLY_PLUGIN
    if rule.endpoint in PORTAL_ONLY_ENDPOINTS:
        return True
    return rule.endpoint == 'plugins.plugin_proxy' and path.split('/')[3] == PORTAL_ONLY_PLUGIN


def _probes(app):
    """(rule, method, path, websocket) for every rule under /api/ and each of its methods,
    with a path that routes back to that very rule. A rule registered a second time under
    the same pattern is never reached (the first one serves it) and is left out."""
    adapter = app.url_map.bind('localhost')
    probes, astray = [], []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith('/api/'):
            continue
        path, ws = _fill(rule), bool(getattr(rule, 'websocket', False))
        for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
            try:
                hit = adapter.match(path, method=method, websocket=ws, return_rule=True)[0]
            except Exception as e:
                hit = e
            if hit is rule:
                probes.append((rule, method, path, ws))
            elif getattr(hit, 'rule', None) != rule.rule:
                astray.append((method, rule.rule, path, hit))
    assert not astray, astray
    return probes


def _send(client, method, path, ws, credential):
    import pegaprox.globals as ppglobals
    # the whole sweep is one client to the rate limiter
    ppglobals.api_rate_window.reset()
    ppglobals.api_request_counts.clear()
    headers = dict(credential)
    if method != 'GET':
        headers.update({'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'})
    if ws:
        headers.update(WS_HEADERS)
    kw = {'json': {}} if method in ('POST', 'PUT', 'PATCH') else {}
    return client.open(path, method=method, headers=headers, base_url='http://localhost', **kw)


def _session_headers(sid):
    return {'X-Session-ID': sid, 'Cookie': f'session_id={sid}'}


@pytest.fixture
def offline(monkeypatch):
    """No route body reaches the network in a sweep: every outbound connection fails at
    once instead of waiting for a timeout."""
    def refuse(*a, **k):
        raise OSError('no network in this test')
    for mod in (socket, gevent.socket):
        monkeypatch.setattr(mod, 'create_connection', refuse)
        monkeypatch.setattr(mod, 'getaddrinfo', refuse)
    monkeypatch.setattr(gevent.socket.socket, 'connect', refuse)
    monkeypatch.setattr(gevent.socket.socket, 'connect_ex', refuse)


@pytest.mark.parametrize('credential', ['session', 'api_token'])
def test_every_other_api_route_refuses_a_portal_account(world, db, credential, monkeypatch):
    """Both clusters are there, so a body that ran would not stop at a missing manager:
    the 403 has to be the gate's, before the body. A body that breaks answers 500 and is
    listed with the rest."""
    monkeypatch.setitem(world.app.config, 'PROPAGATE_EXCEPTIONS', False)
    cust = _account(db, 'cust', portal_only=True)
    if credential == 'session':
        headers = _session_headers(world.as_user(cust).session_id)
    else:
        headers = {'Authorization': f'Bearer {_token("cust")}'}
    client = world.app.test_client(use_cookies=False)

    probes = _probes(world.app)
    asked = [p for p in probes if not _allowed(p[0], p[2])]
    wrong = []
    for rule, method, path, ws in asked:
        r = _send(client, method, path, ws, headers)
        if rule.endpoint in UNREAD:
            # reads no credential, says the same to anyone
            expected = (200, None)
        elif credential == 'api_token' and rule.endpoint in TOKENLESS_UNCOUNTED:
            # takes no API token at all: the token opens nothing there
            expected = (401, _code(r))
        else:
            expected = REFUSED
        if (r.status_code, _code(r)) != expected:
            wrong.append((method, rule.rule, r.status_code, _code(r)))

    # every rule and method of the map but the few the portal needs
    assert len(asked) > 950 and len(probes) - len(asked) < 25, (len(probes), len(asked))
    assert not wrong, (len(wrong), wrong)



def test_a_made_up_token_buys_no_db_read_outside_the_rate_limit(world, db, monkeypatch):
    """/api/health and /api/sse are not counted by the API rate limit. A made-up API token
    there must not cost a DB read per request, nor a 503 when the DB is unreadable."""
    import pegaprox.utils.auth as auth_mod
    reads = []
    real = auth_mod._api_token_owner

    def counting(token):
        reads.append(token)
        return real(token)
    monkeypatch.setattr(auth_mod, '_api_token_owner', counting)
    client = world.app.test_client(use_cookies=False)
    made_up = {'Authorization': 'Bearer pgx_deadbeef_' + 'x' * 32}

    for _ in range(20):
        assert client.get('/api/health', headers=made_up, base_url='http://localhost').status_code == 200
        client.get('/api/sse/updates', headers=made_up, base_url='http://localhost')
    assert reads == []

    # a counted route still has the token looked up, a held account's token included
    _account(db, 'cust', portal_only=True)
    held = {'Authorization': f'Bearer {_token("cust")}'}
    r = client.get('/api/auth/validate', headers=held, base_url='http://localhost')
    assert (r.status_code, _code(r)) == REFUSED and len(reads) == 1

    # and the health answer does not hang on the DB
    def broken(token):
        raise RuntimeError('db gone')
    monkeypatch.setattr(auth_mod, '_api_token_owner', broken)
    monkeypatch.setattr(auth_mod, 'get_db', lambda: (_ for _ in ()).throw(RuntimeError('db gone')))
    assert client.get('/api/health', headers=held, base_url='http://localhost').status_code == 200

def test_the_same_account_without_the_flag_is_never_told_portal_only(api, db, offline, monkeypatch):
    """The counter-sweep: what decides is the flag, not the role, the routes or the dummy
    values. Every route runs its body here: no cluster is set up, each request gets a fresh
    session (one of them signs out), nothing reaches the network, and a body that breaks
    on the dummy values answers 500 instead of ending the sweep."""
    from pegaprox.utils.auth import create_session
    monkeypatch.setitem(api.app.config, 'PROPAGATE_EXCEPTIONS', False)
    _account(db, 'other')
    client = api.app.test_client(use_cookies=False)
    told, answered, served = [], 0, 0
    for rule, method, path, ws in _probes(api.app):
        if _allowed(rule, path):
            continue
        with api.app.test_request_context('/', base_url='http://localhost'):
            sid = create_session('other', 'user')
        r = _send(client, method, path, ws, _session_headers(sid))
        answered += 1
        served += r.status_code == 200
        if _code(r) == 'PORTAL_ONLY':
            told.append((method, rule.rule, r.status_code))
    assert answered > 950
    # the bodies ran: a sweep the session never got through would pass as well
    assert served > 50, served
    assert not told, told


# ── what the portal needs still works ────────────────────────────────────────

def test_the_portal_routes_work_for_a_portal_account(world, db, portal):
    cust = world.as_user(_account(db, 'cust', portal_only=True))

    check = cust.get('/api/auth/check')
    assert check.status_code == 200
    assert check.get_json()['user']['portal_only'] is True

    vms = cust.get('/api/plugins/client_portal/api/my-vms')
    assert vms.status_code == 200
    assert [(v['cluster_id'], v['vmid']) for v in vms.get_json()['vms']] == [(HOME, 100)]

    on = cust.post('/api/plugins/client_portal/api/vm/power',
                   json={'cluster_id': HOME, 'vmid': 100, 'action': 'start'})
    assert on.status_code == 200 and on.get_json().get('success') is True, on.get_json()

    tfa = cust.post('/api/auth/2fa/setup')
    assert tfa.status_code == 200 and tfa.get_json().get('secret')

    # another plugin is not the portal
    assert (cust.get('/api/plugins/hello_world/api/ui').status_code,
            _code(cust.get('/api/plugins/hello_world/api/ui'))) == REFUSED

    out = cust.post('/api/auth/logout')
    assert out.status_code == 200
    assert cust.get('/api/auth/check').status_code == 401


def test_an_api_token_of_a_portal_account_reaches_the_portal_and_nothing_else(world, db, portal):
    _account(db, 'cust', portal_only=True)
    bearer = {'Authorization': f'Bearer {_token("cust")}'}
    client = world.anon()

    vms = client.get('/api/plugins/client_portal/api/my-vms', headers=bearer)
    assert vms.status_code == 200 and [v['vmid'] for v in vms.get_json()['vms']] == [100]
    stop = client.post(f'/api/clusters/{FOREIGN}/vms/n1/qemu/300/stop', headers=bearer)
    assert (stop.status_code, _code(stop)) == REFUSED


def test_the_portal_console_opens_for_its_own_guest(world, db, portal):
    """The console as the portal opens it behind a reverse proxy: vm/console mints a ws
    token, the socket on the main port takes it. Over HTTP the route answers 426 once
    every check passed."""
    cust = world.as_user(_account(db, 'cust', portal_only=True))

    minted = cust.get(f'/api/plugins/client_portal/api/vm/console?cluster_id={HOME}&vmid=100')
    assert minted.status_code == 200 and minted.get_json().get('ws_token'), minted.get_json()
    path = f'/api/clusters/{HOME}/vms/n1/qemu/100/vncwebsocket'

    opened = world.anon().get(f'{path}?token={minted.get_json()["ws_token"]}')
    assert opened.status_code == 426, opened.get_json()

    # counter-checks: its session in the URL is no ticket, and a token of its own does not
    # open a guest that is not its own
    by_session = world.anon().get(f'{path}?session={cust.session_id}')
    assert by_session.status_code == 403 and _code(by_session) == 'INSUFFICIENT_PERMISSIONS'
    from pegaprox.utils.realtime import create_ws_token
    foreign = world.anon().get(f'/api/clusters/{FOREIGN}/vms/n1/qemu/300/vncwebsocket'
                               f'?token={create_ws_token("cust", "user")}')
    assert foreign.status_code == 403
    # and the account without the flag opens it with its session as before
    other = world.as_user(_account(db, 'other'))
    assert world.anon().get(f'{path}?session={other.session_id}').status_code == 426


def test_console_authz_keeps_a_portal_account_to_its_guests(world, db):
    from pegaprox.api.vms import _console_authz
    cust = _account(db, 'cust', portal_only=True)
    other = _account(db, 'other')

    assert _console_authz(cust, HOME, 100, 'qemu')[0] is True
    assert _console_authz(cust, HOME, 100, 'qemu', by_session=True)[0] is False
    assert _console_authz(cust, FOREIGN, 300, 'qemu')[0] is False
    # counter-check: the role alone opens the foreign guest for the account without the flag
    assert _console_authz(other, FOREIGN, 300, 'qemu', by_session=True)[0] is True


# ── the attack ────────────────────────────────────────────────────────────────

def test_a_portal_account_cannot_stop_a_guest_it_has_no_acl_for(world, db, portal):
    """The proof of concept: role user, default tenant, a cluster without an ACL row for
    the account. Counter-check: the same account without the flag still may (the role
    grants it), so the 403 is the flag's."""
    cust = world.as_user(_account(db, 'cust', portal_only=True))
    other = world.as_user(_account(db, 'other'))
    route = f'/api/clusters/{FOREIGN}/vms/n1/qemu/300/stop'

    r = cust.post(route)
    assert (r.status_code, _code(r)) == REFUSED
    from pegaprox.globals import cluster_managers
    cluster_managers[FOREIGN].vm_action.assert_not_called()

    # nor through the portal's own power route
    via_portal = cust.post('/api/plugins/client_portal/api/vm/power',
                           json={'cluster_id': FOREIGN, 'vmid': 300, 'action': 'stop'})
    assert via_portal.get_json() == {'error': 'Permission denied'}
    cluster_managers[FOREIGN]._api_post.assert_not_called()

    assert other.post(route).status_code == 200
    cluster_managers[FOREIGN].vm_action.assert_called_once()


def test_the_inline_routes_refuse_a_portal_account(world, db):
    """The routes that find their caller themselves: the SSH server's validate calls, the
    live streams, a ws or SSE token in the query. A ws token is single-use and stays."""
    from pegaprox.utils.realtime import create_ws_token, create_sse_token
    from pegaprox.globals import ws_tokens
    cust = world.as_user(_account(db, 'cust', portal_only=True))
    anon = world.anon()
    # a client that sends the Cookie header it is given, as the SSH server does
    bare = world.app.test_client(use_cookies=False)

    ws_token = create_ws_token('cust', 'user')
    r = anon.get(f'/api/ws/token/validate?token={ws_token}&cluster_id={HOME}&shell=node')
    assert (r.status_code, _code(r)) == REFUSED
    assert ws_token in ws_tokens

    r = bare.get('/api/auth/validate', headers={'Cookie': f'session={cust.session_id}'})
    assert (r.status_code, _code(r)) == REFUSED
    r = bare.get(f'/api/internal/cluster-creds/{HOME}',
                 headers={'Cookie': f'session={cust.session_id}'})
    assert (r.status_code, _code(r)) == REFUSED
    r = anon.get(f'/api/sse/updates?token={create_sse_token("cust", None)}')
    assert (r.status_code, _code(r)) == REFUSED
    r = anon.get(f'/api/clusters/{HOME}/nodes/n1/shellws?session={cust.session_id}',
                 headers=WS_HEADERS)
    assert (r.status_code, _code(r)) == REFUSED

    # counter-check: the account without the flag gets past the hook on the same calls
    other = world.as_user(_account(db, 'other'))
    r = bare.get('/api/auth/validate', headers={'Cookie': f'session={other.session_id}'})
    assert r.status_code == 200


def test_the_live_updates_socket_refuses_a_portal_account(world, db):
    """/api/ws/updates takes its session from the first message, past the hook."""
    from pegaprox.api import realtime
    cust = world.as_user(_account(db, 'cust', portal_only=True))
    handler = next(world.app.view_functions[r.endpoint] for r in world.app.url_map.iter_rules()
                   if r.rule == '/api/ws/updates').__wrapped__

    class _WS:
        def __init__(self, first):
            self.first, self.sent = first, []

        def receive(self, timeout=None):
            msg, self.first = self.first, None
            if msg is None:
                raise ConnectionError('the test does not talk back')
            return msg

        def send(self, data):
            self.sent.append(json.loads(data))

        def close(self, *a, **k):
            pass

    ws = _WS(json.dumps({'session_id': cust.session_id}))
    with world.app.test_request_context('/api/ws/updates'):
        handler(ws)
    assert ws.sent and ws.sent[0].get('code') == 'PORTAL_ONLY', ws.sent
    assert not any(c.get('user') == 'cust' for c in realtime.ws_clients.values())

    other = world.as_user(_account(db, 'other'))
    ws = _WS(json.dumps({'session_id': other.session_id}))
    with world.app.test_request_context('/api/ws/updates'):
        handler(ws)
    assert ws.sent and ws.sent[0].get('type') == 'connected', ws.sent


# ── administrators ───────────────────────────────────────────────────────────

def test_an_admin_is_not_held(world, db):
    admin = world.as_user(_account(db, 'boss', role='admin'))
    assert admin.get('/api/users').status_code == 200
    assert admin.post(f'/api/clusters/{FOREIGN}/vms/n1/qemu/300/stop').status_code == 200


def test_an_admin_a_group_mapping_promoted_keeps_the_main_ui(world, db, portal):
    """users.py never lets admin and portal_only meet, a directory group mapping does at
    sign-in. The portal turns admins away, so such an account is not held: it gets the main
    API and the main UI (auth/check says portal_only false, the SPA does not send it on),
    and the portal still turns it away."""
    boss = world.as_user(_account(db, 'boss', role='admin', portal_only=True))

    assert boss.get('/api/users').status_code == 200
    check = boss.get('/api/auth/check').get_json()
    assert check['user']['role'] == 'admin' and check['user']['portal_only'] is False
    assert boss.get('/api/plugins/client_portal/api/my-vms').get_json() == {
        'redirect': '/', 'reason': 'admin'}
    # its token is not held either, and stays at its own role
    r = world.anon().get('/api/users', headers={'Authorization': f'Bearer {_token("boss")}'})
    assert r.status_code == 200
    # demoted again by the mapping, it is held again
    rec = db.get_user('boss')
    rec['role'] = 'user'
    db.save_user('boss', rec)
    r = boss.get('/api/users')
    assert (r.status_code, _code(r)) == REFUSED


def test_the_login_answer_says_what_the_server_holds(world, db):
    _account(db, 'cust', portal_only=True)
    _account(db, 'boss', role='admin', portal_only=True)
    for name, held in (('cust', True), ('boss', False)):
        r = world.anon().post('/api/auth/login', json={'username': name, 'password': PASSWORD})
        body = r.get_json()
        assert r.status_code == 200 and body['success'], body
        assert body['portal_only'] is held and body['user']['portal_only'] is held


# ── at runtime ────────────────────────────────────────────────────────────────

class _Page:
    def __init__(self, browser, api, sid=None):  # noqa: F811
        self.backend = _RealBackend(api.app)
        self.backend.sid = sid
        self.ctx = browser.new_context(viewport={'width': 1280, 'height': 900})
        self.page = self.ctx.new_page()
        self.errors = []
        self.page.on('pageerror', lambda e: self.errors.append(str(e)))
        self.page.route('**/*', self.backend.handle)

    def refused(self):
        return [c for c in self.backend.calls if c[3] == 'PORTAL_ONLY']

    def sees_its_guests(self):
        self.page.wait_for_url(BASE + '/portal', timeout=15000)
        self.page.get_by_text('cust-web').first.wait_for(timeout=15000)
        assert self.page.get_by_text('someone-elses').count() == 0

    def close(self):
        self.ctx.close()


@pytest.fixture
def pages(browser):  # noqa: F811
    opened = []

    def _open(api, sid=None):
        p = _Page(browser, api, sid)
        opened.append(p)
        return p
    yield _open
    for p in opened:
        p.close()


def test_runtime_a_portal_account_signs_in_to_the_portal_and_sees_its_guests(world, db, portal, pages):
    _account(db, 'cust', portal_only=True)
    p = pages(world)
    p.page.goto(BASE + '/portal', wait_until='load')
    p.page.locator('#lu').fill('cust')
    p.page.locator('#lp').fill(PASSWORD)
    p.page.locator('#lf button[type="submit"]').click()

    p.sees_its_guests()
    assert ('GET', '/api/plugins/client_portal/api/my-vms', 200, None) in p.backend.calls
    # the portal asks for nothing the server holds back
    assert not p.refused(), p.backend.calls
    assert not p.errors, p.errors


def test_runtime_opening_the_main_page_still_ends_in_the_portal(world, db, portal, pages):
    sid = world.as_user(_account(db, 'cust', portal_only=True)).session_id
    p = pages(world, sid)

    p.page.goto(BASE + '/', wait_until='load')

    p.sees_its_guests()
    assert p.page.evaluate("sessionStorage.getItem('portal-sid')") == sid
    assert not p.refused(), p.backend.calls
    assert not p.errors, p.errors


def test_an_unreadable_account_is_no_free_pass(world, db, monkeypatch):
    """The hook cannot read the account behind the credential: it refuses (503) instead
    of letting the route run unheld."""
    import pegaprox.utils.auth as auth_mod
    cust = world.as_user(_account(db, 'cust', portal_only=True))
    real = auth_mod.get_db()

    class _Broken:
        def __getattr__(self, name):
            return getattr(real, name)

        def get_user(self, name):
            raise RuntimeError('database is locked')
    monkeypatch.setattr(auth_mod, 'get_db', lambda: _Broken())

    r = world.app.test_client(use_cookies=False).get(
        '/api/auth/validate', headers={'Cookie': f'session={cust.session_id}'})
    assert (r.status_code, _code(r)) == (503, 'ACCOUNT_UNREADABLE')
