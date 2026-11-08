"""The ESXi, PBS and Proxmox VE clients follow no redirect.

The host checks of the ESXi and PBS routes look at the host somebody typed in. requests
follows a 3xx on its own, to any host and from https down to plain http, and on a 307 it
sends the body again: the call, its session id, the login form with the password. So an
endpoint (or whoever sits in front of one with TLS verification off) could send PegaProx
on to an address the check refuses, and the answer came back as server info or a PBS
version. None of these APIs redirects in normal operation, so a 3xx is now an error that
says so, and nothing goes to the Location. The same holds for the calls made next to the
managers: the PBS storage preflight, the connection check, and the logins, tickets and
websocket upgrades of the consoles.

Real requests: an HTTPS endpoint on loopback answers what each test asks for, and a plain
HTTP server stands for the place a redirect points at. It must never see a request.
"""
import datetime
import json
import ssl
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

import pegaprox.core.manager as mgrmod
from pegaprox.core.pbs import PBSManager
from pegaprox.core.vmware import VMwareManager
from pegaprox.models.tasks import PegaProxConfig

SECRET = 'answer-of-the-redirect-target'
PASSWORD = 'pw-that-stays-with-the-endpoint'


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _any(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n) if n else b''
        self.server.seen.append((self.command, self.path, body.decode('utf-8', 'replace')))
        code, headers, out = self.server.answer(self.command, self.path)
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _any


def _serve(answer, ctx=None):
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    srv.daemon_threads = True
    srv.seen, srv.answer = [], answer
    if ctx is not None:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.port = srv.server_address[1]
    return srv


@pytest.fixture(scope='module')
def tls(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    d = tmp_path_factory.mktemp('tls')
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'endpoint.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (d / 'c.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / 'k.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(d / 'c.pem'), str(d / 'k.pem'))
    return ctx


@pytest.fixture
def net(tls):
    """net(code, routes): the endpoint answers (method, path-prefix) from routes and every
    other request with `code` and a Location on the target server."""
    servers = []
    target = _serve(lambda m, p: (200, {'Content-Type': 'application/json'},
                                  json.dumps({'data': {'version': SECRET, 'ticket': SECRET,
                                                       'CSRFPreventionToken': SECRET},
                                              'value': SECRET}).encode()))
    servers.append(target)

    def start(code, routes=()):
        def answer(method, path):
            for (m, prefix), reply in routes:
                if m == method and path.startswith(prefix):
                    return reply
            return code, {'Location': f'http://127.0.0.1:{target.port}/elsewhere{path}'}, b''
        endpoint = _serve(answer, tls)
        servers.append(endpoint)
        return endpoint

    yield types.SimpleNamespace(start=start, target=target)
    for s in servers:
        s.shutdown()
        s.server_close()


def _json(code, value):
    return code, {'Content-Type': 'application/json'}, json.dumps(value).encode()


CODES = [302, 307]


# --- ESXi ---------------------------------------------------------------------------------

def _esxi(port):
    mgr = VMwareManager('t', {'host': '127.0.0.1', 'port': port, 'username': 'root',
                              'password': PASSWORD})
    mgr._connect_soap = lambda: False   # the REST client is what is tested here
    return mgr


@pytest.mark.parametrize('code', CODES)
def test_an_esxi_login_that_redirects_stops_with_an_error_that_says_so(net, code):
    endpoint = net.start(code)
    mgr = _esxi(endpoint.port)
    ok = mgr.connect()
    assert endpoint.seen and net.target.seen == []
    assert ok is False
    assert 'redirect' in mgr.last_error and str(code) in mgr.last_error


@pytest.mark.parametrize('code', CODES)
def test_esxi_reads_writes_and_the_keepalive_do_not_follow_a_redirect(net, code):
    endpoint = net.start(code, [
        (('POST', '/api/session'), _json(201, 'sess-1')),
        (('GET', '/api/vcenter/vm'), _json(200, [])),
        (('POST', '/api/vcenter/vm/vm-1'), _json(200, {})),
    ])
    mgr = _esxi(endpoint.port)
    assert mgr.connect() is True, mgr.last_error
    errors = [mgr.api_get('/api/appliance/networking').get('error', ''),
              mgr.api_post('/api/content/library', {'x': 1}).get('error', ''),
              mgr.api_delete('/api/content/library/lib-2').get('error', '')]
    # the CPU change lands, the notes PATCH after it is redirected
    mgr.update_vm_config('vm-1', {'cpu_count': 2, 'notes': 'note-for-the-guest'})
    mgr._ping_session()
    assert net.target.seen == []
    # the version lookup during connect was redirected too: nothing of the target in server_info
    assert SECRET not in json.dumps(mgr.server_info)
    assert all('redirect' in e for e in errors), errors
    seen = [(m, p) for m, p, _ in endpoint.seen]
    assert ('PATCH', '/api/vcenter/vm/vm-1') in seen and ('GET', '/api/session') in seen


def test_the_esxi_connection_test_hands_back_nothing_from_a_redirect(net, api, seed):
    endpoint = net.start(302, [
        (('POST', '/api/session'), _json(201, 'sess-1')),
        (('GET', '/api/vcenter/vm'), _json(200, [])),
    ])
    admin = api.as_user(seed.user('root_adm', role='admin'))
    r = admin.post('/api/vmware/test-connection', json={
        'host': '127.0.0.1', 'port': endpoint.port, 'username': 'root', 'password': PASSWORD})
    assert net.target.seen == []
    assert r.status_code == 200, r.get_json()
    assert SECRET not in json.dumps(r.get_json())


# --- PBS ----------------------------------------------------------------------------------

def _pbs(port, **extra):
    cfg = {'name': 'p', 'host': '127.0.0.1', 'port': port}
    cfg.update(extra or {'api_token_id': 'root@pam!pp', 'api_token_secret': 'tok-secret'})
    return PBSManager('p', cfg)


@pytest.mark.parametrize('code', CODES)
def test_a_pbs_token_login_that_redirects_is_refused(net, code):
    endpoint = net.start(code)
    mgr = _pbs(endpoint.port)
    ok = mgr.connect()
    assert endpoint.seen and net.target.seen == []
    assert ok is False
    assert 'redirect' in mgr.last_error and str(code) in mgr.last_error


@pytest.mark.parametrize('code', CODES)
def test_a_pbs_password_login_is_not_sent_on(net, code):
    endpoint = net.start(code)
    mgr = _pbs(endpoint.port, user='root@pam', password=PASSWORD)
    ok = mgr.connect()
    assert net.target.seen == []
    assert ok is False and 'redirect' in mgr.last_error
    assert [m for m, _, _ in endpoint.seen] == ['POST']


@pytest.mark.parametrize('code', CODES)
def test_pbs_calls_after_the_login_do_not_follow_a_redirect(net, code):
    endpoint = net.start(code, [(('GET', '/api2/json/version'), _json(200, {'data': {'version': '3.4'}}))])
    mgr = _pbs(endpoint.port)
    assert mgr.connect() is True, mgr.last_error
    errors = [mgr.api_get('admin/datastore').get('error', ''),
              mgr.api_post('admin/datastore/s1/gc', {'x': 1}).get('error', ''),
              mgr.api_put('config/datastore/s1', {'comment': 'c'}).get('error', ''),
              mgr.api_delete('admin/datastore/s1/snapshots').get('error', '')]
    raw = mgr.api_get_raw('admin/datastore/s1/file-download')
    assert net.target.seen == []
    assert all('redirect' in e for e in errors), errors
    assert raw is None and len(endpoint.seen) == 6


def test_the_pbs_connection_test_reports_the_redirect(net, api, seed):
    endpoint = net.start(302)
    admin = api.as_user(seed.user('root_adm', role='admin'))
    r = admin.post('/api/pbs/test-connection', json={
        'host': '127.0.0.1', 'port': endpoint.port, 'api_token_id': 'root@pam!pp',
        'api_token_secret': 'tok-secret'})
    body = r.get_json()
    assert net.target.seen == []
    assert r.status_code == 400 and 'redirect' in body['error'], body
    assert SECRET not in json.dumps(body)


# --- Proxmox VE ---------------------------------------------------------------------------

def _pve(port, user='root@pam', pw=PASSWORD):
    return mgrmod.PegaProxManager('c1', PegaProxConfig({
        'name': 'lab', 'host': '127.0.0.1', 'api_port': port, 'user': user, 'pass': pw}))


@pytest.mark.parametrize('code', CODES)
def test_a_proxmox_password_login_that_redirects_is_refused(net, db, code):
    endpoint = net.start(code)
    m = _pve(endpoint.port)
    ok = m.connect_to_proxmox()
    assert net.target.seen == []
    assert ok is False
    assert 'redirect' in m.connection_error and str(code) in m.connection_error
    assert [(mt, p) for mt, p, _ in endpoint.seen] == [('POST', '/api2/json/access/ticket')]


@pytest.mark.parametrize('code', CODES)
def test_a_proxmox_token_check_that_redirects_is_refused(net, db, code):
    endpoint = net.start(code)
    m = _pve(endpoint.port, user='root@pam!pp', pw='tok-secret')
    ok = m.connect_to_proxmox()
    assert net.target.seen == []
    assert ok is False and 'redirect' in m.connection_error
    assert [(mt, p) for mt, p, _ in endpoint.seen] == [('GET', '/api2/json/version')]


@pytest.mark.parametrize('code', CODES)
def test_the_proxmox_api_session_does_not_follow_a_redirect(net, db, code):
    endpoint = net.start(code)
    m = _pve(endpoint.port)
    m._ticket, m._csrf_token = 'PVE:root@pam:T', 'csrf'
    base = f'https://127.0.0.1:{endpoint.port}/api2/json'
    s = m._create_session()
    calls = [
        lambda: s.get(f'{base}/cluster/resources', allow_redirects=True),
        lambda: s.post(f'{base}/nodes/pve1/qemu/100/status/start', data={'x': 1}),
        lambda: s.put(f'{base}/nodes/pve1/qemu/100/config', data={'name': 'n'}),
        lambda: s.delete(f'{base}/nodes/pve1/qemu/100/snapshot/s1'),
        lambda: m._api_get(f'{base}/version'),
    ]
    errors = []
    for call in calls:
        try:
            call()
            errors.append('')
        except requests.exceptions.RequestException as e:
            errors.append(str(e))
    assert net.target.seen == []
    assert all('redirect' in e for e in errors), errors
    assert len(endpoint.seen) == len(calls)


def test_the_root_session_for_disk_operations_is_not_sent_on(net, db):
    endpoint = net.start(307)
    m = _pve(endpoint.port)
    s, err = m.create_privileged_session()
    assert net.target.seen == []
    assert s is None and 'Redirect' in err
    assert [(mt, p) for mt, p, _ in endpoint.seen] == [('POST', '/api2/json/access/ticket')]


# --- the clients next to the managers --------------------------------------------------------

@pytest.mark.parametrize('code', CODES)
def test_the_pbs_storage_preflight_does_not_send_its_login_on(net, api, seed, code):
    """The preflight logs in with a session of its own, after the host check of the route."""
    endpoint = net.start(code)
    api.set_manager('c1', api.make_fake_manager('c1'))
    admin = api.as_user(seed.user('root_adm', role='admin'))
    r = admin.post('/api/clusters/c1/storage-preflight', json={
        'type': 'pbs', 'server': '127.0.0.1', 'port': endpoint.port, 'datastore': 'ds1',
        'username': 'root@pam', 'password': PASSWORD})
    body = r.get_json()
    assert net.target.seen == []
    assert body['ok'] is False and any('redirect' in i for i in body['issues']), body
    assert SECRET not in json.dumps(body)
    assert [(m, p) for m, p, _ in endpoint.seen] == [('POST', '/api2/json/access/ticket')]


@pytest.mark.parametrize('authed', [False, True])
def test_the_connection_check_names_a_redirect_and_does_not_follow_it(net, db, authed):
    """Without a connected cluster the check went out on a session of its own."""
    from pegaprox.core import conncheck
    endpoint = net.start(302)
    m = _pve(endpoint.port)
    m._ticket, m._csrf_token = 'PVE:root@pam:T', 'csrf'
    item = conncheck.probe_host(m, '127.0.0.1', authed=authed)
    assert net.target.seen == []
    assert (item['status'], item['hint'], item['http']) == ('warn', 'api_http', 302), item
    assert 'redirect' in item['detail']


TICKET = _json(200, {'data': {'ticket': 'PVE:root@pam:CONSOLE', 'CSRFPreventionToken': 'csrf-c',
                              'username': 'root@pam'}})
VNCPROXY = _json(200, {'data': {'ticket': 'PVEVNC:t', 'port': 5900}})
CONSOLE_STEPS = {
    'login': [],
    'vncproxy': [(('POST', '/api2/json/access/ticket'), TICKET)],
    'upgrade': [(('POST', '/api2/json/access/ticket'), TICKET),
                (('POST', '/api2/json/nodes/pve1/qemu/100/vncproxy'), VNCPROXY)],
}


def _upgrade_redirect(net, code=302):
    # websocket-client only goes on to a ws:// or wss:// Location
    return (('GET', '/api2/json/nodes/pve1/qemu/100/vncwebsocket'),
            (code, {'Location': f'ws://127.0.0.1:{net.target.port}/elsewhere'}, b''))


@pytest.mark.parametrize('step', sorted(CONSOLE_STEPS))
def test_opening_a_console_stops_at_a_redirect_on_every_step(net, api, seed, step):
    """Login, vncproxy and the upgrade of the console go past the manager's session."""
    endpoint = net.start(302, CONSOLE_STEPS[step] + [_upgrade_redirect(net)])
    api.set_manager('c1', _pve(endpoint.port))
    admin = api.as_user(seed.user('root_adm', role='admin'))
    r = admin.post('/api/clusters/c1/vms/pve1/qemu/100/vnc-poll', json={'action': 'open'})
    assert net.target.seen == []
    # websocket-client 1.9.2 stops at the 3xx itself ('Redirect limit exhausted'), 1.9.0 hands
    # it back and _refuse_ws_redirect closes it; either way the upgrade names the redirect
    assert r.status_code == 502 and 'redirect' in r.get_json()['error'].lower(), r.get_json()


@pytest.mark.parametrize('code', CODES)
def test_the_console_upgrade_of_a_token_cluster_keeps_the_token_with_the_endpoint(net, api, seed, code):
    endpoint = net.start(code, [(('POST', '/api2/json/nodes/pve1/qemu/100/vncproxy'), VNCPROXY),
                                _upgrade_redirect(net, code)])
    m = _pve(endpoint.port, user='root@pam!pp', pw='tok-secret')
    m.is_connected, m._using_api_token, m._api_token = True, True, 'root@pam!pp=tok-secret'
    api.set_manager('c1', m)
    admin = api.as_user(seed.user('root_adm', role='admin'))
    r = admin.post('/api/clusters/c1/vms/pve1/qemu/100/vnc-poll', json={'action': 'open'})
    assert net.target.seen == []
    assert r.status_code == 502 and 'redirect' in r.get_json()['error'].lower(), r.get_json()
    assert ('GET', '/api2/json/nodes/pve1/qemu/100/vncwebsocket') in [(mt, p.split('?')[0])
                                                                      for mt, p, _ in endpoint.seen]


def test_the_terminal_ticket_is_not_sent_on(net, api, seed):
    endpoint = net.start(302, CONSOLE_STEPS['vncproxy'])
    api.set_manager('c1', _pve(endpoint.port))
    admin = api.as_user(seed.user('root_adm', role='admin'))
    r = admin.post('/api/clusters/c1/vms/pve1/qemu/100/termproxy')
    assert net.target.seen == []
    assert r.status_code == 500 and SECRET not in json.dumps(r.get_json()), r.get_json()
    assert [(mt, p) for mt, p, _ in endpoint.seen][-1] == ('POST', '/api2/json/nodes/pve1/qemu/100/termproxy')


def test_a_console_session_ticket_does_not_come_from_a_redirect(net, db):
    endpoint = net.start(302)
    m = _pve(endpoint.port)
    assert m.mint_console_auth_ticket() is None
    assert net.target.seen == []
    assert [(mt, p) for mt, p, _ in endpoint.seen] == [('POST', '/api2/json/access/ticket')]


def test_the_screenshot_frame_is_not_fetched_through_a_redirect(net, db):
    from pegaprox.api import vms
    endpoint = net.start(302, CONSOLE_STEPS['upgrade'] + [_upgrade_redirect(net)])
    m = _pve(endpoint.port)
    m._ticket, m._csrf_token = 'PVE:root@pam:T', 'csrf'
    with pytest.raises(Exception) as caught:
        vms._screenshot_via_rfb(m, 'pve1', 'qemu', 100, timeout=5)
    assert net.target.seen == []
    assert 'redirect' in str(caught.value).lower()


def test_every_console_upgrade_and_ticket_call_refuses_redirects():
    """The console handlers dial PVE with websocket-client and urllib, not with the
    manager's session. Each upgrade passes redirect_limit=0 and checks what came back,
    each urllib call goes through pve_opener. A new one without it fails here."""
    import ast
    import inspect
    import pegaprox.api.vms as vms
    clients = ('websocket.create_connection', 'ws_client.create_connection')
    tree = ast.parse(inspect.getsource(vms))
    upgrades, checks = [], 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        first = ast.unparse(node.args[0]) if node.args else ''
        if name in clients or first in clients:      # a direct call, or one handed to to_thread
            limit = [k for k in node.keywords if k.arg == 'redirect_limit']
            upgrades.append((node.lineno, bool(limit) and ast.unparse(limit[0].value) == '0'))
        checks += name == '_refuse_ws_redirect'
    assert len(upgrades) >= 5
    assert [u for u in upgrades if not u[1]] == []
    assert checks == len(upgrades)
    for module in (vms, mgrmod):
        calls = [n.lineno for n in ast.walk(ast.parse(inspect.getsource(module)))
                 if isinstance(n, ast.Call) and ast.unparse(n.func).split('.')[-1] == 'urlopen']
        assert calls == [], (module.__name__, calls)


# --- every ESXi request says it ------------------------------------------------------------

def test_every_request_of_the_esxi_client_refuses_redirects():
    """The ESXi client has no session to set it on once, so each call carries the flag.
    A new call without it fails here."""
    import ast
    import inspect
    import pegaprox.core.vmware as esxi_client
    tree = ast.parse(inspect.getsource(esxi_client))
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        if name.startswith('requests.') and name.split('.')[-1] in (
                'get', 'post', 'put', 'patch', 'delete', 'head', 'request') \
                or name == 'ha_transport.http':
            flag = [k for k in node.keywords if k.arg == 'allow_redirects']
            calls.append((node.lineno, name, bool(flag) and ast.unparse(flag[0].value) == 'False'))
    assert len(calls) >= 12
    assert [c for c in calls if not c[2]] == []
