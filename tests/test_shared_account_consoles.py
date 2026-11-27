"""Several people on one account (a shared admin) must not hang up each other's consoles.

The consoles were counted per account (utils/realtime.py): past 24 the account's oldest
was hung up, whoever's it was, and noVNC opened the dropped console again by itself, which
hung up the next one. A console now hangs up only the oldest of its own session, past
MAX_CONSOLES_PER_SESSION. The account as a whole has a higher cap, past which the new
console is refused, nobody's hung up, with a close code of its own (4429) that the console
page shows and does not retry. A reconnect is still never refused because of the dead
socket it left behind, at the account's cap or the instance's. The SSE streams of an
account follow the same rule.

Around it: a console relays without the database connection its greenlet signed in with,
the console cap of the instance counts more than two descriptors per console, and the TLS
context towards PVE is made once per cluster and verify flag, not per console.

MK Nov 2026
"""
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import types

import gevent
import pytest
import websocket
from flask import Flask

import pegaprox.api.realtime as rt
import pegaprox.globals as ppglobals
import pegaprox.utils.realtime as rtu
from pegaprox.api import vms
from pegaprox.utils.realtime import create_ws_token

from test_node_shell_login_and_output import node  # noqa: F401
from test_websocket_user_cap import VNC, _closed_with, _echoes, _hung_up, budgets, serve  # noqa: F401

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Sock:
    """A WebSocket as far as hold_websocket and _hang_up look at it."""

    def __init__(self):
        self.sock, self.client = socket.socketpair()
        self.client.setblocking(False)

    def hung_up(self):
        try:
            return self.client.recv(1) == b''
        except BlockingIOError:
            return False

    def dispose(self):
        self.sock.close()
        self.client.close()


@pytest.fixture
def socks(budgets):
    made = []

    def make():
        s = _Sock()
        made.append(s)
        return s
    yield make
    for s in made:
        s.dispose()


_tiny = Flask('shared-account-consoles')


def _hold(ws, sid, user='ops'):
    """A console of `user` opened under session `sid`; never released, as a socket whose
    browser went away before the server noticed."""
    with _tiny.test_request_context('/'):
        return rtu.hold_websocket(user, ws, sid=sid, console=True)


def _budgets(monkeypatch, session, account, instance=1000):
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_SESSION', session, raising=False)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES_PER_USER', account)
    monkeypatch.setattr(rtu, 'MAX_CONSOLES', instance)


# --- one session never hangs up another's console ------------------------------------------

def test_a_session_never_hangs_up_a_colleagues_console(socks, monkeypatch):
    """Two people on one account: the one past their own budget loses their own oldest
    console, the colleague keeps all of theirs."""
    _budgets(monkeypatch, session=2, account=4)
    a1, a2, b1, b2, b3 = (socks() for _ in range(5))
    for ws in (a1, a2):
        assert _hold(ws, 's-A') is True
    for ws in (b1, b2):
        assert _hold(ws, 's-B') is True

    assert _hold(b3, 's-B') is True

    assert not a1.hung_up() and not a2.hung_up(), "session B's console hung up session A's"
    assert b1.hung_up(), "session B's oldest console is still open past its budget"
    assert not b2.hung_up() and not b3.hung_up()
    assert rtu.consoles_open() == 4


def test_the_oldest_console_of_the_session_goes_past_its_budget(socks, monkeypatch):
    _budgets(monkeypatch, session=2, account=100)
    first, second, third = socks(), socks(), socks()
    for ws in (first, second, third):
        assert _hold(ws, 's-A') is True
    assert first.hung_up(), 'the oldest console of the session is still open past its budget'
    assert not second.hung_up() and not third.hung_up()
    assert rtu.consoles_open() == 2


def test_past_the_account_cap_the_new_console_is_refused(socks, monkeypatch):
    """A third person on the account finds it full: their console is refused (None), and
    nobody else's is hung up for it."""
    _budgets(monkeypatch, session=24, account=3)
    held = [socks() for _ in range(3)]
    for ws, sid in zip(held, ('s-A', 's-A', 's-B')):
        assert _hold(ws, sid) is True

    late = socks()
    assert _hold(late, 's-C') is None
    assert not any(ws.hung_up() for ws in held + [late])
    assert rtu.consoles_open() == 3
    assert late not in [ws for _, ws in rtu._held_ws.values()]


@pytest.mark.parametrize('cap', ['account', 'instance'])
def test_a_reconnect_at_the_cap_replaces_its_own_dead_console(socks, monkeypatch, cap):
    """The console of session B went away and is still counted. B opens it again on a full
    account (or instance): B's dead socket makes room, not A's live console."""
    if cap == 'account':
        _budgets(monkeypatch, session=24, account=2)
    else:
        _budgets(monkeypatch, session=24, account=100, instance=2)
    alive, dead, again = socks(), socks(), socks()
    assert _hold(alive, 's-A') is True
    assert _hold(dead, 's-B') is True

    assert _hold(again, 's-B') is True
    assert dead.hung_up(), "the reconnect did not take the place of its own dead console"
    assert not alive.hung_up(), "the reconnect hung up a colleague's console"
    assert rtu.consoles_open() == 2


def test_a_session_without_a_console_is_refused_on_a_full_instance(socks, monkeypatch):
    """The instance's cap keeps its rule, by session now: the new one is refused (False)
    rather than a console of another session of the same account hung up."""
    _budgets(monkeypatch, session=24, account=100, instance=2)
    a, b = socks(), socks()
    assert _hold(a, 's-A') is True
    assert _hold(b, 's-A') is True
    late = socks()
    assert _hold(late, 's-B') is False
    assert not any(ws.hung_up() for ws in (a, b, late))


# --- what the browser is told -------------------------------------------------------------

def _session(api, name='ops'):
    return api.as_user({'username': name, 'role': 'admin'}).session_id


def _console_under(connect, sid, vmid=100, user='ops'):
    return connect(VNC.format(vmid=vmid, token=create_ws_token(user, 'admin', sid=sid)))


def test_the_refused_console_says_why_with_its_own_close_code(serve, api, seed, monkeypatch):
    """Over the real route: the console past the account's cap is closed with 4429 and the
    reason, the consoles of the other sessions keep relaying."""
    connect, _ = serve
    _budgets(monkeypatch, session=24, account=2)
    seed.user('ops', role='admin')
    sid_a, sid_b, sid_c = _session(api), _session(api), _session(api)
    mine = _console_under(connect, sid_a, 100)
    theirs = _console_under(connect, sid_b, 101)
    assert _echoes(mine) and _echoes(theirs)

    late = _console_under(connect, sid_c, 102)

    code, reason = _closed_with(late)
    assert code == 4429, (code, reason)
    assert reason == vms.ACCOUNT_CONSOLES_ERROR
    assert code != 1013, 'the page retries 1013 by itself'
    assert _echoes(mine) and _echoes(theirs), 'a console of another session went for it'
    assert rtu.consoles_open() == 2


def test_another_session_of_the_account_keeps_its_console_over_the_route(serve, api, seed,
                                                                         monkeypatch):
    connect, _ = serve
    _budgets(monkeypatch, session=1, account=10)
    seed.user('ops', role='admin')
    sid_a, sid_b = _session(api), _session(api)
    mine = _console_under(connect, sid_a, 100)
    first = _console_under(connect, sid_b, 101)
    assert _echoes(mine) and _echoes(first)

    second = _console_under(connect, sid_b, 102)

    assert _echoes(second)
    assert _hung_up(first), "session B's older console is still open past its budget"
    assert _echoes(mine), "session B hung up session A's console"


def test_the_terminal_says_why_as_well(api, seed, monkeypatch):
    from test_console_one_port import _Browser, _cluster, _query, _refusal, _terminal
    seed.user('ops', role='admin')
    _cluster(api)
    # hold_websocket's answer for a full account
    monkeypatch.setattr(vms, 'hold_websocket', lambda *a, **kw: None)
    said, code = _refusal(_terminal(api, _query(create_ws_token('ops', 'admin')),
                                    browser=_Browser()))
    assert (said, code) == (vms.ACCOUNT_CONSOLES_ERROR, 4429)


# --- the console page does not retry it -----------------------------------------------------

def _src(path):
    with open(os.path.join(REPO, path), encoding='utf-8') as fh:
        return fh.read()


def _vnc_connect_block(src):
    """From the refusal watch to the end of noVNC's disconnect handler, as shipped."""
    start = src.index('let refused = false;')
    handler = src.index("rfbInstance.addEventListener('disconnect'", start)
    end_mark = '\n                        });\n'
    end = src.index(end_mark, handler) + len(end_mark)
    return src[start:end]


def test_the_page_knows_the_servers_close_code():
    src = _src('web/src/node_modals.js')
    m = re.search(r'const ACCOUNT_FULL_CLOSE = (\d+);', src)
    assert m, 'the console page has no close code for a refusal of the account'
    assert int(m.group(1)) == vms.ACCOUNT_CONSOLES_CLOSE


def test_every_socket_novnc_gets_is_watched_for_the_refusal():
    """noVNC's disconnect only says clean or not; the code is on the socket. A URL handed to
    noVNC is a socket nobody else can watch."""
    block = _vnc_connect_block(_src('web/src/node_modals.js'))
    sockets = re.findall(r'new window\.RFB\(canvasRef\.current, (\w+),', block)
    assert len(sockets) == 2, sockets
    for name in sockets:
        assert name != 'wsUrl', 'noVNC opens the plain console from its URL, unwatched'
        watch = block.find(f'watchRefusal({name})')
        assert 0 <= watch < block.find(f'new window.RFB(canvasRef.current, {name},'), name


def test_the_disconnect_handler_stops_before_the_retry():
    block = _vnc_connect_block(_src('web/src/node_modals.js'))
    handler = block[block.index("rfbInstance.addEventListener('disconnect'"):]
    stop = re.search(r'if \(refused\) return;', handler)
    assert stop, 'the disconnect handler does not stop for a refused console'
    assert stop.start() < handler.index('startVNC()'), 'the retry comes before the stop'


_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf-8');
const start = src.indexOf('let refused = false;');
const handler = src.indexOf("rfbInstance.addEventListener('disconnect'", start);
const endMark = '\n                        });\n';
const end = src.indexOf(endMark, handler) + endMark.length;
if (start < 0 || handler < 0 || end < endMark.length) { console.error('no block'); process.exit(2); }
const block = src.slice(start, end);

// a socket as the browser dispatches it: listeners and the on* handler in the order they
// were added, the handler where it was first set (noVNC sets onclose when it attaches)
class Sock {
    constructor(url) { this.url = url; this.list = []; this.handlers = {}; Sock.made.push(this); }
    addEventListener(t, fn) { this.list.push([t, fn]); }
    set onclose(fn) {
        if (!('close' in this.handlers)) this.list.push(['close', (ev) => this.handlers.close && this.handlers.close(ev)]);
        this.handlers.close = fn;
    }
    get onclose() { return this.handlers.close; }
    fire(t, ev) { for (const [type, fn] of this.list) if (type === t) fn(ev); }
}
Sock.made = [];

// noVNC as far as the page sees it: opens a URL as a socket of its own or attaches to the
// one it is given, and a close before the RFB handshake is a disconnect that was not clean
class RFB {
    constructor(target, urlOrSock) {
        const sock = typeof urlOrSock === 'string' ? new Sock(urlOrSock) : urlOrSock;
        this.list = {};
        sock.onclose = () => (this.list.disconnect || []).forEach(fn => fn({ detail: { clean: false } }));
    }
    addEventListener(t, fn) { (this.list[t] = this.list[t] || []).push(fn); }
}

async function run(stable, code) {
    Sock.made = [];
    const out = { statuses: [], why: null, retries: 0 };
    const window = { RFB, connectVnc: async () => new Sock('secure') };
    const WebSocket = Sock;
    const ACCOUNT_FULL_CLOSE = __CODE__;
    const setRefusedWhy = (w) => { out.why = w; };
    const setConnectionStatus = (s) => out.statuses.push(s);
    const retryCount = { current: 0 };
    const maxRetries = 8;
    const retryDelayMs = () => 0;
    const rfbRef = { current: null };
    const canvasRef = { current: {} };
    const startVNC = () => { out.retries++; };
    const setTimeout = (fn) => fn();
    const cancelled = false;
    const stableHandle = stable ? { key_b64: 'k', session_id: 's' } : null;
    const wsUrl = 'wss://pegaprox/vnc', pollUrl = '', vncPassword = 'pw';
    const API_URL = '', clusterId = 'c', vm = { node: 'n', type: 'qemu', vmid: 100 };
    const getAuthHeaders = () => ({});
    const console = { log() {}, error() {} };
    await eval('(async () => {' + block + '})()');
    Sock.made[Sock.made.length - 1].fire('close', { code, reason: 'This account has too many consoles open' });
    return out;
}

(async () => {
    const jobs = JSON.parse(process.argv[3]);
    const res = {};
    for (const [name, [stable, code]] of Object.entries(jobs)) res[name] = await run(stable, code);
    console.log(JSON.stringify(res));
})();
"""


def test_the_page_retries_a_dropped_console_but_not_a_refused_one(tmp_path):
    """The shipped block runs in node against a socket and a noVNC that behave like the
    browser's: a refusal of the account (4429) shows its reason and is not opened again, a
    dropped console (1006) or a full instance (1013) still is."""
    if not shutil.which('node'):
        pytest.skip('node is needed to run the shipped console block')
    harness = tmp_path / 'refusal_harness.js'
    harness.write_text(_HARNESS.replace('__CODE__', str(vms.ACCOUNT_CONSOLES_CLOSE)),
                       encoding='utf-8')
    jobs = {'plain_refused': [False, 4429], 'stable_refused': [True, 4429],
            'plain_dropped': [False, 1006], 'stable_dropped': [True, 1006],
            'plain_instance_full': [False, 1013]}
    p = subprocess.run(['node', str(harness), os.path.join(REPO, 'web/src/node_modals.js'),
                        json.dumps(jobs)], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout)
    for name in ('plain_refused', 'stable_refused'):
        assert got[name]['retries'] == 0, (name, got[name])
        assert got[name]['statuses'][-1] == 'refused', (name, got[name])
        assert got[name]['why'] == 'This account has too many consoles open', got[name]
    for name in ('plain_dropped', 'stable_dropped', 'plain_instance_full'):
        assert got[name]['retries'] == 1, (name, got[name])
        assert 'refused' not in got[name]['statuses'], (name, got[name])


# --- the SSE streams of a shared account ----------------------------------------------------

@pytest.fixture
def registry():
    ppglobals.sse_clients.clear()
    try:
        yield ppglobals.sse_clients
    finally:
        ppglobals.sse_clients.clear()


def _stream(app, sid, user='ops'):
    with app.test_request_context(f'/api/sse/updates?token={rt.create_sse_token(user, None, sid=sid)}'):
        return app.make_response(rt.sse_updates())


def _streams_of(registry, sid):
    return sorted(cid for cid, c in registry.items() if c.get('sid') == sid)


def test_a_stream_never_supersedes_a_colleagues(api, seed, registry, monkeypatch):
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_SESSION', 2, raising=False)
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_USER', 4)
    seed.user('ops', role='user')
    for _ in range(2):
        assert _stream(api.app, 's-A').status_code == 200
    theirs = _streams_of(registry, 's-A')
    b_first = None
    for i in range(3):
        assert _stream(api.app, 's-B').status_code == 200
        if i == 0:
            b_first = _streams_of(registry, 's-B')[0]

    assert _streams_of(registry, 's-A') == theirs, "session B's tab superseded session A's stream"
    assert b_first not in registry, "session B's oldest stream is still open past its budget"
    assert len(_streams_of(registry, 's-B')) == 2


def test_past_the_account_cap_a_new_session_gets_no_stream(api, seed, registry, monkeypatch):
    monkeypatch.setattr(rt, 'MAX_SSE_STREAMS_PER_USER', 2)
    seed.user('ops', role='user')
    assert _stream(api.app, 's-A').status_code == 200
    assert _stream(api.app, 's-B').status_code == 200
    before = sorted(registry)

    late = _stream(api.app, 's-C')

    assert late.status_code == 429
    assert late.get_json()['code'] == 'SSE_ACCOUNT_FULL'
    assert late.headers.get('Retry-After')
    assert sorted(registry) == before, 'a stream of another session was dropped for it'

    # the dashboard's five-minute reconnect of a session that holds one replaces its own
    again = _stream(api.app, 's-B')
    assert again.status_code == 200
    assert len(_streams_of(registry, 's-A')) == 1 and len(_streams_of(registry, 's-B')) == 1


# --- a console relays without its database connection --------------------------------------

def _db_conn():
    from pegaprox.core.db import get_db
    return getattr(get_db()._local, 'conn', None)


class _RecordingBrowser:
    """Notes whether this greenlet has a database connection while the relay reads from it,
    then goes away."""

    def __init__(self):
        self.seen = []
        self.connected = True

    def receive(self, timeout=None):
        self.seen.append(_db_conn())
        self.connected = False
        gevent.sleep(0.01)
        return None

    def send(self, data):
        pass

    def close(self, *a, **k):
        self.connected = False


class _IdlePve:
    def __init__(self, sock):
        self.sock = sock

    def settimeout(self, t):
        pass

    def recv(self):
        gevent.sleep(0.01)
        raise websocket.WebSocketTimeoutException('read slice')

    def send(self, *a):
        pass

    send_binary = ping = send

    def close(self):
        pass


@pytest.fixture
def vnc_cluster(api, seed, monkeypatch):
    from test_console_token_cluster_955 import _PasswordManager, _Pve
    seed.user('root', role='admin')
    fake = _Pve(password_ok=True)
    contexts = []

    def opener(context=None):
        contexts.append(context)
        return fake.opener(context)
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', opener)
    idle, peer = socket.socketpair()
    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: _IdlePve(idle))
    mgr = api.set_manager('c1', _PasswordManager())
    yield types.SimpleNamespace(manager=mgr, contexts=contexts)
    idle.close()
    peer.close()


def _vnc(api, browser):
    from test_console_token_cluster_955 import _PATH, _query
    view = api.app.view_functions['__flask_sock.vnc_websocket_proxy'].__wrapped__
    with api.app.test_request_context(f'{_PATH}?{_query(True)}'):
        view(browser, 'c1', 'pve1', 'qemu', 100)


def test_a_vnc_console_relays_without_a_database_connection(api, seed, vnc_cluster):
    assert _db_conn() is not None, 'the test needs a connection to start with'
    browser = _RecordingBrowser()
    _vnc(api, browser)
    assert browser.seen, 'the console never got to its relay'
    assert browser.seen[0] is None, 'the relay kept the connection it signed in with'
    # and the next use opens one again
    from pegaprox.core.db import get_db
    assert get_db().get_user('root') is not None


def test_a_terminal_relays_without_a_database_connection(api, seed, monkeypatch):
    from test_console_one_port import _Browser, _cluster, _query, _terminal
    seed.user('root', role='admin')
    _cluster(api)
    seen = []

    class _Pve:
        status = 101

        def __init__(self):
            self.sock, self._peer = socket.socketpair()
            self._peer.send(b'x')

        def settimeout(self, t):
            pass

        def recv(self):
            return 'OK'

        def send(self, data):
            pass

        def recv_data(self):
            gevent.sleep(0.01)
            raise websocket.WebSocketTimeoutException('read slice')

        def close(self):
            self.sock.close()
            self._peer.close()

    monkeypatch.setattr(websocket, 'create_connection', lambda *a, **k: _Pve())

    class _Seeing(_Browser):
        def receive(self, timeout=None):
            seen.append(_db_conn())
            return super().receive(timeout)

    assert _db_conn() is not None
    _terminal(api, _query(create_ws_token('root', 'admin')), browser=_Seeing())
    assert seen and seen[0] is None, 'the terminal relay kept its database connection'


def test_a_node_shell_relays_without_a_database_connection(api, seed, node):
    from test_node_shell_login_and_output import _Channel, _Page, _login, _run
    node.channel = _Channel([b'root@pve2:~# '])
    seen = []

    class _Seeing(_Page):
        def receive(self, timeout=None):
            if '{"status":"connected"}' in self.sent:
                seen.append(_db_conn())
            return super().receive(timeout)

    assert _db_conn() is not None
    page = _run(api, seed, _Seeing(_login(username='root', password='pw')))
    assert '{"status":"connected"}' in page.sent, page.sent
    assert seen and seen[0] is None, 'the shell relay kept its database connection'


def test_a_connection_with_an_open_transaction_is_not_released(db):
    """Closing a connection rolls back what it has not committed: never that one."""
    conn = db.conn
    conn.execute("INSERT INTO users (username, password_salt, password_hash) "
                 "VALUES ('pending', 's', 'h')")
    assert conn.in_transaction
    assert db.release_connection() is False
    assert db.conn is conn
    conn.commit()
    assert db.release_connection() is True
    assert db.conn is not conn
    row = db.conn.execute("SELECT username FROM users WHERE username = 'pending'").fetchone()
    assert row is not None


# --- the descriptors a console holds --------------------------------------------------------

@pytest.mark.parametrize('soft', [1024, 2048, 4096])
def test_the_console_cap_leaves_the_instance_half_of_its_descriptors(monkeypatch, soft):
    """A console holds four descriptors while its greenlet has a database connection (the
    browser's socket, PVE's, the file and its WAL), not two: at the default cap the
    consoles still leave half of the limit to everything else."""
    import resource
    monkeypatch.setattr(resource, 'getrlimit', lambda _which: (soft, soft))
    assert rtu._default_max_consoles() * 4 <= soft // 2


# --- one TLS context per cluster and verify flag --------------------------------------------

@pytest.fixture
def made_contexts(monkeypatch):
    made = []
    real = ssl.create_default_context

    def counting(*a, **kw):
        ctx = real(*a, **kw)
        made.append(ctx)
        return ctx
    monkeypatch.setattr(ssl, 'create_default_context', counting)
    monkeypatch.setattr(vms, '_console_ssl', {}, raising=False)
    return made


def test_vnc_opens_share_one_tls_context(api, seed, vnc_cluster, made_contexts):
    """create_default_context() reads the whole CA store; it was made again per console."""
    for _ in range(3):
        _vnc(api, _RecordingBrowser())
    assert len(vnc_cluster.contexts) == 3, 'the consoles did not all log in to PVE'
    assert len(made_contexts) == 1, f'{len(made_contexts)} TLS contexts for three consoles'
    ctx = vnc_cluster.contexts[0]
    assert all(c is ctx for c in vnc_cluster.contexts)
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname


def test_the_verify_flag_of_the_cluster_still_decides(api, seed, vnc_cluster, made_contexts):
    """Switching ssl_verification on is never answered with the context made while it was
    off, and off again not with the verifying one."""
    _vnc(api, _RecordingBrowser())
    vnc_cluster.manager._ssl_verify = True
    _vnc(api, _RecordingBrowser())
    _vnc(api, _RecordingBrowser())
    vnc_cluster.manager._ssl_verify = False
    _vnc(api, _RecordingBrowser())
    off, on, on_again, off_again = vnc_cluster.contexts
    assert off.verify_mode == ssl.CERT_NONE and not off.check_hostname
    assert on.verify_mode == ssl.CERT_REQUIRED and on.check_hostname
    assert on_again is on and off_again is off
    assert len(made_contexts) == 2


def test_a_verifying_context_is_made_again_when_the_ca_bundle_changes(tmp_path, monkeypatch,
                                                                       made_contexts):
    bundle = tmp_path / 'ca.pem'
    bundle.write_text('', encoding='utf-8')
    paths = ssl.DefaultVerifyPaths(str(bundle), None, 'SSL_CERT_FILE', str(bundle),
                                   'SSL_CERT_DIR', str(tmp_path / 'none'))
    monkeypatch.setattr(ssl, 'get_default_verify_paths', lambda: paths)
    first = vms._console_ssl_context('c1', True)
    assert vms._console_ssl_context('c1', True) is first
    st = os.stat(bundle)
    os.utime(bundle, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    again = vms._console_ssl_context('c1', True)
    assert again is not first, 'a changed CA bundle was not read again'
    assert again.verify_mode == ssl.CERT_REQUIRED and again.check_hostname
    # the context without verification reads no CA store, a changed one is no reason
    off = vms._console_ssl_context('c1', False)
    os.utime(bundle, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
    assert vms._console_ssl_context('c1', False) is off


def test_the_terminal_ticket_reuses_the_consoles_context(api, seed, monkeypatch, made_contexts):
    """The termproxy ticket the terminal page asks for first made its own context too."""
    import urllib.error
    seed.user('root', role='admin')
    mgr = api.make_fake_manager('cluster_1')
    mgr.host = mgr.auth_host = '10.0.0.5'
    mgr.api_port = 8006
    mgr._ssl_verify = False
    mgr.config = types.SimpleNamespace(user='root@pam', pass_='pw', password='pw')
    api.set_manager('cluster_1', mgr)
    handed = []

    def unreachable(req, *a, **k):
        raise urllib.error.URLError('no PVE in this test')

    def opener(context=None):
        handed.append(context)
        return types.SimpleNamespace(open=unreachable)
    monkeypatch.setattr('pegaprox.core.manager.pve_opener', opener)
    c = api.as_user({'username': 'root', 'role': 'admin'})
    for _ in range(2):
        c.post('/api/clusters/cluster_1/vms/pve1/qemu/100/termproxy', json={})
    assert len(handed) == 2, handed
    assert handed[0] is handed[1] and handed[0].verify_mode == ssl.CERT_NONE
    assert len(made_contexts) == 1
