"""How PegaProx answers plain HTTP while it serves HTTPS, with the settings as they ship.

- The TLS port: with http_redirect_port -1, the default of every install,
  _start_gevent_server ran its server without the protocol check, and a browser that opened
  http://host:5000 got a connection reset instead of a 301 (Chromium ERR_CONNECTION_RESET,
  curl exit code 56). A trusted proxy that forwards plain HTTP with X-Forwarded-Proto: https
  got the same reset. -1 now means no extra port and nothing else.
- The extra port main() opens (_resolve_http_redirect_port): 0 (auto) only ever opened port
  80 as root, which none of the packages runs as.

The real server runs in a subprocess, called the way main() calls it, with no redirect
setting at all: once on 127.0.0.1 and once on ::1. MK
"""
import inspect
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

import gevent
import pytest

import pegaprox.app as app_mod
from pegaprox import globals as g
from test_redirect_head_deadline import _tls_files

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = '/vms/101?tab=console&x=1'

_SERVER = r'''
import gevent.monkey; gevent.monkey.patch_all()
import sys
import threading
from flask import Flask
import pegaprox.app as app_mod

app_mod._start_console_servers = lambda *a, **k: None
web = Flask('redirect-defaults')

# loopback is always a trusted proxy, so a peer at 127.0.0.2 stands in for a host on the
# network that is none
import pegaprox.utils.audit as audit
_trusted = audit._is_trusted_proxy
audit._is_trusted_proxy = lambda addr: not str(addr).endswith('127.0.0.2') and _trusted(addr)

# an HTTP-01 challenge in progress
import pegaprox.core.acme as acme
acme._pending_challenges['tok-known_1'] = 'tok-known_1.key-authorization'


@web.route('/ping')
def ping():
    return 'pong'


@web.route('/state')
def state():
    from pegaprox import globals as g
    return g.HTTP_REDIRECT_STATE


# the extra port, started the way main() starts it
threading.Thread(target=app_mod._start_http_redirect,
                 args=(sys.argv[1], int(sys.argv[5]), int(sys.argv[2]), ''), daemon=True).start()
app_mod._start_gevent_server(web, sys.argv[1], int(sys.argv[2]), (sys.argv[3], sys.argv[4]),
                             None, 4)
'''


def _ipv6():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(('::1', 0))
        return True
    except OSError:
        return False


def _free_port(host):
    with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def _connect(host, port, src=None, timeout=5):
    s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
    s.settimeout(timeout)
    if src:
        s.bind((src, 0))
    s.connect((host, port))
    return s


def _read_all(s):
    data = b''
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except ConnectionResetError:
        data += b'<reset>'
    except socket.timeout:
        data += b'<timeout>'
    finally:
        s.close()
    return data


def _plain(host, port, head, src=None, timeout=5):
    """Send a plain-HTTP request head, return everything that comes back. A reset or a
    timeout reads as the marker <reset> or <timeout>, which no answer starts with."""
    s = _connect(host, port, src, timeout)
    s.sendall(head.encode())
    return _read_all(s)


def _tls_get(host, port, path='/ping', timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(_connect(host, port, timeout=timeout))
    s.sendall(f'GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'.encode())
    return _read_all(s)


def _location(answer):
    for line in answer.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]:
        name, _, value = line.partition(b':')
        if name.strip().lower() == b'location':
            return value.strip().decode()
    return None


def _start(where, host):
    cert, key = _tls_files(where)
    port, extra = _free_port(host), _free_port(host)
    log = open(where / 'server.log', 'w')
    env = {**os.environ, 'PYTHONPATH': REPO, 'PEGAPROX_CONFIG_DIR': str(where / 'config')}
    proc = subprocess.Popen([sys.executable, '-c', _SERVER, host, str(port), cert, key, str(extra)],
                            cwd=str(where), env=env, stdout=log, stderr=subprocess.STDOUT)
    end = time.monotonic() + 60
    while True:
        try:
            if b'pong' in _tls_get(host, port, timeout=2) and _plain(
                    host, extra, 'GET / HTTP/1.1\r\nHost: x\r\n\r\n', timeout=2).startswith(b'HTTP/1.1 301'):
                return proc, log, (port, extra)
        except OSError:
            pass
        if proc.poll() is not None or time.monotonic() > end:
            log.flush()
            _stop(proc, log)
            pytest.fail('test server did not come up:\n' + (where / 'server.log').read_text())
        gevent.sleep(0.2)


def _stop(proc, log):
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)
    log.close()


@pytest.fixture(scope='module')
def ports(tmp_path_factory):
    """(TLS port, extra port) of a server on 127.0.0.1"""
    proc, log, both = _start(tmp_path_factory.mktemp('redirect4'), '127.0.0.1')
    yield both
    _stop(proc, log)


@pytest.fixture(scope='module')
def server(ports):
    return ports[0]


@pytest.fixture(scope='module')
def extra(ports):
    return ports[1]


@pytest.fixture(scope='module')
def server6(tmp_path_factory):
    if not _ipv6():
        pytest.skip('no IPv6 loopback here')
    proc, log, both = _start(tmp_path_factory.mktemp('redirect6'), '::1')
    yield both[0]
    _stop(proc, log)


def test_plain_http_and_tls_share_the_port_by_default(server):
    answer = _plain('127.0.0.1', server,
                    f'GET {PATH} HTTP/1.1\r\nHost: 127.0.0.1:{server}\r\nConnection: close\r\n\r\n')

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://127.0.0.1:{server}{PATH}'
    assert _tls_get('127.0.0.1', server).endswith(b'pong')


def test_an_ipv6_client_is_sent_to_its_bracketed_address(server6):
    answer = _plain('::1', server6,
                    f'GET {PATH} HTTP/1.1\r\nHost: [::1]:{server6}\r\nConnection: close\r\n\r\n')

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://[::1]:{server6}{PATH}'
    assert _tls_get('::1', server6).endswith(b'pong')


def test_a_trusted_proxy_that_terminated_tls_is_served(server):
    """Loopback is always a trusted proxy (utils.audit._is_trusted_proxy)."""
    answer = _plain('127.0.0.1', server, 'GET /ping HTTP/1.1\r\nHost: pegaprox.example\r\n'
                                         'X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n')

    assert answer.startswith(b'HTTP/1.1 200'), answer[:120]
    assert answer.endswith(b'pong')


# -- ACME HTTP-01 ------------------------------------------------------------------------
#
# Only the extra port answered a challenge token. With port 80 forwarded to the TLS port
# the token got a redirect to :5000, and Let's Encrypt follows one only to port 80 or 443.

def test_a_known_acme_token_is_answered_on_both_ports_an_unknown_one_redirected(server, extra):
    def ask(port, token):
        return _plain('127.0.0.1', port, f'GET /.well-known/acme-challenge/{token} HTTP/1.1\r\n'
                                         'Host: pegaprox.example\r\nConnection: close\r\n\r\n')

    for port in (extra, server):
        known, unknown = ask(port, 'tok-known_1'), ask(port, 'tok-unknown_2')
        assert known.startswith(b'HTTP/1.1 200'), (port, known[:120])
        assert known.endswith(b'\r\n\r\ntok-known_1.key-authorization'), known
        assert unknown.startswith(b'HTTP/1.1 301'), (port, unknown[:120])
        assert _location(unknown) == f'https://pegaprox.example:{server}/.well-known/acme-challenge/tok-unknown_2'


# -- the port in the Host header -------------------------------------------------------
#
# The TLS port sent every client to the port it listens on. Behind docker -p 8443:5000 or a
# port forward the client reached it through another one, and https://host:5000 led nowhere.

def test_the_tls_port_sends_a_client_back_to_the_port_it_came_through(server, extra):
    def location(port, host):
        return _location(_plain('127.0.0.1', port, f'GET {PATH} HTTP/1.1\r\nHost: {host}\r\n'
                                                   'Connection: close\r\n\r\n'))

    assert location(server, 'pegaprox.lan:8443') == f'https://pegaprox.lan:8443{PATH}'
    assert location(server, '192.0.2.5:8443') == f'https://192.0.2.5:8443{PATH}'
    assert location(server, '[2001:db8::10]:8443') == f'https://[2001:db8::10]:8443{PATH}'
    assert location(server, 'pegaprox.lan:443') == f'https://pegaprox.lan{PATH}'
    # no port, or none that is one: the port it listens on
    for host in ('pegaprox.lan', 'pegaprox.lan:', 'pegaprox.lan:abc', 'pegaprox.lan:70000',
                 '[2001:db8::10]', '[evil.example]:8443'):
        assert location(server, host).endswith(f':{server}{PATH}'), host
    # the extra port is no way to the TLS port, whatever the client typed
    assert location(extra, 'pegaprox.lan:8080') == f'https://pegaprox.lan:{server}{PATH}'


# -- forwarded headers -----------------------------------------------------------------
#
# X-Forwarded-Proto and X-Forwarded-Port count only from a trusted proxy. The redirect
# followed an X-Forwarded-Port from anyone, ended without an answer on one that was no
# number, and on the TLS port closed the connection on an X-Forwarded-Proto https from
# anyone, which a browser shows as an empty reply.

UNTRUSTED = '127.0.0.2'


def test_forwarded_headers_from_a_host_that_is_no_proxy_change_nothing(server):
    head = (f'GET {PATH} HTTP/1.1\r\nHost: pegaprox.lan:{server}\r\nX-Forwarded-Proto: https\r\n'
            'X-Forwarded-Port: 443\r\nConnection: close\r\n\r\n')
    answer = _plain('127.0.0.1', server, head, src=UNTRUSTED)

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://pegaprox.lan:{server}{PATH}'


def test_a_trusted_proxy_saying_https_on_a_plain_redirect_gets_a_400(server, extra):
    """The extra port, and the TLS port when the header comes after the first segment, so
    the look ahead of DualProtocolWSGIServer does not see it. Both closed without a word."""
    whole = 'GET / HTTP/1.1\r\nHost: pegaprox.lan\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n'
    on_extra = _plain('127.0.0.1', extra, whole)

    # a server slow to accept looks ahead after the second segment and serves the request,
    # the 404 of the app; then again with a longer gap
    for gap in (0.3, 1.0, 2.0):
        s = _connect('127.0.0.1', server)
        s.sendall(b'GET / HTTP/1.1\r\nHost: pegaprox.lan\r\n')
        gevent.sleep(gap)
        s.sendall(b'X-Forwarded-Proto: https\r\nConnection: close\r\n\r\n')
        on_tls_port = _read_all(s)
        if not on_tls_port.startswith(b'HTTP/1.1 404'):
            break

    for answer in (on_extra, on_tls_port):
        assert answer.startswith(b'HTTP/1.1 400'), answer[:120]
        assert b'X-Forwarded-Proto' in answer


class _Stop(BaseException):
    """Ends the accept loop; BaseException so the server's own handlers let it through."""


class _FakeClient:
    def __init__(self, raw):
        self.raw, self.sent, self.closed = raw, b'', threading.Event()

    def settimeout(self, t):
        pass

    def recv(self, n):
        return self.raw[:n]

    def sendall(self, data):
        self.sent += data

    def close(self):
        self.closed.set()


def _extra_port_answer(monkeypatch, lines, src, https_port=5000, target='/dashboard'):
    """The extra port's answer to one request from `src`, on a fake socket module."""
    client = _FakeClient((f'GET {target} HTTP/1.1\r\nHost: pegaprox.example\r\n'
                          + ''.join(l + '\r\n' for l in lines) + '\r\n').encode())
    queue = [client]

    class Listener:
        def __init__(self, *a, **k):
            pass

        def setsockopt(self, *a):
            pass

        def bind(self, addr):
            pass

        def listen(self, n):
            pass

        def settimeout(self, t):
            pass

        def accept(self):
            if not queue:
                raise _Stop()
            return queue.pop(), (src, 40000)

    with monkeypatch.context() as m:
        m.setattr(app_mod.socket, 'socket', Listener)
        with pytest.raises(_Stop):
            app_mod._start_http_redirect('0.0.0.0', 8080, https_port, '')
    assert client.closed.wait(5)
    return client.sent


@pytest.mark.parametrize('lines', [
    ['X-Forwarded-Port: 443'],
    ['X-Forwarded-Proto: https', 'X-Forwarded-Port: 443'],
    ['X-Forwarded-Port: abc'],
    ['X-Forwarded-Port: 8443'],
])
def test_the_extra_port_ignores_forwarded_headers_from_a_host_that_is_no_proxy(monkeypatch, lines):
    answer = _extra_port_answer(monkeypatch, lines, src='192.0.2.7')

    assert answer.startswith(b'HTTP/1.1 301'), answer
    assert _location(answer) == 'https://pegaprox.example:5000/dashboard'


def test_a_trusted_proxy_moves_the_port_only_with_a_number(monkeypatch):
    wanted = {'8443': ':8443', '443': '', ' 9443 ': ':9443', '': ':5000',
              'abc': ':5000', '0': ':5000', '70000': ':5000', '-1': ':5000', '+443': ':5000'}
    got = {}
    for value in wanted:
        answer = _extra_port_answer(monkeypatch, [f'X-Forwarded-Port: {value}'], src='127.0.0.1')
        got[value] = _location(answer)

    assert got == {v: f'https://pegaprox.example{p}/dashboard' for v, p in wanted.items()}


# -- the request target ------------------------------------------------------------------
#
# It went after the host as it came. A target that starts with an at sign turned the host
# and port into the user part of the Location, and the absolute form gave no URL at all.

AT = '@'                                     # spelled out, two targets below use it


@pytest.mark.parametrize('target, path', [
    (AT + 'other.example/x', '/'),
    (AT + 'other.example', '/'),
    ('http://other.example/x?y=1', '/x?y=1'),
    (f'http://u{AT}other.example/x', '/x'),
    ('https://other.example', '/'),
    ('other.example/x', '/'),
    ('*', '/'),
    ('/dashboard?tab=1', '/dashboard?tab=1'),
    ('//other.example/x', '//other.example/x'),   # a path, after a host
])
def test_only_a_path_goes_after_the_host(monkeypatch, server, target, path):
    on_extra = _location(_extra_port_answer(monkeypatch, [], src='192.0.2.7', target=target))
    on_tls_port = _location(_plain('127.0.0.1', server, f'GET {target} HTTP/1.1\r\nHost: pegaprox.lan:8443\r\n'
                                                        'Connection: close\r\n\r\n'))

    assert on_extra == f'https://pegaprox.example:5000{path}'
    assert on_tls_port == f'https://pegaprox.lan:8443{path}'


# -- the extra port --------------------------------------------------------------------
#
# It answered one client after the other, with a 5 s timeout on each: three connections that
# sent nothing held a redirect back for 15 s, without a login. And it read a single
# recv(4096), so a head that came in two segments lost its Host and the redirect went to
# localhost.

def test_idle_clients_on_the_extra_port_do_not_hold_up_a_redirect(server, extra):
    idle = [_connect('127.0.0.1', extra) for _ in range(3)]
    try:
        gevent.sleep(0.2)
        t0 = time.monotonic()
        answer = _plain('127.0.0.1', extra,
                        f'GET {PATH} HTTP/1.1\r\nHost: 127.0.0.1:{extra}\r\nConnection: close\r\n\r\n')
        took = time.monotonic() - t0
    finally:
        for s in idle:
            s.close()

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://127.0.0.1:{server}{PATH}'
    assert took < 1, f'three idle clients held the redirect back for {took:.1f}s'


def test_a_head_in_two_segments_keeps_its_host_on_the_extra_port(server, extra):
    s = _connect('127.0.0.1', extra)
    s.sendall(f'GET {PATH} HTTP/1.1\r\n'.encode())
    gevent.sleep(0.3)
    s.sendall(b'Host: pegaprox.lan\r\nConnection: close\r\n\r\n')
    answer = _read_all(s)

    assert answer.startswith(b'HTTP/1.1 301'), answer[:120]
    assert _location(answer) == f'https://pegaprox.lan:{server}{PATH}'


def test_a_head_with_bare_line_feeds_is_answered_on_both_ports(server, extra):
    """printf 'GET / HTTP/1.0\\n\\n' | nc ends its head with LF LF. Both listeners waited
    for CRLF CRLF until their recv ran out after 5 s and closed without an answer, and the
    one recv the extra port had before lost the Host of such a head."""
    head = f'GET {PATH} HTTP/1.0\nHost: pegaprox.lan\n\n'
    for port in (extra, server):
        answer = _plain('127.0.0.1', port, head, timeout=3)

        assert answer.startswith(b'HTTP/1.1 301'), (port, answer[:120])
        assert _location(answer) == f'https://pegaprox.lan:{server}{PATH}', port


def test_the_log_says_what_became_of_the_extra_port(monkeypatch, capsys):
    """Listening only once bound, a refused bind names what it needs, and main() no longer
    announces the port before it knows."""
    class Refused:
        def __init__(self, *a, **k):
            pass

        def setsockopt(self, *a):
            pass

        def bind(self, addr):
            raise PermissionError(13, 'Permission denied')

    with monkeypatch.context() as m:
        m.setattr(app_mod.socket, 'socket', Refused)
        app_mod._start_http_redirect('0.0.0.0', 80, 5000, '')
    refused = capsys.readouterr().out

    with socket.socket() as taken:
        taken.bind(('127.0.0.1', 0))
        taken.listen(1)
        app_mod._start_http_redirect('127.0.0.1', taken.getsockname()[1], 5000, '')
    busy = capsys.readouterr().out

    assert 'needs root or CAP_NET_BIND_SERVICE' in refused and 'listening' not in refused
    assert 'already in use' in busy and 'listening' not in busy
    assert 'Started additional' not in inspect.getsource(app_mod.main)


# -- which extra port main() opens -------------------------------------------------------
#
# 0 (auto) looked at the uid only. The deb, deploy.sh, the appliances and the Docker image
# all run as the pegaprox user, whose units grant CAP_NET_BIND_SERVICE as an ambient
# capability, so auto never opened port 80 anywhere it was asked for. A PEGAPROX_HTTP_PORT
# that is no number stopped the start with a ValueError.

NO_CAP = 'Name:\tpython3\nCapInh:\t0000000000000000\nCapEff:\t0000000000000000\n'
NET_BIND = 'Name:\tpython3\nCapInh:\t0000000000000400\nCapEff:\t0000000000000400\n'
FULL_SET = 'Name:\tpython3\nCapEff:\t000001ffffffffff\n'


@pytest.fixture
def host(monkeypatch, tmp_path):
    """The uid, the capability line and the kernel's port limit this process sees."""
    status, start = tmp_path / 'status', tmp_path / 'ip_unprivileged_port_start'
    monkeypatch.setattr(app_mod, '_PROC_STATUS', str(status))
    monkeypatch.setattr(app_mod, '_UNPRIVILEGED_PORT_START', str(start))
    monkeypatch.delenv('PEGAPROX_HTTP_PORT', raising=False)

    def set_(uid=1000, caps=NO_CAP, limit='1024', env=None):
        monkeypatch.setattr(app_mod.os, 'geteuid', lambda: uid)
        for path, text in ((status, caps), (start, limit)):
            if text is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(text + '\n')
        if env is not None:
            monkeypatch.setenv('PEGAPROX_HTTP_PORT', env)
    return set_


@pytest.mark.parametrize('setting, seen, expected', [
    (-1, {}, -1),
    (None, {}, -1),
    (0, {'uid': 0}, 80),
    (0, {'caps': NET_BIND}, 80),                  # the ambient capability of the units
    (0, {'caps': FULL_SET}, 80),
    (0, {}, -1),                                  # a plain user, limit 1024
    (0, {'limit': '0'}, 80),                      # inside a Docker container
    (0, {'limit': '80'}, 80),
    (0, {'limit': '81'}, -1),
    (0, {'caps': None, 'limit': None}, -1),       # nothing readable: no port 80
    (0, {'caps': 'CapEff:\tzz\n'}, -1),
    (80, {}, 80),                                 # an explicit port is opened as asked
    (18080, {}, 18080),
    ('8081', {}, 8081),
    ('abc', {}, -1),
    (-5, {}, -1),
    (70000, {}, -1),
    # PEGAPROX_HTTP_PORT wins over the setting, and goes the same way
    (-1, {'env': '18080'}, 18080),
    (80, {'env': '-1'}, -1),
    (-1, {'env': '0', 'caps': NET_BIND}, 80),
    (-1, {'env': '0'}, -1),
    (8080, {'env': ' 9090 '}, 9090),
])
def test_the_extra_port_main_opens(host, setting, seen, expected):
    host(**seen)
    assert app_mod._resolve_http_redirect_port(setting, 5000) == expected


def test_an_env_port_that_is_no_number_is_warned_about_not_fatal(host, capsys):
    host(env='abc')

    assert app_mod._resolve_http_redirect_port(8080, 5000) == 8080
    assert "PEGAPROX_HTTP_PORT='abc' is not a port number" in capsys.readouterr().out


def test_auto_without_port_80_says_why_in_one_line(host, capsys):
    host(uid=os.getuid() or 1000)

    assert app_mod._resolve_http_redirect_port(0, 5000) == -1
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) == 1, lines
    assert 'port 80 not available' in lines[0]
    assert 'needs root or CAP_NET_BIND_SERVICE' in lines[0]
    assert 'HTTP on port 5000 still redirects' in lines[0]


def test_the_https_port_is_no_extra_port(host, capsys):
    """The extra listener bound it first and the main one then stopped the start with
    "Address already in use". Plain HTTP on that port redirects without it."""
    host(caps=NET_BIND)
    got = {'setting': app_mod._resolve_http_redirect_port(5000, 5000),
           'auto on 80': app_mod._resolve_http_redirect_port(0, 80),
           'next to it': app_mod._resolve_http_redirect_port(5001, 5000)}
    host(env='5000')
    got['env'] = app_mod._resolve_http_redirect_port(-1, 5000)
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]

    assert got == {'setting': -1, 'auto on 80': -1, 'next to it': 5001, 'env': -1}
    assert len(lines) == 3 and all('is the HTTPS port' in l for l in lines), lines


def test_the_help_names_no_default_port():
    """It said "default 80", which no install opens without being asked to."""
    out = subprocess.run([sys.executable, os.path.join(REPO, 'pegaprox_multi_cluster.py'), '--help'],
                         cwd=REPO, capture_output=True, text=True, timeout=60,
                         env={**os.environ, 'PEGAPROX_NO_GEVENT': '1'}).stdout
    line, = [l for l in out.splitlines() if l.strip().startswith('PEGAPROX_HTTP_PORT')]
    assert line.split(None, 1)[1] == 'extra http port for the redirect (default none)'


def test_main_asks_the_resolver_and_opens_nothing_behind_a_reverse_proxy():
    """main() is too big to run here, so how it gets to the port is read in its source."""
    src = inspect.getsource(app_mod.main)
    block = src[src.index('_resolve_http_redirect_port(') - 200:src.index('target=_start_http_redirect')]
    assert 'if ssl_context and not reverse_proxy:' in block
    assert 'PEGAPROX_HTTP_PORT' not in src


# -- what the settings show ------------------------------------------------------------
#
# The settings page had only the stored number and a hint that was wrong for -1. It now gets
# what this process actually runs as http_redirect_state, which no save writes back.

@pytest.fixture(autouse=True)
def state(monkeypatch):
    """A state of its own for each test; the in-process ones bind, refuse and resolve."""
    fresh = {'same_port': None, 'extra_port': None, 'extra_error': ''}
    monkeypatch.setattr(g, 'HTTP_REDIRECT_STATE', fresh, raising=False)
    return fresh


def test_the_running_server_records_both_redirects(server, extra):
    answer = _tls_get('127.0.0.1', server, '/state')
    body = answer.split(b'\r\n\r\n', 1)[1]

    assert answer.startswith(b'HTTP/1.1 200'), answer[:200]
    assert json.loads(body) == {'same_port': server, 'extra_port': extra, 'extra_error': ''}


def test_the_state_says_why_an_extra_port_is_not_listening(state, monkeypatch, host):
    class Refused:
        def __init__(self, *a, **k):
            pass

        def setsockopt(self, *a):
            pass

        def bind(self, addr):
            raise PermissionError(13, 'Permission denied')

    with monkeypatch.context() as m:
        m.setattr(app_mod.socket, 'socket', Refused)
        app_mod._start_http_redirect('0.0.0.0', 81, 5000, '')
    refused = dict(state)

    with socket.socket() as taken:
        taken.bind(('127.0.0.1', 0))
        taken.listen(1)
        busy_port = taken.getsockname()[1]
        app_mod._start_http_redirect('127.0.0.1', busy_port, 5000, '')
        busy = dict(state)

    host()                                     # a plain user without the capability
    app_mod._resolve_http_redirect_port(0, 5000)
    auto = dict(state)

    assert refused == {'same_port': None, 'extra_port': 81, 'extra_error': 'needs root or CAP_NET_BIND_SERVICE'}
    assert busy == {'same_port': None, 'extra_port': busy_port, 'extra_error': 'already in use'}
    assert auto == {'same_port': None, 'extra_port': 80, 'extra_error': 'needs root or CAP_NET_BIND_SERVICE'}


def test_the_settings_read_shows_the_state_and_no_save_stores_it(api, db, seed, state):
    state.update(same_port=5000, extra_port=80, extra_error='already in use')
    c = api.as_user(seed.user('root', role='admin'))

    read = c.get('/api/settings/server')
    assert read.status_code == 200, read.get_data(as_text=True)[:300]
    shown = read.get_json()['http_redirect_state']
    assert shown == {'same_port': 5000, 'extra_port': 80, 'extra_error': 'already in use'}

    sent = {'http_redirect_port': 8080, 'http_redirect_state': {'same_port': 1, 'extra_port': 2}}
    assert c.post('/api/settings/server', json=sent).status_code == 200
    assert c.post('/api/settings/server', data={'domain': '', 'port': '5000', 'http_redirect_port': '-1',
                                                'http_redirect_state': 'x'}).status_code == 200

    from pegaprox.api.helpers import load_server_settings
    stored = load_server_settings()
    assert 'http_redirect_state' not in stored
    assert stored['http_redirect_port'] == -1
    assert g.HTTP_REDIRECT_STATE == {'same_port': 5000, 'extra_port': 80, 'extra_error': 'already in use'}
