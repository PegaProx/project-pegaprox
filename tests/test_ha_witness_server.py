"""The witness server (#625 stage 2), the real process on a port of its own.

What it must survive: sockets that hold a connection and send nothing, or send their
head and then a body a byte at a time. A pool that such sockets fill takes the third
vote offline without one signed byte; here every connection has a deadline from its
accept, a source address holds a few unsigned connections and gives one up for the next
(one that sent nothing first), the source that holds the most gives way when all are
taken, and a connection whose call carried a good signature is served from a reserve
of its own. With an allow list, other addresses are closed at the accept.

MK Oct 2026 (#625)
"""
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import warnings
from collections import deque

import pytest

from pegaprox import witness as wm
from pegaprox.core import ha_vote as hv
from pegaprox.core import ha_wire
from test_ha_witness_install import _free_port

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A, B, W = 'a' * 32, 'b' * 32, 'f' * 32
KEYS = {i: ha_wire.new_signing_key() for i in (A, B, W)}


def _pub(i):
    return ha_wire.public_of(ha_wire.private_key(KEYS[i]))


def _genesis():
    import base64
    key = ha_wire.private_key(KEYS[A])
    voters = [{'id': i, 'public_key': _pub(i), 'voter': True, 'may_lead': True, 'site': ''} for i in (A, B)]
    body = {'mode': hv.MODE_AUTO, 'lease_s': 20, 'voters': voters,
            'witness': {'id': W, 'public_key': _pub(W), 'site': 'dc3'}, 'quarantined': []}
    return hv.make_cfg(None, 1, A, body, lambda m: base64.b64encode(key.sign(m)).decode())


class _Running:
    def __init__(self, path, port, proc):
        self.dir, self.port, self.proc = path, port, proc


def _tls(port, timeout=5):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(('127.0.0.1', port), timeout=timeout)
    return ctx.wrap_socket(raw)


def _start(path, args=(), env=None):
    """A paired witness on a free port, `args` before the command: (dir, port, process)."""
    d = wm.check_dir(str(path / 'w'))
    wm.tls_pair(d)
    wm.Witness(d, started=0, boot_id='x').write({
        'role': hv.ROLE_WITNESS, 'instance_id': W, 'signing_key': KEYS[W], 'own_url': 'https://127.0.0.1',
        'paired': {'instance_id': A, 'url': 'https://127.0.0.1:1', 'fingerprint': '', 'at': 'x'},
        'epoch': 1, 'voted_for': None, 'gen': 0, 'cfg': _genesis(), 'cfg_chain': [], 'floor_cv': [0, 0],
        'led': None, 'released': None, 'campaign_after': None, 'promised': None})
    port = _free_port()
    proc = subprocess.Popen([sys.executable, '-m', 'pegaprox.witness', '--dir', d, '--host', '127.0.0.1',
                             '--port', str(port), *args, 'run'],
                            env=dict(os.environ, PYTHONPATH=ROOT, **(env or {})),
                            cwd=str(path), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 30
    while True:
        try:
            _tls(port, timeout=1).close()
            break
        except OSError:
            if time.time() > deadline or proc.poll() is not None:
                proc.kill()
                proc.wait(10)
                pytest.fail('the witness did not come up')
            time.sleep(0.2)
    return _Running(d, port, proc)


def _stop(running):
    running.proc.terminate()
    try:
        running.proc.wait(10)
    except subprocess.TimeoutExpired:
        running.proc.kill()
        running.proc.wait(10)


@pytest.fixture
def server(tmp_path):
    running = _start(tmp_path)
    yield running
    _stop(running)


def _call(port, kind, payload=None, sender=A, session=None, timeout=2.0):
    """A signed call as a member sends it: (status or the exception's name, answer, seconds)."""
    import requests
    method = 'GET' if kind == 'status' else 'POST'
    path = wm.STATUS_PATH if kind == 'status' else wm.VOTE_PATH
    raw = ha_wire.wire_body(payload) if method == 'POST' else b''
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[sender]), sender, W, method, path, raw, time.time())
    if raw:
        h['Content-Type'] = 'application/json'
    t0 = time.monotonic()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            r = (session or requests).request(method, f'https://127.0.0.1:{port}{path}', data=raw or None,
                                              headers=h, verify=False, timeout=timeout)
            return r.status_code, r.json(), time.monotonic() - t0
        except Exception as e:
            return type(e).__name__, None, time.monotonic() - t0


VOTE = {'epoch': 2, 'candidate': A, 'pre': True, 'why': 'timer', 'cv': [1, 5], 'cfg_id': [1, 1],
        'lease_s': 20}


def _answer(sock, limit=5.0):
    """What the server sends until it closes or `limit` passes."""
    sock.settimeout(limit)
    data = b''
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except (OSError, ssl.SSLError):
        pass
    return data


def _closed_after(sock, t0, limit, trickle=b''):
    """Seconds from t0 until the server closed `sock`, sending it `trickle` a byte every
    half second meanwhile; None when it was still open after `limit`. A read that times
    out here is no close: the server's TLS session tickets make the socket readable
    without any data behind them."""
    sock.settimeout(0.2)
    while time.monotonic() - t0 < limit:
        try:
            if not sock.recv(1024):
                return time.monotonic() - t0
        except (socket.timeout, ssl.SSLWantReadError):
            pass
        except (OSError, ssl.SSLError):
            return time.monotonic() - t0
        if trickle:
            try:
                sock.send(trickle[:1])
            except (OSError, ssl.SSLError):
                return time.monotonic() - t0
            trickle = trickle[1:]
        time.sleep(0.3)
    return None


def test_idle_and_slow_sockets_leave_a_signed_call_its_answer(server):
    """200 sockets that never start TLS and 64 that send a head and then dribble a body,
    all from the member's own address: a signed vote on a new connection still has its
    answer in well under a second, and so has a status call."""
    port = server.port
    assert _call(port, 'status')[0] == 200
    held = []
    try:
        for _ in range(200):
            held.append(socket.create_connection(('127.0.0.1', port), timeout=5))
        for i in range(64):
            s = _tls(port)
            # half claim a member without a signature, half a voter only a chain could
            # name - the body of those is read, under the deadline of its connection
            sender = A if i % 2 else 'c' * 32
            s.sendall(f'POST {wm.VOTE_PATH} HTTP/1.1\r\nHost: w\r\nContent-Type: application/json\r\n'
                      f'Content-Length: 60000\r\n{ha_wire.PEER_HEADER}: {sender}\r\n\r\n{{'.encode())
            held.append(s)
        time.sleep(0.5)
        status, ans, took = _call(port, 'vote', VOTE)
        print(f'200 idle + 64 slow-body sockets: signed vote answered {status} in {took * 1000:.0f} ms')
        assert status == 200 and ans['reason'] in ('', 'HOLD_AFTER_START') and took < 1.0, (status, took)
        status, ans, took = _call(port, 'status')
        print(f'  signed status answered {status} in {took * 1000:.0f} ms')
        assert status == 200 and took < 1.0
    finally:
        for s in held:
            s.close()


def test_a_connection_has_a_deadline_from_its_accept(server):
    """A socket that sends nothing is closed _ANON_S after its accept; one that sends its
    head a byte at a time is closed then as well - a byte that arrives does not start the
    wait over, as a socket timeout would."""
    port = server.port
    t0 = time.monotonic()
    idle = socket.create_connection(('127.0.0.1', port), timeout=5)
    took = _closed_after(idle, t0, wm._ANON_S + 5)
    idle.close()
    assert took is not None and wm._ANON_S - 1 <= took <= wm._ANON_S + 2.5, took
    t0 = time.monotonic()
    slow = _tls(port)
    took = _closed_after(slow, t0, wm._ANON_S + 10,
                         trickle=b'GET /api/ha/peer/status HTTP/1.1\r\nX-Padding: ' + b'a' * 100)
    slow.close()
    assert took is not None and took <= wm._ANON_S + 2.5, took


def test_a_call_refused_whatever_it_says_is_answered_without_its_body(server):
    port = server.port
    s = _tls(port)
    t0 = time.monotonic()
    s.sendall(f'POST {wm.VOTE_PATH} HTTP/1.1\r\nHost: w\r\nContent-Length: 60000\r\n'
              f'{ha_wire.PEER_HEADER}: {A}\r\n\r\n'.encode())
    data = _answer(s)
    s.close()
    assert data.startswith(b'HTTP/1.1 401 ') and b'Connection: close' in data
    assert time.monotonic() - t0 < 1.0
    for head, want in ((f'GET {wm.STATUS_PATH}?x=1 HTTP/1.1\r\n\r\n', b'400'),
                       (f'POST {wm.VOTE_PATH} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n', b'400'),
                       (f'POST {wm.VOTE_PATH} HTTP/1.1\r\nContent-Length: {wm.MAX_BODY + 1}\r\n\r\n', b'413'),
                       ('GET /api/ha/peer/snapshot HTTP/1.1\r\n\r\n', b'404'),
                       ('BREW / HTTP/1.1\r\nA: 1\r\nA: 2\r\n\r\n', b'400')):
        s = _tls(port)
        s.sendall(head.encode())
        data = _answer(s)
        s.close()
        assert data.startswith(b'HTTP/1.1 ' + want), (head, data[:40])


def _on(sock, kind, payload=None):
    """One signed call on the open connection `sock`: (status, answer, head)."""
    method = 'GET' if kind == 'status' else 'POST'
    path = wm.STATUS_PATH if kind == 'status' else wm.VOTE_PATH
    raw = ha_wire.wire_body(payload) if method == 'POST' else b''
    h = ha_wire.signed_headers(ha_wire.private_key(KEYS[A]), A, W, method, path, raw, time.time())
    head = f'{method} {path} HTTP/1.1\r\nHost: w\r\nContent-Length: {len(raw)}\r\n'
    sock.sendall((head + ''.join(f'{k}: {v}\r\n' for k, v in h.items()) + '\r\n').encode() + raw)
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        assert chunk, 'the connection was closed'
        buf += chunk
    head, _sep, rest = buf.partition(b'\r\n\r\n')
    length = int(re.search(rb'Content-Length: (\d+)', head).group(1))
    while len(rest) < length:
        rest += sock.recv(4096)
    return int(head.split()[1]), json.loads(rest[:length]), head


def test_a_member_keeps_its_connection(server):
    """The leader renews on a kept session: its connection outlives the deadline of an
    unsigned one, and stays in the reserve while others fill their share."""
    port = server.port
    s = _tls(port, timeout=10)
    try:
        status, ans, head = _on(s, 'status')
        assert status == 200 and b'Connection: keep-alive' in head
        time.sleep(wm._ANON_S + 1)
        held = [socket.create_connection(('127.0.0.1', port), timeout=5) for _ in range(40)]
        try:
            for _ in range(3):
                t0 = time.monotonic()
                status, ans, head = _on(s, 'vote', VOTE)
                assert status == 200 and time.monotonic() - t0 < 1.0
        finally:
            for c in held:
                c.close()
        # a refused call ends the connection
        s.sendall(f'GET {wm.STATUS_PATH} HTTP/1.1\r\nHost: w\r\n\r\n'.encode())
        data = _answer(s)
        assert data.startswith(b'HTTP/1.1 401') and b'Connection: close' in data
    finally:
        s.close()


def test_health_fails_while_the_state_cannot_be_written(server, capsys):
    if os.geteuid() == 0:
        pytest.skip('root writes into a 0500 directory')
    args = ['--dir', server.dir, '--host', '127.0.0.1', '--port', str(server.port), 'health']
    assert wm.main(args) == 0
    os.chmod(server.dir, 0o500)
    try:
        assert wm.main(args) == 1
        assert 'cannot write the state directory' in capsys.readouterr().err
    finally:
        os.chmod(server.dir, 0o700)
    assert wm.main(args) == 0


# --- who gives way -----------------------------------------------------------------------

class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _conn(addr):
    return wm._Conn(wm._source((addr, 1)), None, wm._group((addr, 1)))


def test_a_source_gives_up_the_connection_stuck_the_longest():
    """A host behind the member's address (NAT, or its IPv6 /64) opens connection after
    connection, silent or with a first byte it never follows up. The member's connection
    moves on (first byte, handshake, head): what gives way is the one stuck the longest,
    never one inside a call. To push the member out the flood has to bring per_source new
    ones within one step of the member's."""
    for talks in (False, True):
        clock = _Clock()
        gate = wm._Gate(now=clock)
        member, busy = _conn('192.0.2.10'), _conn('192.0.2.10')
        busy.busy = True
        gate.admit(member)
        gate.admit(busy)
        for i in range(1000):
            clock.t += 0.01
            flood = _conn('192.0.2.10')
            gate.admit(flood)
            if talks:
                clock.t += 0.0001       # its first byte, after the accept
                gate.moved(flood)
            if i % 10 == 0:
                gate.moved(member)      # a step every 100 ms
        assert member in gate.anon and busy in gate.anon
        assert sum(1 for c in gate.anon if c.source == '192.0.2.10') == wm._PER_SOURCE + 1
    # a member stuck while per_source newer ones came is the one that goes: that is the bound
    clock = _Clock()
    gate = wm._Gate(now=clock)
    member = _conn('192.0.2.10')
    gate.admit(member)
    for _ in range(wm._PER_SOURCE):
        clock.t += 0.001
        gate.admit(_conn('192.0.2.10'))
    assert member not in gate.anon


@pytest.mark.parametrize('flood', ['24 addresses', 'an address each', 'an address each, talking first',
                                   'one IPv6 /48'])
def test_the_source_that_holds_the_most_gives_way_once_all_are_taken(flood):
    """However many addresses a flood comes from and whatever it sends, the member's
    connection is not the one that goes once the server holds _ANON_MAX: the source that
    holds the most gives one up, and among sources that hold as many, the one stuck the
    longest. With an address each that all sent their first byte, the member is the only
    one still silent on its way in: it stays as long as it moves on. An IPv6 flood counts
    by its /48 there."""
    clock = _Clock()
    gate = wm._Gate(now=clock)
    member = _conn('2001:db8:2::7' if flood == 'one IPv6 /48' else '198.51.100.7')
    for i in range(5000):
        addr = {'24 addresses': f'203.0.113.{i % 24 + 1}',
                'one IPv6 /48': f'2001:db8:1:{i:x}::1'}.get(
            flood, f'10.{i // 62500}.{i // 250 % 250}.{i % 250 + 1}')
        clock.t += 0.002                # 500 a second
        attacker = _conn(addr)
        gate.admit(attacker)
        if flood.endswith('talking first'):
            clock.t += 0.0001
            gate.moved(attacker)
        if i == 2000:
            gate.admit(member)
        elif i > 2000 and i % 25 == 0:
            gate.moved(member)          # its steps 50 ms apart
    assert member in gate.anon and len(gate.anon) == wm._ANON_MAX


def test_a_member_silent_on_its_way_in_is_not_the_one_a_talking_flood_singles_out():
    """_ANON_MAX addresses each hold one connection that sent its first byte and then
    stalls its handshake; the member's new one is silent for its round trip. The next
    connection pushes out the one stuck the longest, which is not the member's."""
    clock = _Clock()
    gate = wm._Gate(now=clock)
    for i in range(wm._ANON_MAX - 1):
        clock.t += 0.001
        c = _conn(f'10.1.{i // 250}.{i % 250 + 1}')
        gate.admit(c)
        clock.t += 0.0001
        gate.moved(c)
    clock.t += 0.001
    member = _conn('198.51.100.7')
    gate.admit(member)
    for i in range(wm._ANON_MAX - 1):
        clock.t += 0.0005
        c = _conn(f'10.2.{i // 250}.{i % 250 + 1}')
        gate.admit(c)
        clock.t += 0.0001
        gate.moved(c)
    assert member in gate.anon
    # only once _ANON_MAX newer ones came while it did not move on does it go
    clock.t += 0.0005
    gate.admit(_conn('10.3.0.1'))
    assert member not in gate.anon


def test_an_allow_list_names_networks():
    nets = wm.allow_list(['192.0.2.0/24, 2001:db8::/48', '198.51.100.7'])
    assert wm._allowed(('192.0.2.200', 1), nets) and wm._allowed(('198.51.100.7', 1), nets)
    assert wm._allowed(('::ffff:192.0.2.9', 1, 0, 0), nets) and wm._allowed(('2001:db8:0:5::1', 1, 0, 0), nets)
    assert not wm._allowed(('198.51.100.8', 1), nets) and not wm._allowed(('2001:db9::1', 1, 0, 0), nets)
    # this host, for health
    assert wm._allowed(('127.0.0.1', 1), nets) and wm._allowed(('::1', 1, 0, 0), nets)
    assert not wm._allowed(('127.0.0.2', 1), nets)
    assert wm.allow_list([]) is None and wm.allow_list(['', ' , ']) is None
    with pytest.raises(wm.WitnessError, match='not .10.0.0.0/33.'):
        wm.allow_list(['10.0.0.0/33'])
    with pytest.raises(wm.WitnessError):
        wm.allow_list(['witness.example'])


def _status_from(port, src, timeout=2.0):
    """A signed status call on a new connection from the address `src`."""
    raw = socket.socket()
    raw.bind((src, 0))
    raw.settimeout(timeout)
    try:
        raw.connect(('127.0.0.1', port))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw) as tls:
            return _on(tls, 'status')[0]
    except (OSError, AssertionError) as e:
        return type(e).__name__
    finally:
        raw.close()


@pytest.mark.parametrize('how', ['--allow', 'PEGAPROX_WITNESS_ALLOW'])
def test_with_an_allow_list_other_addresses_are_closed_at_once(tmp_path, how):
    args, env = ((['--allow', '127.0.0.3/32', '--allow', '192.0.2.0/24'], None) if how == '--allow'
                 else ((), {'PEGAPROX_WITNESS_ALLOW': '127.0.0.3, 192.0.2.0/24'}))
    running = _start(tmp_path, args, env)
    try:
        assert _status_from(running.port, '127.0.0.3') == 200
        # the address the health check comes from
        assert _status_from(running.port, '127.0.0.1') == 200
        t0 = time.monotonic()
        refused = _status_from(running.port, '127.0.0.2')
        assert refused != 200 and time.monotonic() - t0 < 1.0, refused
        assert wm.main(['--dir', running.dir, '--host', '127.0.0.1', '--port', str(running.port), 'health']) == 0
    finally:
        _stop(running)


def test_a_witness_with_an_allow_list_it_cannot_read_does_not_start(tmp_path, capsys):
    assert wm.main(['--dir', str(tmp_path / 'w'), '--allow', '10.0.0.0/33', 'run']) == wm.EXIT_CONFIG
    assert '--allow takes networks' in capsys.readouterr().err


class _Flood:
    """Connections that send nothing, `rate` a second from the addresses in `sources`, each
    held for two seconds: a thread of its own until the block ends."""

    def __init__(self, port, sources, rate):
        self.port, self.sources, self.rate = port, sources, rate
        self.stop = threading.Event()
        self.opened = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        time.sleep(1.0)
        return self

    def __exit__(self, *_exc):
        self.stop.set()
        self.thread.join(10)

    def _run(self):
        held = deque()
        t0 = time.monotonic()
        while not self.stop.is_set():
            due = int(self.rate * (time.monotonic() - t0)) - self.opened
            for _ in range(max(0, min(due, 64))):
                s = socket.socket()
                s.setblocking(False)
                try:
                    s.bind((self.sources[self.opened % len(self.sources)], 0))
                    s.connect_ex(('127.0.0.1', self.port))
                except OSError:
                    s.close()
                    continue
                self.opened += 1
                held.append((time.monotonic(), s))
            while held and time.monotonic() - held[0][0] > 2:
                held.popleft()[1].close()
            time.sleep(0.002)
        for _at, s in held:
            s.close()


def _member(port, before_tls=0.0, before_head=0.0, timeout=2.0):
    """A signed status call on a new connection from the member's address: silent for
    `before_tls` after the connect, and its head `before_head` after the handshake (a
    round trip away). The status, or what went wrong."""
    raw = socket.socket()
    raw.bind(('127.0.0.1', 0))
    raw.settimeout(timeout)
    try:
        raw.connect(('127.0.0.1', port))
        time.sleep(before_tls)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw) as tls:
            time.sleep(before_head)
            return _on(tls, 'status')[0]
    except (OSError, AssertionError) as e:
        return type(e).__name__
    finally:
        raw.close()


def test_a_flood_from_the_members_address_leaves_its_new_connection_alone(server):
    """200 connections a second from the member's own address that send nothing, so its 32
    places last 160 ms. The member's new connection takes 200 ms on its way in, 100 ms before
    its handshake and 100 ms for its head: it outlives the flood only because each step counts
    as moving on, and each step has 60 ms to spare. (At 300 a second the places lasted 107 ms
    against a 100 ms wait, which a loaded machine lost now and then.)"""
    with _Flood(server.port, ['127.0.0.1'], 200) as flood:
        got = []
        for _ in range(10):
            got.append(_member(server.port, before_tls=0.1, before_head=0.1))
            time.sleep(0.05)
    print(f'same address, {flood.opened} connections opened: {got}')
    assert sum(1 for s in got if s == 200) >= 9, got


def test_a_flood_from_many_addresses_leaves_a_member_its_share(server):
    """400 connections a second from 24 addresses that send nothing fill the 128 the
    server holds over and over. A member that is slow on its way in, silent for 0.3 s
    before its handshake, keeps its connection: its source holds one, the flood's hold
    more. (Before, the oldest anywhere went.)"""
    with _Flood(server.port, [f'127.0.0.{i}' for i in range(2, 26)], 400) as flood:
        got = []
        for _ in range(8):
            got.append(_member(server.port, before_tls=0.3, before_head=0.15))
            time.sleep(0.05)
    print(f'24 addresses, {flood.opened} connections opened: {got}')
    assert sum(1 for s in got if s == 200) >= 7, got
