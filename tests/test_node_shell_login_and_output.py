"""The node shell's login and session on the main port.

The SSH console server on port+2 was the shell that took a private key, waited five
minutes for the login dialog and sent the node's output as text; the main port route
had a password only, a minute, and raw bytes. It is the only node shell now and does
what the dialog offers: a key (the password field is its passphrase and goes nowhere
else), five minutes to type, no login with neither, and the terminal gets text frames,
a UTF-8 character split over two reads in one piece. What the page types goes to the
node whole, a paste bigger than one SSH window included.

The handler runs as flask-sock calls it. paramiko's client is a stand-in that records
the login and hands out a channel the test scripts; the reader greenlet runs whenever
the page's receive yields.

MK Nov 2026
"""
import io
import json
import socket

import gevent
import paramiko
import pytest

import pegaprox.api.vms as vms
from test_node_shell_target_1143 import _cluster, _let_go, _token  # noqa: F401

KEY_ERROR = 'SSH key error: Could not parse SSH key - unsupported format'
NEEDS_LOGIN = 'Password or SSH key required'


class _Page:
    """The browser end: the dialog's answer and what is typed after it, then idle
    receives that let the reader run until the node ends the session."""

    def __init__(self, *incoming):
        self.incoming = list(incoming)
        self.sent = []
        self.timeouts = []
        self.connected = True
        self._idle = 0

    def send(self, data):
        self.sent.append(data)

    def receive(self, timeout=None):
        self.timeouts.append(timeout)
        if self.incoming:
            return self.incoming.pop(0)
        gevent.sleep(0.01)
        self._idle += 1
        if self._idle > 300:
            self.connected = False
        return None

    def close(self, *a, **k):
        self.connected = False

    def status(self):
        return [json.loads(m) for m in self.sent if isinstance(m, str) and m.startswith('{"status"')]

    def errors(self):
        return [m['message'] for m in self.status() if m.get('status') == 'error']

    def output(self):
        """The frames after "connected": the node's output."""
        frames = list(self.sent)
        i = frames.index('{"status":"connected"}')
        return frames[i + 1:]


class _Channel:
    """What invoke_shell hands back: recv() plays `chunks` (an exception is raised, b''
    is the node closing), what goes in is kept."""

    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.got, self.resized = [], []
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def recv(self, n):
        if not self.chunks:
            return b''
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        return chunk

    def sendall(self, data):
        self.got.append(data)

    def send(self, data):
        raise AssertionError('send() may write part of a paste, the shell uses sendall()')

    def resize_pty(self, width=80, height=24):
        self.resized.append((width, height))

    def close(self):
        pass


@pytest.fixture
def node(monkeypatch):
    """The SSH side: every login is kept with its keyword arguments, the shell opens on
    `node.channel`."""
    state = type('Node', (), {})()
    state.logins = []
    state.channel = _Channel()

    class _Client:
        def connect(self, **kw):
            state.logins.append(kw)

        def invoke_shell(self, **kw):
            return state.channel

        def close(self):
            pass

    monkeypatch.setattr(paramiko, 'SSHClient', _Client)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    monkeypatch.setattr(vms, 'persist_host_keys', lambda client: None)
    return state


def _run(api, seed, page, node_name='pve2'):
    _cluster(api)
    tok = _token(api, seed.user('root', role='admin'))
    view = api.app.view_functions['__flask_sock.node_shell_websocket_proxy'].__wrapped__
    with api.app.test_request_context(f'/api/clusters/cluster_1/nodes/{node_name}/shellws?token={tok}'):
        view(page, 'cluster_1', node_name)
    return page


def _login(**creds):
    return json.dumps(creds)


def _key_text(kind, passphrase=None):
    """A private key as the dialog's key field holds it, and its public half."""
    if kind == 'ed25519':
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        enc = (serialization.BestAvailableEncryption(passphrase.encode()) if passphrase
               else serialization.NoEncryption())
        text = ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc).decode()
        return text, paramiko.Ed25519Key.from_private_key(io.StringIO(text), password=passphrase).get_base64()
    key = paramiko.RSAKey.generate(1024) if kind == 'rsa' else paramiko.ECDSAKey.generate()
    buf = io.StringIO()
    key.write_private_key(buf, password=passphrase)
    return buf.getvalue(), key.get_base64()


# --- the login ------------------------------------------------------------------------------

@pytest.mark.parametrize('kind', ['rsa', 'ed25519', 'ecdsa'])
def test_a_private_key_logs_in_with_the_key_alone(api, seed, node, kind):
    text, public = _key_text(kind)
    page = _run(api, seed, _Page(_login(username='admin', privateKey=text)))
    assert len(node.logins) == 1, page.sent
    login = node.logins[0]
    assert login['pkey'].get_base64() == public
    assert 'password' not in login
    assert login['username'] == 'admin' and login['hostname'] == '10.0.0.12' and login['port'] == 22
    assert login['allow_agent'] is False and login['look_for_keys'] is False


@pytest.mark.parametrize('kind', ['rsa', 'ed25519'])
def test_the_password_unlocks_an_encrypted_key_and_is_not_offered_to_the_node(api, seed, node, kind):
    """The dialog's password field is the key's passphrase. It must not reach sshd as a
    password: a node that refuses the key would see the passphrase in its auth log."""
    text, public = _key_text(kind, passphrase='open-sesame')
    _run(api, seed, _Page(_login(username='root', privateKey=text, password='open-sesame')))
    assert [lg['pkey'].get_base64() for lg in node.logins] == [public]
    assert 'password' not in node.logins[0]


@pytest.mark.parametrize('key,passphrase', [
    ('not a key at all', 'pw'),
    ('-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n', ''),
    ('encrypted', 'the-wrong-one'),
], ids=['garbage', 'truncated', 'wrong-passphrase'])
def test_a_key_it_cannot_read_is_no_login_and_no_password_login(api, seed, node, key, passphrase):
    """A key that does not parse ends the attempt: no fallback to the password field."""
    if key == 'encrypted':
        key, _public = _key_text('rsa', passphrase='open-sesame')
    page = _run(api, seed, _Page(_login(username='root', privateKey=key, password=passphrase)))
    assert node.logins == []
    assert page.errors() == [KEY_ERROR], page.sent


def test_a_password_logs_in_with_the_password(api, seed, node):
    """Counterproof for the key cases: no key field, the password is the login."""
    _run(api, seed, _Page(_login(username='root', password='pw')))
    assert len(node.logins) == 1
    assert node.logins[0]['password'] == 'pw' and 'pkey' not in node.logins[0]
    assert node.logins[0]['username'] == 'root'


@pytest.mark.parametrize('creds', [
    {'username': 'root'},
    {'username': 'root', 'password': '', 'privateKey': ''},
    {'username': 'root', 'password': None, 'privateKey': None},
], ids=['nothing', 'empty', 'null'])
def test_neither_password_nor_key_is_no_login(api, seed, node, creds):
    page = _run(api, seed, _Page(json.dumps(creds)))
    assert node.logins == []
    assert page.errors() == [NEEDS_LOGIN], page.sent
    assert '{"status":"connecting"}' not in page.sent


def test_a_user_name_left_empty_logs_in_as_root(api, seed, node):
    _run(api, seed, _Page(_login(username='', password='pw')))
    assert [lg['username'] for lg in node.logins] == ['root']


@pytest.mark.parametrize('raw', ['[]', '"root"', '42', 'not json'])
def test_an_answer_that_is_no_login_object_is_refused(api, seed, node, raw):
    page = _run(api, seed, _Page(raw))
    assert node.logins == []
    assert page.errors() == ['Failed to receive credentials'], page.sent


# --- the dialog's five minutes --------------------------------------------------------------

def test_the_login_dialog_has_five_minutes(api, seed, node):
    page = _run(api, seed, _Page(_login(username='root', password='pw')))
    assert page.timeouts[0] == 300
    assert len(node.logins) == 1


def test_no_answer_within_them_is_a_timeout(api, seed, node):
    page = _run(api, seed, _Page(None))
    assert page.timeouts == [300]
    assert page.errors() == ['Login timeout']
    assert node.logins == []


# --- the session ----------------------------------------------------------------------------

def test_the_nodes_output_reaches_the_page_as_text(api, seed, node):
    """xterm.js on the page writes strings; a UTF-8 character the node's two reads split
    is decoded whole, and a quiet second (the channel's read timeout) ends nothing."""
    euro = '€'.encode('utf-8')
    node.channel = _Channel([b'root@pve2:~# ', euro[:1], euro[1:] + b' ok\r\n',
                             socket.timeout(), b'\x1b[0mbye'])
    page = _run(api, seed, _Page(_login(username='root', password='pw')))
    out = page.output()
    assert out and all(isinstance(f, str) for f in out), out
    assert ''.join(out) == 'root@pve2:~# € ok\r\n\x1b[0mbye'
    assert '�' not in ''.join(out)
    assert node.channel.timeout == 1.0


def test_what_the_page_types_goes_to_the_node_whole(api, seed, node):
    """A paste bigger than one SSH window goes out in full (sendall), a resize resizes,
    and a line that only looks like JSON is typed as it is."""
    paste = 'x' * 200000
    page = _run(api, seed, _Page(_login(username='root', password='pw'),
                                 'ls -la\r', json.dumps({'type': 'resize', 'cols': 132, 'rows': 50}),
                                 paste, '{not json', b'\x03'))
    assert node.channel.got == [b'ls -la\r', paste.encode(), b'{not json', b'\x03'], page.sent
    assert node.channel.resized == [(132, 50)]


def test_a_failed_login_says_so_in_english(api, seed, monkeypatch):
    """The old main port shell answered in German; the page shows the sentence as it is."""
    class _Refusing:
        def connect(self, **kw):
            raise paramiko.AuthenticationException('no')

        def close(self):
            pass

    monkeypatch.setattr(paramiko, 'SSHClient', _Refusing)
    monkeypatch.setattr(vms, 'apply_host_key_policy', lambda client, _p: client)
    page = _run(api, seed, _Page(_login(username='root', password='pw')))
    assert page.errors() == ['SSH login failed - wrong user name, password or key']
