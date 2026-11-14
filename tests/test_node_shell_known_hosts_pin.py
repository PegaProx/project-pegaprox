"""The node shell server pins a host key only where the pin can be stored.

The node shell runs in its own process from the script start_ssh_websocket_server writes
(server_script in api/vms.py), so it never picked up what utils/ssh_security.py does
since the save of a new host key may fail: refuse first use when known_hosts or its
folder cannot be written, and write the file through a temp file and a rename. Its
policy took any unknown key in memory, logged in, and dropped the failed save without a
word, so the next shell to that node trusted whatever key it met again. paramiko's
save() also truncated the file before writing, so a disk that filled up half way cut
the pins after the first line.

These tests load the script the way the launcher writes it and run its handler against
a fake SSH client whose connect asks the script's policy, as paramiko does.
MK Nov 2026
"""
import ast
import asyncio
import errno
import json
import os
import types

import pytest

paramiko = pytest.importorskip('paramiko')
pytest.importorskip('websockets')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KEYS = {}

needs_non_root = pytest.mark.skipif(os.geteuid() == 0, reason='root writes read-only files')


def _key(name):
    if name not in _KEYS:
        _KEYS[name] = paramiko.RSAKey.generate(1024)
    return _KEYS[name]


def _server_script():
    """server_script as start_ssh_websocket_server writes it to disk."""
    with open(os.path.join(REPO, 'pegaprox', 'api', 'vms.py'), encoding='utf-8') as f:
        tree = ast.parse(f.read())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == 'start_ssh_websocket_server')
    assign = next(n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                  and any(getattr(t, 'id', None) == 'server_script' for t in n.targets))
    return ast.literal_eval(assign.value)


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _WS:
    """The websockets connection: asks for the shell, answers the login dialog once."""

    def __init__(self, path, creds):
        self.request = types.SimpleNamespace(path=path)
        self._creds = creds
        self.sent, self.closed = [], None

    async def send(self, data):
        self.sent.append(data)

    async def recv(self):
        creds, self._creds = self._creds, None
        if creds is None:
            raise ConnectionError('the test does not talk back')
        return json.dumps(creds)

    async def close(self, code=1000, reason=''):
        self.closed = (code, reason)

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


def _client_class(server_key, logins):
    class _Client(paramiko.SSHClient):
        """connect() checks the host key the way paramiko does and then logs in."""

        def connect(self, hostname, port=22, username=None, password=None, **kw):
            name = hostname if port == 22 else f'[{hostname}]:{port}'
            known = self._host_keys.lookup(name)
            if known is None or server_key.get_name() not in known:
                self._policy.missing_host_key(self, name, server_key)
            elif known[server_key.get_name()] != server_key:
                raise paramiko.BadHostKeyException(name, server_key, known[server_key.get_name()])
            logins.append((hostname, username, password))

        def invoke_shell(self, **kw):
            raise paramiko.SSHException('the test opens no shell')
    return _Client


@pytest.fixture
def known_hosts(tmp_path, monkeypatch):
    folder = tmp_path / 'config'
    folder.mkdir()
    path = str(folder / '.ssh_known_hosts')
    monkeypatch.setenv('PEGAPROX_SSH_KNOWN_HOSTS', path)
    monkeypatch.delenv('PEGAPROX_SSH_STRICT_HOST_KEYS', raising=False)
    yield path
    os.chmod(str(folder), 0o700)
    if os.path.exists(path):
        os.chmod(path, 0o600)


def _script_ns():
    ns = {'__name__': 'ssh_ws_server_under_test'}
    exec(compile(_server_script(), '.ssh_ws_server.py', 'exec'), ns)
    return ns


def _open_shell(ns, server_key):
    """One node shell to n1 at 10.0.0.5 with a password; returns (logins, messages)."""
    logins = []
    fake = types.ModuleType('paramiko')
    fake.__dict__.update(vars(paramiko))
    fake.SSHClient = _client_class(server_key, logins)
    ns['paramiko'] = fake

    def get(url, **kw):
        assert '/api/ws/token/validate' in url, url
        return _Resp(200, {'valid': True, 'cluster_context': {
            'host': '10.0.0.5', 'node_ips': {'n1': '10.0.0.5'}, 'ssh_port': 22}})
    ns['requests'] = types.SimpleNamespace(get=get, exceptions=ns['requests'].exceptions)

    ws = _WS('/api/clusters/c1/nodes/n1/shellws?token=t', {'username': 'root', 'password': 'secret'})
    asyncio.run(ns['ssh_handler'](ws))
    return logins, ws.sent


def _pin(path, *hosts):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    for host in hosts:
        hk.add(host, _key(host).get_name(), _key(host))
    hk.save(path)


def _raw(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()


def _disk(path):
    hk = paramiko.hostkeys.HostKeys()
    if os.path.exists(path):
        hk.load(path)
    return hk


def _leftovers(path):
    folder = os.path.dirname(path)
    return sorted(n for n in os.listdir(folder) if n != os.path.basename(path))


# --- first use only with a known_hosts that takes the pin ---------------------------------

@needs_non_root
def test_a_folder_that_takes_no_new_file_refuses_first_use_before_the_login(known_hosts):
    os.chmod(os.path.dirname(known_hosts), 0o500)
    ns = _script_ns()

    for offered in ('genuine', 'other'):
        logins, sent = _open_shell(ns, _key(offered))
        assert logins == [], 'the password went to a host whose key was never pinned'
        assert any('could not be written' in m for m in sent), sent
    assert not os.path.exists(known_hosts)


@needs_non_root
def test_a_read_only_known_hosts_refuses_first_use_before_the_login(known_hosts):
    _pin(known_hosts, 'node-a')
    os.chmod(known_hosts, 0o444)
    before = _raw(known_hosts)
    ns = _script_ns()

    logins, sent = _open_shell(ns, _key('genuine'))
    assert logins == []
    assert any('could not be written' in m for m in sent), sent
    assert _raw(known_hosts) == before


@needs_non_root
def test_a_pinned_host_still_opens_with_known_hosts_read_only(known_hosts):
    """Counterproof: the refusal is about first use only. A node whose key is on disk
    already needs no write and keeps its shell."""
    _pin(known_hosts, '10.0.0.5')
    os.chmod(known_hosts, 0o444)
    ns = _script_ns()

    logins, _sent = _open_shell(ns, _key('10.0.0.5'))
    assert logins == [('10.0.0.5', 'root', 'secret')]


def test_a_writable_known_hosts_pins_on_first_use_and_holds_the_pin(known_hosts):
    _pin(known_hosts, 'node-a')
    ns = _script_ns()

    logins, _sent = _open_shell(ns, _key('genuine'))
    assert logins == [('10.0.0.5', 'root', 'secret')]
    assert _disk(known_hosts).lookup('10.0.0.5')['ssh-rsa'] == _key('genuine')
    assert _disk(known_hosts).lookup('node-a')['ssh-rsa'] == _key('node-a')
    assert _leftovers(known_hosts) == []

    # the next shell meets another key and is refused before the login
    logins, sent = _open_shell(ns, _key('other'))
    assert logins == []
    assert any('SSH Error' in m for m in sent), sent


def test_the_pin_keeps_the_mode_of_the_file_it_replaces(known_hosts):
    _pin(known_hosts, 'node-a')
    os.chmod(known_hosts, 0o640)
    ns = _script_ns()

    _open_shell(ns, _key('genuine'))
    assert _disk(known_hosts).lookup('10.0.0.5') is not None
    assert os.stat(known_hosts).st_mode & 0o777 == 0o640


# --- a save that fails after the login ----------------------------------------------------

def test_a_save_that_fails_half_way_leaves_the_old_file_whole(known_hosts, monkeypatch, capsys):
    _pin(known_hosts, 'node-a', 'node-b')
    before = _raw(known_hosts)

    def _half(self, filename):
        with open(filename, 'w') as f:
            f.write(self._entries[0].to_line())
        raise OSError(errno.ENOSPC, 'No space left on device')
    monkeypatch.setattr(paramiko.hostkeys.HostKeys, 'save', _half)
    ns = _script_ns()

    logins, _sent = _open_shell(ns, _key('genuine'))
    assert logins == [('10.0.0.5', 'root', 'secret')]
    assert _raw(known_hosts) == before, 'the failed write cut the pins after its first line'
    assert _leftovers(known_hosts) == []
    out = capsys.readouterr().out
    assert 'could not write known_hosts' in out and 'No space left' in out, out


# --- the two helpers on their own ---------------------------------------------------------

@needs_non_root
def test_writable_check_follows_the_file_and_its_folder(known_hosts):
    ns = _script_ns()
    assert ns['_kh_writable'](known_hosts) is True
    _pin(known_hosts, 'node-a')
    assert ns['_kh_writable'](known_hosts) is True
    os.chmod(known_hosts, 0o444)
    assert ns['_kh_writable'](known_hosts) is False
    os.chmod(known_hosts, 0o600)
    os.chmod(os.path.dirname(known_hosts), 0o500)
    assert ns['_kh_writable'](known_hosts) is False


def test_write_goes_through_a_symlink_to_the_real_file(known_hosts, tmp_path):
    real = tmp_path / 'real_known_hosts'
    real.write_text('')
    os.symlink(str(real), known_hosts)
    ns = _script_ns()

    hk = paramiko.hostkeys.HostKeys()
    hk.add('node-a', _key('node-a').get_name(), _key('node-a'))
    ns['_write_kh'](known_hosts, hk.save)
    assert os.path.islink(known_hosts)
    assert _disk(str(real)).lookup('node-a') is not None
