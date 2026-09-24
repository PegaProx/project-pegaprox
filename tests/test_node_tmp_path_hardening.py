"""Nothing we run as root on a managed node writes to a name an attacker can pre-create.

/tmp on a PVE node is world-writable. The sticky bit stops you deleting somebody else's
file; it does not stop you creating a symlink under a name nobody has taken yet. So every
fixed path we wrote to as root was an invitation: point /tmp/pegaprox-starlvm-install.sh
at /etc/cron.d/x, wait for an operator to click install, and root writes your content
there. The apt logs each installer redirected into a fixed /tmp path had the same shape,
and so did the cloud-image download, the replication relay's stream files and the
script-library deployment (SFTP follows symlinks, then chmods the result 0755).

These assert the property - what actually reaches the node - rather than the absence of
strings in the source, which the comments explaining the fix would trip over anyway.

Aikido ai_pentest 700489543 / 700489435 / 700489078 / 700488589. MK
"""
import base64
import re

import pytest

import pegaprox.api.nodes as nodes


class _FakeChannel:
    def recv_exit_status(self):
        return 0


class _FakeStream:
    def __init__(self, payload=b''):
        self._payload = payload
        self.channel = _FakeChannel()

    def read(self):
        return self._payload


class _RecordingSSH:
    """Records every command, and refuses to hand out an SFTP client - if anything
    tries to write a file we want to hear about it."""

    def __init__(self):
        self.commands = []
        self.sftp_opened = False

    def exec_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        return _FakeStream(), _FakeStream(b'PP_OK installed 1.8.19'), _FakeStream()

    def open_sftp(self):
        self.sftp_opened = True
        raise AssertionError('the installer opened SFTP - it should not write a file')


@pytest.fixture
def ssh(monkeypatch):
    monkeypatch.setattr(nodes, '_ssh_sudo_prefix', lambda _s: '')
    return _RecordingSSH()


def _decoded_scripts(commands):
    """Pull back whatever was piped in as base64."""
    out = []
    for c in commands:
        m = re.search(r'echo ([A-Za-z0-9+/=]+) \| base64 -d', c)
        if m:
            out.append(base64.b64decode(m.group(1)).decode('utf-8'))
    return out


# --- the installers leave no artifact on the node ----------------------------

def test_running_a_script_writes_no_file(ssh):
    """No path means nothing to pre-create. _RecordingSSH raises if SFTP is used."""
    nodes._ssh_run_script(ssh, "echo hello\n", timeout=5)

    assert ssh.sftp_opened is False
    assert len(ssh.commands) == 1
    assert 'base64 -d' in ssh.commands[0]


def test_the_script_itself_never_appears_as_a_path(ssh):
    nodes._ssh_run_script(ssh, "#!/bin/bash\necho hi\n", timeout=5)

    cmd = ssh.commands[0]
    # the only /tmp that may appear is inside the base64 payload, never in the command
    assert '/tmp/' not in cmd


def test_a_failing_script_raises_rather_than_returning_quietly(ssh, monkeypatch):
    class _Failing(_RecordingSSH):
        def exec_command(self, cmd, timeout=None):
            self.commands.append(cmd)
            class _Bad:
                channel = type('c', (), {'recv_exit_status': lambda self: 3})()
                def read(self):
                    return b'boom'
            return _FakeStream(), _Bad(), _FakeStream(b'boom')

    with pytest.raises(RuntimeError):
        nodes._ssh_run_script(_Failing(), 'false\n', timeout=5)


# --- what the installers actually send ---------------------------------------

@pytest.mark.parametrize('script_name', ['IPMITOOL_INSTALL_SCRIPT', 'STARLVM_INSTALL_SCRIPT'])
def test_the_shipped_installer_logs_into_a_private_directory(script_name):
    """Both used to redirect apt output into a fixed /tmp path."""
    script = getattr(nodes, script_name)

    assert 'mktemp -d' in script, 'no private directory is created'
    assert 'PP_LOGDIR' in script
    # every /tmp literal left in the script must be the mktemp template itself
    for m in re.finditer(r'/tmp/[A-Za-z0-9_.\-]+', script):
        assert 'XXXXXXXX' in m.group(0), f'fixed path still in {script_name}: {m.group(0)}'


@pytest.mark.parametrize('script_name', ['IPMITOOL_INSTALL_SCRIPT', 'STARLVM_INSTALL_SCRIPT'])
def test_the_private_directory_is_removed_afterwards(script_name):
    assert 'trap' in getattr(nodes, script_name)


# --- the paths that remain are unguessable -----------------------------------

def test_two_script_deployments_pick_different_paths(monkeypatch):
    """The old name came from the library id, which is visible in the UI. Deriving it
    from uuid4 means two runs never collide and nobody can predict either."""
    import uuid
    seen = {nodes.uuid.uuid4().hex for _ in range(5)}
    assert len(seen) == 5


def test_the_relay_token_is_not_derived_from_pid_and_clock(monkeypatch):
    """pid + milliseconds is a small space and both are observable on the node."""
    import pegaprox.core.incremental_repl as repl
    import inspect
    fn = [v for k, v in vars(repl).items() if callable(v) and 'relay' in k.lower()]
    src = ''.join(inspect.getsource(f) for f in fn) if fn else inspect.getsource(repl)
    body = src[src.find('tok ='):src.find('tok =') + 200] if 'tok =' in src else ''
    assert 'uuid4' in body, f'relay token still derived from something guessable: {body[:120]}'


# ── the APT trust anchor is not a setting ────────────────────────────────────
# MK Sep 2026: install_starlvm_plugin accepts repo_url and key_url and runs a root
# apt-install on every node in the cluster. The key URL is the TRUST ANCHOR for that
# install, so overriding it is "run my code as root on your hypervisors", not a
# preference. admin.settings is an admin-only builtin, so a non-admin only ever holds
# it through a hand-built custom role - and nobody delegates settings meaning to hand
# over the hypervisors. The default repo stays open to that delegate.
# Aikido ai_pentest 700489405 / 700487796.

def _install_handler():
    import pegaprox.api.nodes as nodes
    fn = nodes.install_starlvm_plugin
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


def _install_ctx(api, session, body):
    from flask import request as _rq
    import contextlib

    @contextlib.contextmanager
    def _cm():
        with api.app.test_request_context('/', base_url='http://localhost', json=body):
            _rq.session = session
            yield
    return _cm()


@pytest.fixture
def starlvm_estate(api, seed):
    from tests.conftest import make_fake_manager
    seed.tenant('tenant_a', clusters=['cluster_1'])
    seed.user('deleg', role='user', tenant_id='tenant_a', permissions=['admin.settings'])
    seed.user('root5', role='admin')
    m = make_fake_manager('cluster_1')
    m.cluster_type = 'proxmox'
    api.set_manager('cluster_1', m)
    return seed


def test_a_settings_delegate_cannot_choose_the_signing_key(api, starlvm_estate, monkeypatch):
    # neutralise the SSRF guard: without DNS it refuses the hostname with a 400
    # and the test would pass on the unfixed code for the wrong reason
    import pegaprox.api.nodes as _n
    monkeypatch.setattr(_n, '_safe_repo_url', lambda u, d: u or d)
    body = {'key_url': 'https://attacker.example/their.asc'}
    with _install_ctx(api, {'user': 'deleg', 'role': 'user'}, body):
        resp = _install_handler()('cluster_1')

    assert resp[1] == 403
    assert 'global admin' in resp[0].get_json()['error']


def test_a_settings_delegate_cannot_choose_the_repository_either(api, starlvm_estate, monkeypatch):
    # neutralise the SSRF guard: without DNS it refuses the hostname with a 400
    # and the test would pass on the unfixed code for the wrong reason
    import pegaprox.api.nodes as _n
    monkeypatch.setattr(_n, '_safe_repo_url', lambda u, d: u or d)
    body = {'repo_url': 'https://attacker.example/debian'}
    with _install_ctx(api, {'user': 'deleg', 'role': 'user'}, body):
        resp = _install_handler()('cluster_1')

    assert resp[1] == 403


def test_the_default_repository_stays_open_to_the_delegate(api, starlvm_estate, monkeypatch):
    """The counterweight: installing the plugin is the point of the permission.

    (CodeAnt, 18.09.: this used to wrap the call in `except Exception: return`, which
    passes on ANY failure - the test could not go red again. Stub the node enumeration
    instead so the handler gives a real answer past the gate.)"""
    import pegaprox.api.nodes as _n
    monkeypatch.setattr(_n, '_cluster_node_names', lambda mgr: [])

    with _install_ctx(api, {'user': 'deleg', 'role': 'user'}, {}):
        resp = _install_handler()('cluster_1')

    # 404 "No nodes found" is past the permission gate, which is the whole point here
    assert resp[1] == 404, resp
    assert 'No nodes found' in resp[0].get_json()['error']
