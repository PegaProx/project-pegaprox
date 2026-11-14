# ESXi -> Proxmox migration: the ESXi password is part of no command line, on the target
# node or on this host.
#
# A command run on the node is the command line of the shell sshd starts for it, readable
# by every local account there while it runs, and the argv of the ssh binary here when the
# call falls back to it. The password used to be in such commands for the SSHFS mounts
# (printf), the SSH copy (SSHPASS=), the curl login and the delta copy (a base64 echo), the
# copy scripts (written inline) and the QEMU secret of the HTTPS boot (printf). It now
# reaches the node on the stdin of the call: sshfs reads it there, everything else from a
# 0600 file in /run written from stdin, which the run removes when it is done with it and
# the end of the run removes in any case. A file that did not get all of it counts as not
# written, nothing logs in with it.
#
# The runs use the ESXi host, API and Proxmox node of tests/test_v2p_tpm_and_folder_copy.py.

import base64
import io
import re
import shlex
import socket
import subprocess
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.core.v2p as v2p
import test_v2p_tpm_and_folder_copy as farm
from pegaprox.utils import ssh as ssh_mod

PASSWORD = 'pa ss"w\'o$rd\\1 x'
FORMS = {PASSWORD, shlex.quote(PASSWORD), base64.b64encode(PASSWORD.encode()).decode(),
         base64.b64encode(f'root:{PASSWORD}'.encode()).decode()}
SECRET_WRITE = 'umask 077; rm -f /run/pegaprox-v2p-t1-'


class Recorder:
    """_pve_node_exec: what each node call got as its command and on stdin."""

    def __init__(self, inner):
        self.inner = inner
        self.sent = []

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        self.sent.append((cmd, kw.get('stdin_data')))
        return self.inner(mgr, node, cmd, timeout, **kw)


class _NoLibssh(farm.Node):
    """QEMU on the node cannot reach ESXi over libssh. `https` says whether it can over
    HTTPS, `mount` whether the SSHFS mount still shows the disk files."""

    def __init__(self, log, vols, https, mount):
        super().__init__(log, vols)
        self.https, self.mount = https, mount

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'qemu-img info' in cmd and ('json:' in cmd or 'ssh://' in cmd):
            self.log.append(('node', node, cmd))
            if self.https and '"file.driver":"https"' in cmd:
                return 0, 'file format: raw\nvirtual size: 1 GiB\n', ''
            return 1, 'Could not open: authentication failed', ''
        if cmd.startswith('for i in 1 2 3'):
            self.log.append(('node', node, cmd))
            return (0, f'{farm.GiB}', '') if self.mount else (1, 'NOTFOUND', '')
        return super().__call__(mgr, node, cmd, timeout, **kw)


def _run(monkeypatch, mode, key=None, boot=None):
    if mode == 'snapshot_zero':
        monkeypatch.setattr(v2p, '_snapshot_zero_v2p_delta_loop', lambda *a, **k: (True, 1, []))
    r = farm.Run(monkeypatch, mode=mode, ndisks=2, tpm=False, ssh_key=key)
    r.task.esxi_password = PASSWORD
    if boot:
        r.node = _NoLibssh(r.log, r.vols, https=boot == 'https', mount=boot == 'sshfs')
        # the VM never comes up on the remote disks: the run copies them over ssh instead
        r.pve._api_post = lambda url, data=None, **kw: farm._Resp('UPID:pve1:1:2:x')
    rec = Recorder(r.node)
    monkeypatch.setattr(v2p, '_pve_node_exec', rec)
    esxi = []
    for name in ('_ssh_exec', '_ssh_esxi_exec'):
        inner = getattr(v2p, name)
        monkeypatch.setattr(v2p, name, lambda h, u, p, cmd, *a, _i=inner, **k: esxi.append(cmd) or _i(h, u, p, cmd, *a, **k))
    r.go()
    return r, rec, esxi


COPIES = {'curl-0', 'ssh-0', 'curl-1', 'ssh-1'}


# mode, ssh key on ESXi, how the Live Mirror boots, the secret files the run writes, the
# number of SSHFS mounts
@pytest.mark.parametrize('mode,key,boot,files,mounts', [
    ('offline', None, None, COPIES, 1),
    ('snapshot_zero', None, None, COPIES, 1),
    ('vmkfstools_clone', None, None, COPIES, 1),
    ('sshfs_boot', None, None, {'copy'}, 1),        # no key on ESXi: the copy scripts log in by password
    # the QEMU secret of the HTTPS boot; the run mounts the datastore again either way
    ('sshfs_boot', '/tmp/v2p-key-fixed', 'https', {'qemu'}, 2),
    ('sshfs_boot', '/tmp/v2p-key-fixed', 'gone', {'qemu'}, 2),    # the SSHFS mount is gone and comes back
], ids=['offline', 'snapshot_zero', 'live_clone', 'live_mirror_password', 'live_mirror_https',
        'live_mirror_remount'])
def test_no_command_of_a_run_carries_the_esxi_password(monkeypatch, mode, key, boot, files, mounts):
    r, rec, esxi = _run(monkeypatch, mode, key, boot)
    for cmd in [c for c, _ in rec.sent] + esxi:
        assert not [f for f in FORMS if f in cmd], f'a command line carries the password: {cmd[:300]}'
    assert r.task.status == 'completed', r.task.error

    # on stdin it goes to sshfs, or into a new 0600 file in /run: as it is for sshpass,
    # QEMU and sshfs, in a curl config for curl
    fed = [(c, d) for c, d in rec.sent if d is not None]
    assert fed and {d for _, d in fed} <= {PASSWORD, v2p._curl_login_config('root', PASSWORD)}
    for cmd, _ in fed:
        assert cmd.startswith(SECRET_WRITE) or 'sshfs -o password_stdin' in cmd, cmd
    assert len([c for c, _ in fed if 'sshfs -o password_stdin' in c]) == mounts

    # every file written is removed again, and the run holds none at its end
    written = [re.search(r'cat > (\S+)', c).group(1) for c, _ in fed if c.startswith(SECRET_WRITE)]
    assert {w[len('/run/pegaprox-v2p-t1-'):] for w in written} == files, written
    removed = {p for c, _ in rec.sent if c.startswith('rm -f ') for p in shlex.split(c)[2:]}
    assert set(written) <= removed, (written, removed)
    assert not getattr(r.task, '_node_secrets', None)
    if boot == 'https':
        # QEMU gets the file, never the password
        args = [c for c, _ in rec.sent if c.startswith("echo 'args: ")]
        assert args and any('secret,id=v2pesxipw,file=/run/pegaprox-v2p-t1-qemu' in a for a in args)


def test_a_secret_file_whose_write_failed_is_still_removed_at_the_end(monkeypatch):
    sent = []

    def node(mgr, n, cmd, timeout=600, **kw):
        sent.append(cmd)
        return (1, '', 'connection reset') if kw.get('stdin_data') else (0, '', '')
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
    monkeypatch.setattr(v2p, 'log_audit', lambda *a, **k: None)
    t = v2p.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm',
                             config={'esxi_password': PASSWORD})
    mgr = object()
    assert v2p._node_secret_file(mgr, t, 'ssh-0', PASSWORD) is None
    assert v2p._node_secret_file(mgr, t, 'curl-0', 'cfg') is None
    t.set_phase('failed', 'the copy failed')
    assert sent[-1] == 'rm -f /run/pegaprox-v2p-t1-ssh-0 /run/pegaprox-v2p-t1-curl-0', sent
    assert t._node_secrets == [] and t.esxi_password == ''


@pytest.mark.parametrize('arrives', ['nothing', 'half'])
def test_a_secret_file_counts_only_when_all_of_the_secret_arrived(monkeypatch, tmp_path, arrives):
    # the node runs the write in bash, /run is a folder of the test; the channel hands on
    # all of stdin, half of it or nothing, and cat exits 0 in each case
    secret = 'pässwort mit leer 1'
    cut = [{'nothing': lambda d: '', 'half': lambda d: d[:len(d) // 2]}[arrives]]

    def node(mgr, n, cmd, timeout=600, stdin_data=None, **kw):
        p = subprocess.run(['bash', '-c', cmd.replace('/run/', f'{tmp_path}/')],
                           input=cut[0](stdin_data or ''), capture_output=True, text=True,
                           encoding='utf-8')
        return p.returncode, p.stdout, p.stderr
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    t = types.SimpleNamespace(id='t1', target_node='pve1')
    # sshpass, curl or QEMU would log in with what is there: the write counts as failed
    assert v2p._node_secret_file(object(), t, 'ssh-0', secret) is None
    # all of it arrives: counted in bytes, the umlauts take two each
    cut[0] = lambda d: d
    assert v2p._node_secret_file(object(), t, 'ssh-0', secret) == '/run/pegaprox-v2p-t1-ssh-0'
    assert (tmp_path / 'pegaprox-v2p-t1-ssh-0').read_text(encoding='utf-8') == secret


# --------------------------------------------------------------------------- the node call

class _Stdin:
    def __init__(self):
        self.data, self.closed = [], False
        self.channel = types.SimpleNamespace(shutdown_write=self._close)

    def _close(self):
        self.closed = True

    def write(self, data):
        self.data.append(data)

    def flush(self):
        pass


class _Chan:
    def settimeout(self, t):
        pass

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return 0


class _Out:
    def __init__(self, data=b''):
        self._buf = io.BytesIO(data)
        self.channel = _Chan()

    def read(self, n=-1):
        return self._buf.read(n)


class _Client:
    def __init__(self):
        self.cmds, self.stdin = [], _Stdin()

    def exec_command(self, cmd, timeout=None):
        self.cmds.append(cmd)
        return self.stdin, _Out(b'ok\n'), _Out()

    def close(self):
        pass


class _Mgr:
    """A PVE manager as _pve_node_exec sees it: the API exec answers, and _ssh_connect
    hands out `client` (None: the key leg is not there)."""

    nodes = {'pve1': {'node': 'pve1'}}

    def __init__(self, client=None, ssh_key='', user='root@pam', pass_='node-root-pw'):
        self.id, self.host, self.api_port = 'c1', '10.0.0.1', 8006
        self.config = types.SimpleNamespace(user=user, pass_=pass_, ssh_user='', ssh_key=ssh_key,
                                            ssh_disabled=False)
        self.client = client
        self.api_calls = []

    def _is_node_blocked(self, node): return (False, 0)
    def _register_node_failure(self, node): pass
    def _reset_node_failures(self, node): pass
    def _get_node_ip(self, node): return '10.0.0.7'
    def ssh_diagnose(self, node): return None

    def _api_post(self, url, data=None, **kw):
        self.api_calls.append(data)
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': 'ran over the API'})

    def _ssh_connect(self, host, failure=None, **kw):
        return self.client


@pytest.fixture
def no_network(monkeypatch):
    from pegaprox.core import ha_transport
    ssh_mod._node_ip_cache.clear()
    monkeypatch.setattr(ssh_mod, '_node_key_refused', {}, raising=False)
    monkeypatch.setattr(ha_transport, 'guard_ssh', lambda *a, **k: None)
    monkeypatch.setattr(socket, 'create_connection',
                        lambda *a, **k: (_ for _ in ()).throw(OSError('no network in tests')))
    yield
    ssh_mod._node_ip_cache.clear()


def test_a_node_command_with_stdin_skips_the_api_and_gives_the_secret_to_stdin_only(no_network):
    client = _Client()
    mgr = _Mgr(client=client, ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n')
    rc, out, _ = ssh_mod._pve_node_exec(mgr, 'pve1', 'umask 077; cat > /run/x', timeout=10,
                                        stdin_data=PASSWORD)
    assert (rc, out.strip()) == (0, 'ok')
    # the API exec has no stdin: it was not asked, the stored key's client ran the command
    assert mgr.api_calls == []
    assert client.cmds == ['umask 077; cat > /run/x']
    assert client.stdin.data == [PASSWORD] and client.stdin.closed
    # without stdin a node command still goes to the API first
    assert ssh_mod._pve_node_exec(mgr, 'pve1', 'uptime', timeout=10)[1] == 'ran over the API'


def test_the_password_leg_gives_the_secret_to_stdin_over_paramiko(no_network, monkeypatch):
    import paramiko
    client = _Client()
    fake = MagicMock(return_value=client)
    client.connect = lambda *a, **k: None
    client.load_host_keys = client.set_missing_host_key_policy = lambda *a, **k: None
    monkeypatch.setattr(paramiko, 'SSHClient', fake)
    monkeypatch.setattr(ssh_mod, 'persist_host_keys', lambda c: None)
    rc, out, _ = ssh_mod._pve_node_exec(_Mgr(), 'pve1', 'umask 077; cat > /run/x', timeout=10,
                                        stdin_data=PASSWORD)
    assert (rc, out.strip()) == (0, 'ok')
    assert client.cmds == ['umask 077; cat > /run/x']
    assert client.stdin.data == [PASSWORD] and client.stdin.closed


def test_the_ssh_binary_fallback_keeps_the_secret_off_this_hosts_command_line(no_network, monkeypatch):
    """Paramiko cannot connect, so the call runs `sshpass -e ssh ... <command>` here: the
    command is on this host's process list, the secret goes to the binary's stdin."""
    import paramiko
    from pegaprox.core import ha_transport
    fake = MagicMock()
    fake.return_value.connect.side_effect = OSError('no network in tests')
    monkeypatch.setattr(paramiko, 'SSHClient', fake)
    ran = []

    def node_cmd(argv, **kw):
        ran.append((list(argv), kw))
        return types.SimpleNamespace(returncode=0, stdout='ok', stderr='')
    monkeypatch.setattr(ha_transport, 'node_cmd', node_cmd)
    rc, _, _ = ssh_mod._pve_node_exec(_Mgr(), 'pve1', 'umask 077; cat > /run/x', timeout=10,
                                      stdin_data=PASSWORD)
    assert rc == 0
    (argv, kw), = ran
    assert argv[:3] == ['sshpass', '-e', 'ssh'] and argv[-1] == 'umask 077; cat > /run/x'
    assert not [a for a in argv if PASSWORD in a]
    assert kw['input'] == PASSWORD
