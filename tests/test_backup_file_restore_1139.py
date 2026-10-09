"""One file out of a Proxmox Backup Server backup, back into the running guest (#1139).

GET .../backups/files lists what is inside a PBS backup, POST .../backups/file-restore
takes one file out of it and writes it into the guest: a VM through the guest agent's
file-write, a container through `pct exec ... sh -c 'cat > dest'` on its node over SSH.

What these hold, against a faked cluster:

  * PVE's file-write takes 60 KiB of base64 and opens the file 'wb' on every call
    (Agent.pm), so the file goes in one call, already base64 with encode=0 (with 1 PVE
    encodes it a second time and the guest gets the base64 text), and a file over
    45 KiB is refused with a 413 before the agent is asked
  * PVE answers the download 200 before the extraction has run (FileRestore.pm streams a
    fifo a worker fills), so a failed one is an empty or short body: only a regular file
    the listing of its directory shows goes in, and only with all the bytes it lists
  * a container's file goes through the manager's own SSH helper, at the address of a
    member node and nowhere else, quoted, and not at all with SSH switched off; pct runs
    through sudo -n when that login is not root
  * writing a file as root in a guest is a console's worth of access: vm.console on
    the guest, on top of vm.backup on it and on the guest the backup was taken of
  * a 401/403 of PVE is a 502 UPSTREAM_AUTH, never the browser's own 401 (#1142)

Every refusal also shows the request that is let through, so a refusal cannot pass for
the wrong reason. MK Oct 2026
"""
import base64
import os
import shlex
import types
from unittest.mock import MagicMock

import pytest

CID = 'cluster_1'
URL = f'/api/clusters/{CID}/vms/pve1'
OWN = 'pbs1:backup/vm/100/2026-10-01T02:00:00Z'
OWN_CT = 'pbs1:backup/ct/101/2026-10-01T02:00:00Z'
FOREIGN = 'pbs1:backup/vm/200/2026-10-01T02:00:00Z'
FILE = 'cm9vdC5weGFyLmRpZHgvZXRjL2hvc3Rz'   # a filepath as PVE lists it
DIR = 'cm9vdC5weGFyLmRpZHgvZXRj'            # root.pxar.didx/etc, the directory FILE is in
AGENT_MAX = 46080
CT_MAX = 50 * 1024 * 1024


class _Resp:
    def __init__(self, status=200, body=None, content=b'', text=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.content = content
        self.text = text if text is not None else ''

    def json(self):
        return self._body

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Chan:
    def __init__(self, rc):
        self.rc, self.shut = rc, False

    def shutdown_write(self):
        self.shut = True

    def recv_exit_status(self):
        return self.rc


class _Stdin:
    def __init__(self, chan):
        self.channel, self.data = chan, bytearray()

    def write(self, b):
        self.data += b

    def flush(self):
        pass


class _Out:
    def __init__(self, chan, data=b''):
        self.channel, self._data = chan, data

    def read(self, n=-1):
        data, self._data = self._data, b''
        return data


class _Client:
    """What _ssh_connect hands out, as far as the route uses it."""

    def __init__(self, rc=0, err=b''):
        self.rc, self.err = rc, err
        self.cmds, self.stdin, self.closed = [], None, False

    def exec_command(self, cmd, timeout=None):
        chan = _Chan(self.rc)
        self.cmds.append(cmd)
        self.stdin = _Stdin(chan)
        return self.stdin, _Out(chan), _Out(chan, self.err)

    def close(self):
        self.closed = True


@pytest.fixture
def pve(api):
    """A connected cluster with nodes pve1 (10.0.0.11) and pve2 (no address known). The
    backup holds `state.file`; PVE answers the listing, the download and the agent."""
    fake = api.make_fake_manager(CID)
    fake.is_connected = True
    fake.host, fake.api_port = 'pve-api.lab', 8006
    fake.config.name = 'lab'
    fake.config.ssh_user, fake.config.user = '', 'root@pam'
    fake.nodes ={'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
    fake.member_node_ip.side_effect = lambda n: {'pve1': '10.0.0.11'}.get(n)
    fake.ssh_blocked_reason.return_value = None
    state = types.SimpleNamespace(
        fake=fake, session=fake._create_session.return_value, client=_Client(),
        file=b'127.0.0.1 localhost\n', listing=[{'text': 'etc', 'type': 'd', 'leaf': 0, 'filepath': 'ZXRj'}],
        list_resp=None, dl_resp=None, agent_resp=None, entry={})
    fake._ssh_connect.side_effect = lambda host, **kw: state.client

    def get(url, **kw):
        if url.endswith('/file-restore/list'):
            if state.list_resp:
                return state.list_resp
            if kw['params']['filepath'] == DIR:
                # FILE in the listing of its directory; state.entry changes what PVE says of it
                hosts = dict({'text': 'hosts', 'type': 'f', 'leaf': 1, 'size': len(state.file),
                              'filepath': FILE}, **state.entry)
                return _Resp(200, {'data': [{'text': 'hostname', 'type': 'f', 'leaf': 1, 'size': 9,
                                             'filepath': 'cm9vdC5weGFyLmRpZHgvZXRjL2hvc3RuYW1l'}, hosts]})
            return _Resp(200, {'data': state.listing})
        if url.endswith('/file-restore/download'):
            return state.dl_resp or _Resp(200, content=state.file)
        raise AssertionError(f'unexpected GET {url}')

    def post(url, **kw):
        assert url.endswith('/agent/file-write'), url
        return state.agent_resp or _Resp(200, {'data': None})

    state.session.get.side_effect = get
    state.session.post.side_effect = post
    api.set_manager(CID, fake)
    return state


@pytest.fixture
def admin(api, seed):
    seed.user('root', role='admin')
    return api.as_user({'username': 'root', 'role': 'admin'})


def _scoped(api, seed, perms=None, also=None):
    """A tenant user granted guest 100 (all of it, or only `perms`), and `also`:
    {vmid: perms} more."""
    seed.tenant('acme', clusters=[CID])
    user = seed.user('bob', role='user', tenant_id='acme')
    if perms is None:
        seed.vm_acl(CID, 100, ['bob'])
    else:
        seed.vm_acl(CID, 100, ['bob'], inherit_role=False, permissions=perms)
    for vmid, p in (also or {}).items():
        seed.vm_acl(CID, vmid, ['bob'], inherit_role=False, permissions=p)
    return api.as_user(user)


def _browse(client, volid=OWN, vm='qemu/100', **q):
    return client.get(f'{URL}/{vm}/backups/files', query_string={'volid': volid, **q})


def _restore(client, volid=OWN, vm='qemu/100', dest='/etc/hosts', node='pve1'):
    return client.post(f'/api/clusters/{CID}/vms/{node}/{vm}/backups/file-restore',
                       json={'volid': volid, 'filepath': FILE, 'dest_path': dest})


def _urls(session, verb):
    return [c.args[0] for c in getattr(session, verb).call_args_list]


# --- browsing --------------------------------------------------------------------------------

def test_browsing_lists_the_backup_at_the_root(admin, pve):
    r = _browse(admin)
    assert r.status_code == 200, r.get_json()
    assert r.get_json() == pve.listing
    call = pve.session.get.call_args
    assert call.args[0] == 'https://pve-api.lab:8006/api2/json/nodes/pve1/storage/pbs1/file-restore/list'
    assert call.kwargs['params'] == {'volume': OWN, 'filepath': base64.b64encode(b'/').decode()}
    # a directory PVE listed goes back as PVE named it
    _browse(admin, path='ZXRj')
    assert pve.session.get.call_args.kwargs['params']['filepath'] == 'ZXRj'


def test_browsing_needs_vm_view_on_the_guest(api, seed, pve):
    bob = _scoped(api, seed, perms=['vm.backup'])
    r = _browse(bob)
    assert r.status_code == 403 and 'vm.view' in r.get_json()['error']
    assert not pve.session.get.called


def test_browsing_with_vm_view_goes_through(api, seed, pve):
    """Counterproof: the same grant with vm.view lists the backup."""
    bob = _scoped(api, seed, perms=['vm.view', 'vm.backup'])
    r = _browse(bob)
    assert r.status_code == 200, r.get_json()
    assert pve.session.get.called


@pytest.mark.parametrize('volid', [FOREIGN, 'pbs1:backup/vm/100/2026-10-01T02:00:00Z/../../vm/200/x',
                                   'pbs1:vm/100/2026-10-01T02:00:00Z'])
def test_browsing_someone_elses_backup_is_refused(api, seed, pve, volid):
    bob = _scoped(api, seed)
    r = _browse(bob, volid=volid)
    assert r.status_code == 403, r.get_json()
    assert r.get_json()['error'] == 'Permission denied for source backup'
    assert not pve.session.get.called
    # counterproof: their own backup through the same door, and an admin through any
    assert _browse(bob, volid=OWN).status_code == 200


def test_an_admin_browses_any_backup(admin, pve):
    assert _browse(admin, volid=FOREIGN).status_code == 200


@pytest.mark.parametrize('volid,kind', [
    ('local:backup/vzdump-qemu-100-2026_10_01-02_00_00.vma.zst', 'VMA'),
    ('local:backup/vzdump-qemu-100-2026_10_01-02_00_00.vma', 'VMA'),
    ('nfs:backup/vzdump-lxc-101-2026_10_01-02_00_00.tar.zst', 'tar'),
    ('nfs:backup/vzdump-lxc-101-2026_10_01-02_00_00.tar.gz', 'tar'),
])
def test_a_vzdump_archive_is_not_browsed(api, seed, admin, pve, volid, kind):
    r = _browse(admin, volid=volid)
    assert r.status_code == 400
    assert f'not available for vzdump {kind} backups' in r.get_json()['error']
    assert not pve.session.get.called
    # a scoped user hears the same reason, not a 403 about the source
    bob = _scoped(api, seed)
    assert 'vzdump' in _browse(bob, volid=volid).get_json()['error']
    # and restoring a file out of one is refused alike
    r = _restore(admin, volid=volid)
    assert r.status_code == 400 and 'vzdump' in r.get_json()['error']
    assert not pve.session.get.called


@pytest.mark.parametrize('upstream', [401, 403])
def test_browsing_a_backup_pve_refuses_us_is_a_502(admin, pve, upstream):
    pve.list_resp = _Resp(upstream, text='{"message":"authentication failure"}')
    r = _browse(admin)
    body = r.get_json()
    assert r.status_code == 502 and body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == upstream
    assert pve.session.get.called


def test_other_statuses_of_the_listing_go_out_as_they_came(admin, pve):
    """Counterproof: only 401/403 changed. A 400 of PVE stays a 400, with its words."""
    pve.list_resp = _Resp(400, text='{"message":"unable to open snapshot"}')
    r = _browse(admin)
    assert r.status_code == 400 and r.get_json() == {'error': 'unable to open snapshot'}


# --- a VM: the guest agent -----------------------------------------------------------------

def test_a_vm_gets_the_file_once_already_base64(admin, pve):
    pve.file = bytes(range(256)) * 4 + b'\n# end\n'
    r = _restore(admin, dest='/etc/app/blob.bin')
    assert r.status_code == 200 and r.get_json() == {'success': True}
    assert pve.session.post.call_count == 1
    call = pve.session.post.call_args
    assert call.args[0] == 'https://pve-api.lab:8006/api2/json/nodes/pve1/qemu/100/agent/file-write'
    sent = call.kwargs['data']
    assert sent['file'] == '/etc/app/blob.bin' and sent['encode'] == 0
    assert sent['content'] == base64.b64encode(pve.file).decode()
    # counterproof: decoded once it is the file; with encode=1 PVE would have written the
    # base64 text into the guest
    assert base64.b64decode(sent['content']) == pve.file
    dl = pve.session.get.call_args
    assert dl.args[0].endswith('/nodes/pve1/storage/pbs1/file-restore/download')
    assert dl.kwargs['params'] == {'volume': OWN, 'filepath': FILE}


@pytest.mark.parametrize('size,want', [(AGENT_MAX, 200), (AGENT_MAX + 1, 413)])
def test_the_guest_agent_takes_45_kb(admin, pve, size, want):
    pve.file = b'a' * size
    r = _restore(admin)
    assert r.status_code == want, r.get_json()
    if want == 200:
        assert len(pve.session.post.call_args.kwargs['data']['content']) == 60 * 1024
    else:
        assert '45 KB' in r.get_json()['error'] and r.get_json()['limit_bytes'] == AGENT_MAX
        # refused on the size the listing gave, before the download and the agent
        assert not pve.session.post.called
        assert not [u for u in _urls(pve.session, 'get') if u.endswith('/download')]


@pytest.mark.parametrize('where', ['download', 'agent'])
@pytest.mark.parametrize('upstream', [401, 403])
def test_a_pve_refusing_the_stored_login_is_a_502(admin, pve, where, upstream):
    refused = _Resp(upstream, text='{"message":"authentication failure"}')
    setattr(pve, 'dl_resp' if where == 'download' else 'agent_resp', refused)
    r = _restore(admin)
    body = r.get_json()
    assert r.status_code == 502, body
    assert body['code'] == 'UPSTREAM_AUTH' and body['upstream_status'] == upstream
    assert body['error'].startswith('Proxmox VE ') and 'authentication failure' in body['error']
    # the cluster said it, at the step named
    assert pve.session.post.called == (where == 'agent')


def test_a_guest_agent_that_is_not_running_keeps_its_500(admin, pve):
    """Counterproof: PVE's own 500 is not turned into anything else."""
    pve.agent_resp = _Resp(500, text='{"message":"QEMU guest agent is not running"}')
    r = _restore(admin)
    assert r.status_code == 500
    assert r.get_json() == {'error': 'Guest agent file-write failed: QEMU guest agent is not running'}


# --- a container: pct exec over SSH ---------------------------------------------------------

def test_a_container_file_of_50_mb_goes_through_the_ssh_helper(admin, pve):
    pve.file = b'x' * (CT_MAX - 7) + b'\x00\xff\n\r\x1b[m'
    dest = "/etc/my app/it's.conf"
    r = _restore(admin, volid=OWN_CT, vm='lxc/101', dest=dest)
    assert r.status_code == 200, r.get_json()
    # the node's own address, through the manager's guarded helper
    assert pve.fake._ssh_connect.call_args.args == ('10.0.0.11',)
    client = pve.client
    assert client.cmds == [f"pct exec 101 -- sh -c {shlex.quote('cat > ' + shlex.quote(dest))}"]
    # the shell on the node runs exactly cat > dest, dest as one word
    assert shlex.split(shlex.split(client.cmds[0])[-1]) == ['cat', '>', dest]
    assert bytes(client.stdin.data) == pve.file and client.stdin.channel.shut and client.closed
    assert not pve.session.post.called


def test_a_container_file_over_50_mb_is_refused_before_ssh(admin, pve):
    pve.file = b'x' * (CT_MAX + 1)
    r = _restore(admin, volid=OWN_CT, vm='lxc/101')
    assert r.status_code == 413 and '50 MB' in r.get_json()['error']
    assert not pve.fake._ssh_connect.called


def test_pct_failing_is_said(admin, pve):
    pve.client = _Client(rc=1, err=b"sh: can't create /etc/x/y: nonexistent directory\n")
    r = _restore(admin, volid=OWN_CT, vm='lxc/101', dest='/etc/x/y')
    assert r.status_code == 500
    assert r.get_json()['error'] == ("pct exec failed (exit 1): sh: can't create /etc/x/y: "
                                     "nonexistent directory")


def test_a_failed_ssh_login_is_a_502_not_a_401(admin, pve):
    def refused(host, failure=None, **kw):
        failure.update(kind='auth', detail='Authentication failed.')
        return None
    pve.fake._ssh_connect.side_effect = refused
    r = _restore(admin, volid=OWN_CT, vm='lxc/101')
    assert r.status_code == 502 and r.get_json()['error'] == 'SSH to node pve1 failed (auth)'


def _real_ssh_gate(fake, **config):
    """The manager's own SSH settings check on the fake, over `config`."""
    from pegaprox.core.manager import PegaProxManager
    for k, v in dict(dict(ssh_disabled=False, ssh_key='', user='root@pam', pass_='pw'), **config).items():
        setattr(fake.config, k, v)
    fake.ssh_blocked_reason = types.MethodType(PegaProxManager.ssh_blocked_reason, fake)


@pytest.mark.parametrize('config,code', [({'ssh_disabled': True, 'ssh_key': 'KEY'}, 'SSH_DISABLED'),
                                         ({'user': 'root@pam!automation'}, 'SSH_NO_CREDENTIALS')])
def test_ssh_switched_off_or_without_credentials_refuses(admin, pve, config, code):
    _real_ssh_gate(pve.fake, **config)
    r = _restore(admin, volid=OWN_CT, vm='lxc/101')
    assert r.status_code == 409 and r.get_json()['code'] == code
    assert 'not available for this cluster' in r.get_json()['error']
    assert not pve.fake._ssh_connect.called and not pve.session.get.called


def test_ssh_switched_on_goes_through(admin, pve):
    """Counterproof: the same gate with SSH on and a key lets the file through."""
    _real_ssh_gate(pve.fake, ssh_key='KEY')
    assert _restore(admin, volid=OWN_CT, vm='lxc/101').status_code == 200
    assert pve.fake._ssh_connect.called


@pytest.mark.parametrize('node', ['pve2', 'pve9', 'pve-api.lab'])
def test_a_node_without_an_address_of_its_own_refuses(admin, pve, node):
    """pve2 is a member whose address is not known, pve9 is none, and the connection host
    is no node: none of them falls back to a name or to the host PegaProx talks to (#1143)."""
    r = _restore(admin, volid=OWN_CT, vm='lxc/101', node=node)
    assert r.status_code == 400 and r.get_json()['error'] == f'Could not find the address of node {node}'
    assert not pve.fake._ssh_connect.called and not pve.session.get.called
    # only a member was looked up at all
    assert [c.args[0] for c in pve.fake.member_node_ip.call_args_list] == (['pve2'] if node == 'pve2' else [])


def test_the_managers_ssh_helper_logs_in_as_the_cluster_says(admin, pve, monkeypatch):
    """The route hands the address to PegaProxManager._ssh_connect itself: the configured
    SSH user and port, the host key policy, and a client whose execs ask the HA guard."""
    import threading
    import pegaprox.core.manager as manager_mod
    import pegaprox.globals as _g
    import pegaprox.utils.ssh_security as ssh_security
    from pegaprox.core.manager import PegaProxManager
    monkeypatch.setattr(_g, '_ssh_semaphore', threading.BoundedSemaphore(4))
    fake = pve.fake
    _real_ssh_gate(fake, ssh_user='pegaprox', ssh_port=2222)
    for name in ('_ssh_connect', 'ssh_password_to_offer'):
        setattr(fake, name, types.MethodType(getattr(PegaProxManager, name), fake))
    raw = MagicMock(name='SSHClient()')
    raw.exec_command.side_effect = pve.client.exec_command
    paramiko = MagicMock(name='paramiko')
    paramiko.SSHClient.return_value = raw
    monkeypatch.setattr(manager_mod, 'get_paramiko', lambda: paramiko)
    policy = MagicMock(name='apply_host_key_policy')
    monkeypatch.setattr(ssh_security, 'apply_host_key_policy', policy)
    monkeypatch.setattr(ssh_security, 'persist_host_keys', lambda *a, **k: None)

    r = _restore(admin, volid=OWN_CT, vm='lxc/101')
    assert r.status_code == 200, r.get_json()
    kw = raw.connect.call_args.kwargs
    assert (kw['hostname'], kw['port'], kw['username'], kw['password']) == ('10.0.0.11', 2222, 'pegaprox', 'pw')
    assert policy.call_args.args[0] is raw
    # guard_client put its own exec_command in front of the client's
    assert not isinstance(raw.exec_command, MagicMock) and raw.exec_command.__name__ == 'guarded'
    # logged in as pegaprox, pct goes through sudo without a prompt
    assert pve.client.cmds == ["sudo -n pct exec 101 -- sh -c 'cat > /etc/hosts'"]
    assert bytes(pve.client.stdin.data) == pve.file


@pytest.mark.parametrize('ssh_user,user,sudo', [('', 'root@pam', False), ('root', 'pegaprox@pve', False),
                                                ('pegaprox', 'root@pam', True), ('', 'ops@pam', True)])
def test_pct_runs_as_root_or_through_sudo(admin, pve, ssh_user, user, sudo):
    """pct wants root: the login _ssh_connect makes (ssh_user, else the API user's name)
    decides whether it goes through sudo -n."""
    pve.fake.config.ssh_user, pve.fake.config.user = ssh_user, user
    assert _restore(admin, volid=OWN_CT, vm='lxc/101').status_code == 200
    plain = "pct exec 101 -- sh -c 'cat > /etc/hosts'"
    assert pve.client.cmds == [('sudo -n ' + plain) if sudo else plain]


_FAKE_PCT = '''#!/bin/sh
# pct exec <vmid> -- <command...>: runs the command here, where the container would
[ "$1" = exec ] && [ "$2" = 101 ] && [ "$3" = -- ] || exit 97
shift 3
exec "$@"
'''
_FAKE_SUDO = '''#!/bin/sh
[ "$1" = -n ] || exit 98
shift
exec "$@"
'''


@pytest.mark.parametrize('ssh_user', ['', 'pegaprox'])
def test_the_command_writes_the_bytes_to_that_path_in_a_real_shell(admin, pve, tmp_path, ssh_user):
    """What the node's shell makes of the command: run by sh with stand-ins for pct and
    sudo, the file lands at the literal path, byte for byte, and nothing in the path runs."""
    import subprocess
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for name, body in (('pct', _FAKE_PCT), ('sudo', _FAKE_SUDO)):
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    work = tmp_path / 'guest'
    work.mkdir()
    dest = str(work / "it's a $(touch PWNED) `touch PWNED2` \"x\";\n|name & ..")
    pve.file = bytes(range(256)) * 9 + b'\r\n\x00\x04'
    pve.fake.config.ssh_user = ssh_user
    r = _restore(admin, volid=OWN_CT, vm='lxc/101', dest=dest)
    assert r.status_code == 200, r.get_json()
    run = subprocess.run(['sh', '-c', pve.client.cmds[0]], input=bytes(pve.client.stdin.data),
                         cwd=str(work), capture_output=True, timeout=20,
                         env={'PATH': f'{bindir}:/usr/bin:/bin'})
    assert run.returncode == 0, run.stderr
    with open(dest, 'rb') as fh:
        assert fh.read() == pve.file
    assert sorted(os.listdir(work)) == [os.path.basename(dest)]


# --- the download is checked against the listing before the guest sees it (#1139) -----------

@pytest.mark.parametrize('vm,volid', [('qemu/100', OWN), ('lxc/101', OWN_CT)])
@pytest.mark.parametrize('got', [b'', b'127.0.0.1 loc', b'127.0.0.1 localhost\n::1 localhost\n'])
def test_a_download_that_is_not_the_whole_file_writes_nothing(admin, pve, vm, volid, got):
    """PVE answers the download 200 before the extraction has run: a failed one sends
    nothing or a part. Written into the guest that would empty its own copy."""
    pve.entry = {'size': 20}
    pve.file = got
    r = _restore(admin, volid=volid, vm=vm)
    assert r.status_code == 502, r.get_json()
    assert r.get_json() == {'code': 'SHORT_DOWNLOAD',
                            'error': f'The download of hosts brought {len(got)} bytes, the backup '
                                     'lists 20. Nothing was written into the guest'}
    assert not pve.session.post.called and not pve.fake._ssh_connect.called
    # counterproof: all 20 bytes, and the same request writes them
    pve.file = b'127.0.0.1 localhost\n'
    assert _restore(admin, volid=volid, vm=vm).status_code == 200
    assert pve.session.post.called or pve.fake._ssh_connect.called


@pytest.mark.parametrize('kind', ['d', 'l', 'v', 'h'])
def test_only_a_regular_file_is_restored(admin, pve, kind):
    """A directory downloads as a zip, a link or a hard link without a size: neither is
    the file the guest would get."""
    pve.entry = {'type': kind}
    r = _restore(admin)
    assert r.status_code == 400
    assert r.get_json()['error'] == ('hosts is not a regular file. Only a single file can be '
                                     'restored into the guest')
    assert _urls(pve.session, 'get') == ['https://pve-api.lab:8006/api2/json/nodes/pve1/storage/pbs1/file-restore/list']
    assert pve.session.get.call_args.kwargs['params'] == {'volume': OWN, 'filepath': DIR}
    # counterproof: the same entry as a file goes through
    pve.entry = {'type': 'f'}
    assert _restore(admin).status_code == 200


def test_a_size_pve_does_not_give_writes_nothing(admin, pve):
    pve.entry = {'size': None}
    r = _restore(admin)
    assert r.status_code == 502 and 'did not say how big hosts is' in r.get_json()['error']
    assert not pve.session.post.called


def test_a_file_the_listing_does_not_show_is_refused(admin, pve):
    shadow = base64.b64encode(b'root.pxar.didx/etc/shadow').decode()
    r = admin.post(f'{URL}/qemu/100/backups/file-restore',
                   json={'volid': OWN, 'filepath': shadow, 'dest_path': '/etc/shadow'})
    assert r.status_code == 404 and r.get_json()['error'] == 'shadow is not in this backup'
    assert not [u for u in _urls(pve.session, 'get') if u.endswith('/download')]


@pytest.mark.parametrize('filepath', ['not base64!', 'Lw==', '', base64.b64encode(b'root.pxar.didx').decode()])
def test_a_filepath_that_is_no_file_of_the_backup_is_refused(admin, pve, filepath):
    """Garbage, the root, nothing, and an archive itself: the root's listing names the
    archive as a 'v' entry, not a file."""
    pve.listing = [{'text': 'root.pxar.didx', 'type': 'v', 'leaf': 0,
                    'filepath': base64.b64encode(b'/root.pxar.didx').decode()}]
    r = admin.post(f'{URL}/qemu/100/backups/file-restore',
                   json={'volid': OWN, 'filepath': filepath, 'dest_path': '/etc/hosts'})
    assert r.status_code == 400, r.get_json()
    assert not pve.session.post.called
    assert not [u for u in _urls(pve.session, 'get') if u.endswith('/download')]


def test_the_audit_names_the_file_not_its_base64(admin, pve, monkeypatch):
    import pegaprox.api.vms as vms
    lines = []
    monkeypatch.setattr(vms, 'log_audit', lambda user, action, text, **kw: lines.append((action, text)))
    assert _restore(admin).status_code == 200
    assert lines == [('backup.file_restored',
                      f"Restored '/root.pxar.didx/etc/hosts' from {OWN} to qemu/100:/etc/hosts")]


@pytest.mark.parametrize('dest', ['/etc/hosts\x00.bak', '/' + 'a' * 4096])
def test_a_destination_no_guest_can_take_is_refused(admin, pve, dest):
    r = _restore(admin, dest=dest)
    assert r.status_code == 400 and r.get_json()['error'] == 'dest_path is not a path the guest can take'
    assert not pve.session.get.called
    # counterproof: 4096 bytes is a path
    assert _restore(admin, dest='/' + 'a' * 4095).status_code == 200


# --- who may write into the guest ---------------------------------------------------------

def test_a_caller_without_vm_console_on_the_guest_gets_403(api, seed, pve):
    bob = _scoped(api, seed, perms=['vm.view', 'vm.backup'])
    r = _restore(bob)
    assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied: vm.console'
    assert not pve.session.get.called and not pve.session.post.called


def test_the_same_caller_with_vm_console_restores(api, seed, pve):
    """Counterproof: vm.console added, nothing else changed."""
    bob = _scoped(api, seed, perms=['vm.view', 'vm.backup', 'vm.console'])
    r = _restore(bob)
    assert r.status_code == 200, r.get_json()
    assert pve.session.post.called


def test_vm_backup_on_the_guest_is_still_needed(api, seed, pve):
    bob = _scoped(api, seed, perms=['vm.view', 'vm.console'])
    r = _restore(bob)
    assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied: vm.backup'


def test_a_non_admin_needs_vm_backup_on_the_guest_the_backup_is_of(api, seed, pve):
    bob = _scoped(api, seed)
    r = _restore(bob, volid=FOREIGN)
    assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied for source backup'
    assert not pve.session.get.called


def test_vm_backup_on_the_source_guest_lets_it_through(api, seed, pve, admin):
    """Counterproof: a grant of vm.backup on guest 200 is what was missing; an admin needs none."""
    bob = _scoped(api, seed, also={200: ['vm.backup']})
    assert _restore(bob, volid=FOREIGN).status_code == 200
    assert _restore(admin, volid=FOREIGN).status_code == 200


def test_an_operator_of_the_whole_cluster_restores_unless_vm_console_is_taken(api, seed, pve):
    """The unconfined non-admin: role user in the tenant that owns the cluster, no ACL, no
    pool. Their role carries vm.console, so the gate lets them through, any guest's backup
    included; with vm.console denied on the account it does not, browsing stays."""
    seed.tenant('acme', clusters=[CID])
    ops = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    assert _restore(ops).status_code == 200
    assert _restore(ops, volid=FOREIGN).status_code == 200
    nocon = api.as_user(seed.user('nocon', role='user', tenant_id='acme', denied=['vm.console']))
    r = _restore(nocon)
    assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied: vm.console'
    assert _browse(nocon).status_code == 200


def test_a_pool_scoped_caller_of_another_tenant_needs_vm_console_in_the_grant(api, seed, pve, monkeypatch):
    """Confined: their tenant does not own the cluster, a pool grant brings them in."""
    import time
    from pegaprox.utils import rbac
    monkeypatch.setitem(rbac._pool_membership_cache, CID, {
        'data': {'100:qemu': 'p1', '200:qemu': 'p2'}, 'timestamp': time.time(), 'refreshing': False})
    seed.tenant('other', clusters=[])
    seed.pool(CID, 'p1', 'eve', ['vm.backup'])
    eve = api.as_user(seed.user('eve', role='user', tenant_id='other'))
    r = _restore(eve)
    assert r.status_code == 403 and r.get_json()['error'] == 'Permission denied: vm.console'
    seed.pool(CID, 'p1', 'eve', ['vm.backup', 'vm.console'])
    assert _restore(eve).status_code == 200
    # guest 200 is in a pool they hold nothing on: neither its backup nor the guest itself
    assert _restore(eve, volid=FOREIGN).get_json()['error'] == 'Permission denied for source backup'
    assert _restore(eve, vm='qemu/200').status_code == 403


def test_a_guest_type_the_route_does_not_know_is_refused(admin, pve):
    r = _restore(admin, vm='openvz/100')
    assert r.status_code == 400 and not pve.session.get.called


@pytest.mark.parametrize('body', [{'volid': OWN, 'filepath': FILE, 'dest_path': 'etc/hosts'},
                                  {'volid': OWN, 'filepath': FILE},
                                  {'volid': [OWN], 'filepath': FILE, 'dest_path': '/etc/hosts'}])
def test_a_body_without_an_absolute_destination_is_refused(admin, pve, body):
    r = admin.post(f'{URL}/qemu/100/backups/file-restore', json=body)
    assert r.status_code == 400 and not pve.session.get.called
