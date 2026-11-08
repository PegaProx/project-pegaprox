# ESXi -> Proxmox migration: the copy commands, run in a real shell on this machine.
#
# A disk name and the ESXi password used to reach the node's shell in ways it parsed:
#   * the remote command of the ssh copies sat in double quotes, so the node's shell
#     expanded $(...) and backticks of a name before ssh sent it to ESXi
#   * SSHPASS=<password> was part of the SSH copy's command, a base64 echo of it part of the
#     delta copy's, and the copy scripts carried it in their bodies: a command line is
#     readable by every local account on the node while it runs
#   * curl took the login as --user $(cat file), split at every space of the password
# The password now reaches the node on stdin only, into a 0600 file in /run that sshpass -f
# or curl -K reads, and each name is quoted for every shell that reads it.
#
# The node and the ESXi host are this machine: /run, /tmp/v2p-* and /vmfs/volumes of the
# commands map to folders of the test, ssh and sshpass are stand-ins (sshpass notes the
# password it was handed, ssh runs the remote command here in sh), and the HTTPS endpoint
# of ESXi is a local HTTP server that notes the login it gets. The names below carry a
# command substitution: the copies are called directly, behind the check of the names.

import base64
import os
import shlex
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p

MiB = 1024 ** 2
PASSWORD = 'pa ss"w\'o$rd\\1 x'
NAME = 'web $(touch canary) & (1) #+ä.vmdk'
FLAT = NAME[:-len('.vmdk')] + '-flat.vmdk'

SSHPASS_STANDIN = r'''#!/bin/sh
case "$1" in
  -f) cat "$2" >> "$SAW"; echo >> "$SAW"; shift 2 ;;
  -e) printf '%s\n' "$SSHPASS" >> "$SAW"; shift ;;
esac
exec "$@"
'''
SSH_STANDIN = r'''#!/bin/sh
[ -n "$FAIL_SSH" ] && exit 255
while :; do
  case "$1" in -o|-i|-c|-p) shift 2 ;; *) break ;; esac
done
shift
exec sh -c "$*"
'''
# O_DIRECT on a test file is beside the point
DD_STANDIN = '#!/bin/sh\nfor a; do shift; [ "$a" = oflag=direct ] || set -- "$@" "$a"; done\nexec %s "$@"\n'
XXHSUM_STANDIN = '#!/bin/sh\nexec md5sum\n'


class Machine:
    """_pve_node_exec and _ssh_exec against folders of this test."""

    # what runs for real on the node and on ESXi; anything else is answered without running.
    # SSHPASS= is how the SSH copy began before the password moved to a file.
    RUNS = ('umask 077;', 'bash ', 'rm -f ', 'curl ', 'sshpass ', 'SSHPASS=', 'ls -la ', 'dd if=',
            'i=0; while', 'for i in ')
    ESXI_RUNS = ('stat ', 'echo LZ4=', 'i=0; while')

    def __init__(self, tmp, monkeypatch, http_port=None):
        self.tmp = tmp
        for d in ('run', 'node-tmp', 'vmfs', 'bin'):
            (tmp / d).mkdir()
        dd = shutil.which('dd')
        for name, body in (('sshpass', SSHPASS_STANDIN), ('ssh', SSH_STANDIN),
                           ('dd', DD_STANDIN % dd), ('xxhsum', XXHSUM_STANDIN)):
            (tmp / 'bin' / name).write_text(body)
            (tmp / 'bin' / name).chmod(0o755)
        self.saw = tmp / 'sshpass-saw'
        self.env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
        self.env.update(PATH=f"{tmp / 'bin'}:{os.environ.get('PATH', '')}", SAW=str(self.saw),
                        LC_ALL='C')
        self.http_port = http_port
        self.node_sent, self.esxi_sent = [], []
        monkeypatch.setattr(v2p, '_pve_node_exec', self.node)
        monkeypatch.setattr(v2p, '_ssh_exec', self.esxi)
        monkeypatch.setattr(v2p, '_node_hkc', lambda: 'accept-new')
        monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)
        monkeypatch.setattr(v2p, 'log_audit', lambda *a, **k: None)

    def local(self, cmd):
        cmd = (cmd.replace('/run/', f'{self.tmp}/run/')
                  .replace('/tmp/v2p-', f'{self.tmp}/node-tmp/v2p-')
                  .replace('/vmfs/volumes/', f'{self.tmp}/vmfs/'))
        if self.http_port:
            cmd = cmd.replace('https://esx1.lab/', f'http://127.0.0.1:{self.http_port}/')
        return cmd

    def remote(self, text):
        return (text.replace(f'{self.tmp}/node-tmp/v2p-', '/tmp/v2p-')
                    .replace(f'{self.tmp}/vmfs/', '/vmfs/volumes/'))

    def _sh(self, shell, cmd, stdin=''):
        p = subprocess.run([shell, '-c', self.local(cmd)], capture_output=True, text=True,
                           input=stdin, cwd=self.tmp, env=self.env, timeout=120)
        return p.returncode, self.remote(p.stdout), self.remote(p.stderr)

    def node(self, mgr, node, cmd, timeout=600, **kw):
        self.node_sent.append((cmd, kw.get('stdin_data')))
        if cmd.startswith('which '):
            return 0, '/usr/bin/x\n', ''
        if cmd.startswith('if [ -d /sys/fs/cgroup ]'):
            return 1, '', ''
        if not cmd.startswith(self.RUNS):
            return 0, '', ''
        return self._sh('bash', cmd, kw.get('stdin_data') or '')

    def esxi(self, host, user, pw, cmd, timeout=30, **kw):
        self.esxi_sent.append(cmd)
        if not cmd.startswith(self.ESXI_RUNS):
            return 0, '', ''
        return self._sh('sh', cmd)

    def flat(self, data, folder='ds1/web01', name=FLAT):
        p = self.tmp / 'vmfs' / folder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def handed_to_sshpass(self):
        return self.saw.read_text().splitlines() if self.saw.exists() else []

    def assert_password_off_command_lines(self, user='root'):
        forms = {PASSWORD, shlex.quote(PASSWORD), base64.b64encode(PASSWORD.encode()).decode(),
                 base64.b64encode(f'{user}:{PASSWORD}'.encode()).decode()}
        for cmd in [c for c, _ in self.node_sent] + self.esxi_sent:
            assert not [f for f in forms if f in cmd], f'a command line carries the password: {cmd[:300]}'
        # on stdin it goes into a new file in /run, and nowhere else
        fed = [c for c, data in self.node_sent if data is not None]
        assert fed and all(c.startswith('umask 077; rm -f /run/') and ' && cat > /run/' in c
                           for c in fed), fed
        assert not list((self.tmp / 'run').iterdir()), 'a secret file stayed on the node'

    def assert_no_command_ran_from_the_name(self):
        assert not (self.tmp / 'canary').exists(), 'a shell ran what the disk name held'


def _task(tid='t1'):
    t = v2p.V2PMigrationTask(tid, 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm', vm_name='web01',
                             config={'esxi_password': PASSWORD, 'esxi_host': 'esx1.lab',
                                     'start_after': False})
    t.proxmox_vmid = 120
    return t


@pytest.fixture
def esxi_https():
    """The /folder endpoint of ESXi: notes the login of every request, serves no data."""
    logins = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            auth = self.headers.get('Authorization') or ''
            if auth.startswith('Basic '):
                logins.append(base64.b64decode(auth[6:]).decode('utf-8', 'replace'))
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(port=server.server_port, logins=logins)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# --------------------------------------------------------------------------- the disk copy

@pytest.mark.parametrize('way', ['ssh', 'sshfs'])
def test_the_disk_copy_reads_the_named_file_and_hands_the_password_over_files(
        monkeypatch, tmp_path, esxi_https, way):
    m = Machine(tmp_path, monkeypatch, http_port=esxi_https.port)
    data = os.urandom(3 * MiB + 4096)
    m.flat(data)
    if way == 'sshfs':
        # the SSH copy fails, the copy from the SSHFS mount of the datastore follows
        m.env['FAIL_SSH'] = '1'
        m.flat(data, folder='../node-tmp/v2p-t1/web01')
    vol = tmp_path / 'vm-120-disk-0'
    monkeypatch.setattr(v2p, '_pvesm_alloc_disk', lambda *a, **k: ('local-lvm:vm-120-disk-0', str(vol)))
    monkeypatch.setattr(v2p, '_monitor_disk_write', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_rbd_map_sink', lambda task: [])
    t = _task()

    got = v2p._ssh_pipe_transfer(SimpleNamespace(), t, 'esx1.lab', 'root', PASSWORD,
                                 'ds1', 'web01', NAME, 0)

    m.assert_no_command_ran_from_the_name()
    assert got == ('local-lvm:vm-120-disk-0', str(vol)), t.log_lines[-12:]
    assert vol.read_bytes() == data
    # curl took the login from its config file, all of it, spaces and quotes included
    assert esxi_https.logins and set(esxi_https.logins) == {f'root:{PASSWORD}'}, esxi_https.logins
    if way == 'ssh':
        assert m.handed_to_sshpass() == [PASSWORD]
    m.assert_password_off_command_lines()


def test_the_block_replay_reads_the_named_file_and_hands_the_password_over_a_file(monkeypatch, tmp_path):
    import random
    m = Machine(tmp_path, monkeypatch)
    monkeypatch.setattr(v2p, 'DELTA_BLOCK_SIZE', MiB)
    rnd = random.Random(7)
    old = rnd.randbytes(4 * MiB)
    new = bytearray(old)
    new[MiB + 5000:MiB + 9000] = rnd.randbytes(4000)
    new[3 * MiB:3 * MiB + 10] = rnd.randbytes(10)
    m.flat(bytes(new))
    vol = tmp_path / 'vm-120-disk-0'
    vol.write_bytes(old)
    t = _task()

    ok = v2p._delta_sync_blocks(SimpleNamespace(), t, 'esx1.lab', 'root', PASSWORD,
                                f'/vmfs/volumes/ds1/web01/{FLAT}', str(vol), len(new), 0)

    m.assert_no_command_ran_from_the_name()
    assert ok, t.log_lines[-12:]
    assert vol.read_bytes() == bytes(new)
    assert m.handed_to_sshpass() == [PASSWORD, PASSWORD]      # one ssh per changed block
    m.assert_password_off_command_lines()


def test_the_copy_without_a_key_reads_the_named_file_and_keeps_the_password_out_of_its_scripts(
        monkeypatch, tmp_path):
    m = Machine(tmp_path, monkeypatch)
    data = os.urandom(8 * MiB)
    m.flat(data)
    vol = tmp_path / 'vm-120-disk-0'
    monkeypatch.setattr(v2p, '_pvesm_alloc_disk', lambda *a, **k: ('local-lvm:vm-120-disk-0', str(vol)))
    monkeypatch.setattr(v2p, '_rbd_map_sink', lambda task: [])
    monkeypatch.setattr(v2p, '_setup_temp_ssh_key', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_maybe_convert_disks_to_qcow2', lambda *a, **k: None)
    t = _task()
    t.disk_progress = {'disk0': {'copied': 0, 'total': len(data), 'pct': 0}}

    v2p._do_offline_qemuimg_copy(SimpleNamespace(), t, 'esx1.lab', 'root', PASSWORD,
                                 'ds1', 'web01', [NAME], 'scsi', '/tmp/v2p-t1')

    m.assert_no_command_ran_from_the_name()
    assert t.status == 'completed', t.error
    assert vol.read_bytes() == data
    assert any('Verified' in line for line in t.log_lines), t.log_lines[-12:]
    # the copy stream and the check after it, each with the password from the file
    assert m.handed_to_sshpass() == [PASSWORD, PASSWORD]
    m.assert_password_off_command_lines()


# --------------------------------------------------------------------------- a lost stdin

def _copy_by_pipe(m, monkeypatch, tmp_path, t):
    m.flat(os.urandom(MiB))
    vol = tmp_path / 'vm-120-disk-0'
    monkeypatch.setattr(v2p, '_pvesm_alloc_disk', lambda *a, **k: ('local-lvm:vm-120-disk-0', str(vol)))
    monkeypatch.setattr(v2p, '_monitor_disk_write', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_rbd_map_sink', lambda task: [])
    return v2p._ssh_pipe_transfer(SimpleNamespace(), t, 'esx1.lab', 'root', PASSWORD,
                                  'ds1', 'web01', NAME, 0) == (None, None)


def _copy_by_blocks(m, monkeypatch, tmp_path, t):
    monkeypatch.setattr(v2p, 'DELTA_BLOCK_SIZE', MiB)
    m.flat(b'\1' * (2 * MiB))
    vol = tmp_path / 'vm-120-disk-0'
    vol.write_bytes(b'\0' * (2 * MiB))
    return v2p._delta_sync_blocks(SimpleNamespace(), t, 'esx1.lab', 'root', PASSWORD,
                                  f'/vmfs/volumes/ds1/web01/{FLAT}', str(vol), 2 * MiB, 0) is False


def _copy_by_scripts(m, monkeypatch, tmp_path, t):
    m.flat(os.urandom(2 * MiB))
    vol = tmp_path / 'vm-120-disk-0'
    monkeypatch.setattr(v2p, '_pvesm_alloc_disk', lambda *a, **k: ('local-lvm:vm-120-disk-0', str(vol)))
    monkeypatch.setattr(v2p, '_rbd_map_sink', lambda task: [])
    monkeypatch.setattr(v2p, '_setup_temp_ssh_key', lambda *a, **k: None)
    monkeypatch.setattr(v2p, '_maybe_convert_disks_to_qcow2', lambda *a, **k: None)
    t.disk_progress = {'disk0': {'copied': 0, 'total': 2 * MiB, 'pct': 0}}
    v2p._do_offline_qemuimg_copy(SimpleNamespace(), t, 'esx1.lab', 'root', PASSWORD,
                                 'ds1', 'web01', [NAME], 'scsi', '/tmp/v2p-t1')
    return t.status == 'failed'


@pytest.mark.parametrize('copy', [_copy_by_pipe, _copy_by_blocks, _copy_by_scripts],
                         ids=['pipe', 'blocks', 'scripts'])
def test_a_password_that_did_not_reach_the_node_is_never_tried(monkeypatch, tmp_path, esxi_https, copy):
    # the node call loses what it should hand on to stdin, so each secret file stays empty:
    # no login with an empty password (enough failed ones lock the ESXi account), the copy
    # fails instead
    m = Machine(tmp_path, monkeypatch, http_port=esxi_https.port)
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda mgr, node, cmd, timeout=600, **kw: m.node(
        mgr, node, cmd, timeout, **{**kw, 'stdin_data': None if kw.get('stdin_data') is None else ''}))
    t = _task()

    failed = copy(m, monkeypatch, tmp_path, t)
    assert m.handed_to_sshpass() == [], 'sshpass logged in with an empty password'
    assert failed, t.log_lines[-12:]
    assert esxi_https.logins == []
    m.assert_no_command_ran_from_the_name()
    # the end of the run removes the empty files as well
    t.set_phase('failed', 'the copy failed')
    assert not list((tmp_path / 'run').iterdir()), 'a secret file stayed on the node'
