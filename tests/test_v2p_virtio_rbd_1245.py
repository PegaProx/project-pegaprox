"""#1245 - the VirtIO injection never ran on a Ceph RBD target, and nobody was told.

The rbd branch of the node script cut pool and image out of the volume id. For RBD that
is <storage>:<image>, so both came back as the image name and `rbd map -p <image>
<image>` failed with "error opening pool". The pool is only in the pvesm path, which also
carries the conf, the client id, the keyring and, for an external Ceph, the monitors;
none of that reached `rbd map` either. The failure was one log line under COMPLETED.

These tests do not grep the source. _inject_virtio_drivers runs as it does in a
migration, every command it sends to the node goes through bash, and the node's pvesm,
pvesh, rbd, mount and losetup are fakes on PATH. The fake rbd reads its arguments the way
the real CLI does (-p/--namespace/-c/-m/--id/--keyring, and a pool/ns/image spec overrides
-p) and only maps images its cluster has. losetup always refuses, so each run stops
right after the rbd branch has handed over its block device.
MK
"""
import json
import os
import stat
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p

VOL_ID = 'vm-rbd:vm-100-disk-0'
MANAGED = ('rbd:vm-rbd/vm-100-disk-0:conf=/etc/pve/ceph.conf:id=admin'
           ':keyring=/etc/pve/priv/ceph/vm-rbd.keyring')
NAMESPACED = ('rbd:vm-rbd/tenant-a/vm-100-disk-0:conf=/etc/pve/ceph.conf:id=admin'
              ':keyring=/etc/pve/priv/ceph/vm-rbd.keyring')
# what PVE writes for an external cluster: monitors with escaped colons, ';' between them
EXTERNAL = (r'rbd:ext-pool/vm-100-disk-0:conf=/etc/pve/priv/ceph/vm-rbd.conf'
            r':mon_host=10.0.0.1\:6789;10.0.0.2\:6789;[fd00\:\:3]\:3300'
            r':auth_client_required=cephx:id=pvecluster'
            r':keyring=/etc/pve/priv/ceph/vm-rbd.keyring')
# PVE before Ceph 19.2.6 wrote auth_supported; here an external cluster without cephx
OLD_PVE_NO_AUTH = (r'rbd:ext-pool/vm-100-disk-0:conf=/etc/pve/priv/ceph/vm-rbd.conf'
                   r':mon_host=10.0.0.1\:6789;10.0.0.2\:6789:auth_supported=none')
# krbd: pvesm path names only the device link, which is not there while nothing maps it
KRBD_FSID = '0f3c7a52-8e41-4d1e-9a3b-6e2d8c5b1f00'
KRBD_UNMAPPED = f'/dev/rbd-pve/{KRBD_FSID}/vm-rbd/vm-100-disk-0'
KRBD_EXT_UNMAPPED = f'/dev/rbd-pve/{KRBD_FSID}/ext-pool/vm-100-disk-0'

_FAKE_RBD = r'''#!{python}
import json, os, re, sys

argv = sys.argv[1:]
log = os.environ['FAKE_RBD_LOG']
VAL = {{'-p': 'pool', '--pool': 'pool', '--namespace': 'ns', '-c': 'conf', '--conf': 'conf',
        '-m': 'mon_host', '--mon_host': 'mon_host', '--mon-host': 'mon_host',
        '--id': 'id', '-i': 'id', '-n': 'name', '--name': 'name',
        '--keyring': 'keyring', '-k': 'keyring',
        '--auth_client_required': 'auth_client_required',
        '--auth-client-required': 'auth_client_required'}}
req, pos, i = {{'pool': 'rbd', 'ns': ''}}, [], 0
while i < len(argv):
    a = argv[i]
    if a.startswith('-'):
        key, eq, val = a.partition('=')
        if key not in VAL:
            print(f"rbd: unrecognised option '{{a}}'", file=sys.stderr)
            sys.exit(22)
        if not eq:
            i += 1
            val = argv[i]
        req[VAL[key]] = val
    else:
        pos.append(a)
    i += 1
if pos[:1] == ['device']:
    pos = pos[1:]
op = pos[0] if pos else ''
if 'name' in req:
    req['id'] = req.pop('name').split('.', 1)[-1]


def record(entry):
    with open(log, 'a') as f:
        f.write(json.dumps(entry) + '\n')


if op == 'unmap':
    record({{'op': 'unmap', 'dev': pos[1] if len(pos) > 1 else ''}})
    sys.exit(0)
if op != 'map':
    record({{'op': op, 'argv': argv}})
    sys.exit(0)
m = re.fullmatch(r'(?:([^/@]+)/(?:([^/@]+)/)?)?([^/@]+)', pos[1] if len(pos) > 1 else '')
if not m:
    print('rbd: image name was not specified', file=sys.stderr)
    sys.exit(22)
if m.group(1):
    req['pool'] = m.group(1)
if m.group(2):
    req['ns'] = m.group(2)
req['image'] = m.group(3)
req['op'] = 'map'
record(req)
# the node's ceph.conf asks for cephx; a cluster without it only lets in a client told
# --auth_client_required none
if os.environ.get('FAKE_RBD_CLUSTER_AUTH') == 'none' and req.get('auth_client_required') != 'none':
    print("rbd: couldn't connect to the cluster!", file=sys.stderr)
    sys.exit(1)
have = [x.split('/') for x in os.environ.get('FAKE_RBD_IMAGES', '').split(',') if x]
if req['pool'] not in [h[0] for h in have]:
    print(f"rbd: error opening pool '{{req['pool']}}': (2) No such file or directory",
          file=sys.stderr)
    sys.exit(2)
if [req['pool'], req['ns'], req['image']] not in have:
    print(f"rbd: error opening image {{req['image']}}: (2) No such file or directory",
          file=sys.stderr)
    sys.exit(2)
print(os.environ['FAKE_RBD_DEV'])
'''

_FAKE_PVESM = '''#!/bin/sh
case "$1" in
  path) printf '%s\\n' "$FAKE_PVESM_PATH" ;;
  status) printf 'Name Type Status Total Used Available %%\\n'
          printf '%s %s active 1000 100 900 10.00%%\\n' "$3" "$FAKE_STYPE" ;;
  *) exit 1 ;;
esac
'''

# `pvesh get /storage/<id> --output-format json`, from FAKE_PVESH_STORAGE (unset: fails)
_FAKE_PVESH = '''#!/bin/sh
[ "$1" = get ] && [ "$2" = "/storage/$FAKE_STORAGE_ID" ] && [ -n "$FAKE_PVESH_STORAGE" ] || exit 2
printf '%s\\n' "$FAKE_PVESH_STORAGE"
'''


def _block_device():
    """Some block device of the test host, for `[ -b ]`. Nothing ever opens it: mount and
    losetup are fakes."""
    for name in sorted(os.listdir('/dev')):
        p = os.path.join('/dev', name)
        try:
            if stat.S_ISBLK(os.stat(p).st_mode):
                return p
        except OSError:
            continue
    return None


DEV = _block_device()
needs_dev = pytest.mark.skipif(DEV is None, reason='no block device on this host')


class _Node:
    """A Proxmox node whose commands run in bash, with fakes for what a test must not run."""

    def __init__(self, tmp_path, vol_path, images=(), stype='rbd', storage=None,
                 cluster_auth=''):
        self.bin = tmp_path / 'bin'
        self.bin.mkdir()
        self.rbd_log = tmp_path / 'rbd.jsonl'
        self.cmd_log = tmp_path / 'cmds.log'
        self._fake('rbd', _FAKE_RBD.format(python=sys.executable))
        self._fake('pvesm', _FAKE_PVESM)
        self._fake('pvesh', _FAKE_PVESH)
        for name in ('apt-get', 'mount', 'umount', 'sync', 'lvchange', 'modprobe'):
            self._fake(name, f'#!/bin/sh\necho "{name} $*" >> "$FAKE_CMD_LOG"\n')
        # refuses every time: the run ends right after the storage branch
        self._fake('losetup', '#!/bin/sh\necho "losetup $*" >> "$FAKE_CMD_LOG"\n'
                              'echo "losetup: refused by the test"\nexit 1\n')
        self.env = {
            'PATH': f'{self.bin}:/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(tmp_path),
            'FAKE_RBD_LOG': str(self.rbd_log), 'FAKE_CMD_LOG': str(self.cmd_log),
            'FAKE_PVESM_PATH': vol_path, 'FAKE_STYPE': stype,
            'FAKE_RBD_IMAGES': ','.join(images), 'FAKE_RBD_DEV': DEV or '/dev/none',
            'FAKE_STORAGE_ID': 'vm-rbd', 'FAKE_RBD_CLUSTER_AUTH': cluster_auth,
            'FAKE_PVESH_STORAGE': json.dumps(storage) if storage is not None else '',
        }

    def _fake(self, name, body):
        p = self.bin / name
        p.write_text(textwrap.dedent(body))
        p.chmod(0o755)

    def __call__(self, pve_mgr, node, cmd, timeout=600, **kw):
        p = subprocess.run(['bash', '-c', cmd], env=self.env, capture_output=True, text=True,
                           timeout=120)
        return p.returncode, p.stdout, p.stderr

    def rbd(self, op):
        if not self.rbd_log.exists():
            return []
        rows = [json.loads(ln) for ln in self.rbd_log.read_text().splitlines()]
        return [r for r in rows if r.get('op') == op]

    def cmds(self, name):
        if not self.cmd_log.exists():
            return []
        return [ln for ln in self.cmd_log.read_text().splitlines() if ln.startswith(name + ' ')]


@pytest.fixture
def run(tmp_path, monkeypatch):
    sse = []
    monkeypatch.setattr(v2p, 'broadcast_sse', lambda kind, data: sse.append((kind, data)))

    def _run(vol_path, images=(), iso=True, storage=None, priv=(), cluster_auth=''):
        node = _Node(tmp_path, vol_path, images, storage=storage, cluster_auth=cluster_auth)
        monkeypatch.setattr(v2p, '_pve_node_exec', node)
        # /etc/pve/priv/ceph of this node: the storage's keyring and conf
        priv_dir = tmp_path / 'priv-ceph'
        priv_dir.mkdir()
        for name in priv:
            (priv_dir / name).write_text('[client.x]\n')
        monkeypatch.setattr(v2p, '_CEPH_PRIV_DIR', str(priv_dir))
        iso_path = tmp_path / 'virtio-win.iso'
        if iso:
            iso_path.write_bytes(b'')
        task = v2p.V2PMigrationTask('m1245', 'vw1', 'vm-7', 'pve-cl', 'pve1', 'vm-rbd',
                                    config={'install_virtio_drivers': True,
                                            'virtio_iso_path': str(iso_path)})
        task.proxmox_vmid = 100
        task.record_disk_volume(0, VOL_ID)
        mgr = SimpleNamespace(host='pve1', api_port=8006,
                              _api_get=lambda *a, **k: SimpleNamespace(status_code=500))
        ok = v2p._inject_virtio_drivers(mgr, task)
        return SimpleNamespace(ok=ok, node=node, task=task, sse=sse, priv=priv_dir)
    return _run


def _mapped(r):
    maps = r.node.rbd('map')
    assert len(maps) == 1, (maps, r.task.log_lines[-6:])
    return maps[0]


def _monitors(value):
    return [m for m in value.replace(';', ',').replace(' ', ',').split(',') if m]


# -- the rbd branch maps the image the path names, with the storage's own auth ---------

@needs_dev
def test_a_managed_pool_is_mapped_from_the_path_with_its_conf_id_and_keyring(run):
    r = run(MANAGED, images=['vm-rbd//vm-100-disk-0'])
    req = _mapped(r)
    assert (req['pool'], req['ns'], req['image']) == ('vm-rbd', '', 'vm-100-disk-0')
    assert req.get('conf') == '/etc/pve/ceph.conf'
    assert req.get('id') == 'admin'
    assert req.get('keyring') == '/etc/pve/priv/ceph/vm-rbd.keyring'
    # the device rbd handed back is what the script goes on with ...
    assert any(c.split()[-1] == DEV for c in r.node.cmds('losetup')), r.node.cmds('losetup')
    # ... and the map made for this run is undone when it ends
    assert [u['dev'] for u in r.node.rbd('unmap')] == [DEV]


@needs_dev
def test_a_namespace_reaches_rbd_as_a_namespace_not_as_the_pool(run):
    r = run(NAMESPACED, images=['vm-rbd/tenant-a/vm-100-disk-0'])
    req = _mapped(r)
    assert (req['pool'], req['ns'], req['image']) == ('vm-rbd', 'tenant-a', 'vm-100-disk-0')
    assert req.get('keyring') == '/etc/pve/priv/ceph/vm-rbd.keyring'
    assert any(c.split()[-1] == DEV for c in r.node.cmds('losetup'))
    assert [u['dev'] for u in r.node.rbd('unmap')] == [DEV]


@needs_dev
def test_an_external_ceph_gets_its_monitors_conf_and_client(run):
    r = run(EXTERNAL, images=['ext-pool//vm-100-disk-0'])
    req = _mapped(r)
    assert (req['pool'], req['ns'], req['image']) == ('ext-pool', '', 'vm-100-disk-0')
    assert _monitors(req.get('mon_host', '')) == ['10.0.0.1:6789', '10.0.0.2:6789',
                                                  '[fd00::3]:3300']
    assert req.get('conf') == '/etc/pve/priv/ceph/vm-rbd.conf'
    assert req.get('id') == 'pvecluster'
    assert req.get('keyring') == '/etc/pve/priv/ceph/vm-rbd.keyring'
    assert req.get('auth_client_required') == 'cephx'
    assert [u['dev'] for u in r.node.rbd('unmap')] == [DEV]


@needs_dev
def test_a_krbd_image_proxmox_has_mapped_is_used_and_its_map_left_alone(run):
    # krbd: pvesm path is the /dev/rbd-pve link of a map PVE made and owns
    r = run(DEV, images=['vm-rbd//vm-100-disk-0'])
    assert r.node.rbd('map') == [], 'a second map of an image that is already a block device'
    assert any(c.split()[-1] == DEV for c in r.node.cmds('losetup')), r.node.cmds('losetup')
    assert r.node.rbd('unmap') == [], "the script unmapped PVE's own map"


@needs_dev
def test_an_unmapped_krbd_image_of_an_external_ceph_is_mapped_with_the_storage_settings(run):
    # the /dev path has no conf, monitors or keyring in it; PVE takes them from the storage
    r = run(KRBD_EXT_UNMAPPED, images=['ext-pool//vm-100-disk-0'],
            storage={'type': 'rbd', 'pool': 'ext-pool', 'krbd': 1, 'username': 'pvecluster',
                     'monhost': '10.0.0.1:6789 10.0.0.2;fd00::3'},
            priv=('vm-rbd.keyring', 'vm-rbd.conf'))
    req = _mapped(r)
    assert (req['pool'], req['ns'], req['image']) == ('ext-pool', '', 'vm-100-disk-0')
    assert _monitors(req.get('mon_host', '')) == ['10.0.0.1:6789', '10.0.0.2', '[fd00::3]']
    assert req.get('conf') == str(r.priv / 'vm-rbd.conf')
    assert req.get('id') == 'pvecluster'
    assert req.get('keyring') == str(r.priv / 'vm-rbd.keyring')
    assert req.get('auth_client_required') == 'cephx'
    assert any(c.split()[-1] == DEV for c in r.node.cmds('losetup')), r.node.cmds('losetup')
    # the map was made here, so it is undone here
    assert [u['dev'] for u in r.node.rbd('unmap')] == [DEV]


@needs_dev
def test_an_unmapped_krbd_image_of_the_pve_ceph_gets_its_conf_and_keyring(run):
    r = run(KRBD_UNMAPPED, images=['vm-rbd//vm-100-disk-0'],
            storage={'type': 'rbd', 'pool': 'vm-rbd', 'krbd': 1}, priv=('vm-rbd.keyring',))
    req = _mapped(r)
    assert (req['pool'], req['ns'], req['image']) == ('vm-rbd', '', 'vm-100-disk-0')
    assert req.get('conf') == '/etc/pve/ceph.conf'
    assert req.get('id') == 'admin'
    assert req.get('keyring') == str(r.priv / 'vm-rbd.keyring')
    # a pveceph cluster's own conf sets its auth, and there are no monitors to name
    assert 'mon_host' not in req and 'auth_client_required' not in req, req
    assert [u['dev'] for u in r.node.rbd('unmap')] == [DEV]


@needs_dev
def test_an_older_pve_path_without_cephx_still_maps(run):
    r = run(OLD_PVE_NO_AUTH, images=['ext-pool//vm-100-disk-0'], cluster_auth='none')
    req = _mapped(r)
    assert req.get('auth_client_required') == 'none', req
    assert any(c.split()[-1] == DEV for c in r.node.cmds('losetup')), r.task.log_lines[-4:]
    assert not any('RBD_MAP_FAILED' in w for w in r.task.to_dict()['warnings'])


# -- a failed injection is in the result, not only in the log -------------------------

def test_a_failed_map_is_a_warning_in_the_migration_result(run):
    r = run(MANAGED, images=['other-pool//vm-100-disk-0'])
    assert r.ok is False
    shown = r.task.to_dict()['warnings']
    assert len(shown) == 1, shown
    assert 'VirtIO drivers were not injected' in shown[0]
    assert 'RBD_MAP_FAILED' in shown[0] and "error opening pool 'vm-rbd'" in shown[0], shown
    # nothing was mapped, so nothing is unmapped
    assert r.node.rbd('unmap') == []

    # the run still completes, and the update that says so carries the warning
    r.task.set_phase('completed')
    assert r.task.status == 'completed'
    final = [d for kind, d in r.sse if kind == 'vmware_migration' and d.get('phase') == 'completed']
    assert final and final[-1].get('warnings') == shown


def test_a_missing_virtio_iso_is_a_warning_too(run):
    r = run(MANAGED, images=['vm-rbd//vm-100-disk-0'], iso=False)
    assert r.ok is False
    shown = r.task.to_dict()['warnings']
    assert len(shown) == 1 and 'virtio-win.iso was not found' in shown[0], shown


def test_a_reason_ending_in_a_full_stop_is_one_sentence():
    t = v2p.V2PMigrationTask('m1245', 'vw1', 'vm-7', 'pve-cl', 'pve1', 'vm-rbd', config={})
    v2p._virtio_not_injected(t, RuntimeError('rbd: image is locked.'))
    v2p._virtio_not_injected(t, RuntimeError(''))
    first, second = t.to_dict()['warnings']
    assert 'rbd: image is locked. The guest' in first and '..' not in first, first
    assert 'not injected: . ' not in second and ':  ' not in second, second


class _Stop(BaseException):
    pass


@pytest.mark.parametrize('mode', ['auto', 'sshfs_boot'])
def test_the_live_mirror_tells_that_the_drivers_were_not_injected(monkeypatch, mode):
    # auto mode falls back to the live mirror when the pre-sync hits a locked disk; the
    # mirror boots the guest from the source, so no driver gets staged
    monkeypatch.setattr(v2p, 'broadcast_sse', lambda *a, **k: None)

    def _node(*a, **k):
        raise _Stop()
    monkeypatch.setattr(v2p, '_pve_node_exec', _node)
    t = v2p.V2PMigrationTask('m1245', 'vw1', 'vm-7', 'pve-cl', 'pve1', 'vm-rbd',
                             config={'install_virtio_drivers': True, 'transfer_mode': mode})
    t.proxmox_vmid = 100
    mgr = SimpleNamespace(host='pve1', api_port=8006)
    with pytest.raises(_Stop):
        v2p._do_sshfs_boot_migration(mgr, t, SimpleNamespace(), 'esxi1', 'root', 'pw',
                                     'ds1', 'vm-7', ['vm-7.vmdk'], 'scsi', '/mnt/v2p-x')
    shown = t.to_dict()['warnings']
    assert len(shown) == 1 and 'VirtIO drivers were not injected' in shown[0], shown
    assert 'live mirror' in shown[0], shown

    off = v2p.V2PMigrationTask('m1245', 'vw1', 'vm-7', 'pve-cl', 'pve1', 'vm-rbd',
                               config={'transfer_mode': mode})
    with pytest.raises(_Stop):
        v2p._do_sshfs_boot_migration(mgr, off, SimpleNamespace(), 'esxi1', 'root', 'pw',
                                     'ds1', 'vm-7', ['vm-7.vmdk'], 'scsi', '/mnt/v2p-x')
    assert off.to_dict()['warnings'] == []


def test_no_warning_when_the_drivers_were_not_asked_for():
    t = v2p.V2PMigrationTask('m1245', 'vw1', 'vm-7', 'pve-cl', 'pve1', 'vm-rbd', config={})
    assert v2p._inject_virtio_drivers(SimpleNamespace(), t) is False
    assert t.to_dict()['warnings'] == []
