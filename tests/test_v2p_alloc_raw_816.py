# #816 - ESXi migration into an LVM storage on PVE 9 failed at `qm set` with "Image is not in
# qcow2 format". _pvesm_alloc_disk tried `pvesm alloc` without --format first. PVE 9 can put
# qcow2 on LVM, so the storage default handed back vm-N-disk-M.qcow2, the dd pipe wrote the raw
# disk into it, and attaching the volume as qcow2 failed. Every caller writes raw, so every
# attempt has to ask for raw.

import re
from unittest.mock import MagicMock

import pegaprox.core.v2p as v2p

STOR = 'san-lvm-01'
VG = f'/dev/vg-{STOR}'
GiB = 1024 ** 3


class _FakeNode:
    """pvesm on one node. `kind` is the storage type pvesm status reports.
    `default_fmt` is what alloc picks without --format (qcow2 = PVE 9 LVM with volume chains).
    `raw_ok=False` makes every raw alloc fail, to see what the helper falls back to."""

    def __init__(self, kind='lvm', default_fmt='qcow2', raw_ok=True):
        self.kind = kind
        self.default_fmt = default_fmt
        self.raw_ok = raw_ok
        self.allocs = []
        self.volumes = {}

    def _path(self, vol):
        name = vol.split(':', 1)[1]
        if self.kind == 'dir':
            return f'/var/lib/vz/images/117/{name}'
        return f'{VG}/{name}'

    def __call__(self, pve_mgr, node, cmd, timeout=30):
        if cmd.startswith('pvesm status'):
            return 0, f'{STOR} {self.kind} active 1000000 1000 999000 0.10%', ''
        if cmd.startswith('pvesm alloc'):
            self.allocs.append(cmd)
            m = re.match(r'pvesm alloc (\S+) (\d+) (\S+) \S+(?: --format (\w+))?', cmd)
            storage, _vmid, name, fmt = m.groups()
            fmt = fmt or self.default_fmt
            if fmt == 'raw' and not self.raw_ok:
                return 1, 'storage error: allocation failed', ''
            if self.kind != 'dir' and fmt == 'qcow2' and not name.endswith('.qcow2'):
                name += '.qcow2'          # PVE 9 names qcow2 LVs with the suffix
            vol = f'{storage}:{name}'
            self.volumes[vol] = fmt
            return 0, f"successfully created '{vol}'", ''
        if cmd.startswith('pvesm path'):
            vol = cmd.split()[2].strip("'")
            if vol in self.volumes:
                return 0, self._path(vol) + '\n', ''
            return 1, f"no such volume '{vol}'", ''
        return 0, '', ''


def _run(monkeypatch, fake):
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    mgr = MagicMock(host='pve1', api_port=8006)
    mgr._api_post.return_value = MagicMock(status_code=500)
    errbuf = []
    vol, path = v2p._pvesm_alloc_disk(mgr, 'pve1', STOR, 117, 0, 16 * GiB, errbuf=errbuf)
    return vol, path, errbuf


def test_pve9_lvm_gets_a_raw_volume_not_its_qcow2_default(monkeypatch):
    fake = _FakeNode(kind='lvm', default_fmt='qcow2')
    vol, path, _ = _run(monkeypatch, fake)
    assert vol == f'{STOR}:vm-117-disk-0'
    assert path == f'{VG}/vm-117-disk-0'
    assert fake.volumes[vol] == 'raw'
    assert not any(name.endswith('.qcow2') for name in fake.volumes)
    assert '--format raw' in fake.allocs[0]


def test_block_storage_attempts_all_ask_for_raw(monkeypatch):
    # every raw attempt fails: the helper must give up, not retry without a format or as qcow2
    fake = _FakeNode(kind='lvm', default_fmt='qcow2', raw_ok=False)
    vol, path, errbuf = _run(monkeypatch, fake)
    assert (vol, path) == (None, None)
    assert errbuf and errbuf[0]
    assert fake.allocs, 'no alloc attempted'
    assert all(cmd.replace(' 2>&1', '').endswith('--format raw') for cmd in fake.allocs), fake.allocs
    assert fake.volumes == {}


def test_file_storage_keeps_qcow2_as_the_last_attempt(monkeypatch):
    fake = _FakeNode(kind='dir', default_fmt='raw', raw_ok=False)
    vol, path, _ = _run(monkeypatch, fake)
    assert all('--format raw' in cmd and 'vm-117-disk-0.raw' in cmd for cmd in fake.allocs[:-1])
    assert '--format qcow2' in fake.allocs[-1] and 'vm-117-disk-0.qcow2' in fake.allocs[-1]
    assert vol == f'{STOR}:vm-117-disk-0.qcow2'
