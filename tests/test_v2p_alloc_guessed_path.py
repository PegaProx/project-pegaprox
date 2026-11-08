# A disk alloc on the target node: when `pvesm path` cannot name the new volume, the helper
# guessed a path from the storage ID. That ID is not the VG, the ZFS pool or the dir path
# (local-lvm lives in VG pve), and a dd onto a path that is not there writes a plain file:
# the disk is lost without an error. The guess now counts only when the node has a block
# device or a file there. And btrfs keeps its images as files with a suffix, like dir.

import re
from unittest.mock import MagicMock

import pytest

import pegaprox.core.v2p as v2p

GiB = 1024 ** 3


class _Node:
    def __init__(self, kind, present=()):
        self.kind = kind
        self.present = set(present)       # the paths `test -b|-f` finds
        self.cmds = []
        self.volumes = set()

    def __call__(self, pve_mgr, node, cmd, timeout=30):
        self.cmds.append(cmd)
        if cmd.startswith('pvesm status'):
            return 0, f'st {self.kind} active 1000000 1000 999000 0.10%', ''
        if cmd.startswith('pvesm list'):
            return 0, 'Volid Format Type Size VMID\n', ''
        if cmd.startswith('pvesm alloc'):
            m = re.match(r'pvesm alloc (\S+) (\d+) (\S+)', cmd)
            storage, vmid, name = m.groups()
            if self.kind in ('dir', 'btrfs') and not name.endswith(('.raw', '.qcow2')):
                return 1, f"illegal name '{name}' - should be 'vm-{vmid}-*'", ''
            vol = f'{storage}:{vmid}/{name}' if self.kind in ('dir', 'btrfs') else f'{storage}:{name}'
            self.volumes.add(vol)
            return 0, f"successfully created '{vol}'", ''
        if cmd.startswith('pvesm path'):
            return 1, 'storage plugin answered nothing useful', ''
        if cmd.startswith('test '):
            path = cmd.split()[2].strip("'")
            return (0, 'present\n', '') if path in self.present else (1, '', '')
        if cmd.startswith('pvesm free'):
            self.volumes.discard(cmd.split()[2].strip("'"))
            return 0, '', ''
        return 0, '', ''


def _alloc(monkeypatch, node, storage='st'):
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    mgr = MagicMock(host='pve1', api_port=8006)
    mgr._api_post.return_value = MagicMock(status_code=500)
    errbuf = []
    vol, path = v2p._pvesm_alloc_disk(mgr, 'pve1', storage, 117, 0, 16 * GiB, errbuf=errbuf)
    return vol, path, errbuf


@pytest.mark.parametrize('kind,guess,test', [
    ('lvmthin', '/dev/st/vm-117-disk-0', '-b'),
    ('lvm', '/dev/st/vm-117-disk-0', '-b'),
    ('zfspool', '/dev/zvol/st/vm-117-disk-0', '-b'),
])
def test_a_guessed_block_path_that_is_not_there_fails_and_frees_the_volume(monkeypatch, kind, guess, test):
    node = _Node(kind)
    vol, path, errbuf = _alloc(monkeypatch, node)
    assert (vol, path) == (None, None)
    assert any(c == f"test {test} {guess} && echo present" for c in node.cmds)
    assert any('could not be resolved' in e for e in errbuf)
    # nothing of this call stays behind on the storage
    assert not node.volumes
    assert any(c.startswith('pvesm free st:vm-117-disk-0') for c in node.cmds)


def test_a_guessed_block_path_the_node_has_is_used(monkeypatch):
    node = _Node('lvmthin', present={'/dev/st/vm-117-disk-0'})
    vol, path, _ = _alloc(monkeypatch, node)
    assert (vol, path) == ('st:vm-117-disk-0', '/dev/st/vm-117-disk-0')
    assert not any(c.startswith('pvesm free') for c in node.cmds)


def test_a_guessed_file_path_needs_a_file(monkeypatch):
    node = _Node('dir')
    assert _alloc(monkeypatch, node)[:2] == (None, None)
    assert any(c == 'test -f /mnt/pve/st/images/117/vm-117-disk-0.raw && echo present' for c in node.cmds)
    node = _Node('dir', present={'/mnt/pve/st/images/117/vm-117-disk-0.raw'})
    assert _alloc(monkeypatch, node)[:2] == ('st:117/vm-117-disk-0.raw',
                                              '/mnt/pve/st/images/117/vm-117-disk-0.raw')


def test_btrfs_gets_a_file_name_and_its_folder_volid(monkeypatch):
    node = _Node('btrfs')
    _alloc(monkeypatch, node)
    allocs = [c for c in node.cmds if c.startswith('pvesm alloc')]
    assert allocs and allocs[0].startswith('pvesm alloc st 117 vm-117-disk-0.raw ')
    assert 'st:117/vm-117-disk-0.raw' in node.volumes or any(
        c.startswith('pvesm free st:117/vm-117-disk-0.raw') for c in node.cmds)
