"""A disk copied in part is not a disk copied.

_ssh_pipe_transfer took 90% of the bytes as done and never read the exit status it printed, so a copy
that lost its SSH connection at 95% went on to completed with the end of the disk missing. Where the
data file was not found it copied the descriptor, a few hundred bytes of text, as the disk.
"""
from types import SimpleNamespace

import pytest

import pegaprox.core.v2p as v2p

GB = 1024 ** 3
SIZE = 10 * GB


def _dd(copied):
    return f'{copied} bytes (10 GB, 10 GiB) copied, 60 s, 170 MB/s'


class _World:
    def __init__(self, monkeypatch, ssh, sshfs=None, stat=None):
        self.sent, self.freed, self.logs, self.allocated = [], [], [], 0
        self.ssh, self.sshfs = ssh, sshfs
        stat = stat if stat is not None else {'flat': SIZE}

        def on_esxi(host, user, password, cmd, timeout=None):
            if cmd.startswith('stat'):
                size = stat.get('flat' if '-flat.vmdk' in cmd else 'desc')
                return (0, str(size), '') if size is not None else (1, '', '')
            return 1, '', ''

        def on_node(mgr, node, cmd, timeout=None, **kw):
            self.sent.append(cmd)
            if cmd.startswith('pvesm free'):
                self.freed.append(cmd)
            if 'sshpass -e ssh' in cmd:
                return 0, self.ssh, ''
            if cmd.startswith('ls -la'):
                return (0, 'file', '') if self.sshfs else (1, 'gone', '')
            if cmd.startswith('dd if='):
                return 0, self.sshfs or '', ''
            return 0, '', ''

        def alloc(*a, **k):
            self.allocated += 1
            return 'store:vm-100-disk-0', '/dev/store/vm-100-disk-0'
        monkeypatch.setattr(v2p, '_ssh_exec', on_esxi)
        monkeypatch.setattr(v2p, '_pve_node_exec', on_node)
        monkeypatch.setattr(v2p, '_pvesm_alloc_disk', alloc)
        monkeypatch.setattr(v2p, '_monitor_disk_write', lambda *a, **k: None)
        monkeypatch.setattr(v2p, '_rbd_map_sink', lambda task: [])

    def copy(self):
        recorded = []
        task = SimpleNamespace(id='t1', target_node='pve1', target_storage='store', proxmox_vmid=100,
                               log=self.logs.append, config={}, record_disk_volume=lambda i, v: recorded.append(v))
        got = v2p._ssh_pipe_transfer(SimpleNamespace(), task, 'esxi', 'root', 'x', 'ds1', 'web01', 'web01.vmdk', 0)
        self.recorded = recorded
        return got


def test_every_byte_is_done(monkeypatch):
    world = _World(monkeypatch, f'PIPE=0/0\n{_dd(SIZE)}')
    assert world.copy() == ('store:vm-100-disk-0', '/dev/store/vm-100-disk-0')
    assert world.recorded == ['store:vm-100-disk-0'] and not world.freed


@pytest.mark.parametrize('copied', [int(SIZE * 0.95), int(SIZE * 0.9), SIZE - 1])
def test_a_copy_that_stopped_short_fails_and_frees_the_volume(monkeypatch, copied):
    world = _World(monkeypatch, f'PIPE=255/0\n{_dd(copied)}')
    assert world.copy() == (None, None)
    assert world.recorded == [] and len(world.freed) == 1, world.logs


def test_all_bytes_with_a_failed_source_are_not_done(monkeypatch):
    world = _World(monkeypatch, f'PIPE=1/0\n{_dd(SIZE)}')
    assert world.copy() == (None, None)
    assert any('PIPE=1/0' in line for line in world.logs), world.logs


def test_the_next_method_may_still_finish_it(monkeypatch):
    world = _World(monkeypatch, f'PIPE=255/0\n{_dd(int(SIZE * 0.95))}', sshfs=_dd(SIZE))
    assert world.copy()[0] == 'store:vm-100-disk-0'
    assert not world.freed


def test_a_descriptor_is_not_copied_as_the_disk(monkeypatch):
    world = _World(monkeypatch, f'PIPE=0/0\n{_dd(512)}', stat={'desc': 512})
    assert world.copy() == (None, None)
    assert world.allocated == 0, world.sent
    assert any('only a descriptor' in line for line in world.logs), world.logs


def test_a_disk_with_its_data_in_the_one_file_is_still_copied(monkeypatch):
    world = _World(monkeypatch, f'PIPE=0/0\n{_dd(SIZE)}', stat={'desc': SIZE})
    assert world.copy()[0] == 'store:vm-100-disk-0'
