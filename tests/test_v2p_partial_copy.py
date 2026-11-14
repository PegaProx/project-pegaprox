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


def _answer(spec):
    # a plain string is what the command printed, a tuple is the whole (rc, out, err) of the node call
    return spec if isinstance(spec, tuple) else (0, spec, '')


class _World:
    """https: what the full HTTPS download prints. Set, the source runs and the 1 MB probe gets data,
    so HTTPS goes first; left out, the source is off and the copy starts with the SSH pipe."""

    def __init__(self, monkeypatch, ssh, sshfs=None, stat=None, https=None):
        self.sent, self.freed, self.logs, self.allocated = [], [], [], 0
        self.ssh, self.sshfs, self.https = ssh, sshfs, https
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
            if 'sshpass -f ' in cmd:
                return _answer(self.ssh)
            if '-r 0-1048575' in cmd:
                return 0, ('HTTP=206 DL=1048576 FSIZE=1048576' if self.https is not None else ''), ''
            if '--connect-timeout' in cmd:
                return _answer(self.https or '')
            if cmd.startswith('ls -la'):
                return (0, 'file', '') if self.sshfs else (1, 'gone', '')
            if cmd.startswith('dd if='):
                return _answer(self.sshfs or '')
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
        task = SimpleNamespace(id='t1', target_node='pve1', target_storage='store', proxmox_vmid=100, vm_id='vm-1',
                               log=self.logs.append, config={}, record_disk_volume=lambda i, v: recorded.append(v),
                               disk_target=lambda i: 'store')
        if self.https is not None:
            task._vmware_mgr_ref = SimpleNamespace(get_vm=lambda vm: {'data': {'power_state': 'POWERED_ON'}})
        got = v2p._ssh_pipe_transfer(SimpleNamespace(), task, 'esxi', 'root', 'x', 'ds1', 'web01', 'web01.vmdk', 0)
        self.recorded = recorded
        return got

    def ran(self, part):
        return any(part in cmd for cmd in self.sent)


def test_every_byte_is_done(monkeypatch):
    world = _World(monkeypatch, f'PIPE=0/0\n{_dd(SIZE)}')
    assert world.copy() == ('store:vm-100-disk-0', '/dev/store/vm-100-disk-0')
    assert world.recorded == ['store:vm-100-disk-0'] and not world.freed


@pytest.mark.parametrize('status', ['PIPE=255/0', 'PIPE=0/0'])
@pytest.mark.parametrize('copied', [int(SIZE * 0.95), int(SIZE * 0.9), SIZE - 1])
def test_a_copy_that_stopped_short_fails_and_frees_the_volume(monkeypatch, copied, status):
    """The byte count is a check of its own: a clean status with bytes missing is no finished copy either."""
    world = _World(monkeypatch, f'{status}\n{_dd(copied)}')
    assert world.copy() == (None, None)
    assert world.recorded == [] and len(world.freed) == 1, world.logs


def test_all_bytes_with_a_failed_source_are_not_done(monkeypatch):
    world = _World(monkeypatch, f'PIPE=1/0\n{_dd(SIZE)}')
    assert world.copy() == (None, None)
    assert any('PIPE=1/0' in line for line in world.logs), world.logs


def test_the_next_method_may_still_finish_it(monkeypatch):
    world = _World(monkeypatch, f'PIPE=255/0\n{_dd(int(SIZE * 0.95))}', sshfs=f'RC=0/0\n{_dd(SIZE)}')
    assert world.copy()[0] == 'store:vm-100-disk-0'
    assert not world.freed


def test_the_last_method_reads_its_exit_status_too(monkeypatch):
    world = _World(monkeypatch, f'PIPE=255/0\n{_dd(int(SIZE * 0.95))}', sshfs=f'RC=1/0\n{_dd(SIZE)}')
    assert world.copy() == (None, None)
    assert any('echo RC=$?/0' in cmd for cmd in world.sent), 'the command prints no status'


def test_a_short_copy_by_the_last_method_fails(monkeypatch):
    world = _World(monkeypatch, f'PIPE=255/0\n{_dd(0)}', sshfs=f'RC=0/0\n{_dd(int(SIZE * 0.95))}')
    assert world.copy() == (None, None)
    assert world.recorded == [] and len(world.freed) == 1
    assert any('SSHFS incomplete' in line for line in world.logs), world.logs


def test_https_with_every_byte_and_a_clean_status_is_done(monkeypatch):
    world = _World(monkeypatch, 'not asked', https=f'RC=0/0\n{_dd(SIZE)}')
    assert world.copy()[0] == 'store:vm-100-disk-0'
    assert world.ran('--connect-timeout') and not world.ran('sshpass -f ')


@pytest.mark.parametrize('https', [f'RC=0/0\n{_dd(int(SIZE * 0.95))}', f'RC=18/0\n{_dd(SIZE)}'],
                         ids=['short', 'curl-18'])
def test_a_short_or_failed_https_download_is_not_done(monkeypatch, https):
    """curl 18 is a transfer that ended early, whatever dd counted."""
    world = _World(monkeypatch, f'PIPE=255/0\n{_dd(0)}', https=https)
    assert world.copy() == (None, None)
    assert world.ran('--connect-timeout'), 'HTTPS was never tried'
    assert any('HTTPS incomplete' in line for line in world.logs), world.logs
    assert world.recorded == [] and len(world.freed) == 1


@pytest.mark.parametrize('ssh', [(1, '', "cannot resolve reachable IP for node 'pve1'"), 'PIPE=0/0'],
                         ids=['node-call-failed', 'no-byte-count'])
def test_the_ssh_pipe_does_not_inherit_the_https_byte_count(monkeypatch, ssh):
    world = _World(monkeypatch, ssh, https=f'RC=18/0\n{_dd(SIZE)}')
    assert world.copy() == (None, None)
    assert world.ran('sshpass -f ')
    assert not any('SSH OK' in line for line in world.logs), world.logs
    assert world.recorded == [] and len(world.freed) == 1


@pytest.mark.parametrize('how', ['HTTPS', 'SSH', 'SSHFS'])
def test_output_without_an_exit_status_is_not_done(monkeypatch, how):
    """Every copy command prints its status, so all bytes without one is output that was cut off."""
    failed_ssh = f'PIPE=255/0\n{_dd(0)}'
    world = _World(monkeypatch, _dd(SIZE) if how == 'SSH' else failed_ssh,
                   sshfs=_dd(SIZE) if how == 'SSHFS' else None,
                   https=_dd(SIZE) if how == 'HTTPS' else None)
    assert world.copy() == (None, None)
    assert any(f'{how} incomplete' in line and 'no exit status' in line for line in world.logs), world.logs
    assert world.recorded == []


def test_a_descriptor_is_not_copied_as_the_disk(monkeypatch):
    world = _World(monkeypatch, f'PIPE=0/0\n{_dd(512)}', stat={'desc': 512})
    assert world.copy() == (None, None)
    assert world.allocated == 0, world.sent
    assert any('only a descriptor' in line for line in world.logs), world.logs


def test_a_disk_with_its_data_in_the_one_file_is_still_copied(monkeypatch):
    world = _World(monkeypatch, f'PIPE=0/0\n{_dd(SIZE)}', stat={'desc': SIZE})
    assert world.copy()[0] == 'store:vm-100-disk-0'
