"""A disk transfer to Proxmox that fails says when its partial volume stays behind.

The XCP-ng to Proxmox transfer freed the volume it had allocated on each of its three
ways out (cancelled, every attempt failed, an unexpected error), but swallowed whatever
went wrong there and never read pvesm's exit code. ESXi to Proxmox did not free it at all
when qemu-img convert failed. Either way an orphan vm-<id>-disk-N stayed on the target
storage and the failed task said nothing of it. A refused lease, or a connection that is
gone, leaves it behind as well. Each of them now frees it through _free_partial, and the
failed phase names the volume and the command that removes it when that did not work.

An ESXi disk that fails with an error also frees the volume it allocated (never one an
earlier disk imported), unmounts the datastore it mounted on the node (with the ESXi
login), removes the scp copy, and closes its client.

MK Nov 2026
"""
import re

import pytest

import pegaprox.core.xhm as xhm
from pegaprox.core import federation

VOL = 'local-lvm:vm-900-disk-0'


class _Chan:
    def __init__(self, rc):
        self._rc = rc

    def recv_exit_status(self):
        return self._rc

    def shutdown_write(self):
        pass


class _Stream:
    def __init__(self, payload=b'', rc=0):
        self._payload = payload
        self.channel = _Chan(rc)

    def read(self, *a):
        return self._payload

    def write(self, s):
        pass

    def flush(self):
        pass


class _Node:
    """A PVE node shell. `answers`: (command prefix, exit code, stderr) for the commands
    that do not exit 0; `raises`: a command prefix that raises."""

    def __init__(self, listing=b'web01-flat.vmdk\n', answers=(), raises=None):
        self.calls, self.closed = [], 0
        self._listing, self._answers, self._raises = listing, answers, raises

    def exec_command(self, cmd, timeout=None, **kw):
        self.calls.append(cmd)
        if self._raises and cmd.startswith(self._raises):
            raise RuntimeError('the channel went away')
        for prefix, rc, err in self._answers:
            if cmd.startswith(prefix):
                return _Stream(), _Stream(rc=rc), _Stream(err)
        if cmd.lstrip().startswith('ls '):
            return _Stream(), _Stream(self._listing), _Stream()
        if cmd.startswith('pvesm alloc'):
            return _Stream(), _Stream(f"successfully created '{VOL}'\n".encode()), _Stream()
        if cmd.startswith('pvesm path'):
            return _Stream(), _Stream(b'/dev/pve/vm-900-disk-0\n'), _Stream()
        return _Stream(), _Stream(), _Stream()

    def close(self):
        self.closed += 1


class _Mgr:
    is_connected = True
    host = '10.0.0.9'
    api_port = 8006

    class config:
        ssh_user, pass_, ssh_key, ssh_port = 'root', 'pw', '', 22

    def get_vm_disks_for_export(self, vmid):
        return {'data': {'name': 'web01', 'guest_os': 'ubuntu64Guest', 'memory_mb': 2048,
                         'cpu_count': 2,
                         'disks': [{'vmdk_file': '[datastore1] web01/web01.vmdk',
                                    'capacity_bytes': 1 << 30, 'capacity_gb': 1,
                                    'label': 'Hard disk 1'}]}}


class _TwoDisks(_Mgr):
    def get_vm_disks_for_export(self, vmid):
        out = super().get_vm_disks_for_export(vmid)
        out['data']['disks'].append({'vmdk_file': '[datastore1] web01/web01_1.vmdk',
                                     'capacity_bytes': 1 << 30, 'capacity_gb': 1,
                                     'label': 'Hard disk 2'})
        return out


@pytest.fixture
def esxi_to_pve(monkeypatch):
    def run(node, source=_Mgr):
        monkeypatch.setitem(xhm.cluster_managers, 'esxi1', source())
        monkeypatch.setitem(xhm.cluster_managers, 'pve1', _Mgr())
        monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, n: '10.0.0.9')
        monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 900, raising=False)
        monkeypatch.setattr(xhm, '_connect_ssh', lambda *a, **kw: node)
        task = xhm.XHMigrationTask(
            mid='deadbeef', direction='esxi_to_pve', source_cluster='esxi1', source_node='esx-a',
            source_vmid=42, target_cluster='pve1', target_node='pve-a', target_storage='local-lvm')
        xhm._run_esxi_to_pve(task)
        return task
    return run


# --- the helper -------------------------------------------------------------------------------

def test_a_volume_that_went_adds_nothing():
    node = _Node()
    assert xhm._free_partial(node, VOL) == ''
    assert node.calls == [f'pvesm free {VOL}']


@pytest.mark.parametrize('node,why', [
    (_Node(answers=(('pvesm free', 2, b"volume is busy\n"),)), 'volume is busy'),
    (_Node(answers=(('pvesm free', 1, b''),)), 'exit 1'),
    (_Node(raises='pvesm free'), 'the channel went away'),
], ids=['pvesm-error', 'exit-code', 'raised'])
def test_a_volume_that_stayed_says_why(node, why):
    assert xhm._free_partial(node, VOL) == why


def test_a_refused_lease_is_a_reason_too():
    class _Fenced:
        def exec_command(self, cmd, **kw):
            raise federation.LeaseRefused('c1', 'no live lease')
    assert xhm._free_partial(_Fenced(), VOL)


def test_every_free_of_a_partial_volume_goes_through_the_helper():
    """The XCP-ng transfer has three ways out that free the volume; none of them frees it
    on its own any more, so none of them swallows why it stayed."""
    import inspect
    rest = inspect.getsource(xhm).replace(inspect.getsource(xhm._free_partial), '')
    assert not re.findall(r'exec_command\(f?"pvesm free', rest)
    assert inspect.getsource(xhm._run_xcpng_to_pve).count('_free_partial(') == 3


# --- ESXi to Proxmox, driven -----------------------------------------------------------------

@pytest.mark.parametrize('listing', [b'web01-flat.vmdk\n', b''], ids=['sshfs', 'scp-fallback'])
def test_a_failed_convert_frees_the_volume(esxi_to_pve, listing):
    node = _Node(listing, answers=(('qemu-img convert', 1, b'read error'),))
    task = esxi_to_pve(node)
    assert f'pvesm free {VOL}' in node.calls
    assert task.phase == 'failed' and 'qemu-img convert failed' in task.error
    assert 'stays on' not in task.error


@pytest.mark.parametrize('listing', [b'web01-flat.vmdk\n', b''], ids=['sshfs', 'scp-fallback'])
def test_a_volume_the_failed_convert_left_is_named(esxi_to_pve, listing):
    node = _Node(listing, answers=(('qemu-img convert', 1, b'read error'),
                                   ('pvesm free', 2, b'volume is busy')))
    task = esxi_to_pve(node)
    assert task.phase == 'failed'
    assert f"the partial volume {VOL} stays on local-lvm: remove it with 'pvesm free {VOL}'" \
        in task.error, task.error


def test_an_error_after_the_mount_unmounts_it_and_closes_the_client(esxi_to_pve):
    node = _Node(raises='pvesm alloc')
    task = esxi_to_pve(node)
    assert task.phase == 'failed' and 'Transfer error' in task.error
    undo = [c for c in node.calls if c.startswith('fusermount -u')]
    assert len(undo) == 1 and '/mnt-0' in undo[0], node.calls
    assert node.closed == 1
    assert 'stays mounted' not in task.error


def test_an_error_after_the_scp_copy_removes_it(esxi_to_pve):
    node = _Node(b'', raises='pvesm alloc')
    task = esxi_to_pve(node)
    assert task.phase == 'failed'
    assert [c for c in node.calls if c.startswith('rm -f') and 'disk0.vmdk' in c], node.calls
    assert node.closed == 1


@pytest.mark.parametrize('listing', [b'web01-flat.vmdk\n', b''], ids=['sshfs', 'scp-fallback'])
def test_a_convert_that_raises_frees_the_volume(esxi_to_pve, listing):
    """The convert raises (a refused lease, a channel that went away): the volume it was
    writing goes, and when that is refused as well the failed phase names it."""
    node = _Node(listing, raises='qemu-img convert')
    task = esxi_to_pve(node)
    assert f'pvesm free {VOL}' in node.calls
    assert task.phase == 'failed' and 'Transfer error' in task.error and 'stays on' not in task.error
    node = _Node(listing, raises='qemu-img convert', answers=(('pvesm free', 2, b'volume is busy'),))
    task = esxi_to_pve(node)
    assert f"the partial volume {VOL} stays on local-lvm" in task.error, task.error


def test_a_later_disk_that_fails_leaves_the_volume_imported_before(esxi_to_pve):
    class _SecondAllocFails(_Node):
        def exec_command(self, cmd, timeout=None, **kw):
            if cmd.startswith('pvesm alloc') and any(c.startswith('pvesm alloc') for c in self.calls):
                self.calls.append(cmd)
                raise RuntimeError('the channel went away')
            return super().exec_command(cmd, timeout, **kw)
    node = _SecondAllocFails()
    task = esxi_to_pve(node, source=_TwoDisks)
    assert task.phase == 'failed' and 'Transfer error' in task.error
    assert len([c for c in node.calls if c.startswith('pvesm alloc')]) == 2
    assert not [c for c in node.calls if c.startswith('pvesm free')], node.calls
    assert 'stays on' not in task.error
