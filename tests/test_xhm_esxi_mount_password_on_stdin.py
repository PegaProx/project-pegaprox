"""The ESXi password of the cross-hypervisor engine reaches the PVE node on stdin only.

_run_esxi_to_pve mounts the ESXi datastore with sshfs on the target node. The mount took
its password as a here-string, which makes it part of the command the node's shell runs,
readable in that shell's command line by every local account for as long as the mount
takes. The scp fallback next to it already fed the password over stdin. These tests run
the real engine with a recording node and look at every command it sent and at what went
to each command's stdin. MK
"""
import pytest

import pegaprox.core.xhm as xhm

ESXI_PW = "s3cret pw'with$odd`chars"


class _Chan:
    def __init__(self, owner):
        self._owner = owner

    def recv_exit_status(self):
        return 0

    def shutdown_write(self):
        self._owner.closed = True


class _Stdin:
    def __init__(self):
        self.data = ''
        self.closed = False
        self.channel = _Chan(self)

    def write(self, s):
        self.data += s

    def flush(self):
        pass


class _Stream:
    def __init__(self, payload=b''):
        self._payload = payload
        self.channel = _Chan(self)

    def read(self):
        return self._payload


class _RecordingNode:
    """Every command with the stdin it got. `listing` is what an ls of the mount shows:
    something keeps the sshfs path, nothing drives the scp fallback."""

    def __init__(self, listing):
        self.calls = []
        self._listing = listing

    def exec_command(self, cmd, timeout=None, **kw):
        stdin = _Stdin()
        self.calls.append((cmd, stdin))
        if cmd.lstrip().startswith('ls '):
            return stdin, _Stream(self._listing), _Stream()
        return stdin, _Stream(), _Stream()

    def close(self):
        pass


class _Config:
    ssh_user = 'root'
    pass_ = ESXI_PW
    ssh_key = ''
    ssh_port = 22


class _Mgr:
    is_connected = True
    host = '10.0.0.9'
    config = _Config()

    def get_vm_disks_for_export(self, vmid):
        return {'data': {'name': 'web01', 'guest_os': 'ubuntu64Guest', 'memory_mb': 2048,
                         'cpu_count': 2,
                         'disks': [{'vmdk_file': '[datastore1] web01/web01.vmdk',
                                    'capacity_bytes': 8 * 1024 ** 3, 'capacity_gb': 8,
                                    'label': 'Hard disk 1'}]}}


@pytest.fixture
def run(monkeypatch):
    def _run(listing):
        node = _RecordingNode(listing)
        monkeypatch.setitem(xhm.cluster_managers, 'esxi1', _Mgr())
        monkeypatch.setitem(xhm.cluster_managers, 'pve1', _Mgr())
        monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, node: '10.0.0.9')
        monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 900, raising=False)
        monkeypatch.setattr(xhm, '_connect_ssh', lambda *a, **kw: node)
        task = xhm.XHMigrationTask(
            mid='deadbeef', direction='esxi_to_pve', source_cluster='esxi1', source_node='esx-a',
            source_vmid=42, target_cluster='pve1', target_node='pve-a', target_storage='local')
        xhm._run_esxi_to_pve(task)
        return node.calls

    return _run


@pytest.mark.parametrize('listing', [b'vm.vmdk\n', b''], ids=['sshfs', 'scp_fallback'])
def test_no_command_the_node_runs_carries_the_esxi_password(run, listing):
    calls = run(listing)

    assert calls, 'the engine sent nothing to the node'
    assert [cmd for cmd, _ in calls if 'pw' in cmd and ESXI_PW.split()[0] in cmd] == []
    assert [cmd for cmd, _ in calls if '<<<' in cmd] == []


def test_the_mount_reads_the_password_on_its_stdin_and_sees_the_end(run):
    calls = run(b'vm.vmdk\n')

    mounts = [(cmd, stdin) for cmd, stdin in calls if cmd.startswith('sshfs ')]
    assert len(mounts) == 1, [c for c, _ in calls]
    cmd, stdin = mounts[0]
    assert 'password_stdin' in cmd
    # sshfs reads up to the line end, the shut write side ends a read that waits for more
    assert stdin.data == ESXI_PW + '\n'
    assert stdin.closed


def test_the_scp_fallback_still_gets_it_on_stdin_after_the_failed_mount(run):
    calls = run(b'')

    fed = [cmd for cmd, stdin in calls if stdin.data == ESXI_PW + '\n']
    assert any(c.startswith('sshfs ') for c in fed)
    assert any('sshpass -e' in c and 'scp ' in c for c in fed)
