"""A failed ESXi migration takes away the VM it created on Proxmox VE while nothing was
copied into it.

Seen on a lab node: the SSHFS mount failed after the VM was created, and the empty VM
stayed on the node; the next try took a new VMID. Every VM that holds data or may is
kept: one with a copied byte, one of a run that got to the delta sync or the switchover,
one that runs, and one this run did not create.
"""
import pytest

import test_v2p_tpm_and_folder_copy as farm
from pegaprox.core import v2p

VMID = farm.VMID


class _Pve(farm.Pve):
    """The farm's Proxmox API, which also deletes a VM"""

    def __init__(self, log, vols, delete_status=200, exitstatus='OK', state=200):
        super().__init__(log, vols)
        self.deleted = []
        self.delete_status = delete_status
        self.exitstatus = exitstatus
        self.state = state

    def _api_get(self, url, **kw):
        if '/tasks/UPID:pve1:9:9:qmdestroy' in url:
            return farm._Resp({'status': 'stopped', 'exitstatus': self.exitstatus})
        if url.endswith('/status/current') and self.state != 200:
            return farm._Resp({}, status=self.state)
        return super()._api_get(url, **kw)

    def _api_delete(self, url, **kw):
        self.deleted.append((url.split('/api2/json', 1)[-1], kw.get('params')))
        return farm._Resp(f'UPID:pve1:9:9:qmdestroy:{VMID}:root@pam:', status=self.delete_status)


class _NoSshfs(farm.Node):
    """a target node without sshfs: every mount attempt fails"""

    def __call__(self, mgr, node, cmd, timeout=600, **kw):
        if 'sshfs -o' in cmd:
            self.log.append(('node', node, cmd))
            return 127, '', 'bash: line 1: sshfs: command not found'
        return super().__call__(mgr, node, cmd, timeout, **kw)


def _run(monkeypatch, **pve_kw):
    r = farm.Run(monkeypatch, mode='offline', ndisks=1, tpm=False)
    r.pve = _Pve(r.log, r.vols, **pve_kw)
    monkeypatch.setattr(v2p, 'cluster_managers', {'pve-cl': r.pve})
    return r


def test_a_run_failing_at_the_mount_removes_the_vm_it_created(monkeypatch):
    r = _run(monkeypatch)
    node = _NoSshfs(r.log, r.vols)
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    r.go()
    assert r.task.status == 'failed'
    assert 'SSHFS mount failed' in (r.task.error or '')
    assert r.pve.deleted == [(f'/nodes/pve1/qemu/{VMID}', {'purge': 1, 'destroy-unreferenced-disks': 1})]
    assert any(f'Removed the empty VM {VMID} this run had created on pve1' in l for l in r.task.log_lines)


def test_a_run_that_completed_removes_nothing(monkeypatch):
    r = _run(monkeypatch).go()
    assert r.task.status == 'completed', r.task.error
    assert r.pve.deleted == []


class _Task:
    """the parts of a V2PMigrationTask the check reads"""

    def __init__(self, made=True, copied=0, phases=('planning', 'pre_sync', 'failed')):
        self.proxmox_vmid = VMID
        self._made_target = made
        self.disk_progress = {'disk0': {'copied': copied, 'total': 10, 'pct': 0}}
        self.phase_times = {p: {} for p in phases}
        self.target_cluster = 'pve-cl'
        self.target_node = 'pve1'
        self.logs = []

    def log(self, line):
        self.logs.append(line)


def _check(monkeypatch, task, running=False, **pve_kw):
    pve = _Pve([], {}, **pve_kw)
    pve.running = running
    monkeypatch.setattr(v2p, 'cluster_managers', {'pve-cl': pve})
    monkeypatch.setattr(v2p.time, 'sleep', lambda s: None)
    return v2p._drop_empty_target(task), pve


def test_the_empty_vm_is_deleted(monkeypatch):
    task = _Task()
    dropped, pve = _check(monkeypatch, task)
    assert dropped is True and len(pve.deleted) == 1
    assert task._made_target is False


@pytest.mark.parametrize('task,why', [
    (_Task(copied=4096), 'a copied byte'),
    (_Task(made=False), 'a VM this run did not create'),
    (_Task(phases=('planning', 'pre_sync', 'delta_sync', 'failed')), 'the delta sync ran'),
    (_Task(phases=('planning', 'pre_sync', 'awaiting_confirmation')), 'held for confirmation'),
    (_Task(phases=('planning', 'pre_sync', 'cutover', 'failed')), 'the switchover ran'),
])
def test_a_vm_that_holds_data_or_may_is_kept(monkeypatch, task, why):
    dropped, pve = _check(monkeypatch, task)
    assert dropped is False and pve.deleted == [], why


def test_a_running_vm_is_kept(monkeypatch):
    dropped, pve = _check(monkeypatch, _Task(), running=True)
    assert dropped is False and pve.deleted == []


def test_a_vm_whose_state_cannot_be_read_is_kept_and_the_log_says_so(monkeypatch):
    task = _Task()
    dropped, pve = _check(monkeypatch, task, state=500)
    assert dropped is False and pve.deleted == []
    assert any('could not be read' in l for l in task.logs)


@pytest.mark.parametrize('kw', [{'delete_status': 500}, {'exitstatus': 'unable to destroy'}])
def test_a_delete_that_fails_says_to_delete_it_by_hand(monkeypatch, kw):
    task = _Task()
    dropped, _pve = _check(monkeypatch, task, **kw)
    assert dropped is False
    assert task._made_target is True
    assert any('could not be removed' in l and 'delete it on the node' in l for l in task.logs)
