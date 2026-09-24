"""ESXi -> Proxmox migration allocates a VMID instead of dying on an undefined name.

`_run_esxi_to_pve` has called `_next_pve_vmid(tgt_mgr)` since 0.9.2 (March 2026). The
function was never written and never imported, and `task.target_vmid` is None for every
task the API creates, so the `or` always evaluated it. The whole outer body sits in a
`try`, so the NameError surfaced to the operator as "Migration error: name
'_next_pve_vmid' is not defined" after the planning phase - the direction has never once
completed. The XCP-ng -> PVE leg had the same lookup inline behind a bare `except` that
silently fell back to VMID 100; it uses the shared helper now. MK
"""
import pytest

import pegaprox.core.xhm as xhm


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {'data': 137}

    def json(self):
        return self._payload


class _Mgr:
    host = '10.0.0.9'
    api_port = 8006

    def __init__(self, resp=None, boom=False):
        self._resp = resp or _Resp()
        self._boom = boom
        self.asked = []

    def _api_get(self, url, **kw):
        self.asked.append(url)
        if self._boom:
            raise OSError('connection refused')
        return self._resp


def test_the_helper_exists_and_is_reachable_from_the_migration_legs():
    assert callable(getattr(xhm, '_next_pve_vmid', None))


def test_it_asks_the_target_cluster_for_the_next_free_id():
    mgr = _Mgr()

    assert xhm._next_pve_vmid(mgr) == 137
    assert mgr.asked == ['https://10.0.0.9:8006/api2/json/cluster/nextid']


def test_an_unreachable_cluster_yields_no_id_rather_than_a_guess():
    """The old inline version fell back to VMID 100 on any error, which is either taken
    or lands the new VM on top of somebody's numbering scheme."""
    assert xhm._next_pve_vmid(_Mgr(boom=True)) is None


def test_a_non_200_answer_yields_no_id():
    assert xhm._next_pve_vmid(_Mgr(resp=_Resp(status=500))) is None


def test_the_esxi_leg_no_longer_dies_before_it_starts(monkeypatch):
    """Drives the real leg far enough to see it get past allocation."""
    reached = {}

    class _SrcMgr:
        is_connected = True
        host = 'esx.local'

        class config:
            ssh_user = 'root'
            pass_ = 'pw'
            ssh_key = ''
            ssh_port = 22

        def get_vm_disks_for_export(self, vmid):
            return {'data': {'name': 'web01', 'guest_os': 'ubuntu64Guest', 'memory_mb': 1024,
                             'cpu_count': 1,
                             'disks': [{'vmdk_file': '[ds1] web01/web01.vmdk',
                                        'capacity_bytes': 1, 'capacity_gb': 8, 'label': 'd1'}]}}

    class _TgtMgr(_SrcMgr):
        api_port = 8006
        host = '10.0.0.9'

    def _stop(*a, **kw):
        reached['vmid'] = True
        raise RuntimeError('stop here - allocation is what this test is about')

    monkeypatch.setitem(xhm.cluster_managers, 'esxi1', _SrcMgr())
    monkeypatch.setitem(xhm.cluster_managers, 'pve1', _TgtMgr())
    monkeypatch.setattr(xhm, '_resolve_pve_node_ip', lambda mgr, node: '10.0.0.9')
    monkeypatch.setattr(xhm, '_next_pve_vmid', lambda mgr: 137)
    monkeypatch.setattr(xhm, '_connect_ssh', _stop)

    task = xhm.XHMigrationTask(
        mid='cafe1234', direction='esxi_to_pve', source_cluster='esxi1', source_node='esx-a',
        source_vmid=42, target_cluster='pve1', target_node='pve-a', target_storage='local')
    xhm._run_esxi_to_pve(task)

    assert task.target_vmid == 137
    assert reached.get('vmid'), f'never got to the transfer: {task.error}'
    assert 'not defined' not in (task.error or '')
