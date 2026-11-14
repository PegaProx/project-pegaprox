"""The migration dialog is told what the source VM has (#1253).

The plan route answers with get_vm_disks_for_export, which left out the hardware that get_vm
had just read. The migration itself asks get_vm again, so it went by the real values, while
the dialog always had nothing: "Auto (bios)" on an EFI guest, and the Secure Boot and TPM boxes
empty on a guest that has them and gets them.

Through the real route as an admin, with the manager's get_vm answering.
"""
import types

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.vmware import VMwareManager

from test_ha_api import _admin

HARDWARE = {'firmware': 'efi', 'secure_boot': True, 'has_tpm': True, 'scsi_controller': 'ParaVirtualSCSIController',
            'scsi_controller_pve': 'pvscsi', 'nic_type': 'VirtualVmxnet3', 'nic_type_pve': 'vmxnet3', 'disk_bus': 'scsi'}
VM = {'name': 'win01', 'power_state': 'POWERED_OFF', 'cpu': {'count': 4}, 'memory': {'size_MiB': 8192},
      'guest_OS': 'Microsoft Windows Server 2025 (64-bit)', 'disks': {}, 'nics': [], 'hardware': HARDWARE}


def _manager(answer):
    mgr = VMwareManager.__new__(VMwareManager)
    mgr.host = 'esx1.lab'
    mgr.ensure_connected = lambda: True
    mgr.get_vm = lambda vm_id: answer
    return mgr


@pytest.fixture
def plan(api, seed, monkeypatch):
    client = _admin(api, seed)

    def get(answer=None):
        monkeypatch.setitem(ppglobals.vmware_managers, 'esx', _manager(answer if answer is not None else {'data': VM}))
        r = client.get('/api/vmware/esx/vms/vm-1/migration-plan')
        assert r.status_code == 200, r.data
        return r.get_json()['source']
    return get


def test_the_plan_says_what_the_source_has(plan):
    source = plan()
    assert source['hardware'] == HARDWARE
    assert source['guest_OS'] == VM['guest_OS']


def test_the_export_data_keeps_its_own_fields(plan):
    source = plan()
    assert source['name'] == 'win01' and source['cpu_count'] == 4 and source['memory_mb'] == 8192
    assert source['guest_os'] == VM['guest_OS'] and source['disks'] == [] and source['nics'] == []


def test_a_source_without_hardware_data_gives_an_empty_answer_not_an_error(plan):
    assert plan({'data': {k: v for k, v in VM.items() if k != 'hardware'}})['hardware'] == {}
