"""Saving the settings of an ESXi guest: REST says it cannot, the SOAP detail has hot-add.

The settings tab of an ESXi guest saves CPU, memory, notes and the two hot-add switches
through update_vm_config. Over SOAP that is one ReconfigVM_Task. Over REST it sent a POST
with CPU and memory to the VM itself and a PATCH with the notes after it. The REST API has
neither (CPU and memory are PATCHes on .../hardware/cpu and .../hardware/memory, the notes
are not in its model), so a CPU change failed with whatever the server said about the
unknown call, and a notes-only edit with "No configuration changes specified". REST gives
the answer update_vm_network gives now, before anything leaves the process.

The two switches of the tab showed "off" for every guest, whatever it had. The REST detail
carries cpu.hot_add_enabled and memory.hot_add_enabled; the SOAP detail carries them now as
well, so the tab can show what the guest has. MK
"""
from unittest.mock import MagicMock

import pytest

from pegaprox.core import ha_transport
from pegaprox.core.vmware import VMwareManager

NEEDS_SOAP = {'error': 'Configuration change requires SOAP/pyvmomi connection'}


@pytest.fixture
def rest(monkeypatch):
    mgr = VMwareManager('v1', {'name': 'lab', 'host': '10.0.0.9', 'username': 'root', 'password': 'pw'})
    mgr._connection_type = 'rest'
    mgr.connected, mgr.session_id = True, 'sid'
    calls = []

    class _Ok:
        status_code = 200
        text = '{}'

        def json(self):
            return {}
    monkeypatch.setattr(ha_transport, 'http', lambda method, url, **kw: (calls.append((method, url)), _Ok())[1])
    return mgr, calls


@pytest.mark.parametrize('body', [
    {'cpu_count': 4},
    {'memory_mb': 4096},
    {'notes': 'owner: ops'},
    {'cpu_hot_add': True},
    {'cpu_count': 2, 'memory_mb': 2048, 'notes': '', 'memory_hot_add': False},
    {},
], ids=['cpu', 'memory', 'notes', 'hot-add', 'all', 'nothing'])
def test_over_rest_a_config_change_is_refused_without_a_call(rest, body):
    mgr, calls = rest
    assert mgr.update_vm_config('vm-42', body) == NEEDS_SOAP
    assert calls == [], calls


def _soap_guest(cpu_hot, mem_hot):
    from pyVmomi import vim
    vm = MagicMock()
    vm._moId = 'vm-42'
    vm.config = vim.vm.ConfigInfo(
        name='app01', guestFullName='Ubuntu Linux (64-bit)', guestId='ubuntu64Guest',
        version='vmx-19', firmware='bios', annotation='owner: ops',
        cpuHotAddEnabled=cpu_hot, memoryHotAddEnabled=mem_hot,
        hardware=vim.vm.VirtualHardware(numCPU=4, numCoresPerSocket=2, memoryMB=4096, device=[]))
    vm.runtime.powerState = 'poweredOff'
    vm.guest = None
    return vm


@pytest.mark.parametrize('cpu_hot,mem_hot', [(True, False), (False, True), (None, None)])
def test_the_soap_detail_says_whether_hot_add_is_on(cpu_hot, mem_hot):
    mgr = VMwareManager('v1', {'name': 'lab', 'host': '10.0.0.9', 'server_type': 'esxi'})
    mgr._connection_type = 'soap'
    vm = _soap_guest(cpu_hot, mem_hot)
    mgr._soap_get_managed_object = lambda kind, vm_id: vm
    got = mgr.get_vm('vm-42')
    assert 'error' not in got, got
    d = got['data']
    # the shape of the REST detail, which the settings tab reads either way
    assert d['cpu']['hot_add_enabled'] is bool(cpu_hot), d['cpu']
    assert d['memory']['hot_add_enabled'] is bool(mem_hot), d['memory']
    assert (d['cpu']['count'], d['memory']['size_MiB'], d['notes']) == (4, 4096, 'owner: ops')
