"""The XCP-ng to Proxmox plan names the NIC model the migration gives each NIC.

The plan looked up a fixed key in a model table and reported e1000 for every interface,
while _run_xcpng_to_pve builds each Proxmox NIC as virtio. A VIF record has no NIC model to
look up, so the plan now says virtio, which is what the target guest gets.
"""
import types

import pytest

import pegaprox.core.xhm as xhm_core

XCP, PVE = 'xcp1', 'pve1'
NETS = [{'id': '0', 'mac': 'aa:bb:cc:00:00:01', 'network': 'Pool-wide', 'bridge': 'xenbr0', 'mtu': '1500'},
        {'id': '1', 'mac': 'aa:bb:cc:00:00:02', 'network': 'Storage', 'bridge': 'xenbr1', 'mtu': '9000'}]


@pytest.fixture
def plan(monkeypatch):
    cfg = {'name': 'web01', 'power_state': 'Halted', 'platform': {'device_model': 'qemu-upstream'},
           'boot_params': '', 'vcpus': 2, 'memory': 2 << 30, 'disks': [], 'networks': NETS}
    src = types.SimpleNamespace(cluster_type='xcpng', is_connected=True,
                                get_vm_config=lambda node, vmid: {'success': True, 'config': cfg},
                                _api=lambda: None, _resolve_vm=lambda vmid: 'OpaqueRef:x')
    monkeypatch.setitem(xhm_core.cluster_managers, XCP, src)
    monkeypatch.setitem(xhm_core.cluster_managers, PVE, types.SimpleNamespace(is_connected=True))
    monkeypatch.setattr(xhm_core, '_get_pve_targets', lambda mgr: [])
    res = xhm_core.plan_xcpng_to_pve(XCP, '1', PVE)
    assert 'error' not in res, res
    return res


def test_every_nic_is_planned_as_virtio(plan):
    assert [n['target_model'] for n in plan['source']['networks']] == ['virtio', 'virtio']


def test_the_runner_makes_the_same_model():
    import inspect
    src = inspect.getsource(xhm_core._run_xcpng_to_pve)
    assert "f'virtio,bridge={bridge}'" in src and "'virtio,bridge=vmbr0'" in src
