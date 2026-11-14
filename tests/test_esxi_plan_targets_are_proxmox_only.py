"""The migration plan of an ESXi guest lists Proxmox VE clusters as targets, nothing else.

An ESXi host registered for cross-hypervisor migration is in cluster_managers as an
ESXiClusterManager, connected, with no `nodes`. The target loop of the plan read
cmgr.nodes from every connected manager, so with such a host registered the plan was a
500 (AttributeError) for every guest, and the migration dialog could not open. An XCP-ng
pool is no target of this migration either.

Through the real route as an admin; the ESXi host is the real facade class.
"""
import types

import pytest

import pegaprox.globals as ppglobals
from pegaprox.core.esxi_cluster import ESXiClusterManager
from pegaprox.core.vmware import VMwareManager

from test_ha_api import _admin

VM = {'name': 'web01', 'power_state': 'POWERED_OFF', 'cpu': {'count': 2}, 'memory': {'size_MiB': 2048},
      'guest_OS': 'Debian 12 (64-bit)', 'disks': {}, 'nics': []}


def _vmware(host='esx1.lab'):
    mgr = VMwareManager.__new__(VMwareManager)
    mgr.host = host
    mgr.name = host
    mgr.username = 'root'
    mgr.password = 'x'
    mgr.ssl_verify = False
    mgr.connected = True
    mgr.api_version = '8.0'
    mgr.ensure_connected = lambda: True
    mgr.get_vm = lambda vm_id: {'data': VM}
    return mgr


def _pve(api, cid):
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    m.config.name = 'Lab'
    m.host, m.api_port = 'pve.lab', 8006
    m.nodes = {'pve1': {'status': 'online'}}
    m._api_get.return_value = types.SimpleNamespace(
        status_code=200, json=lambda: {'data': [{'storage': 'local-lvm', 'active': 1, 'content': 'images,rootdir'}]})
    return m


@pytest.fixture
def plan(api, seed):
    client = _admin(api, seed)
    ppglobals.vmware_managers['esx'] = _vmware()

    def get():
        r = client.get('/api/vmware/esx/vms/vm-1/migration-plan')
        assert r.status_code == 200, r.get_data(as_text=True)
        return r.get_json()['targets']
    return get


def test_a_registered_esxi_host_is_left_out_of_the_targets(api, plan):
    api.set_manager('pve', _pve(api, 'pve'))
    api.set_manager('esx', ESXiClusterManager('esx', ppglobals.vmware_managers['esx']))
    assert ppglobals.cluster_managers['esx'].is_connected
    targets = plan()
    assert [t['cluster_id'] for t in targets] == ['pve']
    assert targets[0]['nodes'] == ['pve1'] and targets[0]['storages'] == {'pve1': ['local-lvm']}


def test_an_xcpng_pool_is_no_target_either(api, plan):
    api.set_manager('pve', _pve(api, 'pve'))
    xcp = _pve(api, 'xcp')          # connected, with hosts and storage that read fine
    xcp.cluster_type = 'xcpng'
    xcp.config.name = 'Pool'
    api.set_manager('xcp', xcp)
    assert [t['cluster_id'] for t in plan()] == ['pve']
    xcp._api_get.assert_not_called()


def test_with_only_the_esxi_host_the_plan_answers_with_no_targets(api, plan):
    api.set_manager('esx', ESXiClusterManager('esx', ppglobals.vmware_managers['esx']))
    assert plan() == []
