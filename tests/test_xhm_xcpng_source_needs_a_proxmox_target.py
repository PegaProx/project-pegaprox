"""An XCP-ng guest goes to Proxmox only, never to an ESXi host.

plan_xcpng_to_pve turned away an XCP-ng target and took anything else for Proxmox, and both
routes sent every XCP-ng source its way. With an ESXi host as the target the plan read the
node list the host does not have and the request died with a 500, and the start registered
an xcpng_to_pve task that could only fail. Now the plan answers with an error, both routes
answer 400, and no task is made.
"""
import types

import pytest

import pegaprox.api.xhm as xhm_api
import pegaprox.core.xhm as xhm_core
import pegaprox.globals as ppglobals
from pegaprox.core.esxi_cluster import ESXiClusterManager

XCP, ESXI, PVE = 'xcp1', 'esxi1', 'pve1'


def _xcp_source():
    cfg = {'name': 'web01', 'power_state': 'Halted', 'platform': {'device_model': 'qemu-upstream'},
           'boot_params': '', 'vcpus': 2, 'memory': 2 << 30,
           'disks': [{'id': '0', 'name': 'd0', 'uuid': 'u0', 'size': 10 << 30, 'bootable': True}],
           'networks': [{'id': '0', 'mac': 'aa:bb', 'network': 'Pool-wide', 'bridge': 'xenbr0', 'mtu': '1500'}]}
    return types.SimpleNamespace(cluster_type='xcpng', is_connected=True, host='10.0.0.8',
                                 get_vm_config=lambda node, vmid, *a: {'success': True, 'config': cfg},
                                 get_vm_resources=lambda **kw: [],
                                 _api=lambda: None, _resolve_vm=lambda vmid: 'OpaqueRef:x')


def _esxi_target():
    vmw = types.SimpleNamespace(host='10.0.0.9', username='root', password='x', ssl_verify=False,
                                enabled=True, name='esx9', connected=True, api_version='8.0')
    return ESXiClusterManager(ESXI, vmw)


@pytest.fixture
def managers(monkeypatch):
    monkeypatch.setitem(xhm_core.cluster_managers, XCP, _xcp_source())
    monkeypatch.setitem(xhm_core.cluster_managers, ESXI, _esxi_target())
    return xhm_core.cluster_managers


def test_the_plan_turns_an_esxi_target_away(managers):
    res = xhm_core.plan_xcpng_to_pve(XCP, '1', ESXI)
    assert res == {'error': 'Target must be a Proxmox cluster'}, res


def test_the_plan_still_takes_a_proxmox_target(managers, monkeypatch):
    managers[PVE] = types.SimpleNamespace(is_connected=True)     # a Proxmox manager has no cluster_type
    monkeypatch.setattr(xhm_core, '_get_pve_targets', lambda mgr: [{'cluster_id': PVE, 'nodes': ['n1']}])
    res = xhm_core.plan_xcpng_to_pve(XCP, '1', PVE)
    assert res.get('direction') == 'xcpng_to_pve' and res['targets'], res


@pytest.fixture
def routes(api, monkeypatch):
    api.set_manager(XCP, _xcp_source())
    api.set_manager(ESXI, _esxi_target())
    reg, ran = {}, []
    monkeypatch.setattr(ppglobals, '_xhm_migrations', reg)
    monkeypatch.setattr(xhm_api, '_xhm_migrations', reg)
    monkeypatch.setattr(xhm_api, '_run_xcpng_to_pve', lambda task: ran.append(task))
    monkeypatch.setattr(xhm_api.threading, 'Thread',
                        lambda target=None, args=(), **k: types.SimpleNamespace(start=lambda: ran.append(args)))
    return types.SimpleNamespace(registry=reg, ran=ran)


def test_the_plan_route_answers_400(api, seed, routes):
    admin = api.as_user(seed.user('root_admin', role='admin'))
    r = admin.get(f'/api/xhm/plan?source_cluster={XCP}&source_vmid=1&target_cluster={ESXI}')
    assert r.status_code == 400, r.get_data(as_text=True)
    assert 'Unsupported migration' in r.get_json()['error']


def test_the_start_route_answers_400_and_makes_no_task(api, seed, routes):
    admin = api.as_user(seed.user('root_admin', role='admin'))
    r = admin.post('/api/xhm/migrate', json={'source_cluster': XCP, 'source_vmid': '1', 'target_cluster': ESXI,
                                             'target_storage': 'datastore1', 'target_node': 'esx9'})
    assert r.status_code == 400, r.get_data(as_text=True)
    assert routes.registry == {} and routes.ran == []
