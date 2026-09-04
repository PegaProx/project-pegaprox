# #781 (Panxatony) — with an XCP-ng (or ESXi) cluster registered, three endpoints called
# Proxmox-only manager members without a type guard and 500'd. These lock in the guards:
#   1. get_vm_resources(max_age=…) exists on the xcpng/esxi managers too (accept + ignore).
#   2. the node-sensors endpoint degrades gracefully when the manager has no get_node_sensors.

import inspect
import types


def test_xcpng_and_esxi_get_vm_resources_accept_max_age():
    """clusters.py /resources and topology.py call mgr.get_vm_resources(max_age=6); only the
    Proxmox manager used to accept the kwarg, so an XCP-ng/ESXi cluster TypeError'd. Both now do."""
    from pegaprox.core.xcpng import XcpngManager
    from pegaprox.core.esxi_cluster import ESXiClusterManager
    for cls in (XcpngManager, ESXiClusterManager):
        params = inspect.signature(cls.get_vm_resources).parameters
        assert 'max_age' in params, f"{cls.__name__}.get_vm_resources must accept max_age (#781)"


def test_node_sensors_graceful_for_manager_without_sensors(api, seed):
    """lm-sensors is Proxmox-only; XCP-ng/ESXi managers don't implement get_node_sensors. The
    endpoint used to AttributeError → 500; it now returns a clear 'not available' 200 instead."""
    admin = seed.user('root', role='admin', tenant_id='default')
    # a manager WITHOUT get_node_sensors (SimpleNamespace, unlike a MagicMock which fakes any attr)
    fake = types.SimpleNamespace(cluster_id='cluster_1', is_connected=True)
    api.set_manager('cluster_1', fake)

    resp = api.as_user(admin).get('/api/clusters/cluster_1/nodes/node1/sensors')
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert 'not available' in (resp.get_json() or {}).get('error', '').lower()
