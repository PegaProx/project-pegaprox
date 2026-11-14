"""The 5-minute metrics snapshot leaves an ESXi host registered for XHM alone (background/metrics.py).

The ESXi facade (core/esxi_cluster.ESXiClusterManager) is in cluster_managers next to the
Proxmox VE clusters and is connected, but has no `nodes`. The collector read mgr.nodes from
it, failed, and logged "Failed to collect metrics for <id>: 'ESXiClusterManager' object has
no attribute 'nodes'" every cycle. It skips that host now; a Proxmox VE cluster of the same
cycle is collected as before.
"""
import logging
import types

import pytest

import pegaprox.api.nodes as nodes_api
import pegaprox.background.metrics as metrics
from pegaprox.core import ha
from pegaprox.core.esxi_cluster import ESXiClusterManager


def _pve():
    storage = {'data': [{'storage': 'local', 'maxdisk': 100, 'disk': 50}]}
    session = types.SimpleNamespace(get=lambda url, timeout=None: types.SimpleNamespace(
        status_code=200, json=lambda: storage))
    return types.SimpleNamespace(
        is_connected=True, config=types.SimpleNamespace(name='Lab'), cluster_type='proxmox',
        nodes={'pve1': {'status': 'online', 'cpu': 0.5, 'maxcpu': 4, 'mem': 2, 'maxmem': 8}},
        get_vm_resources=lambda: [{'type': 'qemu', 'status': 'running', 'vmid': 100, 'maxmem': 2, 'maxcpu': 1}],
        host='10.0.0.1', api_port=8006, _create_session=lambda: session)


class _Vmw:
    host = name = 'esx1.lab'
    username, password, ssl_verify, connected, api_version = 'root', 'x', False, True, '8.0'

    def get_vms(self):
        raise AssertionError('the collector asked the ESXi host for its guests')


@pytest.fixture
def snapshot(monkeypatch, caplog):
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    monkeypatch.setattr(nodes_api, '_hw_consent_state', lambda: (False, {}))
    monkeypatch.setattr(nodes_api, '_redfish_consent_state', lambda: (False, {}))
    esx = ESXiClusterManager('esx', _Vmw())
    assert esx.is_connected
    monkeypatch.setattr(metrics, 'cluster_managers', {'esx': esx, 'pve': _pve()})
    caplog.set_level(logging.DEBUG)
    # called from the test, so caplog.records holds what the collector logged
    return metrics.collect_metrics_snapshot


def test_the_esxi_host_is_skipped_without_a_failure_line(snapshot, caplog):
    assert 'esx' not in snapshot()['clusters']
    failed = [r.getMessage() for r in caplog.records if 'Failed to collect metrics' in r.getMessage()]
    assert failed == []


def test_the_proxmox_cluster_of_the_same_cycle_is_collected(snapshot):
    cd = snapshot()['clusters']['pve']
    assert cd['nodes']['pve1']['cpu'] == 50.0
    assert cd['totals']['vms_running'] == 1 and cd['storage']['local']['pct'] == 50.0
