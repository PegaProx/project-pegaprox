"""GET /api/clusters/<id>/networks of an XCP-ng pool answers in the shape of a Proxmox VE
cluster: {'networks': [...]}. XcpngManager.get_cluster_networks returned a bare list, and
the Networks tab, the corporate sidebar and the topology read data.networks, so every
XCP-ng pool showed no networks at all.

The rows carry name, bridge, uuid, MTU and the VIF/PIF counts of the network record, with
empty node and guest lists (the record names neither). A confined caller gets the pool's
networks as before: there is no guest in them to cut.
"""
import types

import pytest

from pegaprox.core.xcpng import XcpngManager
from test_node_and_storage_reads_confine_1218 import (  # noqa: F401  (fixtures)
    mgr, who, BASE, CONFINED, WHOLE)

POOL_NET = 'Pool-wide network associated with eth0'
RECORDS = {
    'OpaqueRef:1': {'name_label': POOL_NET, 'bridge': 'xenbr0', 'uuid': 'u1',
                    'VIFs': ['OpaqueRef:v1', 'OpaqueRef:v2'], 'PIFs': ['OpaqueRef:p1'], 'MTU': '1500'},
    'OpaqueRef:2': {'name_label': 'storage-9000', 'bridge': 'xapi1', 'uuid': 'u2',
                    'VIFs': [], 'PIFs': ['OpaqueRef:p2', 'OpaqueRef:p3'], 'MTU': '9000'},
    # a name starting with xapi is left out, as before
    'OpaqueRef:3': {'name_label': 'xapi_internal', 'bridge': 'xapi0', 'uuid': 'u3',
                    'VIFs': [], 'PIFs': [], 'MTU': '1500'},
}


def _pool(records=RECORDS, fail=None):
    errors = []

    def get_all():
        if fail:
            raise fail
        return list(records)

    net = types.SimpleNamespace(get_all=get_all, get_record=lambda ref: records[ref])
    shim = types.SimpleNamespace(_api=lambda: types.SimpleNamespace(network=net),
                                 logger=types.SimpleNamespace(error=errors.append))
    return shim, errors


def test_the_pool_networks_come_in_the_proxmox_shape():
    shim, errors = _pool()
    got = XcpngManager.get_cluster_networks(shim)
    assert isinstance(got, dict) and got['storage_assignments'] == [], got
    assert [n['name'] for n in got['networks']] == [POOL_NET, 'storage-9000']
    first = got['networks'][0]
    assert first == {'name': POOL_NET, 'bridge': 'xenbr0', 'uuid': 'u1', 'active': 1, 'nodes': [], 'vms': [],
                     'vif_count': 2, 'pif_count': 1, 'mtu': 1500}
    assert got['networks'][1]['mtu'] == 9000 and got['networks'][1]['pif_count'] == 2
    assert not errors


def test_no_pool_connection_or_a_failed_read_is_an_empty_list_in_the_same_shape():
    shim = types.SimpleNamespace(_api=lambda: None, logger=types.SimpleNamespace(error=lambda *a: None))
    assert XcpngManager.get_cluster_networks(shim) == {'networks': [], 'storage_assignments': []}
    shim, errors = _pool(fail=RuntimeError('SESSION_INVALID'))
    assert XcpngManager.get_cluster_networks(shim) == {'networks': [], 'storage_assignments': []}
    assert errors and 'SESSION_INVALID' in errors[0]


def test_the_route_hands_every_caller_the_pool_networks(who, mgr):
    shim, _ = _pool()
    mgr.cluster_type = 'xcpng'
    mgr.get_cluster_networks.side_effect = lambda: XcpngManager.get_cluster_networks(shim)
    for kind in WHOLE + CONFINED:
        r = who[kind].get(f'{BASE}/networks')
        assert r.status_code == 200, (kind, r.get_data(as_text=True))
        body = r.get_json()
        assert isinstance(body, dict), (kind, body)
        assert [n['name'] for n in body['networks']] == [POOL_NET, 'storage-9000'], kind
