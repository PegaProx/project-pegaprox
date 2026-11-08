# #946 - GET /api/clusters/<id>/health found the fullest storage by calling
# /nodes/<node>/storage on every online node, on every poll. That endpoint builds live status
# for each storage one after another (a TLS login per PBS datastore), about 2.5 s per node on
# the reported cluster, and the health pill polls it from every open tab.
# Now: one /cluster/resources?type=storage call (pvestatd's cache, all nodes), shared per
# cluster for a short TTL. XCP-ng has no such view and keeps the per-node listing.

import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.api.clusters as clusters_mod
import pegaprox.core.cache as cache_mod
from pegaprox.core.cache import StorageDataCache

CID = 'cluster_1'
ROUTE = f'/api/clusters/{CID}/health'
GiB = 1024 ** 3

_NODES = {
    'pve1': {'status': 'online'},
    'pve2': {'status': 'online'},
    'pve3': {'status': 'offline', 'offline': True},
}


def _stor(node, storage, used_gib, total_gib, status='available', plugintype='lvm'):
    return {'id': f'storage/{node}/{storage}', 'type': 'storage', 'node': node,
            'storage': storage, 'status': status, 'plugintype': plugintype,
            'disk': used_gib * GiB, 'maxdisk': total_gib * GiB, 'shared': 0}


# pve3 is down: pvestatd keeps its last numbers but marks them 'unknown'. 99% there must
# not become the worst storage of the cluster.
_RESOURCES = [
    _stor('pve1', 'local-lvm', 50, 100),
    _stor('pve1', 'backup-pbs', 92, 100, plugintype='pbs'),
    _stor('pve2', 'local-lvm', 85, 100),
    _stor('pve2', 'backup-pbs', 92, 100, plugintype='pbs'),
    _stor('pve2', 'empty-nfs', 0, 0, plugintype='nfs'),
    _stor('pve3', 'local-lvm', 99, 100, status='unknown'),
]


@pytest.fixture(autouse=True)
def _fresh_health_cache(monkeypatch):
    # module-level cache keyed by cluster id; every test here uses cluster_1
    monkeypatch.setattr(clusters_mod, '_health_storage_cache', StorageDataCache(), raising=False)


def _resp(status, data=None):
    r = MagicMock(status_code=status)
    r.json.return_value = {'data': data}
    return r


def _pve_mgr(api, cluster_id=CID, resources=None, status=200):
    m = api.make_fake_manager(cluster_id=cluster_id, get_node_status=dict(_NODES),
                              get_replication_status=[], get_storage_list=[])
    m.is_connected = True
    m.host = '10.0.0.1'
    m.api_port = 8006
    m.storage_calls = []
    payload = list(_RESOURCES if resources is None else resources)

    def _get(url, **kw):
        if '/cluster/resources' in url:
            m.storage_calls.append(url)
            return _resp(status, payload if status == 200 else None)
        return _resp(404)
    m._api_get.side_effect = _get
    return m


def _storage_factor(body):
    return next((f for f in body['factors'] if f['key'] == 'storage'), None)


def test_health_takes_storage_from_one_cluster_resources_call(api, seed):
    mgr = api.set_manager(CID, _pve_mgr(api))
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).get(ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()

    f = _storage_factor(body)
    assert f is not None, body
    assert f['value'] == 'backup-pbs @ pve1 (92%)'
    assert f['delta'] == -15 and f['severity'] == 'warning'
    assert 'Storage near full: backup-pbs @ pve1 at 92%' in body['issues']
    assert '1 node(s) offline: pve3' in body['issues']

    assert len(mgr.storage_calls) == 1
    assert mgr.storage_calls[0].endswith('/api2/json/cluster/resources?type=storage')
    mgr.get_storage_list.assert_not_called()


def test_offline_node_storages_are_skipped_even_if_node_list_is_stale(api, seed):
    # node status still says pve3 is online, its storages already read 'unknown'
    mgr = _pve_mgr(api, resources=[_stor('pve1', 'local-lvm', 40, 100),
                                   _stor('pve3', 'local-lvm', 99, 100, status='unknown')])
    mgr.get_node_status.return_value = {n: {'status': 'online'} for n in _NODES}
    api.set_manager(CID, mgr)
    admin = seed.user('root', role='admin', tenant_id='default')
    body = api.as_user(admin).get(ROUTE).get_json()
    f = _storage_factor(body)
    assert f is not None and f['value'] == 'local-lvm @ pve1 (40%)'
    assert f['delta'] == 0
    mgr.get_storage_list.assert_not_called()


def test_storage_result_is_shared_per_cluster_until_it_expires(api, seed, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(cache_mod, 'time', types.SimpleNamespace(time=lambda: clock[0], sleep=time.sleep))
    a = api.set_manager(CID, _pve_mgr(api))
    b = api.set_manager('cluster_2', _pve_mgr(api, cluster_id='cluster_2'))
    admin = seed.user('root', role='admin', tenant_id='default')
    client = api.as_user(admin)

    for _ in range(3):   # three tabs polling
        assert client.get(ROUTE).status_code == 200
    assert len(a.storage_calls) == 1

    assert client.get('/api/clusters/cluster_2/health').status_code == 200
    assert len(b.storage_calls) == 1          # its own entry, not cluster_1's

    clock[0] += clusters_mod._HEALTH_STORAGE_TTL + 1
    body = client.get(ROUTE).get_json()
    assert len(a.storage_calls) == 2
    assert _storage_factor(body)['value'] == 'backup-pbs @ pve1 (92%)'


def test_failed_storage_lookup_is_not_cached(api, seed):
    mgr = api.set_manager(CID, _pve_mgr(api, status=500))
    admin = seed.user('root', role='admin', tenant_id='default')
    client = api.as_user(admin)
    resp = client.get(ROUTE)
    assert resp.status_code == 200
    assert _storage_factor(resp.get_json()) is None

    mgr._api_get.side_effect = lambda url, **kw: (mgr.storage_calls.append(url),
                                                   _resp(200, list(_RESOURCES)))[1]
    body = client.get(ROUTE).get_json()
    assert len(mgr.storage_calls) == 2
    assert _storage_factor(body)['value'] == 'backup-pbs @ pve1 (92%)'
    mgr.get_storage_list.assert_not_called()


def test_xcpng_cluster_keeps_the_per_node_listing(api, seed):
    srs = [{'storage': 'Local storage', 'type': 'ext', 'total': 100 * GiB, 'used': 85 * GiB,
            'active': True},
           {'storage': 'NFS SR', 'type': 'nfs', 'total': 100 * GiB, 'used': 10 * GiB,
            'active': True}]
    mgr = api.make_fake_manager(cluster_id=CID, cluster_type='xcpng',
                                get_node_status={'xcp1': {'status': 'online'},
                                                 'xcp2': {'status': 'offline', 'offline': True}},
                                get_replication_status=[], get_storage_list=srs)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = seed.user('root', role='admin', tenant_id='default')
    resp = api.as_user(admin).get(ROUTE)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    f = _storage_factor(resp.get_json())
    assert f is not None and f['value'] == 'Local storage @ xcp1 (85%)'
    # online hosts only, and no Proxmox endpoint on an XCP-ng pool
    assert [c.args[0] for c in mgr.get_storage_list.call_args_list] == ['xcp1']
    assert not any('/cluster/resources' in str(c) for c in mgr._api_get.call_args_list)
