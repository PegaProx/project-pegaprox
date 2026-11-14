"""The network topology resolves its guest links in linear time.

Every guest link looked its bridge or vnet up in the list of everything drawn so far,
which by then holds every guest: O(guests x graph). 10k guests on SDN vnets took about
4 s of CPU per request, on the hub. The route is timed at two sizes with every guest
config in the cache (no PVE reads), and the larger one may not cost much more than its
share. Linear gives a ratio near 4 for 4x the guests; the old loop gave near 16.

MK Nov 2026
"""
import time

import pytest

CLUSTER = 'cluster_1'
NODES = [f'pve{i}' for i in range(20)]
VNETS = [f'vnet{i}' for i in range(20)]


class _Resp:
    def __init__(self, data):
        self.status_code = 200
        self._data = data

    def json(self):
        return {'data': self._data}


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_admin', role='admin'))


def _cluster(api, guests):
    m = api.make_fake_manager(CLUSTER)
    m.is_connected = True
    m.host, m.api_port = 'pve.test', 8006
    m.config.name = CLUSTER
    m.nodes = {n: {'status': 'online', 'cpu': 0.1, 'maxcpu': 8, 'mem': 1, 'maxmem': 2} for n in NODES}

    def api_get(url, **kw):
        if url.endswith('/cluster/sdn/vnets'):
            return _Resp([{'vnet': v, 'zone': 'z1'} for v in VNETS])
        if url.endswith('/network'):
            return _Resp([{'iface': 'vmbr0', 'type': 'bridge'}, {'iface': 'vmbr1', 'type': 'bridge'}])
        raise AssertionError(f'no guest config is read, all are cached: {url}')
    m._api_get = api_get
    rows = []
    cache = {}
    for i in range(guests):
        vmid = 100 + i
        rows.append({'type': 'qemu', 'vmid': vmid, 'node': NODES[i % len(NODES)], 'name': f'g{vmid}', 'status': 'running'})
        # most guests on a vnet, the worst case of the old lookup, a few on a node bridge
        cache[('qemu', vmid)] = ['vmbr0'] if i % 10 == 0 else [VNETS[i % len(VNETS)]]
    m.get_vm_resources.return_value = rows
    m._topology_cfg_cache = cache
    m._topology_cfg_time = time.monotonic() + 3600   # fresh for the whole test
    return api.set_manager(CLUSTER, m)


def _timed(client, runs=3):
    best = None
    for _ in range(runs):
        t0 = time.perf_counter()
        r = client.get(f'/api/clusters/{CLUSTER}/topology')
        took = time.perf_counter() - t0
        assert r.status_code == 200, r.get_data(as_text=True)
        best = took if best is None else min(best, took)
    return best, r.get_json()


def test_the_links_are_resolved_in_linear_time(api, admin):
    _cluster(api, 1500)
    small, body = _timed(admin)
    assert sum(1 for l in body['links'] if l['kind'] == 'attached') == 1500
    _cluster(api, 6000)
    large, body = _timed(admin)
    attached = [l for l in body['links'] if l['kind'] == 'attached']
    assert len(attached) == 6000
    ratio = large / small
    assert ratio < 8, f'4x the guests took {ratio:.1f}x as long ({small:.2f} s -> {large:.2f} s)'


def test_the_links_still_go_where_they_went(api, admin):
    _cluster(api, 30)
    _, body = _timed(admin, runs=1)
    by_guest = {l['source']: l['target'] for l in body['links'] if l['kind'] == 'attached'}
    assert by_guest['vm:100'] == 'br:pve0:vmbr0'          # a node bridge on its own node
    assert by_guest['vm:101'] == 'sdn:vnet1'              # a vnet
    # a bridge no node has is left out, as before
    api.set_manager(CLUSTER, _cluster(api, 1))._topology_cfg_cache[('qemu', 100)] = ['vmbr9']
    _, body = _timed(admin, runs=1)
    assert not [l for l in body['links'] if l['kind'] == 'attached']
