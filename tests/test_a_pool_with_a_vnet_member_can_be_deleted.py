"""A pool that has an SDN VNet among its members can be deleted from PegaProx.

Proxmox VE 9.3 (pve-manager fix #7294) lets a pool hold VNets: members of type 'network' whose
'network' is what PUT /pools/{poolid} takes ('vnet/<zone>/<vnet>[/<tag>|/*]'), and DELETE
refuses a pool that still has one ("pool 'X' is not empty (contains network resource ...)").
delete_pool took only the guests out of the pool first, so such a pool could not be deleted.

It now takes the VNets out in the same PUT as the guests. A pool without VNets gets the very PUT
it got before, so a node that knows no 'network' parameter never sees one. Listing pools with
such members keeps working.

MK Nov 2026
"""
import json
import types

import pytest

from pegaprox.core.manager import PegaProxManager

CID = 'cluster_1'
POOL = 'team'
VM = {'type': 'qemu', 'id': 'qemu/100', 'vmid': 100, 'node': 'pve1', 'name': 'web', 'status': 'running'}
CT = {'type': 'lxc', 'id': 'lxc/200', 'vmid': 200, 'node': 'pve1', 'name': 'ct', 'status': 'stopped'}
# the shape of Pool.pm's index for a network member
VNET = {'type': 'network', 'network-type': 'vnet', 'id': 'network/vnet/zone1/vnet1',
        'network': 'vnet/zone1/vnet1', 'text': 'vnet1 (zone1)'}
TAGGED = {'type': 'network', 'network-type': 'vnet', 'id': 'network/vnet/zone1/trunk/42',
          'network': 'vnet/zone1/trunk/42', 'text': 'trunk.42 (zone1)'}


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class _PoolPve:
    """/pools as Pool.pm answers it, for one pool"""

    def __init__(self, members, knows_network=True):
        self.members = [dict(m) for m in members]
        self.knows_network = knows_network
        self.puts, self.deleted = [], False

    def get(self, url, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/pools':
            return _Resp(200, {'data': [{'poolid': POOL}]})
        if path == f'/pools/{POOL}' and not self.deleted:
            return _Resp(200, {'data': {'poolid': POOL, 'members': self.members}})
        return _Resp(500, {'data': None, 'message': f"pool '{POOL}' does not exist\n"})

    def put(self, url, data=None, **kw):
        self.puts.append(dict(data))
        if 'network' in data and not self.knows_network:
            return _Resp(400, {'data': None, 'message': 'Parameter verification failed.\n', 'errors': {
                'network': 'property is not defined in schema and the schema does not allow additional properties'}})
        assert data.get('delete') == 1
        vmids = {int(v) for v in str(data.get('vms', '')).split(',') if v}
        nets = {n for n in str(data.get('network', '')).split(',') if n}
        for v in vmids:
            if not any(m.get('vmid') == v for m in self.members):
                return _Resp(500, {'data': None, 'message': f'VM {v} is not a pool member\n'})
        for n in nets:
            if not any(m.get('network') == n for m in self.members):
                return _Resp(500, {'data': None, 'message': f"Network resource '{n}' is not a pool member\n"})
        self.members = [m for m in self.members if m.get('vmid') not in vmids and m.get('network') not in nets]
        return _Resp(200, {'data': None})

    def delete(self, url, **kw):
        for m in self.members:
            if m.get('vmid'):
                said = f"contains VM {m['vmid']}"
            elif m['type'] == 'network':
                said = f"contains network resource '{m['network']}'"
            else:
                said = f"contains storage '{m['storage']}'"
            return _Resp(500, {'data': None, 'message': f"pool '{POOL}' is not empty ({said})\n"})
        self.deleted = True
        return _Resp(200, {'data': None})


def _manager(api, pve):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '192.0.2.10', 8006
    m.config.name = CID
    m._api_get.side_effect = pve.get
    m._api_put.side_effect = pve.put
    m._api_delete.side_effect = pve.delete
    for name in ('get_pools', 'get_pool_members', 'delete_pool'):
        setattr(m, name, types.MethodType(getattr(PegaProxManager, name), m))
    return api.set_manager(CID, m)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _delete(client):
    return client.delete(f'/api/clusters/{CID}/pools/{POOL}')


def test_a_pool_with_vnets_is_emptied_in_one_put_and_deleted(api, admin):
    pve = _PoolPve([VM, CT, VNET, TAGGED])
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.deleted
    assert pve.puts == [{'vms': '100,200', 'network': 'vnet/zone1/vnet1,vnet/zone1/trunk/42', 'delete': 1}]


def test_a_pool_of_vnets_alone_is_deleted_too(api, admin):
    pve = _PoolPve([VNET])
    _manager(api, pve)
    assert _delete(admin).status_code == 200
    assert pve.deleted and pve.puts == [{'network': 'vnet/zone1/vnet1', 'delete': 1}]


def test_a_pool_without_vnets_gets_the_put_it_got_before(api, admin):
    """A node before PVE 9.3 has no 'network' parameter and refuses a call that names one."""
    pve = _PoolPve([VM, CT], knows_network=False)
    _manager(api, pve)
    assert _delete(admin).status_code == 200
    assert pve.deleted and pve.puts == [{'vms': '100,200', 'delete': 1}]


def test_an_empty_pool_is_deleted_without_a_put(api, admin):
    pve = _PoolPve([])
    _manager(api, pve)
    assert _delete(admin).status_code == 200
    assert pve.deleted and pve.puts == []


def test_the_pool_list_reads_vnet_members_as_members_and_not_as_guests(api, admin):
    pve = _PoolPve([VM, VNET])
    _manager(api, pve)
    r = admin.get(f'/api/clusters/{CID}/pools')
    assert r.status_code == 200, r.get_data(as_text=True)
    (pool,) = r.get_json()
    assert (pool['poolid'], pool['member_count'], pool['vms'], pool['storage']) == (POOL, 2, 1, 0)
    assert VNET in pool['members']
    r = admin.get(f'/api/clusters/{CID}/pools/{POOL}')
    assert r.status_code == 200 and VNET in r.get_json()['members']
