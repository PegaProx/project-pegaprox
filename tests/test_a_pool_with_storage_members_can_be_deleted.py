"""A pool that has storage among its members can be deleted from PegaProx.

Proxmox VE refuses DELETE /pools/{poolid} for a pool that still holds a storage ("pool 'X' is
not empty (contains storage 'local')"), on every version. delete_pool took the guests and, since
PVE 9.3, the VNets out of the pool first, never the storage, so such a pool could not be deleted
from PegaProx at all.

It now takes the storage out in the same PUT ('storage' with delete=1, a parameter as old as
pools). PVE writes that PUT in one go, so when it refuses, nothing left the pool: the answer
names every member that stayed, by kind, with PVE's reason. A pool without storage gets the very
PUT it got before.

Every list of names in the answer stays short enough for a toast: a few per kind and how many
more.

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
# the shape of PVE::API2Tools::extract_storage_stats, as the pool index lists a storage
LOCAL = {'type': 'storage', 'id': 'storage/pve1/local', 'storage': 'local', 'node': 'pve1',
         'plugintype': 'dir', 'status': 'available', 'shared': 0, 'content': 'iso,vztmpl,backup'}
NFS = {'type': 'storage', 'id': 'storage/pve1/nfs1', 'storage': 'nfs1', 'node': 'pve1',
       'plugintype': 'nfs', 'status': 'available', 'shared': 1, 'content': 'images'}
VNET = {'type': 'network', 'network-type': 'vnet', 'id': 'network/vnet/zone1/vnet1',
        'network': 'vnet/zone1/vnet1', 'text': 'vnet1 (zone1)'}


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class _PoolPve:
    """/pools as Pool.pm answers it, for one pool. Its update checks every member first and
    writes user.cfg once at the end, so a refused PUT changes nothing."""

    def __init__(self, members, storage_denied=(), subpools=(), put_answer=None):
        self.members = [dict(m) for m in members]
        self.storage_denied = set(storage_denied)
        self.subpools = list(subpools)
        self.put_answer = put_answer
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
        if self.put_answer:
            return self.put_answer
        assert data.get('delete') == 1
        vmids = {int(v) for v in str(data.get('vms', '')).split(',') if v}
        stores = [s for s in str(data.get('storage', '')).split(',') if s]
        nets = {n for n in str(data.get('network', '')).split(',') if n}
        for v in vmids:
            if not any(m.get('vmid') == v for m in self.members):
                return _Resp(500, {'data': None, 'message': f'VM {v} is not a pool member\n'})
        for s in stores:
            if s in self.storage_denied:
                return _Resp(403, {'data': None, 'message':
                                   f'Permission check failed (/storage/{s}, Permissions.Modify|Datastore.Allocate)\n'})
            if not any(m.get('type') == 'storage' and m.get('storage') == s for m in self.members):
                return _Resp(500, {'data': None, 'message': f"Storage '{s}' is not a pool member\n"})
        for n in nets:
            if not any(m.get('network') == n for m in self.members):
                return _Resp(500, {'data': None, 'message': f"Network resource '{n}' is not a pool member\n"})
        self.members = [m for m in self.members
                        if m.get('vmid') not in vmids and m.get('network') not in nets
                        and not (m.get('type') == 'storage' and m.get('storage') in stores)]
        return _Resp(200, {'data': None})

    def delete(self, url, **kw):
        # the order of Pool.pm's delete: sub-pools, guests, storage, VNets
        for p in self.subpools:
            return _Resp(500, {'data': None, 'message': f"pool '{POOL}' is not empty (contains pool '{p}')\n"})
        for kind in ('guest', 'storage', 'network'):
            for m in self.members:
                if kind == 'guest' and m.get('vmid'):
                    said = f"contains VM {m['vmid']}"
                elif kind == 'storage' and m['type'] == 'storage':
                    said = f"contains storage '{m['storage']}'"
                elif kind == 'network' and m['type'] == 'network':
                    said = f"contains network resource '{m['network']}'"
                else:
                    continue
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
    for name in ('get_pools', 'get_pool_members', 'delete_pool', '_pool_unpool_refusal'):
        if hasattr(PegaProxManager, name):
            setattr(m, name, types.MethodType(getattr(PegaProxManager, name), m))
    return api.set_manager(CID, m)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _delete(client):
    return client.delete(f'/api/clusters/{CID}/pools/{POOL}')


def test_a_pool_with_storage_is_emptied_in_one_put_and_deleted(api, admin):
    pve = _PoolPve([VM, CT, LOCAL, NFS, VNET])
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.deleted and pve.members == []
    assert pve.puts == [{'vms': '100,200', 'storage': 'local,nfs1', 'network': 'vnet/zone1/vnet1',
                         'delete': 1}]


def test_a_pool_of_storage_alone_is_deleted_too(api, admin):
    pve = _PoolPve([LOCAL])
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.deleted and pve.puts == [{'storage': 'local', 'delete': 1}]


def test_a_pool_without_storage_gets_the_put_it_got_before(api, admin):
    pve = _PoolPve([VM, CT])
    _manager(api, pve)
    assert _delete(admin).status_code == 200
    assert pve.deleted and pve.puts == [{'vms': '100,200', 'delete': 1}]


def test_a_refused_put_leaves_the_pool_whole_and_names_every_member_that_stayed(api, admin):
    """The PVE account may not modify one of the storages: PVE takes nothing out, the delete
    fails on the first guest it finds, and the answer names all of them."""
    pve = _PoolPve([VM, CT, LOCAL, NFS, VNET], storage_denied={'nfs1'})
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 400
    assert not pve.deleted and pve.members == [VM, CT, LOCAL, NFS, VNET]
    err = r.get_json()['error']
    assert "Pool 'team' was not deleted" in err
    for named in ('guests 100, 200', 'storage local, nfs1', 'VNets vnet/zone1/vnet1',
                  'PVE 403: Permission check failed (/storage/nfs1, Permissions.Modify|Datastore.Allocate)'):
        assert named in err, err
    assert '{' not in err and '\\n' not in err and '&#' not in err, err


def test_a_refusal_with_reasons_per_field_names_the_field(api, admin):
    refusal = _Resp(400, {'data': None, 'message': 'Parameter verification failed.\n',
                          'errors': {'storage': "invalid format - storage ID 'x y' contains illegal characters\n"}})
    pve = _PoolPve([LOCAL], put_answer=refusal)
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 400 and not pve.deleted
    err = r.get_json()['error']
    assert 'storage local' in err
    assert "PVE 400: storage: invalid format - storage ID 'x y' contains illegal characters" in err, err


def test_a_delete_refused_for_another_reason_answers_as_before(api, admin):
    """The members went out, the delete fails on a pool below this one: PVE's answer as it was."""
    pve = _PoolPve([VM, LOCAL], subpools=['team/sub'])
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 400 and not pve.deleted
    err = r.get_json()['error']
    assert err.startswith('PVE 500: ') and "contains pool 'team/sub'" in err, err


def test_a_refusal_for_a_big_pool_stays_short(api, admin):
    """800 guests and a storage the account may not modify: the toast names a few of each."""
    guests = [dict(VM, id=f'qemu/{v}', vmid=v, name=f'g{v}') for v in range(1000, 1800)]
    pve = _PoolPve([*guests, LOCAL, NFS], storage_denied={'nfs1'})
    _manager(api, pve)
    r = _delete(admin)
    assert r.status_code == 400 and not pve.deleted and len(pve.members) == 802
    err = r.get_json()['error']
    assert len(err) < 500 and '1005' not in err, len(err)
    assert 'guests 1000, 1001, 1002, 1003, 1004 and 795 more; storage local, nfs1' in err, err


def test_deleting_a_pool_still_needs_admin_users(api, seed):
    pve = _PoolPve([VM, LOCAL])
    _manager(api, pve)
    r = _delete(api.as_user(seed.user('bob', role='user')))
    assert r.status_code == 403, r.get_data(as_text=True)
    assert pve.puts == [] and not pve.deleted
