"""Request values that a route puts into a Proxmox VE API path.

A node from the query string or the body, a storage, a volid: each went into the path as
it came. A '/' in one adds path segments, a '?' starts the query and a '#' cuts off what
the code put after it, so the call reached another endpoint than the route names, with
the cluster's own login. These routes take only a name now and answer 400 before the
cluster is asked; names as Proxmox VE gives them still go through as they are.
MK Nov 2026
"""
import io
import json
import types

import pytest
import requests
from requests.adapters import HTTPAdapter

from pegaprox.core.manager import PegaProxManager

from test_audit_round5_batch13 import _pool_user


class _PVE(HTTPAdapter):
    """Records what goes into the request line and answers like a small PVE."""
    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, request, **kw):
        self.sent.append((request.method, request.path_url))
        path = request.path_url.split('?')[0]
        if path.endswith('/api2/json/nodes'):
            data = [{'node': 'n1', 'status': 'online'}]
        elif path.endswith('/cluster/resources'):
            data = []
        elif request.method in ('DELETE', 'POST'):
            data = 'UPID:n1:00001234:0000ABCD:65000000:imgdel:100:root@pam:'
        else:
            data = [{'volid': 'local:iso/a.iso', 'content': 'iso'}]
        r = requests.Response()
        r.status_code = 200
        r._content = json.dumps({'data': data}).encode()
        r.request = request
        return r


@pytest.fixture
def pve(api, monkeypatch):
    """A fake manager whose calls go through the session _create_session builds, with the
    recording transport under it."""
    pm = PegaProxManager.__new__(PegaProxManager)
    pm._api_token, pm._ticket, pm._csrf_token, pm._ssl_verify = None, 'TICKET', 'CSRF', False
    s = pm._create_session()
    rec = _PVE()
    s.mount('https://', rec)
    m = api.make_fake_manager(cluster_id='cluster_1')
    m.is_connected = True
    m.host, m.api_port = '10.0.0.1', 8006
    m.config = types.SimpleNamespace(name='c1', host='10.0.0.1')
    m._create_session.return_value = s
    m._api_get.side_effect = lambda url, **kw: s.get(url, **kw)
    m._api_post.side_effect = lambda url, **kw: s.post(url, **kw)
    api.set_manager('cluster_1', m)
    m.rec = rec
    # no name lookup for the download URL, the node is what is looked at here
    monkeypatch.setattr('pegaprox.utils.url_security.resolve_and_pin_url', lambda url, **kw: url)
    return m


def _storage_admin(api, seed):
    """storage.delete and storage.upload, no vm.delete anywhere."""
    return api.as_user(seed.user('stadm', role='viewer', permissions=[
        'storage.view', 'storage.delete', 'storage.upload', 'cluster.view', 'node.view']))


def _confined_storage_user(api, seed):
    u = _pool_user(seed)        # pool_1 = VM 100
    seed.db.save_user('mallory', dict(seed.db.get_user('mallory'), permissions=[
        'storage.view', 'storage.delete', 'cluster.view', 'node.view']))
    return api.as_user(u)


def _refused(r, what):
    assert r.status_code == 400 and r.get_json() == {'error': what}, (r.status_code, r.get_data(as_text=True))


# a node that reaches VM 200 or a backup's files instead of the storage, with and without the cut
NODES_ELSEWHERE = [
    'n1/qemu/200?purge=1&destroy-unreferenced-disks=1#',
    'n1/qemu/200?purge=1&x=',
    'n1/storage/pbs/file-restore/list?volume=pbs:backup/vm/200/2026-11-01T00:00:00Z&filepath=Lw==#',
    '../cluster',
]


@pytest.mark.parametrize('node', NODES_ELSEWHERE)
@pytest.mark.parametrize('who', ['storage_admin', 'confined'])
def test_a_storage_delete_with_a_node_that_is_no_name_sends_nothing(api, seed, pve, node, who):
    c = _storage_admin(api, seed) if who == 'storage_admin' else _confined_storage_user(api, seed)
    r = c.delete('/api/clusters/cluster_1/datastores/local/content/local:iso/x.iso',
                 query_string={'node': node})
    _refused(r, 'Invalid node name')
    assert pve.rec.sent == []
    # counterproof: the same caller and volume with the node's name
    r = c.delete('/api/clusters/cluster_1/datastores/local/content/local:iso/x.iso',
                 query_string={'node': 'n1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [p for (meth, p) in pve.rec.sent if meth == 'DELETE'] == [
        '/api2/json/nodes/n1/storage/local/content/local%3Aiso%2Fx.iso']


@pytest.mark.parametrize('node', NODES_ELSEWHERE)
def test_a_storage_listing_with_a_node_that_is_no_name_sends_nothing(api, seed, pve, node):
    c = api.as_user(seed.user('stv', role='viewer',
                              permissions=['storage.view', 'cluster.view', 'node.view']))
    r = c.get('/api/clusters/cluster_1/datastores/local/content', query_string={'node': node})
    _refused(r, 'Invalid node name')
    assert pve.rec.sent == []
    # counterproof: a node's name lists it, and with none named the route picks one
    for q in ({'node': 'n1'}, {}):
        r = c.get('/api/clusters/cluster_1/datastores/local/content', query_string=q)
        assert r.status_code == 200, r.get_data(as_text=True)
    assert [p for (meth, p) in pve.rec.sent if 'content' in p] == [
        '/api2/json/nodes/n1/storage/local/content'] * 2


@pytest.mark.parametrize('node,storage', [('n1', 'local'), ('pve-02.lab', 'nfs-iso.2'),
                                          ('7node', 'ceph_fs')])
def test_a_storage_that_is_no_name_sends_nothing_and_a_real_one_goes_out(api, seed, pve, node, storage):
    c = _storage_admin(api, seed)
    for bad in (f'{storage}%3Fx=', f'{storage}%23', f'{storage}%3Ax', f'-{storage}'):
        _refused(c.get(f'/api/clusters/cluster_1/datastores/{bad}/content?node={node}'),
                 'Invalid storage name')
        _refused(c.delete(f'/api/clusters/cluster_1/datastores/{bad}/content/local:iso/x.iso?node={node}'),
                 'Invalid storage name')
    assert pve.rec.sent == []
    r = c.get(f'/api/clusters/cluster_1/datastores/{storage}/content', query_string={'node': node})
    assert r.status_code == 200, r.get_data(as_text=True)
    r = c.delete(f'/api/clusters/cluster_1/datastores/{storage}/content/{storage}:iso/ubuntu-24.04.iso',
                 query_string={'node': node})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert ('GET', f'/api2/json/nodes/{node}/storage/{storage}/content') in pve.rec.sent
    assert ('DELETE', f'/api2/json/nodes/{node}/storage/{storage}/content/'
                      f'{storage}%3Aiso%2Fubuntu-24.04.iso') in pve.rec.sent


@pytest.mark.parametrize('node', NODES_ELSEWHERE)
def test_an_upload_or_download_with_a_node_that_is_no_name_sends_nothing(api, seed, pve, node):
    c = _storage_admin(api, seed)
    r = c.post('/api/clusters/cluster_1/datastores/local/upload',
               data={'node': node, 'content': 'iso', 'file': (io.BytesIO(b'x'), 'a.iso')},
               content_type='multipart/form-data')
    _refused(r, 'Invalid node name')
    r = c.post('/api/clusters/cluster_1/datastores/local/download-url',
               json={'node': node, 'url': 'https://example.org/a.iso'})
    _refused(r, 'Invalid node name')
    assert pve.rec.sent == []


def test_a_volid_stays_one_path_segment(api, seed, pve):
    c = _storage_admin(api, seed)
    r = c.delete('/api/clusters/cluster_1/datastores/local/content/local:iso/x.iso%3Fdelay=0',
                 query_string={'node': 'n1'})
    assert r.status_code == 200, r.get_data(as_text=True)
    deletes = [p for (meth, p) in pve.rec.sent if meth == 'DELETE']
    assert deletes == ['/api2/json/nodes/n1/storage/local/content/local%3Aiso%2Fx.iso%3Fdelay%3D0']


# --- the storage part of the volid of a backup delete ---------------------------------------

def _backup_user(api, seed):
    """Confined to pool_1 = VM 100, with backup rights there and nowhere else."""
    u = _pool_user(seed)
    seed.db.save_user('mallory', dict(seed.db.get_user('mallory'), permissions=[
        'backup.view', 'backup.delete', 'cluster.view', 'node.view', 'storage.view']))
    seed.pool('cluster_1', 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.backup'])
    return api.as_user(u)


OWN = 'backup/vzdump-qemu-100-2026_01_01-00_00_00.vma.zst'
OTHER = 'local%253Abackup%252Fvzdump-qemu-200-2026_01_01-00_00_00.vma.zst'


@pytest.mark.parametrize('volid', [
    # every guest's backups on the storage pruned
    f'local/prunebackups%3Fprune-backups=keep-last=1%23:{OWN}',
    f'local/prunebackups%3Fprune-backups=keep-last=1&x=:{OWN}',
    # another tenant's backup, the guard's '/vm/100/' behind the cut
    f'local/content/{OTHER}%23/vm/100/:x',
])
def test_a_backup_delete_with_a_storage_that_is_no_name_sends_nothing(api, seed, pve, volid):
    c = _backup_user(api, seed)
    r = c.delete('/api/clusters/cluster_1/vms/n1/qemu/100/backups/' + volid)
    _refused(r, 'Invalid storage name')
    assert pve.rec.sent == []
    # counterproof: the caller's own backups, a vzdump file and a PBS snapshot, still go
    for own in (f'local:{OWN}', 'pbs-store.1:backup/vm/100/2026-11-01T00:00:00Z'):
        r = c.delete('/api/clusters/cluster_1/vms/n1/qemu/100/backups/' + own)
        assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.rec.sent == [
        ('DELETE', '/api2/json/nodes/n1/storage/local/content/'
                   'local%3Abackup%2Fvzdump-qemu-100-2026_01_01-00_00_00.vma.zst'),
        ('DELETE', '/api2/json/nodes/n1/storage/pbs-store.1/content/'
                   'pbs-store.1%3Abackup%2Fvm%2F100%2F2026-11-01T00%3A00%3A00Z')]
