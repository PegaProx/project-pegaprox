"""The two read-only overviews of the All Clusters page: storage and the guest inventory.

GET /api/storage-overview lists every storage of every cluster the caller reaches. Proxmox
is read once per cluster with /cluster/resources?type=storage, the read the health check
makes since #946 and now shares with it; shared storage, listed by Proxmox once per node,
becomes one row. A caller confined to a pool or to single guests sees no storage of that
cluster: their grant is a claim on guests.
GET /api/inventory/guests lists the guests behind the CSV export, of one cluster or of all,
guest by guest as far as the caller may see them, with the size Proxmox allocated and the
addresses and used disk the guest agent sweep has cached.
The clusters are faked at the API paths they are asked.
MK Oct 2026
"""
import threading
import types

import pytest

import pegaprox.api.clusters as clusters_mod
from pegaprox.core.cache import StorageDataCache

from test_ha_api import ha_env, _standby_of_active  # noqa: F401

GiB = 1024 ** 3
STORAGE = '/cluster/resources?type=storage'
GUESTS = '/cluster/resources?type=vm'


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data}


class _Pve:
    host, api_port, cluster_type = 'pve.example', 8006, 'proxmox'

    def __init__(self, name, storage=(), guests=(), connected=True, code=200):
        self.config = types.SimpleNamespace(name=name)
        self.is_connected = connected
        self.paths = {STORAGE: (code, [dict(s) for s in storage]), GUESTS: (code, [dict(g) for g in guests])}
        self.calls = []
        self._ip_cache, self._ip_cache_lock = {}, threading.Lock()
        self._disk_cache, self._disk_cache_lock = {}, threading.Lock()

    def _api_get(self, url, timeout=10):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        code, data = self.paths.get(path, (404, None))
        return _Resp(code, data)

    def get_vm_resources(self, max_age=0):
        # get_vm_resources puts the agent's filesystem over maxdisk - the inventory must not use it
        raise AssertionError('the inventory reads /cluster/resources itself')

    def get_node_status(self):
        return {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}

    def get_replication_status(self):
        return []

    def get_pools(self):
        return []

    def count(self, path):
        return self.calls.count(path)


class _Xen:
    cluster_type = 'xcpng'

    def __init__(self, name, srs, vms):
        self.config = types.SimpleNamespace(name=name)
        self.is_connected = True
        self.srs, self.vms = srs, vms
        self.reads = []

    def get_storages(self, node=None):
        self.reads.append('srs')
        return [dict(s) for s in self.srs]

    def get_vm_resources(self, max_age=0):
        self.reads.append(('vms', max_age))
        return [dict(v) for v in self.vms]

    def get_pools(self):
        return []


def _stor(node, storage, used, total, plugintype='lvmthin', shared=0, status='available', content='images'):
    return {'id': f'storage/{node}/{storage}', 'type': 'storage', 'node': node, 'storage': storage,
            'status': status, 'plugintype': plugintype, 'shared': shared, 'content': content,
            'disk': used * GiB, 'maxdisk': total * GiB}


C1_STORAGE = [
    _stor('pve1', 'local', 20, 100, 'dir', content='iso,vztmpl'),
    _stor('pve1', 'local-lvm', 90, 100),
    _stor('pve1', 'nfs-iso', 300, 1000, 'nfs', shared=1, content='iso'),
    _stor('pve2', 'local', 10, 100, 'dir', content='iso,vztmpl'),
    _stor('pve2', 'local-lvm', 40, 200),
    _stor('pve2', 'nfs-iso', 300, 1000, 'nfs', shared=1, content='iso'),
    # pve3 is down: pvestatd keeps its last figures and says unknown
    _stor('pve3', 'nfs-iso', 280, 1000, 'nfs', shared=1, status='unknown', content='iso'),
    _stor('pve3', 'local-lvm', 99, 100, status='unknown'),
]
C2_STORAGE = [_stor('b1', 'local-zfs', 50, 100, 'zfspool')]
SRS = [
    {'storage': 'Local storage', 'type': 'ext', 'total': 100 * GiB, 'used': 60 * GiB, 'status': 'available',
     'shared': False, 'content': 'images'},
    {'storage': 'NFS SR', 'type': 'nfs', 'total': 400 * GiB, 'used': 100 * GiB, 'status': 'available',
     'shared': True, 'content': 'images'},
]

C1_GUESTS = [
    {'vmid': 101, 'type': 'qemu', 'node': 'pve1', 'name': 'web01', 'status': 'running', 'maxcpu': 4,
     'cpu': 0.25, 'mem': 2 * GiB, 'maxmem': 4 * GiB, 'disk': 0, 'maxdisk': 32 * GiB,
     'hastate': 'started', 'pool': 'prod', 'tags': 'web;Prod'},
    {'vmid': 102, 'type': 'lxc', 'node': 'pve2', 'name': 'db01', 'status': 'running', 'maxcpu': 2,
     'cpu': 0.1, 'mem': GiB, 'maxmem': 2 * GiB, 'disk': 3 * GiB, 'maxdisk': 8 * GiB},
    {'vmid': 103, 'type': 'qemu', 'node': 'pve2', 'name': 'lab', 'status': 'stopped', 'maxcpu': 1,
     'cpu': 0, 'mem': 0, 'maxmem': GiB, 'disk': 0, 'maxdisk': 10 * GiB},
    {'vmid': 900, 'type': 'qemu', 'node': 'pve1', 'name': 'tpl', 'status': 'stopped', 'template': 1,
     'maxcpu': 2, 'maxmem': 2 * GiB, 'maxdisk': 20 * GiB},
]
C2_GUESTS = [{'vmid': 201, 'type': 'qemu', 'node': 'b1', 'name': 'erp', 'status': 'running', 'maxcpu': 8,
              'cpu': 0.5, 'mem': 8 * GiB, 'maxmem': 16 * GiB, 'disk': 0, 'maxdisk': 100 * GiB}]
XEN_VMS = [{'vmid': 301, 'type': 'qemu', 'node': 'xcp1', 'name': 'xen-vm', 'status': 'running', 'maxcpu': 2,
            'cpu': 0.05, 'mem': GiB, 'maxmem': 4 * GiB, 'disk': 0, 'maxdisk': 50 * GiB,
            'ip_addresses': ['192.168.1.5'], 'tags': [], 'template': ''},
           {'type': 'node', 'node': 'xcp1', 'status': 'online'}]


@pytest.fixture(autouse=True)
def _fresh_storage_cache(monkeypatch):
    # raising=False: on a tree without the overview the tests fail at what they check
    monkeypatch.setattr(clusters_mod, '_health_storage_cache', StorageDataCache(), raising=False)


@pytest.fixture
def estate(api, seed):
    c1 = api.set_manager('c1', _Pve('Testi', C1_STORAGE, C1_GUESTS))
    c1._ip_cache.update({('pve1', 101): ['10.0.0.11', 'fd00::11'], ('pve2', 102): ['10.0.0.12'],
                         ('pve2', 103): ['10.0.0.99']})
    c1._disk_cache.update({('pve1', 101): {'used': 12 * GiB, 'total': 30 * GiB},
                           ('pve2', 103): {'used': 5 * GiB, 'total': 9 * GiB}})
    c2 = api.set_manager('c2', _Pve('Branch', C2_STORAGE, C2_GUESTS))
    c3 = api.set_manager('c3', _Pve('Cold', C1_STORAGE, C1_GUESTS, connected=False))
    c4 = api.set_manager('c4', _Pve('Locked', code=500))
    x1 = api.set_manager('x1', _Xen('Xen', SRS, XEN_VMS))
    return types.SimpleNamespace(api=api, seed=seed, c1=c1, c2=c2, c3=c3, c4=c4, x1=x1)


def _admin(estate):
    return estate.api.as_user(estate.seed.user('root', role='admin'))


def _storage(client):
    r = client.get('/api/storage-overview')
    return r.status_code, r.get_json()


def _inventory(client, query=''):
    r = client.get('/api/inventory/guests' + query)
    return r.status_code, r.get_json()


def _states(body):
    return [(c['cluster_id'], c['state'], c['count']) for c in body['clusters']]


def _where(body):
    return [(s['cluster_id'], s['node'], s['storage']) for s in body['storages']]


def _ids(body):
    return [(g['cluster_id'], g['vmid']) for g in body['guests']]


# --- the storage overview -------------------------------------------------------------------

def test_the_admin_sees_every_storage_of_every_cluster(estate):
    code, body = _storage(_admin(estate))
    assert code == 200, body
    assert _states(body) == [('c2', 'ok', 1), ('c3', 'offline', 0), ('c4', 'unreadable', 0),
                             ('c1', 'ok', 6), ('x1', 'ok', 2)]
    # shared storage first and once, then node by node
    assert _where(body) == [
        ('c2', 'b1', 'local-zfs'),
        ('c1', '', 'nfs-iso'), ('c1', 'pve1', 'local'), ('c1', 'pve1', 'local-lvm'),
        ('c1', 'pve2', 'local'), ('c1', 'pve2', 'local-lvm'), ('c1', 'pve3', 'local-lvm'),
        ('x1', '', 'NFS SR'), ('x1', '', 'Local storage'),
    ]
    rows = {(s['cluster_id'], s['node'], s['storage']): s for s in body['storages']}
    assert rows[('c1', '', 'nfs-iso')] == {
        'cluster_id': 'c1', 'cluster_name': 'Testi', 'node': '', 'storage': 'nfs-iso', 'type': 'nfs',
        'content': 'iso', 'shared': True, 'used': 300 * GiB, 'total': 1000 * GiB, 'percent': 30.0,
        'active': True, 'nodes': 3, 'inactive_on': ['pve3']}
    full = rows[('c1', 'pve1', 'local-lvm')]
    assert (full['type'], full['shared'], full['percent'], full['active'], full['nodes']) == \
        ('lvmthin', False, 90.0, True, 1)
    assert rows[('c1', 'pve2', 'local-lvm')]['percent'] == 20.0
    # the figures of a storage that is down are pvestatd's last ones: not shown as current
    down = rows[('c1', 'pve3', 'local-lvm')]
    assert (down['active'], down['used'], down['total'], down['percent']) == (False, None, None, None)
    xen = rows[('x1', '', 'NFS SR')]
    assert (xen['type'], xen['shared'], xen['percent'], xen['active']) == ('nfs', True, 25.0, True)
    assert rows[('x1', '', 'Local storage')]['percent'] == 60.0
    # one read per cluster, the offline one not asked at all, and no node on its own
    assert (estate.c1.calls, estate.c2.calls, estate.c3.calls) == ([STORAGE], [STORAGE], [])
    assert estate.x1.reads == ['srs']


def test_the_health_check_and_the_overview_share_the_read(estate):
    c = _admin(estate)
    assert c.get('/api/clusters/c1/health').status_code == 200
    assert _storage(c)[0] == 200
    assert c.get('/api/clusters/c1/health').status_code == 200
    assert estate.c1.count(STORAGE) == 1
    # and the health check still reads the fullest active storage from it
    worst = [f for f in c.get('/api/clusters/c1/health').get_json()['factors'] if f['key'] == 'storage']
    assert worst[0]['value'] == 'local-lvm @ pve1 (90%)'
    for _ in range(3):
        _storage(c)
    assert estate.c1.count(STORAGE) == 1 and estate.x1.reads == ['srs']


def test_a_failed_read_is_asked_again(estate):
    c = _admin(estate)
    _storage(c)
    _storage(c)
    assert estate.c4.count(STORAGE) == 2


def test_without_storage_view_nothing_is_read(estate):
    c = estate.api.as_user(estate.seed.user('plain', role='user', denied=['storage.view']))
    r = c.get('/api/storage-overview')
    assert r.status_code == 403 and r.get_json()['required'] == 'storage.view'
    assert estate.c1.calls == [] and estate.x1.reads == []
    assert estate.api.anon().get('/api/storage-overview').status_code == 401


def test_a_viewer_of_the_owning_tenant_sees_its_clusters(estate):
    estate.seed.tenant('acme', ['c1'])
    code, body = _storage(estate.api.as_user(estate.seed.user('v', role='viewer', tenant_id='acme')))
    assert code == 200
    assert _states(body) == [('c1', 'ok', 6)]
    assert {s['cluster_id'] for s in body['storages']} == {'c1'}
    assert estate.c2.calls == []


def test_a_pool_confined_user_sees_no_storage_of_the_cluster(estate):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    estate.seed.tenant('t_confined', [])
    estate.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {102: ('lxc', 'pool1')})
    code, body = _storage(estate.api.as_user(estate.seed.user('pooled', role='user', tenant_id='t_confined')))
    assert code == 200, body
    assert _states(body) == [('c1', 'confined', 0)] and body['storages'] == []
    assert estate.c1.calls == []


def test_a_portal_user_of_the_owning_tenant_sees_no_storage(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.vm_acl('c1', 103, users=['portal'])
    code, body = _storage(estate.api.as_user(estate.seed.user('portal', role='user', tenant_id='acme')))
    assert code == 200 and _states(body) == [('c1', 'confined', 0)] and body['storages'] == []


def test_a_confined_admin_sees_their_tenant_only(estate):
    estate.seed.tenant('globex', ['c2'])
    c = estate.api.as_user(estate.seed.user('gx', role='admin', tenant_id='globex',
                                            tenant_permissions={'globex': {'role': 'user'}}))
    code, body = _storage(c)
    assert code == 200
    assert _states(body) == [('c2', 'ok', 1)] and _where(body) == [('c2', 'b1', 'local-zfs')]
    assert estate.c1.calls == []


def test_another_tenant_sees_nothing_of_the_cluster(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.tenant('initech', ['c2'])
    code, body = _storage(estate.api.as_user(estate.seed.user('milton', role='user', tenant_id='initech')))
    assert code == 200
    assert _states(body) == [('c2', 'ok', 1)]
    assert 'c1' not in {s['cluster_id'] for s in body['storages']} and estate.c1.calls == []


# --- the guest inventory --------------------------------------------------------------------

def test_the_admin_exports_every_guest_with_its_inventory(estate, db):
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c1', 102, 'Scratch', '')")
    db.conn.commit()
    code, body = _inventory(_admin(estate))
    assert code == 200, body
    assert _states(body) == [('c2', 'ok', 1), ('c3', 'offline', 0), ('c4', 'unreadable', 0),
                             ('c1', 'ok', 4), ('x1', 'ok', 1)]
    assert _ids(body) == [('c2', 201), ('c1', 101), ('c1', 102), ('c1', 103), ('c1', 900), ('x1', 301)]
    web, db01, lab, tpl = body['guests'][1:5]
    assert web == {
        'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 101, 'name': 'web01', 'type': 'qemu',
        'node': 'pve1', 'status': 'running', 'template': False, 'vcpus': 4, 'cpu': 0.25,
        'mem': 2 * GiB, 'memory': 4 * GiB,
        # what Proxmox allocated, not the agent's filesystem total; the agent's used figure
        'disk_allocated': 32 * GiB, 'disk_used': 12 * GiB,
        'ip_addresses': ['10.0.0.11', 'fd00::11'], 'ha_state': 'started', 'pool': 'prod',
        'tags': ['prod', 'web']}
    # a container reports its used disk itself; PegaProx tags count as well
    assert (db01['type'], db01['disk_used'], db01['ip_addresses'], db01['tags']) == \
        ('lxc', 3 * GiB, ['10.0.0.12'], ['scratch'])
    assert (db01['ha_state'], db01['pool']) == ('', '')
    # a stopped guest: what the agent caches still hold of it is not current
    assert (lab['status'], lab['ip_addresses'], lab['disk_used'], lab['disk_allocated']) == \
        ('stopped', [], None, 10 * GiB)
    assert tpl['template'] is True and tpl['vcpus'] == 2
    xen = body['guests'][5]
    assert (xen['node'], xen['ip_addresses'], xen['disk_allocated'], xen['vcpus']) == \
        ('xcp1', ['192.168.1.5'], 50 * GiB, 2)
    # one read per cluster, nothing per guest, the offline one not at all
    assert (estate.c1.calls, estate.c2.calls, estate.c3.calls) == ([GUESTS], [GUESTS], [])
    assert estate.x1.reads == [('vms', 60)]


def test_one_cluster_alone(estate):
    c = _admin(estate)
    code, body = _inventory(c, '?cluster=c1')
    assert code == 200
    assert _states(body) == [('c1', 'ok', 4)] and {g['cluster_id'] for g in body['guests']} == {'c1'}
    assert estate.c2.calls == []
    assert _inventory(c, '?cluster=nope')[0] == 404


def test_a_pool_confined_user_exports_the_guests_of_the_pool(estate):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    estate.seed.tenant('t_confined', [])
    estate.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {102: ('lxc', 'pool1'), 101: ('qemu', 'other')})
    c = estate.api.as_user(estate.seed.user('pooled', role='user', tenant_id='t_confined'))
    code, body = _inventory(c)
    assert code == 200, body
    assert _ids(body) == [('c1', 102)] and _states(body) == [('c1', 'ok', 1)]
    assert _inventory(c, '?cluster=c1')[1]['guests'] == body['guests']
    assert _inventory(c, '?cluster=c2')[0] == 403


def test_a_portal_user_of_the_owning_tenant_exports_their_guest_only(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.vm_acl('c1', 103, users=['portal'])
    code, body = _inventory(estate.api.as_user(estate.seed.user('portal', role='user', tenant_id='acme')))
    assert code == 200 and _ids(body) == [('c1', 103)]


def test_a_confined_admin_exports_their_tenant_only(estate):
    estate.seed.tenant('globex', ['c2'])
    c = estate.api.as_user(estate.seed.user('gx', role='admin', tenant_id='globex',
                                            tenant_permissions={'globex': {'role': 'user'}}))
    code, body = _inventory(c)
    assert code == 200 and _ids(body) == [('c2', 201)] and _states(body) == [('c2', 'ok', 1)]
    assert estate.c1.calls == []
    assert _inventory(c, '?cluster=c1')[0] == 403


def test_another_tenant_exports_nothing_of_the_cluster(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.tenant('initech', ['c2'])
    code, body = _inventory(estate.api.as_user(estate.seed.user('milton', role='user', tenant_id='initech')))
    assert code == 200
    assert 'c1' not in {c['cluster_id'] for c in body['clusters']} and _ids(body) == [('c2', 201)]
    assert estate.c1.calls == []


def test_without_vm_view_no_guest_is_listed(estate):
    estate.seed.tenant('acme', ['c1'])
    c = estate.api.as_user(estate.seed.user('nov', role='user', tenant_id='acme', denied=['vm.view']))
    code, body = _inventory(c)
    assert code == 200 and body['guests'] == [] and _states(body) == [('c1', 'ok', 0)]
    assert estate.api.anon().get('/api/inventory/guests').status_code == 401


# --- both -----------------------------------------------------------------------------------

def test_a_standby_shows_both_and_writes_nothing(ha_env, seed, db):  # noqa: F811
    api = ha_env.api
    m = api.set_manager('c1', _Pve('Testi', C1_STORAGE, C1_GUESTS))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    code, body = _storage(c)
    assert code == 200 and len(body['storages']) == 6
    code, body = _inventory(c)
    assert code == 200 and [g['vmid'] for g in body['guests']] == [101, 102, 103, 900]
    assert m.calls == [STORAGE, GUESTS]
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


@pytest.mark.parametrize('path', ['/api/storage-overview', '/api/inventory/guests'])
def test_the_routes_are_served_once_and_read_only(api, path):
    rules = [r for r in api.app.url_map.iter_rules() if r.rule == path]
    assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']]
