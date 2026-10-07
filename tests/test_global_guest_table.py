"""The guest table of the All Guests page: GET /api/inventory/guests/page.

One page of the guests of every cluster the caller reaches, filtered, sorted and cut on the
server, so 10k guests never cross the wire at once. The guests come from the snapshot the
guest list of a cluster reads (get_vm_resources), one read per cluster and nothing per
guest. A pool-, VM-ACL- or tenant-confined caller gets their guests only, and every row
says which of the table's actions its guest takes from this caller - what the per-guest
routes would answer. The actions themselves go to those routes, which a standby refuses.
The clusters are faked at the manager calls the route makes.
MK Oct 2026
"""
import threading
import time
import types

import pytest

from pegaprox.core.manager import UnreadList

from test_ha_api import ha_env, _standby_of_active  # noqa: F401
from test_audit_bola_high_2026_09 import _seed_pool_membership

GiB = 1024 ** 3
PAGE = '/api/inventory/guests/page'
ALL_TRUE = {'start': True, 'stop': True, 'reboot': True, 'snapshot': True, 'migrate': True}
ALL_FALSE = {'start': False, 'stop': False, 'reboot': False, 'snapshot': False, 'migrate': False}


class _Cluster:
    """A cluster manager as far as the page asks it: its guest snapshot and agent cache."""

    def __init__(self, name, guests=(), cluster_type='proxmox', connected=True, unread=False):
        self.config = types.SimpleNamespace(name=name)
        self.cluster_type = cluster_type
        self.is_connected = connected
        self.guests = [dict(g) for g in guests]
        self.unread = unread
        self.reads = []
        self._ip_cache, self._ip_cache_lock = {}, threading.Lock()

    def get_vm_resources(self, max_age=0):
        self.reads.append(max_age)
        return UnreadList() if self.unread else self.guests

    # the pool membership cache of rbac reads these once per cluster
    def get_pools(self):
        return []

    def get_pool_members(self, pool_id):
        return {'members': []}

    def _api_get(self, url, timeout=10):
        raise AssertionError('the page reads the snapshot, never a walk of its own')


def _vm(vmid, name, node, status='running', type_='qemu', **kw):
    row = {'vmid': vmid, 'name': name, 'node': node, 'type': type_, 'status': status, 'maxcpu': 2,
           'cpu': 0.1, 'mem': GiB, 'maxmem': 4 * GiB, 'disk': 0, 'maxdisk': 32 * GiB,
           'uptime': 3600 if status == 'running' else 0}
    row.update(kw)
    return row


C1 = [
    _vm(101, 'web01', 'pve1', cpu=0.5, tags='web;Prod', pool='prod', disk=12 * GiB, maxdisk=30 * GiB),
    _vm(102, 'db01', 'pve2', type_='lxc', cpu=0.05, mem=3 * GiB, disk=3 * GiB, maxdisk=8 * GiB, uptime=86400),
    _vm(103, 'lab', 'pve2', status='stopped', cpu=0, mem=0),
    _vm(104, 'paused-vm', 'pve1', status='paused', cpu=0),
    _vm(900, 'tpl', 'pve1', status='stopped', template=1, cpu=0, mem=0),
    {'type': 'node', 'node': 'pve1', 'status': 'online'},
]
C2 = [_vm(201, 'erp', 'b1', cpu=0.9, mem=8 * GiB, maxmem=16 * GiB, maxdisk=100 * GiB)]
XEN = [_vm(301, 'xen-vm', 'xcp1', ip_addresses=['192.168.1.5'], tags=[], template=''),
       {'type': 'node', 'node': 'xcp1', 'status': 'online'}]


@pytest.fixture
def estate(api, seed):
    c1 = api.set_manager('c1', _Cluster('Testi', C1))
    c1._ip_cache.update({('pve1', 101): ['10.0.0.11', 'fd00::11'], ('pve2', 103): ['10.0.0.99']})
    c2 = api.set_manager('c2', _Cluster('Branch', C2))
    c3 = api.set_manager('c3', _Cluster('Cold', C1, connected=False))
    c4 = api.set_manager('c4', _Cluster('Locked', unread=True))
    x1 = api.set_manager('x1', _Cluster('Xen', XEN, cluster_type='xcpng'))
    return types.SimpleNamespace(api=api, seed=seed, c1=c1, c2=c2, c3=c3, c4=c4, x1=x1)


def _admin(estate):
    return estate.api.as_user(estate.seed.user('root', role='admin'))


def _page(client, query=''):
    r = client.get(PAGE + query)
    return r.status_code, r.get_json()


def _ids(body):
    return [(g['cluster_id'], g['vmid']) for g in body['guests']]


def _states(body):
    return [(c['cluster_id'], c['state'], c['count']) for c in body['clusters']]


# --- what it lists ------------------------------------------------------------------------

def test_the_admin_gets_every_guest_of_every_cluster(estate, db):
    db.conn.execute("INSERT INTO vm_tags (cluster_id, vmid, tag_name, tag_color) VALUES ('c1', 102, 'Scratch', '')")
    db.conn.commit()
    code, body = _page(_admin(estate))
    assert code == 200, body
    assert _states(body) == [('c2', 'ok', 1), ('c3', 'offline', 0), ('c4', 'unreadable', 0),
                             ('c1', 'ok', 5), ('x1', 'ok', 1)]
    # by name by default, the node rows of the snapshot left out
    assert _ids(body) == [('c1', 102), ('c2', 201), ('c1', 103), ('c1', 104), ('c1', 900),
                          ('c1', 101), ('x1', 301)]
    assert (body['total'], body['count'], body['offset'], body['limit']) == (7, 7, 0, 100)
    assert body['status_counts'] == {'running': 4, 'stopped': 2, 'other': 1}
    assert body['tags'] == ['prod', 'scratch', 'web']
    web = next(g for g in body['guests'] if g['vmid'] == 101)
    assert web == {
        'cluster_id': 'c1', 'cluster_name': 'Testi', 'vmid': 101, 'name': 'web01', 'type': 'qemu',
        'node': 'pve1', 'status': 'running', 'template': False, 'vcpus': 2, 'cpu': 0.5,
        'mem': GiB, 'memory': 4 * GiB, 'disk': 12 * GiB, 'disk_size': 30 * GiB, 'uptime': 3600,
        'ip_addresses': ['10.0.0.11', 'fd00::11'], 'pool': 'prod', 'tags': ['prod', 'web'],
        'can': ALL_TRUE}
    lab = next(g for g in body['guests'] if g['vmid'] == 103)
    # a stopped guest: what the agent cache still holds of it is not current, nor is an uptime
    assert (lab['ip_addresses'], lab['uptime'], lab['disk']) == ([], 0, 0)
    db01 = next(g for g in body['guests'] if g['vmid'] == 102)
    assert (db01['type'], db01['tags'], db01['uptime']) == ('lxc', ['scratch'], 86400)
    xen = next(g for g in body['guests'] if g['vmid'] == 301)
    assert (xen['ip_addresses'], xen['template'], xen['can']) == (['192.168.1.5'], False, ALL_TRUE)
    # the snapshot of each cluster once, the guest list's age for Proxmox, the pool's own for
    # XCP-ng; the offline one is not asked at all
    assert (estate.c1.reads, estate.c2.reads, estate.c3.reads, estate.x1.reads) == ([6], [6], [], [60])


def test_paging_and_order(estate):
    c = _admin(estate)
    code, body = _page(c, '?limit=3')
    assert code == 200 and _ids(body) == [('c1', 102), ('c2', 201), ('c1', 103)]
    assert (body['total'], body['limit'], body['offset']) == (7, 3, 0)
    assert _ids(_page(c, '?limit=3&offset=3')[1]) == [('c1', 104), ('c1', 900), ('c1', 101)]
    assert _ids(_page(c, '?limit=3&offset=6')[1]) == [('x1', 301)]
    # past the end: an empty page that still says how many there are
    code, body = _page(c, '?limit=3&offset=30')
    assert code == 200 and body['guests'] == [] and body['total'] == 7
    assert [g['vmid'] for g in _page(c, '?sort=cpu&dir=desc&limit=3')[1]['guests']] == [201, 101, 301]
    assert [g['vmid'] for g in _page(c, '?sort=vmid')[1]['guests']] == [101, 102, 103, 104, 201, 301, 900]
    assert [g['vmid'] for g in _page(c, '?sort=vmid&dir=desc')[1]['guests']][:2] == [900, 301]
    # equal values fall back to the cluster and the VMID
    assert [g['vmid'] for g in _page(c, '?sort=node')[1]['guests']] == [201, 101, 104, 900, 102, 103, 301]
    assert [g['vmid'] for g in _page(c, '?sort=mem&dir=desc&limit=2')[1]['guests']] == [201, 102]
    # and keep that order when the sort runs the other way
    assert [g['vmid'] for g in _page(c, '?sort=uptime&dir=desc&limit=4')[1]['guests']] == [102, 201, 101, 301]
    assert [g['vmid'] for g in _page(c, '?sort=disk&dir=desc&limit=1')[1]['guests']] == [201]
    assert [g['vmid'] for g in _page(c, '?sort=cluster&limit=1')[1]['guests']] == [201]
    # the templates after the guests when sorted by type
    assert [g['vmid'] for g in _page(c, '?sort=type')[1]['guests']][-1] == 900


def test_filters(estate):
    c = _admin(estate)
    by = lambda q: [g['vmid'] for g in _page(c, q)[1]['guests']]  # noqa: E731
    assert by('?q=WEB') == [101]
    # an address the agent reported, a node, a cluster, a tag, a pool, a VMID
    assert by('?q=10.0.0.11') == [101]
    assert by('?q=xcp1') == [301]
    assert by('?q=branch') == [201]
    assert by('?q=scratch') == []
    assert by('?q=prod') == [101]
    assert by('?q=90') == [900]
    assert by('?status=running') == [102, 201, 101, 301]
    assert by('?status=stopped') == [103, 900]
    assert by('?status=other') == [104]
    assert by('?type=lxc') == [102]
    assert by('?type=qemu') == [201, 103, 104, 101, 301]
    assert by('?type=template') == [900]
    assert by('?tag=web') == [101] and by('?tag=PROD') == [101] and by('?tag=nope') == []
    assert by('?cluster=c2') == [201]
    # the counts by status leave the status filter aside, and follow the others
    code, body = _page(c, '?status=stopped&cluster=c1')
    assert body['status_counts'] == {'running': 2, 'stopped': 2, 'other': 1}
    assert body['total'] == 2 and body['count'] == 5
    assert _page(c, '?q=pve2&status=running')[1]['status_counts'] == {'running': 1, 'stopped': 1, 'other': 0}
    assert _page(c, '?cluster=nope')[0] == 404


@pytest.mark.parametrize('query', [
    '?limit=0', '?limit=501', '?limit=abc', '?limit=-1', '?limit=1.5', '?offset=-1', '?offset=x',
    '?offset=99999999999', '?sort=password', '?dir=up', '?status=deleted', '?type=vm',
    '?q=' + 'x' * 201, '?tag=' + 't' * 65,
])
def test_a_malformed_query_is_a_400(estate, query):
    code, body = _page(_admin(estate), query)
    assert code == 400 and body['error'], body
    # refused before any cluster is read
    assert estate.c1.reads == []


def test_the_route_is_get_only_and_served_once(api):
    rules = [r for r in api.app.url_map.iter_rules() if r.rule == PAGE]
    assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']]
    assert api.anon().get(PAGE).status_code == 401


# --- who sees what, and what each row offers ----------------------------------------------

def test_a_user_without_snapshot_and_migrate_gets_rows_without_them(estate):
    estate.seed.tenant('acme', ['c1', 'x1'])
    c = estate.api.as_user(estate.seed.user('op', role='user', tenant_id='acme',
                                            denied=['vm.snapshot', 'xapi.vm.migrate']))
    code, body = _page(c)
    assert code == 200 and {g['cluster_id'] for g in body['guests']} == {'c1', 'x1'}
    rows = {g['vmid']: g['can'] for g in body['guests']}
    assert rows[101] == dict(ALL_TRUE, snapshot=False)
    # an XCP-ng pool also wants its xapi twin of migrate and snapshot
    assert rows[301] == dict(ALL_TRUE, snapshot=False, migrate=False)
    assert estate.c2.reads == []


def test_a_viewer_sees_the_guests_and_may_act_on_none(estate):
    estate.seed.tenant('acme', ['c1'])
    code, body = _page(estate.api.as_user(estate.seed.user('v', role='viewer', tenant_id='acme')))
    assert code == 200 and len(body['guests']) == 5
    assert all(g['can'] == ALL_FALSE for g in body['guests'])


def test_without_vm_view_no_guest_is_listed(estate):
    estate.seed.tenant('acme', ['c1'])
    code, body = _page(estate.api.as_user(estate.seed.user('nov', role='user', tenant_id='acme',
                                                           denied=['vm.view'])))
    assert code == 200 and body['guests'] == [] and body['count'] == 0 and body['tags'] == []
    assert _states(body) == [('c1', 'ok', 0)]


def test_a_pool_confined_user_gets_the_guests_of_the_pool_and_its_grant(estate):
    estate.seed.tenant('t_confined', [])
    estate.seed.pool('c1', 'pool1', 'pooled', ['vm.start', 'vm.snapshot'])
    _seed_pool_membership('c1', {102: ('lxc', 'pool1'), 101: ('qemu', 'other')})
    c = estate.api.as_user(estate.seed.user('pooled', role='user', tenant_id='t_confined'))
    code, body = _page(c)
    assert code == 200, body
    assert _ids(body) == [('c1', 102)] and _states(body) == [('c1', 'ok', 1)]
    # start and snapshot from the pool grant; stop, reboot and migrate the grant does not carry
    assert body['guests'][0]['can'] == dict(ALL_FALSE, start=True, snapshot=True)
    # the other guests of the cluster leave no trace: not in the count, not among the tags
    assert body['count'] == 1 and body['tags'] == []
    assert _page(c, '?q=web')[1]['guests'] == []
    assert _page(c, '?cluster=c2')[0] == 403


def test_a_portal_user_of_the_owning_tenant_gets_their_guest_only(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.vm_acl('c1', 103, users=['portal'])
    code, body = _page(estate.api.as_user(estate.seed.user('portal', role='user', tenant_id='acme')))
    assert code == 200 and _ids(body) == [('c1', 103)]
    # an ACL that inherits the role grants the whole set of VM actions on that guest
    assert body['guests'][0]['can'] == ALL_TRUE


def test_a_confined_admin_gets_their_tenant_only(estate):
    estate.seed.tenant('globex', ['c2'])
    c = estate.api.as_user(estate.seed.user('gx', role='admin', tenant_id='globex',
                                            tenant_permissions={'globex': {'role': 'viewer'}}))
    code, body = _page(c)
    assert code == 200 and _ids(body) == [('c2', 201)] and _states(body) == [('c2', 'ok', 1)]
    # the role the tenant lowers them to decides, not the stored admin
    assert body['guests'][0]['can'] == ALL_FALSE
    assert estate.c1.reads == []
    assert _page(c, '?cluster=c1')[0] == 403


def test_another_tenant_sees_nothing_of_the_cluster(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.tenant('initech', ['c2'])
    c = estate.api.as_user(estate.seed.user('milton', role='user', tenant_id='initech'))
    code, body = _page(c)
    assert code == 200
    assert 'c1' not in {e['cluster_id'] for e in body['clusters']} and _ids(body) == [('c2', 201)]
    assert estate.c1.reads == [] and _page(c, '?cluster=c1')[0] == 403
    assert _page(c, '?q=web01')[1]['total'] == 0


# --- a standby ------------------------------------------------------------------------------

def test_a_standby_lists_and_refuses_the_actions(ha_env, seed, db):  # noqa: F811
    api = ha_env.api
    m = api.set_manager('c1', _Cluster('Testi', C1))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    code, body = _page(c)
    assert code == 200 and [g['vmid'] for g in body['guests']] == [102, 103, 104, 900, 101]
    assert m.reads == [6]
    # what the table's buttons send is refused here, before the route runs
    for path, payload in (('/api/clusters/c1/vms/pve1/qemu/101/start', None),
                          ('/api/clusters/c1/vms/pve1/qemu/101/snapshots', {'snapname': 'before'}),
                          ('/api/clusters/c1/vms/bulk-migrate', {'vms': [{'vmid': 101, 'node': 'pve1', 'type': 'qemu'}],
                                                                 'target': 'pve2', 'mode': 'sequential'})):
        r = c.post(path, json=payload) if payload is not None else c.post(path)
        assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', (path, r.get_json())
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


# --- scale ----------------------------------------------------------------------------------

def _fleet(prefix, n, nodes=50):
    return [_vm(1000 + i, f'{prefix}-{i:05d}', f'{prefix}-n{i % nodes:02d}',
                status='running' if i % 3 else 'stopped', cpu=(i % 97) / 100.0, tags='fleet' if i % 10 == 0 else '')
            for i in range(n)]


def test_ten_thousand_guests_one_page_at_a_time(api, seed):
    a = api.set_manager('a', _Cluster('Alpha', _fleet('alpha', 5000)))
    b = api.set_manager('b', _Cluster('Beta', _fleet('beta', 5000)))
    c = api.as_user(seed.user('root', role='admin'))
    t0 = time.monotonic()
    r = c.get(PAGE + '?limit=100&sort=cpu&dir=desc')
    spent = time.monotonic() - t0
    body = r.get_json()
    assert r.status_code == 200 and body['total'] == 10000 and len(body['guests']) == 100
    # a page, not the fleet: well under what all 10k rows would weigh
    assert len(r.get_data()) < 80_000, len(r.get_data())
    assert spent < 5, spent
    assert body['tags'] == ['fleet']
    code, page = _page(c, '?limit=50&offset=9950&q=beta-04')
    assert code == 200 and page['total'] == 1000 and page['guests'] == []
    assert _page(c, '?tag=fleet&limit=1')[1]['total'] == 1000
    # one snapshot read per cluster and request, nothing per guest
    assert (len(a.reads), len(b.reads)) == (3, 3)


def _timed(client, query):
    t0 = time.monotonic()
    code, body = _page(client, query)
    return code, body, time.monotonic() - t0


def test_ten_thousand_guests_for_an_operator_and_a_pool_user(api, seed):
    """The per-guest check runs for every guest of a non-admin: it has to stay cheap."""
    api.set_manager('a', _Cluster('Alpha', _fleet('alpha', 10000)))
    seed.tenant('acme', ['a'])
    op = api.as_user(seed.user('op', role='user', tenant_id='acme'))
    code, body, spent = _timed(op, '?limit=200')
    assert code == 200 and body['count'] == 10000 and len(body['guests']) == 200
    assert all(g['can'] == ALL_TRUE for g in body['guests'])
    assert spent < 15, spent

    seed.tenant('t_confined', [])
    seed.pool('a', 'p1', 'pooled', ['vm.start'])
    _seed_pool_membership('a', {1000 + i: ('qemu', 'p1') for i in range(0, 10000, 5)})
    pooled = api.as_user(seed.user('pooled', role='user', tenant_id='t_confined'))
    code, body, spent = _timed(pooled, '?limit=200&sort=vmid')
    assert code == 200 and body['count'] == 2000 and body['total'] == 2000
    assert [g['vmid'] for g in body['guests'][:3]] == [1000, 1005, 1010]
    assert body['guests'][0]['can'] == dict(ALL_FALSE, start=True)
    assert spent < 15, spent
