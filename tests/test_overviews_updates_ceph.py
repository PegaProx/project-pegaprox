"""Two more read-only overviews of the All Clusters page: pending updates and Ceph.

GET /api/updates-overview lists the pending package updates of every node and backup server
on the clusters the caller reaches, from what each cluster's last update check left in the
server's cache: it asks no node anything. The check itself now also reads which repository
each host takes its packages from and the state of its subscription (two short reads per
node, once per check).
GET /api/ceph-overview shows health, capacity, OSDs, placement groups and client I/O of the
Ceph of every cluster from one /cluster/ceph/status per cluster, the read the ceph_health
alert makes; either serves the other for CEPH_FRESH seconds.
A caller confined to a pool or to single guests sees neither for that cluster, another
tenant nothing of it. The clusters are faked at the API paths they are asked.
MK Oct 2026
"""
import time
import types

import pytest

import pegaprox.api.settings as settings_mod
from pegaprox.api.ceph import ceph_rollup
from pegaprox.background import alert_events

from test_ha_api import ha_env, _standby_of_active  # noqa: F401

GiB = 1024 ** 3
CEPH = '/cluster/ceph/status'


class _Resp:
    def __init__(self, code, data):
        self.status_code, self._data = code, data

    def json(self):
        return {'data': self._data}


class _Pve:
    host, api_port, cluster_type = 'pve.example', 8006, 'proxmox'

    def __init__(self, name, paths=None, connected=True, nodes=('pve1', 'pve2'), cluster_type='proxmox'):
        self.config = types.SimpleNamespace(name=name)
        self.cluster_type = cluster_type
        self.is_connected = connected
        self.paths = dict(paths or {})
        self.calls = []
        self.nodes = list(nodes)
        self.updates = {}
        self._rolling_update = None

    def _api_get(self, url, timeout=10):
        path = url.split('/api2/json', 1)[1]
        self.calls.append(path)
        hit = self.paths.get(path, (404, None))
        if isinstance(hit, Exception):
            raise hit
        return _Resp(*hit)

    # what the update check asks
    def _create_session(self):
        outer = self

        class _S:
            def get(self, url, timeout=10):
                outer.calls.append('/nodes')
                return _Resp(200, [{'node': n, 'status': 'online'} for n in outer.nodes])
        return _S()

    def refresh_node_apt(self, node):
        self.calls.append(f'refresh {node}')
        return {'success': True, 'task': f'UPID:{node}:apt'}

    def _wait_for_task(self, node, upid, timeout=120):
        return True

    def get_node_apt_updates(self, node):
        self.calls.append(f'updates {node}')
        return list(self.updates.get(node, []))

    def get_node_status(self):
        return {n: {'status': 'online'} for n in self.nodes}

    def count(self, path):
        return self.calls.count(path)


class _Pbs:
    def __init__(self, name, linked=(), paths=None):
        self.name, self.linked_clusters, self.connected = name, list(linked), True
        self.paths = dict(paths or {})
        self.asked = []

    def get_apt_updates(self):
        self.asked.append('updates')
        return {'data': [{'Package': 'proxmox-backup-server', 'Origin': 'Proxmox'}]}

    def api_get(self, path, params=None, timeout=30):
        self.asked.append(path)
        return self.paths.get(path, {'error': 'HTTP 404', 'status_code': 404})


def _pkg(name, origin='Debian', section='admin'):
    return {'Package': name, 'Origin': origin, 'Section': section, 'Version': '1', 'OldVersion': '0'}


def _host(updates=(), ok=True, **source):
    res = {'success': ok, 'updates': list(updates), 'count': len(updates) if ok else -1}
    if not ok:
        res['error'] = 'apt refresh failed: 401 Unauthorized https://enterprise.proxmox.com'
    res.update(source)
    return res


def _cache(cid, nodes, pbs=None, age=60):
    settings_mod._update_check_cache[cid] = {
        'at': time.time() - age,
        'payload': {'success': True, 'nodes': nodes, 'pbs': pbs or {}, 'summary': {}}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(settings_mod, '_update_check_cache', {})
    monkeypatch.setattr(alert_events, '_ceph', {})
    monkeypatch.setattr(alert_events, '_status', {})


# --- the update overview ----------------------------------------------------------------------

@pytest.fixture
def estate(api, seed):
    import pegaprox.globals as g
    c1 = api.set_manager('c1', _Pve('Testi'))
    c2 = api.set_manager('c2', _Pve('Branch'))
    c3 = api.set_manager('c3', _Pve('Fresh'))
    x1 = api.set_manager('x1', _Pve('Xen', cluster_type='xcpng'))
    p1 = g.pbs_managers['p1'] = _Pbs('backup-a', linked=['c1'])
    p2 = g.pbs_managers['p2'] = _Pbs('backup-shared')
    _cache('c1', {
        'pve1': _host([_pkg('openssl'), _pkg('proxmox-kernel-6.8', 'Proxmox')],
                      channel='enterprise', repo_warnings=0, subscription='active'),
        'pve2': _host(ok=False, channel='enterprise', repo_warnings=1, subscription='notfound'),
    }, pbs={'backup-a': dict(_host([_pkg('proxmox-backup-server', 'Proxmox')], channel='no-subscription',
                                   repo_warnings=0, subscription='notfound'), pbs_id='p1'),
            'backup-shared': dict(_host([]), pbs_id='p2')}, age=120)
    # older than a day: shown, and said to be stale
    _cache('c2', {'b1': _host([])}, pbs={'backup-shared': dict(_host([_pkg('zstd')]), pbs_id='p2')},
           age=settings_mod._UPDATE_CHECK_TTL + 60)
    _cache('x1', {'xcp1': _host([_pkg('kernel', 'xcp-ng-updates', 'updates'),
                                 _pkg('openssh', 'xcp-ng-security', 'security')])})
    c1._rolling_update = {'status': 'running', 'logs': ['x']}
    return types.SimpleNamespace(api=api, seed=seed, c1=c1, c2=c2, c3=c3, x1=x1, p1=p1, p2=p2)


def _admin(estate):
    return estate.api.as_user(estate.seed.user('root', role='admin'))


def _updates(client):
    r = client.get('/api/updates-overview')
    return r.status_code, r.get_json()


def _states(body):
    return [(c['cluster_id'], c['state']) for c in body['clusters']]


def _hosts(body):
    return [(h['cluster_id'], h['kind'], h['name']) for h in body['hosts']]


def test_the_admin_sees_every_host_of_every_cluster(estate):
    code, body = _updates(_admin(estate))
    assert code == 200, body
    assert _states(body) == [('c2', 'ok'), ('c3', 'unchecked'), ('c1', 'ok'), ('x1', 'ok')]
    assert _hosts(body) == [('c2', 'node', 'b1'), ('c1', 'node', 'pve1'), ('c1', 'node', 'pve2'),
                            ('x1', 'node', 'xcp1'), ('c1', 'pbs', 'backup-a'), ('c1', 'pbs', 'backup-shared')]
    rows = {(h['cluster_id'], h['name']): h for h in body['hosts']}
    pve1 = rows[('c1', 'pve1')]
    assert {k: pve1[k] for k in ('ok', 'count', 'security', 'kernel', 'channel', 'repo_warnings',
                                 'subscription', 'pbs_id', 'stale')} == {
        'ok': True, 'count': 2, 'kernel': True, 'channel': 'enterprise', 'repo_warnings': 0,
        'subscription': 'active', 'pbs_id': None, 'stale': False,
        # Proxmox names the origin, not the suite: no security count rather than a wrong 0
        'security': None}
    # a failed check is no "nothing pending", and its error text stays in the update manager
    pve2 = rows[('c1', 'pve2')]
    assert (pve2['ok'], pve2['count'], pve2['security'], pve2['subscription']) == (False, None, None, 'notfound')
    assert 'error' not in pve2 and 'updates' not in pve2
    # XCP-ng names the repository: there the count is known, a 0 as well
    xen = rows[('x1', 'xcp1')]
    assert (xen['count'], xen['security'], xen['kernel'], xen['channel']) == (2, 1, True, None)
    assert rows[('c2', 'b1')]['security'] is None and rows[('c2', 'b1')]['stale'] is True
    clusters = {c['cluster_id']: c for c in body['clusters']}
    assert (clusters['c1']['count'], clusters['c1']['rolling'], clusters['c1']['stale']) == (2, 'running', False)
    assert clusters['c2']['stale'] is True and clusters['c3']['checked_at'] is None
    assert isinstance(clusters['c1']['checked_at'], int)
    # a PBS in the check of two clusters is one row, from the newer check
    shared = rows[('c1', 'backup-shared')]
    assert (shared['pbs_id'], shared['count'], shared['stale']) == ('p2', 0, False)
    assert rows[('c1', 'backup-a')]['channel'] == 'no-subscription'
    # read from the cache: no cluster and no backup server was asked anything
    assert [estate.c1.calls, estate.c2.calls, estate.c3.calls, estate.x1.calls] == [[], [], [], []]
    assert estate.p1.asked == estate.p2.asked == []


def test_without_node_view_nothing_is_listed(estate):
    c = estate.api.as_user(estate.seed.user('plain', role='user', denied=['node.view']))
    r = c.get('/api/updates-overview')
    assert r.status_code == 403 and r.get_json()['required'] == 'node.view'
    assert estate.api.anon().get('/api/updates-overview').status_code == 401


def test_a_viewer_of_the_owning_tenant_sees_its_clusters(estate):
    estate.seed.tenant('acme', ['c1'])
    code, body = _updates(estate.api.as_user(estate.seed.user('v', role='viewer', tenant_id='acme')))
    assert code == 200, body
    assert _states(body) == [('c1', 'ok')]
    # the backup servers too: the one linked to c1, and the one linked to no cluster
    assert _hosts(body) == [('c1', 'node', 'pve1'), ('c1', 'node', 'pve2'),
                            ('c1', 'pbs', 'backup-a'), ('c1', 'pbs', 'backup-shared')]


def test_without_pbs_view_the_backup_servers_stay_out(estate):
    estate.seed.tenant('acme', ['c1'])
    c = estate.api.as_user(estate.seed.user('v', role='viewer', tenant_id='acme', denied=['pbs.view']))
    code, body = _updates(c)
    assert code == 200 and _hosts(body) == [('c1', 'node', 'pve1'), ('c1', 'node', 'pve2')]


def test_a_backup_server_of_another_tenant_stays_out(estate):
    """p1 is linked to c1 only: a user of c2 sees the shared one in c2's check, not p1."""
    import pegaprox.globals as g
    estate.seed.tenant('initech', ['c2'])
    g.pbs_managers['p1'].linked_clusters = ['c1']
    settings_mod._update_check_cache['c2']['payload']['pbs']['backup-a'] = dict(_host([]), pbs_id='p1')
    code, body = _updates(estate.api.as_user(estate.seed.user('milton', role='user', tenant_id='initech')))
    assert code == 200 and _states(body) == [('c2', 'ok')]
    assert _hosts(body) == [('c2', 'node', 'b1'), ('c2', 'pbs', 'backup-shared')]


def test_a_pool_confined_user_sees_no_host_of_the_cluster(estate):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    estate.seed.tenant('t_confined', [])
    estate.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {102: ('lxc', 'pool1')})
    code, body = _updates(estate.api.as_user(estate.seed.user('pooled', role='user', tenant_id='t_confined')))
    assert code == 200, body
    assert _states(body) == [('c1', 'confined')] and body['hosts'] == []
    assert body['clusters'][0]['rolling'] is None


def test_a_portal_user_of_the_owning_tenant_sees_no_host(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.vm_acl('c1', 103, users=['portal'])
    code, body = _updates(estate.api.as_user(estate.seed.user('portal', role='user', tenant_id='acme')))
    assert code == 200 and _states(body) == [('c1', 'confined')] and body['hosts'] == []


def test_a_confined_admin_sees_their_tenant_only(estate):
    estate.seed.tenant('globex', ['c2'])
    c = estate.api.as_user(estate.seed.user('gx', role='admin', tenant_id='globex',
                                            tenant_permissions={'globex': {'role': 'user'}}))
    code, body = _updates(c)
    assert code == 200, body
    assert _states(body) == [('c2', 'ok')]
    assert _hosts(body) == [('c2', 'node', 'b1'), ('c2', 'pbs', 'backup-shared')]


def test_another_tenant_sees_nothing_of_the_cluster(estate):
    estate.seed.tenant('acme', ['c1'])
    estate.seed.tenant('initech', ['c2'])
    code, body = _updates(estate.api.as_user(estate.seed.user('milton', role='user', tenant_id='initech')))
    assert code == 200 and 'c1' not in {c['cluster_id'] for c in body['clusters']}
    assert 'c1' not in {h['cluster_id'] for h in body['hosts']}


def test_the_checks_run_on_the_active_so_a_standby_reads_there(ha_env, seed):  # noqa: F811
    from pegaprox.core import ha
    assert '/api/updates-overview' in ha.FORWARDED_READS
    # its own copy when the active does not answer it: nothing checked here, nothing made up
    assert '/api/updates-overview' not in ha.LEADER_ONLY_READS
    api = ha_env.api
    m = api.set_manager('c1', _Pve('Testi'))
    _standby_of_active(ha_env)
    code, body = _updates(api.as_user(seed.user('root', role='admin')))
    assert code == 200 and _states(body) == [('c1', 'unchecked')] and body['hosts'] == []
    assert m.calls == []


# --- what the check reads for it --------------------------------------------------------------

REPOS_ENTERPRISE = {'files': [], 'errors': [], 'digest': 'x',
                    'infos': [{'kind': 'origin', 'message': 'Proxmox', 'path': '/etc/apt/x', 'index': 0},
                              {'kind': 'warning', 'message': "old suite 'bullseye' configured!",
                               'path': '/etc/apt/sources.list', 'index': 1}],
                    'standard-repos': [{'handle': 'enterprise', 'name': 'Enterprise', 'status': 1},
                                       {'handle': 'no-subscription', 'name': 'No-Subscription', 'status': 0},
                                       {'handle': 'test', 'name': 'Test'},
                                       {'handle': 'ceph-squid-no-subscription', 'status': 1}]}
SUBSCRIPTION = {'status': 'Active', 'level': 'c', 'key': 'pve2c-0123456789', 'productname': 'Proxmox VE Community'}


def test_the_check_reads_repository_and_subscription_once_per_node(api, seed):
    import pegaprox.globals as g
    m = api.set_manager('c1', _Pve('Testi', paths={
        '/nodes/pve1/apt/repositories': (200, REPOS_ENTERPRISE),
        '/nodes/pve1/subscription': (200, SUBSCRIPTION),
        '/nodes/pve2/apt/repositories': (500, None),
        '/nodes/pve2/subscription': ConnectionError('gone'),
    }))
    m.updates = {'pve1': [_pkg('openssl')]}
    g.pbs_managers['p1'] = _Pbs('backup-a', linked=['c1'], paths={
        '/nodes/localhost/apt/repositories': {'data': {'standard-repos': [
            {'handle': 'no-subscription', 'status': 1}], 'infos': []}},
        '/nodes/localhost/subscription': {'data': {'status': 'notfound', 'key': ''}}})
    admin = api.as_user(seed.user('root', role='admin'))
    r = admin.post('/api/clusters/c1/updates/check', json={'force': True})
    assert r.status_code == 200, r.data
    body = r.get_json()
    pve1, pve2 = body['nodes']['pve1'], body['nodes']['pve2']
    assert (pve1['count'], pve1['channel'], pve1['repo_warnings'], pve1['subscription']) == \
        (1, 'enterprise', 1, 'active')
    # what could not be read is unknown, and the check of the node itself stands
    assert (pve2['success'], pve2['channel'], pve2['repo_warnings'], pve2['subscription']) == \
        (True, None, None, None)
    assert 'pve2c-0123456789' not in r.get_data(as_text=True)
    pbs = body['pbs']['backup-a']
    assert (pbs['channel'], pbs['subscription'], pbs['count']) == ('no-subscription', 'notfound', 1)
    for node in ('pve1', 'pve2'):
        assert m.count(f'/nodes/{node}/apt/repositories') == m.count(f'/nodes/{node}/subscription') == 1
    # the overview reads it from there, and asks nobody
    before = list(m.calls)
    code, over = _updates(admin)
    rows = {h['name']: h for h in over['hosts']}
    assert rows['pve1']['channel'] == 'enterprise' and rows['backup-a']['channel'] == 'no-subscription'
    assert m.calls == before
    # within the day the check answers from the cache: no second read of either
    admin.post('/api/clusters/c1/updates/check', json={})
    assert m.count('/nodes/pve1/subscription') == 1


def test_an_xcpng_pool_has_no_repository_to_read(api, seed):
    m = api.set_manager('x1', _Pve('Xen', cluster_type='xcpng'))
    m.get_nodes = lambda: [{'node': 'xcp1', 'status': 'online'}]
    m.updates = {'xcp1': [_pkg('kernel', 'xcp-ng-updates', 'updates')]}
    r = api.as_user(seed.user('root', role='admin')).post('/api/clusters/x1/updates/check', json={'force': True})
    assert r.status_code == 200, r.data
    node = r.get_json()['nodes']['xcp1']
    assert node['count'] == 1 and 'channel' not in node
    assert not [c for c in m.calls if 'repositories' in c or 'subscription' in c]


@pytest.mark.parametrize('repos,want', [
    (REPOS_ENTERPRISE, {'channel': 'enterprise', 'repo_warnings': 1}),
    ({'standard-repos': [{'handle': 'no-subscription', 'status': 1}]}, {'channel': 'no-subscription', 'repo_warnings': 0}),
    ({'standard-repos': [{'handle': 'enterprise', 'status': 1}, {'handle': 'test', 'status': 1}]},
     {'channel': 'mixed', 'repo_warnings': 0}),
    ({'standard-repos': [{'handle': 'enterprise', 'status': 0}]}, {'channel': 'none', 'repo_warnings': 0}),
    ({'standard-repos': []}, {'channel': 'none', 'repo_warnings': 0}),
    ({'files': []}, {'channel': None, 'repo_warnings': None}),
    (None, {'channel': None, 'repo_warnings': None}),
    ('garbage', {'channel': None, 'repo_warnings': None}),
])
def test_the_channel_of_a_host(repos, want):
    assert settings_mod.apt_channel(repos) == want


@pytest.mark.parametrize('data,want', [
    (SUBSCRIPTION, 'active'), ({'status': 'notfound'}, 'notfound'), ({'status': 'Expired'}, 'expired'),
    ({'status': '<b>new-thing</b>'}, 'unknown'), ({'status': ''}, None), ({}, None), (None, None), ([], None),
])
def test_the_subscription_state_is_its_status_only(data, want):
    assert settings_mod.subscription_state(data) == want


@pytest.mark.parametrize('path', ['/api/updates-overview', '/api/ceph-overview'])
def test_the_routes_are_served_once_and_read_only(api, path):
    rules = [r for r in api.app.url_map.iter_rules() if r.rule == path]
    assert [sorted(r.methods - {'HEAD', 'OPTIONS'}) for r in rules] == [['GET']]


# --- the Ceph overview ------------------------------------------------------------------------

def _ceph_ok():
    return {
        'fsid': 'f0e1', 'health': {'status': 'HEALTH_OK', 'checks': {}, 'mutes': []},
        'quorum_names': ['pve1', 'pve2', 'pve3'],
        'monmap': {'epoch': 3, 'min_mon_release_name': 'squid', 'num_mons': 3},
        'osdmap': {'epoch': 120, 'num_osds': 6, 'num_up_osds': 6, 'num_in_osds': 6, 'num_remapped_pgs': 0},
        'pgmap': {'pgs_by_state': [{'state_name': 'active+clean', 'count': 120},
                                   {'state_name': 'active+clean+scrubbing+deep', 'count': 9}],
                  'num_pgs': 129, 'num_pools': 2, 'num_objects': 5000, 'bytes_used': 300 * GiB,
                  'bytes_avail': 2700 * GiB, 'bytes_total': 3000 * GiB, 'read_bytes_sec': 1048576,
                  'write_bytes_sec': 2097152, 'read_op_per_sec': 50, 'write_op_per_sec': 120},
        'mgrmap': {'available': True, 'num_standbys': 2}}


def _ceph_warn():
    """Ceph before Quincy: the OSD map is nested once more, the monitors are listed."""
    return {
        'health': {'status': 'HEALTH_WARN', 'checks': {
            'PG_DEGRADED': {'severity': 'HEALTH_WARN',
                            'summary': {'message': 'Degraded data redundancy: 40 pgs degraded'}},
            'MON_DOWN': {'severity': 'HEALTH_WARN', 'summary': {'message': '1/3 mons down'}},
            'OSD_FULL': {'severity': 'HEALTH_ERR', 'summary': {'message': '1 full osd(s)'}}}},
        'quorum_names': ['a', 'b'],
        'monmap': {'mons': [{'name': 'a'}, {'name': 'b'}, {'name': 'c'}]},
        'osdmap': {'osdmap': {'num_osds': 3, 'num_up_osds': 2, 'num_in_osds': 3}},
        'pgmap': {'pgs_by_state': [{'state_name': 'active+clean', 'count': 88},
                                   {'state_name': 'active+undersized+degraded', 'count': 40}],
                  'num_pgs': 128, 'bytes_used': 900 * GiB, 'bytes_total': 1000 * GiB,
                  'bytes_avail': 100 * GiB, 'recovering_bytes_per_sec': 5242880}}


@pytest.fixture
def hci(api, seed):
    c1 = api.set_manager('c1', _Pve('Testi', paths={CEPH: (200, _ceph_ok())}))
    c2 = api.set_manager('c2', _Pve('Branch', paths={CEPH: (200, _ceph_warn())}))
    # no Ceph: the API host and each node say so
    c3 = api.set_manager('c3', _Pve('Plain', paths={CEPH: (500, None)}))
    c4 = api.set_manager('c4', _Pve('Silent', paths={CEPH: TimeoutError('read timed out')}))
    c5 = api.set_manager('c5', _Pve('Cold', paths={CEPH: (200, _ceph_ok())}, connected=False))
    x1 = api.set_manager('x1', _Pve('Xen', cluster_type='xcpng'))
    return types.SimpleNamespace(api=api, seed=seed, c1=c1, c2=c2, c3=c3, c4=c4, c5=c5, x1=x1)


def _ceph(client):
    r = client.get('/api/ceph-overview')
    return r.status_code, r.get_json()


def test_the_admin_sees_the_ceph_of_every_cluster(hci):
    code, body = _ceph(hci.api.as_user(hci.seed.user('root', role='admin')))
    assert code == 200, body
    assert _states(body) == [('c2', 'ok'), ('c5', 'offline'), ('c3', 'none'), ('c4', 'unreadable'), ('c1', 'ok')]
    assert [r['cluster_id'] for r in body['ceph']] == ['c2', 'c1']
    branch, testi = body['ceph']
    assert (testi['health'], testi['checks'], testi['checks_more']) == ('HEALTH_OK', [], 0)
    assert testi['osds'] == {'total': 6, 'up': 6, 'in': 6}
    assert testi['pgs'] == {'total': 129, 'clean': 129, 'states': [
        {'state': 'active+clean', 'count': 120}, {'state': 'active+clean+scrubbing+deep', 'count': 9}]}
    assert testi['bytes'] == {'used': 300 * GiB, 'avail': 2700 * GiB, 'total': 3000 * GiB}
    assert testi['percent'] == 10.0 and testi['mons'] == {'total': 3, 'quorum': 3}
    assert testi['io'] == {'read_bps': 1048576, 'write_bps': 2097152, 'read_iops': 50, 'write_iops': 120,
                           'recovery_bps': 0}
    assert isinstance(testi['read_at'], int) and testi['cluster_name'] == 'Testi'
    # the worst check first, and what a Ceph before Quincy answers reads the same
    assert [c['name'] for c in branch['checks']] == ['OSD_FULL', 'MON_DOWN', 'PG_DEGRADED']
    assert branch['checks'][0] == {'name': 'OSD_FULL', 'severity': 'HEALTH_ERR', 'message': '1 full osd(s)'}
    assert branch['osds'] == {'total': 3, 'up': 2, 'in': 3} and branch['mons'] == {'total': 3, 'quorum': 2}
    assert (branch['pgs']['total'], branch['pgs']['clean'], branch['percent']) == (128, 88, 90.0)
    assert branch['io']['recovery_bps'] == 5242880
    # one read per cluster; the offline one and the XCP-ng pool not asked at all
    assert hci.c1.calls == [CEPH] and hci.c2.calls == [CEPH] and hci.c5.calls == hci.x1.calls == []
    # without Ceph the nodes were asked once too (#191)
    assert hci.c3.calls == [CEPH, '/nodes/pve1/ceph/status', '/nodes/pve2/ceph/status']


def test_the_alert_and_the_overview_share_the_read(hci):
    c = hci.api.as_user(hci.seed.user('root', role='admin'))
    _ceph(c)
    _ceph(c)
    now = time.time()
    assert alert_events._read_ceph('c1', hci.c1, now)['health']['status'] == 'HEALTH_OK'
    assert hci.c1.count(CEPH) == 1
    # a cluster without Ceph is not asked again before CEPH_RETRY, a silent one each time
    assert len(hci.c3.calls) == 3 and hci.c4.count(CEPH) == 2
    # once the read is older than CEPH_FRESH it is read again, and a change shows
    hci.c1.paths[CEPH] = (200, _ceph_warn())
    st = alert_events._ceph['c1']
    st['last'] = (st['last'][0] - alert_events.CEPH_FRESH - 1, st['last'][1])
    code, body = _ceph(c)
    assert hci.c1.count(CEPH) == 2
    assert {r['cluster_id']: r['health'] for r in body['ceph']}['c1'] == 'HEALTH_WARN'


def test_ceph_that_stops_answering_says_so(hci):
    c = hci.api.as_user(hci.seed.user('root', role='admin'))
    _ceph(c)
    hci.c1.paths[CEPH] = (500, None)
    alert_events._ceph['c1']['last'] = None
    code, body = _ceph(c)
    assert ('c1', 'unreadable') in _states(body) and 'c1' not in [r['cluster_id'] for r in body['ceph']]
    # it had one: the page keeps the panel for it. The silent one never answered, the plain one has none
    had = {e['cluster_id']: e.get('had_ceph') for e in body['clusters']}
    assert (had['c1'], had['c4'], had['c3'], had['c2']) == (True, False, False, None)


def test_without_cluster_view_nothing_is_read(hci):
    c = hci.api.as_user(hci.seed.user('plain', role='user', denied=['cluster.view']))
    r = c.get('/api/ceph-overview')
    assert r.status_code == 403 and r.get_json()['required'] == 'cluster.view'
    assert hci.c1.calls == [] and hci.api.anon().get('/api/ceph-overview').status_code == 401


def test_a_viewer_of_the_owning_tenant_sees_its_ceph(hci):
    hci.seed.tenant('acme', ['c1'])
    code, body = _ceph(hci.api.as_user(hci.seed.user('v', role='viewer', tenant_id='acme')))
    assert code == 200 and _states(body) == [('c1', 'ok')] and len(body['ceph']) == 1
    assert hci.c2.calls == []


def test_a_pool_confined_user_sees_no_ceph(hci):
    from test_audit_bola_high_2026_09 import _seed_pool_membership
    hci.seed.tenant('t_confined', [])
    hci.seed.pool('c1', 'pool1', 'pooled', ['vm.view'])
    _seed_pool_membership('c1', {102: ('lxc', 'pool1')})
    code, body = _ceph(hci.api.as_user(hci.seed.user('pooled', role='user', tenant_id='t_confined')))
    assert code == 200, body
    assert _states(body) == [('c1', 'confined')] and body['ceph'] == [] and hci.c1.calls == []


def test_a_portal_user_of_the_owning_tenant_sees_no_ceph(hci):
    hci.seed.tenant('acme', ['c1'])
    hci.seed.vm_acl('c1', 103, users=['portal'])
    code, body = _ceph(hci.api.as_user(hci.seed.user('portal', role='user', tenant_id='acme')))
    assert code == 200 and _states(body) == [('c1', 'confined')] and body['ceph'] == []


def test_a_confined_admin_sees_their_tenant_only(hci):
    hci.seed.tenant('globex', ['c2'])
    c = hci.api.as_user(hci.seed.user('gx', role='admin', tenant_id='globex',
                                      tenant_permissions={'globex': {'role': 'user'}}))
    code, body = _ceph(c)
    assert code == 200 and _states(body) == [('c2', 'ok')] and [r['cluster_id'] for r in body['ceph']] == ['c2']
    assert hci.c1.calls == []


def test_another_tenant_sees_nothing_of_the_ceph(hci):
    hci.seed.tenant('acme', ['c1'])
    hci.seed.tenant('initech', ['c2'])
    code, body = _ceph(hci.api.as_user(hci.seed.user('milton', role='user', tenant_id='initech')))
    assert code == 200 and _states(body) == [('c2', 'ok')] and hci.c1.calls == []


def test_a_standby_shows_ceph_and_writes_nothing(ha_env, seed, db):  # noqa: F811
    api = ha_env.api
    m = api.set_manager('c1', _Pve('Testi', paths={CEPH: (200, _ceph_ok())}))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    before = db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    code, body = _ceph(c)
    assert code == 200 and [r['health'] for r in body['ceph']] == ['HEALTH_OK']
    assert m.calls == [CEPH]
    assert db.conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0] == before


def test_odd_answers_do_not_break_the_figures():
    empty = ceph_rollup({})
    assert empty['health'] == 'unknown' and empty['percent'] is None
    assert empty['osds'] == {'total': 0, 'up': 0, 'in': 0} and empty['pgs'] == {'total': 0, 'clean': 0, 'states': []}
    odd = ceph_rollup({'health': {'overall_status': 'HEALTH_WARN', 'checks': {'X': 'not a dict'}},
                       'osdmap': [], 'pgmap': {'pgs_by_state': [None, {'state_name': 'peering', 'count': 'x'}],
                                               'bytes_total': -5, 'read_bytes_sec': 'NaN'}})
    assert odd['health'] == 'HEALTH_WARN' and odd['checks'] == [{'name': 'X', 'severity': '', 'message': ''}]
    assert odd['pgs']['states'] == [{'state': 'peering', 'count': 0}] and odd['percent'] is None
    many = ceph_rollup({'health': {'checks': {f'C{i:02d}': {'severity': 'HEALTH_WARN'} for i in range(12)}}})
    assert len(many['checks']) == 8 and many['checks_more'] == 4
