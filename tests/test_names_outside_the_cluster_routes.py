"""Names that reach an API path from routes the request hook does not look at.

The hook checks the names of the /api/clusters/<cluster_id>/ routes. The cross-cluster
migration, the replication jobs, the cross-hypervisor moves, the scheduled tasks, the
recovery plans, the PBS backup diff and the bulk snapshot delete take a node, a guest type,
a VMID or a datastore in their body or query too, and put it into the API path of a
cluster, at once or at every later run. Each of them takes a name only now, checked on the
cluster that name belongs to: an XCP-ng host keeps its free name.
MK Nov 2026
"""
import json
import types
from unittest.mock import MagicMock, create_autospec

import pytest
import requests
from requests.adapters import HTTPAdapter

import pegaprox.globals as ppglobals
from pegaprox.core.manager import PegaProxManager
from pegaprox.core.xcpng import XcpngManager


class _Rec(HTTPAdapter):
    """Records the request line and answers like a small PVE."""
    def __init__(self):
        super().__init__()
        self.sent = []

    def send(self, request, **kw):
        self.sent.append((request.method, request.path_url))
        r = requests.Response()
        r.status_code = 200
        r._content = json.dumps({'data': 'UPID:n1:1:2:3:x:100:root@pam:' if request.method != 'GET'
                                 else []}).encode()
        r.request = request
        return r


def _pve(api, cid):
    pm = PegaProxManager.__new__(PegaProxManager)
    pm._api_token, pm._ticket, pm._csrf_token, pm._ssl_verify = None, 'TICKET', 'CSRF', False
    s = pm._create_session()
    rec = _Rec()
    s.mount('https://', rec)
    m = api.make_fake_manager(cluster_id=cid)
    m.is_connected = True
    m.host, m.api_port = '10.0.0.1', 8006
    m.config = types.SimpleNamespace(name=cid, host='10.0.0.1', user='root@pam')
    m._create_session.return_value = s
    for verb in ('get', 'post', 'delete'):
        getattr(m, f'_api_{verb}').side_effect = (lambda v: lambda url, **kw: getattr(s, v)(url, **kw))(verb)
    api.set_manager(cid, m)
    m.rec = rec
    return m


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root_adm', role='admin'))


def _refused(r, what):
    assert r.status_code == 400 and r.get_json() == {'error': what}, (r.status_code, r.get_data(as_text=True))


ELSEWHERE = ['n1/qemu/200/remote_migrate?x=', 'n1/qemu/200/config#', 'n1%2Fqemu%2F200']


# --- the cross-cluster migration ------------------------------------------------------------

@pytest.fixture
def two_clusters(api, monkeypatch):
    src = _pve(api, 'cluster_1')
    src.get_vm_config = types.MethodType(PegaProxManager.get_vm_config, src)
    tgt = api.make_fake_manager(cluster_id='cluster_2')
    tgt.config = types.SimpleNamespace(name='cluster_2', host='10.0.1.1', user='root@pam')
    tgt.create_api_token.return_value = {'success': False, 'error': 'the test ends here'}
    api.set_manager('cluster_2', tgt)
    # what the preflight would judge is not asked here
    monkeypatch.setattr('pegaprox.api.vms._cross_preflight_for', lambda *a, **k: ({'guests': [{}]}, None))
    return src, tgt


def _migrate(admin, **over):
    body = {'source_cluster': 'cluster_1', 'target_cluster': 'cluster_2', 'vmid': 100,
            'vm_type': 'qemu', 'source_node': 'pve-01', 'target_node': 'pve-02',
            'target_storage': 'local-lvm', 'delete_source': False}
    return admin.post('/api/cross-cluster-migrate', json=dict(body, **over))


@pytest.mark.parametrize('node', ELSEWHERE)
def test_a_cross_cluster_migration_from_a_node_that_is_no_name_sends_nothing(admin, two_clusters, node):
    src, tgt = two_clusters
    _refused(_migrate(admin, source_node=node), 'Invalid node name')
    assert src.rec.sent == [] and not tgt.create_api_token.called
    # counterproof: the source node's name is read and the migration goes on to the target
    _migrate(admin)
    assert src.rec.sent[0] == ('GET', '/api2/json/nodes/pve-01/qemu/100/config')
    assert tgt.create_api_token.called


def test_a_cross_cluster_migration_takes_one_of_the_two_guest_types(admin, two_clusters):
    src, _tgt = two_clusters
    _refused(_migrate(admin, vm_type='qemu/200/status/stop?'), 'vm_type is qemu or lxc')
    assert src.rec.sent == []


# --- the replication jobs --------------------------------------------------------------------

@pytest.fixture
def repl(api):
    for cid in ('cluster_1', 'cluster_2'):
        m = api.make_fake_manager(cluster_id=cid)
        m.config = types.SimpleNamespace(name=cid)
        api.set_manager(cid, m)


def _repl(admin, **over):
    body = {'source_cluster': 'cluster_1', 'target_cluster': 'cluster_2', 'vmid': 100,
            'vm_type': 'qemu', 'target_node': 'pve-02', 'target_storage': 'local-lvm'}
    return admin.post('/api/cross-cluster-replications', json=dict(body, **over))


def _stored_jobs(seed):
    return seed.db.conn.execute('SELECT vm_type, target_node, target_storage FROM cross_cluster_replications').fetchall()


@pytest.mark.parametrize('over,what', [
    ({'vm_type': 'qemu/200/status/stop?'}, 'vm_type is qemu or lxc'),
    ({'target_node': 'n2/qemu/200?x='}, 'Invalid node name'),
    ({'source_node': 'n1/qemu/200#'}, 'Invalid node name'),
    # a comma adds options to the replica's disk lines
    ({'target_storage': 'local-lvm,cache=unsafe'}, 'Invalid storage name'),
    ({'target_storage': 'local/x?'}, 'Invalid storage name'),
])
def test_a_replication_job_keeps_names_only(admin, seed, repl, over, what):
    _refused(_repl(admin, **over), what)
    assert _stored_jobs(seed) == []
    # counterproof: names as Proxmox VE gives them are stored
    r = _repl(admin, vm_type='lxc', source_node='pve-01', target_node='pve-02.lab', target_storage='ceph_pool.1')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [tuple(row) for row in _stored_jobs(seed)] == [('lxc', 'pve-02.lab', 'ceph_pool.1')]


def test_a_replication_onto_an_xcpng_pool_keeps_its_host_name(admin, api, repl):
    api.set_manager('cluster_2', api.make_fake_manager(cluster_id='cluster_2', cluster_type='xcpng'))
    r = _repl(admin, target_node='xen host #1', target_storage='')
    assert r.get_json() != {'error': 'Invalid node name'}, r.get_data(as_text=True)


# --- the cross-hypervisor moves ------------------------------------------------------------------

@pytest.fixture
def xhm(api, monkeypatch):
    started = []
    for name in ('_run_pve_to_xcpng', '_run_xcpng_to_pve'):
        monkeypatch.setattr(f'pegaprox.api.xhm.{name}', lambda task: started.append(task))
    planned = []
    monkeypatch.setattr('pegaprox.api.xhm.plan_pve_to_xcpng',
                        lambda cid, node, vmid, tgt: planned.append(node) or {'source': {}})
    api.set_manager('cluster_1', api.make_fake_manager(cluster_id='cluster_1'))
    api.set_manager('pool_x', api.make_fake_manager(cluster_id='pool_x', cluster_type='xcpng'))
    before = set(ppglobals._xhm_migrations)
    yield types.SimpleNamespace(started=started, planned=planned)
    for mid in set(ppglobals._xhm_migrations) - before:
        ppglobals._xhm_migrations.pop(mid, None)


@pytest.mark.parametrize('node', ELSEWHERE)
def test_a_move_from_proxmox_ve_names_the_source_node(admin, xhm, node):
    body = {'source_cluster': 'cluster_1', 'source_vmid': 100, 'target_cluster': 'pool_x',
            'target_storage': 'local-sr'}
    _refused(admin.post('/api/xhm/migrate', json=dict(body, source_node=node)), 'Invalid node name')
    _refused(admin.get('/api/xhm/plan', query_string={'source_cluster': 'cluster_1', 'source_vmid': 100,
                                                      'target_cluster': 'pool_x', 'source_node': node}),
             'Invalid node name')
    assert xhm.planned == []
    assert not any(t.source_node == node for t in ppglobals._xhm_migrations.values())
    # counterproof: the node's name starts the move and the plan
    r = admin.post('/api/xhm/migrate', json=dict(body, source_node='pve-01'))
    assert r.status_code == 202, r.get_data(as_text=True)
    r = admin.get('/api/xhm/plan', query_string={'source_cluster': 'cluster_1', 'source_vmid': 100,
                                                 'target_cluster': 'pool_x', 'source_node': 'pve-01'})
    assert xhm.planned == ['pve-01']


def test_a_move_onto_proxmox_ve_names_the_target_node(admin, xhm):
    body = {'source_cluster': 'pool_x', 'source_vmid': 100, 'target_cluster': 'cluster_1',
            'target_storage': 'local-lvm', 'source_node': 'xen host #1'}
    _refused(admin.post('/api/xhm/migrate', json=dict(body, target_node='n1/qemu?')), 'Invalid node name')
    assert not any(t.target_node == 'n1/qemu?' for t in ppglobals._xhm_migrations.values())
    # the XCP-ng host keeps its free name, the Proxmox VE node is a name
    r = admin.post('/api/xhm/migrate', json=dict(body, target_node='pve-02'))
    assert r.status_code == 202, r.get_data(as_text=True)
    assert r.get_json()['task']['target_node'] == 'pve-02'


# --- the scheduled tasks ---------------------------------------------------------------------

@pytest.fixture
def tasks(api, seed):
    seed.db.execute('''INSERT INTO clusters (id, name, host, user, pass_encrypted)
                       VALUES ('cluster_1', 'cluster_1', '10.0.0.1', 'root@pam', 'x')''')
    api.set_manager('cluster_1', create_autospec(PegaProxManager, instance=True))
    return api.as_user(seed.user('root', role='admin'))


def _task(client, **over):
    body = {'name': 'nightly', 'cluster_id': 'cluster_1', 'target_type': 'qemu', 'target_id': '101',
            'target_node': 'pve1', 'action': 'snapshot'}
    return client.post('/api/scheduled-tasks', json=dict(body, **over))


@pytest.mark.parametrize('over,what', [
    ({'target_node': 'pve1/qemu/200/snapshot?x='}, 'Invalid node name'),
    ({'target_node': 'pve1#'}, 'Invalid node name'),
    ({'target_type': 'qemu/200/snapshot?x='}, 'Invalid guest type'),
])
def test_a_scheduled_snapshot_on_proxmox_ve_keeps_names_only(tasks, over, what):
    _refused(_task(tasks, **over), what)
    assert tasks.get('/api/scheduled-tasks').get_json()['tasks'] == []
    r = _task(tasks)
    assert r.status_code == 201, r.get_data(as_text=True)
    # and an edit is held to the same names
    _refused(tasks.put(f"/api/scheduled-tasks/{r.get_json()['id']}", json=over), what)


def test_a_scheduled_task_on_xcpng_keeps_its_host_name(api, tasks):
    m = create_autospec(XcpngManager, instance=True)
    m.cluster_type = 'xcpng'
    api.set_manager('cluster_1', m)
    r = _task(tasks, target_node='xen host #1')
    assert r.status_code == 201, r.get_data(as_text=True)


# --- the recovery plans ----------------------------------------------------------------------

def test_a_recovery_plan_guest_is_one_of_the_two_guest_types(api, seed, admin):
    for cid in ('cluster_1', 'cluster_2'):
        api.set_manager(cid, api.make_fake_manager(cluster_id=cid))
    seed.db.conn.execute(
        "INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, created_at) "
        "VALUES ('plan_1', 'g1', 'dr', 'cluster_1', 'cluster_2', '2026-01-01')")
    seed.db.conn.commit()
    url = '/api/site-recovery/plans/plan_1/vms'
    _refused(admin.post(url, json={'vmid': 100, 'vm_type': 'lxc/200/status/stop?'}), 'vm_type is qemu or lxc')
    rows = lambda: seed.db.conn.execute('SELECT vmid, vm_type FROM site_recovery_vms').fetchall()  # noqa: E731
    assert rows() == []
    r = admin.post(url, json={'vmid': 100, 'vm_type': 'lxc'})
    assert r.status_code == 201, r.get_data(as_text=True)
    assert [tuple(x) for x in rows()] == [(100, 'lxc')]


# --- the PBS backup diff ---------------------------------------------------------------------

def test_a_backup_diff_of_a_datastore_that_is_no_name_sends_nothing(admin):
    from pegaprox.core.pbs import PBSManager
    sent = []
    pm = MagicMock()
    pm.connected = True
    pm.linked_clusters = []
    pm.api_get.side_effect = lambda path, **kw: sent.append(path) or {'data': []}
    pm.get_snapshots = types.MethodType(PBSManager.get_snapshots, pm)
    ppglobals.pbs_managers['pbs1'] = pm
    try:
        q = {'type': 'vm', 'id': '100', 'a': '2026-11-01T03:00:00Z', 'b': '2026-11-08T03:00:00Z'}
        for store in ('ds1/groups?x=', 'ds1#', 'ds1%2Fx'):
            _refused(admin.get('/api/pbs/pbs1/backup-diff', query_string=dict(q, store=store)),
                     'Invalid datastore name')
        assert sent == []
        r = admin.get('/api/pbs/pbs1/backup-diff', query_string=dict(q, store='backup-store_1'))
        assert r.status_code == 404, r.get_data(as_text=True)      # no such snapshots, asked
        assert sent == ['/admin/datastore/backup-store_1/snapshots']
    finally:
        ppglobals.pbs_managers.pop('pbs1', None)


# --- the bulk snapshot delete ----------------------------------------------------------------

@pytest.mark.parametrize('field,value', [('vmid', '200/snapshot/before?'), ('node', 'n1/qemu/200#'),
                                         ('vm_type', 'qemu/200'), ('snapshot_name', 'a/b')])
def test_a_bulk_snapshot_delete_names_each_snapshot(api, admin, field, value):
    m = _pve(api, 'cluster_1')
    m.delete_snapshot = types.MethodType(PegaProxManager.delete_snapshot, m)
    item = {'cluster_id': 'cluster_1', 'node': 'n1', 'vmid': 100, 'vm_type': 'qemu', 'snapshot_name': 's1'}
    r = admin.post('/api/snapshots/delete', json={'snapshots': [dict(item, **{field: value})]})
    assert r.get_json()['success'] is False, r.get_data(as_text=True)
    assert m.rec.sent == []
    r = admin.post('/api/snapshots/delete', json={'snapshots': [item]})
    assert r.get_json()['deleted'] == 1, r.get_data(as_text=True)
    assert m.rec.sent == [('DELETE', '/api2/json/nodes/n1/qemu/100/snapshot/s1')]
