"""What a confined account reads of the cluster's nodes, storage and Ceph (#1218).

check_cluster_access gates reachability, and a VM-ACL or a pool grant on one guest answers
it. The node reads (/metrics, /nodes, /nodes-status, /node-progress) then listed every node
of the cluster with its load, versions and fingerprint, the storage reads every storage
definition with its servers, exports and users, and the Ceph reads the fsid, the monitors and
ceph.conf. Only the guests of a node in maintenance were cut.

Now a confined caller (a VM-ACL user of the owning tenant - the Client Portal case -, a pool
user of another tenant, an admin a tenant override lowers who reaches the cluster through an
ACL) gets the nodes their own guests run on, reads storage of those nodes only, and is
refused the whole-cluster storage and Ceph reads before the cluster is asked. Moving a guest
keeps to those nodes too, as clone and restore do (#1081).

Every test has its mirror: an operator of the owning tenant and the admin see all of it.

MK Nov 2026
"""
import json
import time
from datetime import datetime

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.core.manager import UnreadList
from pegaprox.models.tasks import MaintenanceTask

CID = 'cluster_1'
BASE = f'/api/clusters/{CID}'
# 100 and 101 are the confined callers' guests, 200 is somebody else's on n2
GUESTS = [{'vmid': 100, 'node': 'n1', 'type': 'qemu', 'name': 'portal-web'},
          {'vmid': 101, 'node': 'n3', 'type': 'qemu', 'name': 'portal-db'},
          {'vmid': 200, 'node': 'n2', 'type': 'qemu', 'name': 'other-app'}]
THEIRS = {'n1', 'n3'}
ALL = {'n1', 'n2', 'n3'}
CONFINED = ('acl_user', 'pool_user', 'lowered_admin')
WHOLE = ('operator', 'admin')


def _pool_member(mapping):
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': mapping, 'timestamp': time.time(),
                                            'refreshing': False}


def _who(api, seed):
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['other'])
    seed.tenant('t_pool', clusters=[])
    for vmid in (100, 101):
        seed.vm_acl(CID, vmid, users=['portal', 'gx'])
    seed.vm_acl(CID, 200, users=['someone_else'])
    seed.pool(CID, 'pool1', 'pooled', ['vm.view', 'vm.migrate'])
    _pool_member({'100:qemu': 'pool1', '101:qemu': 'pool1'})
    users = {
        'acl_user': seed.user('portal', role='user', tenant_id='acme'),
        'pool_user': seed.user('pooled', role='user', tenant_id='t_pool'),
        'lowered_admin': seed.user('gx', role='admin', tenant_id='globex',
                                   tenant_permissions={'globex': {'role': 'user'}}),
        'operator': seed.user('ops', role='user', tenant_id='acme'),
        'admin': seed.user('root', role='admin'),
    }
    return {k: api.as_user(u) for k, u in users.items()}


def _node_status():
    return {n: {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'pveversion': f'pve-{n}',
                'maintenance_mode': False, 'maintenance_task': None, 'offline': False}
            for n in sorted(ALL)}


def _resp(status, data):
    from unittest.mock import MagicMock
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {'data': data}
    r.text = ''
    return r


def _task(node):
    t = MaintenanceTask(node)
    t.started_at = datetime(2026, 11, 4, 1, 0, 0)
    t.status = 'evacuating'
    t.total_vms, t.migrated_vms = 3, 1
    t.failed_vms = [{'vmid': 987104, 'name': 'db-secret-04', 'error': 'Migration failed'}]
    return t


@pytest.fixture
def mgr(api):
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.host, m.api_port = '192.0.2.10', 8006
    m.get_node_status.return_value = _node_status()
    m.get_vm_resources.return_value = list(GUESTS)
    m.nodes_in_maintenance = {}
    m.nodes_updating = {}
    m.ha_node_status = {}
    m._cached_metrics = None
    m._cached_nodes = None
    m._create_session.return_value.get.return_value = _resp(200, [
        {'node': n, 'status': 'online', 'cpu': 0.05, 'mem': 1, 'maxmem': 4,
         'ssl_fingerprint': f'AA:{n}'} for n in sorted(ALL)])
    m.get_storage_list.return_value = [{'storage': 'local-lvm', 'type': 'lvmthin'}]
    m._api_get.return_value = _resp(200, {'uuid': 'pbs-uuid'})
    m.migrate_vm_manual.return_value = {'success': True, 'upid': 'UPID:n1:migrate'}
    m.config.host, m.config.name = 'n1.example', CID
    m._get_node_ip.return_value = None       # the starlvm probe connects nowhere
    return api.set_manager(CID, m)


@pytest.fixture
def who(api, seed, mgr):
    return _who(api, seed)


# --- the node reads: a confined caller gets the nodes their guests run on -------------------

def _metrics_nodes(r):
    return set(r.get_json())


def _list_nodes(r):
    return {n['node'] for n in r.get_json()}


CUT = {
    'metrics': (f'{BASE}/metrics', _metrics_nodes),
    'nodes': (f'{BASE}/nodes', _list_nodes),
    'nodes-status': (f'{BASE}/nodes-status', _list_nodes),
    'node-progress': (f'{BASE}/node-progress', lambda r: set(r.get_json()['nodes'])),
}


def _all_in_maintenance(mgr):
    mgr.nodes_in_maintenance = {n: _task(n) for n in sorted(ALL)}


@pytest.mark.parametrize('route', sorted(CUT))
@pytest.mark.parametrize('kind', CONFINED)
def test_a_confined_caller_reads_the_nodes_of_their_guests_only(who, mgr, kind, route):
    _all_in_maintenance(mgr)
    path, nodes_of = CUT[route]
    r = who[kind].get(path)
    assert r.status_code == 200, (kind, route, r.data)
    assert nodes_of(r) == THEIRS, (kind, route, r.get_json())
    assert 'AA:n2' not in r.get_data(as_text=True) and 'pve-n2' not in r.get_data(as_text=True)


@pytest.mark.parametrize('route', sorted(CUT))
@pytest.mark.parametrize('kind', WHOLE)
def test_an_operator_and_the_admin_still_read_every_node(who, mgr, kind, route):
    _all_in_maintenance(mgr)
    path, nodes_of = CUT[route]
    r = who[kind].get(path)
    assert r.status_code == 200, (kind, route, r.data)
    assert nodes_of(r) == ALL, (kind, route, r.get_json())


def test_a_maintenance_on_their_node_comes_without_the_guests(who, mgr):
    _all_in_maintenance(mgr)
    mgr.get_node_status.return_value = {n: dict(v, maintenance_mode=True,
                                                maintenance_task=_task(n).to_dict())
                                        for n, v in _node_status().items()}
    for path in (f'{BASE}/metrics', f'{BASE}/node-progress'):
        body = who['acl_user'].get(path).get_json()
        task = (body.get('nodes') or body)['n1']['maintenance_task']
        assert task['status'] == 'evacuating' and 'failed_vms' not in task, path
        full = who['operator'].get(path).get_json()
        assert (full.get('nodes') or full)['n2']['maintenance_task']['failed_vms'], path


def test_the_cut_leaves_the_managers_cache_whole(who, mgr):
    shared = mgr.get_node_status.return_value
    assert _metrics_nodes(who['acl_user'].get(f'{BASE}/metrics')) == THEIRS
    assert set(shared) == ALL and set(mgr._cached_metrics) == ALL
    who['acl_user'].get(f'{BASE}/nodes')
    assert {n['node'] for n in mgr._cached_nodes} == ALL


@pytest.mark.parametrize('kind', CONFINED)
def test_the_fallbacks_of_metrics_are_cut_as_well(who, mgr, kind):
    """Live, from the manager's last answer and from the HA node cache."""
    who['admin'].get(f'{BASE}/metrics')          # fills _cached_metrics
    mgr.is_connected = False
    assert _metrics_nodes(who[kind].get(f'{BASE}/metrics')) == THEIRS
    assert _metrics_nodes(who['operator'].get(f'{BASE}/metrics')) == ALL
    mgr._cached_metrics = None
    mgr.ha_node_status = {n: {'status': 'online'} for n in sorted(ALL)}
    r = who[kind].get(f'{BASE}/metrics')
    assert _metrics_nodes(r) == THEIRS and all(v['from_ha_cache'] for v in r.get_json().values())
    assert _metrics_nodes(who['operator'].get(f'{BASE}/metrics')) == ALL


@pytest.mark.parametrize('source', ['live', 'cached', 'ha_cache', 'xcpng'])
def test_every_answer_of_the_node_list_is_cut(who, mgr, source):
    if source != 'live':
        mgr._create_session.return_value.get.side_effect = ConnectionError('down')
    if source == 'cached':
        mgr._cached_nodes = [{'node': n, 'status': 'online'} for n in sorted(ALL)]
    elif source == 'ha_cache':
        mgr.ha_node_status = {n: {'status': 'online'} for n in sorted(ALL)}
    elif source == 'xcpng':
        mgr.cluster_type = 'xcpng'
        mgr.get_nodes.return_value = [{'node': n, 'type': 'node'} for n in sorted(ALL)]
    for kind in CONFINED:
        r = who[kind].get(f'{BASE}/nodes')
        assert r.status_code == 200 and _list_nodes(r) == THEIRS, (kind, r.get_json())
    assert _list_nodes(who['operator'].get(f'{BASE}/nodes')) == ALL


def test_a_guest_that_moves_takes_the_node_along(who, mgr):
    mgr.get_vm_resources.return_value = [dict(GUESTS[0], node='n2')] + GUESTS[1:]
    assert _metrics_nodes(who['acl_user'].get(f'{BASE}/metrics')) == {'n2', 'n3'}


# --- one node: the storage dialogs of the caller's own guest keep working --------------------

PER_NODE = {
    'storage': ('/nodes/{node}/storage', 'get_storage_list'),
    'identity': ('/nodes/{node}/storage/pbs1/identity', '_api_get'),
}


@pytest.mark.parametrize('route', sorted(PER_NODE))
@pytest.mark.parametrize('kind', CONFINED)
def test_a_confined_caller_reads_storage_of_their_own_nodes_only(who, mgr, kind, route):
    path, method = PER_NODE[route]
    r = who[kind].get(BASE + path.format(node='n2'))
    assert r.status_code == 403, (kind, route, r.data)
    assert 'none of your guests' in r.get_json()['error']
    assert not getattr(mgr, method).called
    for node in sorted(THEIRS):
        r = who[kind].get(BASE + path.format(node=node))
        assert r.status_code == 200, (kind, route, node, r.data)
    assert getattr(mgr, method).call_count == len(THEIRS)


@pytest.mark.parametrize('route', sorted(PER_NODE))
@pytest.mark.parametrize('kind', WHOLE)
def test_an_operator_reads_storage_of_any_node(who, mgr, kind, route):
    path, method = PER_NODE[route]
    r = who[kind].get(BASE + path.format(node='n2'))
    assert r.status_code == 200, (kind, route, r.data)
    assert getattr(mgr, method).called


# --- whole-cluster storage and Ceph: refused before the cluster is asked ---------------------

REFUSED = [
    '/datacenter/storage',
    '/datastores',
    '/datacenter/storage/nfs1',
    '/datacenter/storage/nfs1/status',
    '/storage-clusters',
    '/iso-sync/status',
    '/iso-sync/last-result',
    '/storage/starlvm/status',
    '/datacenter/ceph',
    # n1 runs one of their guests: the refusal is about Ceph, not about the node
    '/nodes/n1/ceph/status',
    '/nodes/n1/ceph/config',
    '/nodes/n1/ceph/osd',
    '/nodes/n1/ceph/mon',
    '/nodes/n1/ceph/mds',
    '/nodes/n1/ceph/mgr',
    '/nodes/n1/ceph/pool',
    '/nodes/n1/ceph/fs',
    '/nodes/n1/ceph/rules',
]


@pytest.fixture
def storage_state(mgr):
    """A storage group and a datastores answer of somebody else's call in the shared cache,
    so a refusal is not just an empty store."""
    import pegaprox.api.storage as storagemod
    import pegaprox.api.vms as vmsmod
    storagemod.storage_clusters_config[CID] = {'clusters': [{'id': 'sc1', 'name': 'secret-group'}]}
    vmsmod._datastores_cache[CID] = (time.time(), {'shared': [{'storage': 'secret-nfs'}], 'local': {}})
    mgr._sync_last_result = {'synced': ['secret.iso']}
    mgr.get_content_sync_status.return_value = {'isos': [{'name': 'secret.iso'}]}
    try:
        yield
    finally:
        storagemod.storage_clusters_config.pop(CID, None)
        vmsmod._datastores_cache.pop(CID, None)


@pytest.mark.parametrize('route', REFUSED)
def test_a_confined_caller_is_refused_the_whole_cluster_storage_and_ceph(who, mgr, storage_state, route):
    for kind in CONFINED:
        r = who[kind].get(BASE + route)
        assert r.status_code == 403, (kind, route, r.data)
        assert 'secret' not in r.get_data(as_text=True), (kind, route)
    # not one call on the manager: no PVE read, no SSH probe
    assert mgr.mock_calls == [], (route, mgr.mock_calls[:3])


@pytest.mark.parametrize('route', REFUSED)
def test_an_operator_and_the_admin_still_read_it(who, mgr, storage_state, route):
    for kind in WHOLE:
        r = who[kind].get(BASE + route)
        assert r.status_code != 403, (kind, route, r.data)
        assert 'whole cluster' not in r.get_data(as_text=True), (kind, route)


def test_the_datastores_cache_serves_the_whole_cluster_only(who, mgr, storage_state):
    r = who['operator'].get(f'{BASE}/datastores')
    assert r.status_code == 200 and r.get_json()['shared'][0]['storage'] == 'secret-nfs'
    assert who['acl_user'].get(f'{BASE}/datastores').status_code == 403


# --- moving a guest: onto a node their guests run on, as clone and restore -------------------

def _migrate(client, target, vmid=100, node='n1'):
    return client.post(f'{BASE}/vms/{node}/qemu/{vmid}/migrate', json={'target': target, 'online': True})


@pytest.mark.parametrize('kind', CONFINED)
def test_a_confined_caller_migrates_only_onto_a_node_of_their_guests(who, mgr, kind):
    r = _migrate(who[kind], 'n2')
    assert r.status_code == 403 and 'node' in r.get_json()['error'], (kind, r.data)
    assert not mgr.migrate_vm_manual.called
    r = _migrate(who[kind], 'n3')
    assert r.status_code == 200, (kind, r.data)
    assert mgr.migrate_vm_manual.call_args[0][3] == 'n3'


def test_the_migrate_target_is_asked_on_a_fresh_guest_list(who, mgr):
    """The snapshot of a moment ago still has 101 on n3; the cluster has it on n1 by now."""
    moved = [GUESTS[0], dict(GUESTS[1], node='n1'), GUESTS[2]]
    mgr.get_vm_resources.side_effect = lambda max_age=0: list(GUESTS) if max_age else moved
    r = _migrate(who['acl_user'], 'n3')
    assert r.status_code == 403, r.data
    assert not mgr.migrate_vm_manual.called


@pytest.mark.parametrize('kind', WHOLE)
def test_an_operator_migrates_onto_any_node(who, mgr, kind):
    r = _migrate(who[kind], 'n2')
    assert r.status_code == 200, (kind, r.data)
    assert mgr.migrate_vm_manual.call_args[0][3] == 'n2'


@pytest.mark.parametrize('kind', CONFINED)
def test_a_bulk_move_keeps_to_the_same_nodes(who, mgr, kind):
    r = who[kind].post(f'{BASE}/vms/bulk-migrate', json={
        'vms': [{'vmid': 100, 'node': 'n1', 'type': 'qemu'}], 'target': 'n2', 'mode': 'sequential'})
    assert r.status_code == 403 and 'none of your guests' in r.get_json()['error'], (kind, r.data)
    assert not mgr.migrate_vm_manual.called


def test_a_bulk_move_of_an_operator_is_not_held_by_it(who, mgr):
    r = who['operator'].post(f'{BASE}/vms/bulk-migrate', json={
        'vms': [{'vmid': 100, 'node': 'n1', 'type': 'qemu'}], 'target': 'n2', 'dry_run': True})
    assert 'none of your guests' not in r.get_data(as_text=True), r.data


# --- a guest list that did not answer is no allow-list and no silent deny ------------------

@pytest.mark.parametrize('broken', ['unread', 'raises'])
def test_without_the_guest_list_a_confined_caller_gets_no_node(who, mgr, broken):
    if broken == 'unread':
        mgr.get_vm_resources.return_value = UnreadList('timeout', offline=True)
    else:
        mgr.get_vm_resources.side_effect = RuntimeError('cluster/resources broke off')
    c = who['acl_user']
    assert c.get(f'{BASE}/metrics').get_json() == {}
    assert c.get(f'{BASE}/node-progress').get_json() == {'nodes': {}}
    for path in ('/nodes', '/nodes-status', '/nodes/n1/storage', '/nodes/n1/storage/pbs1/identity'):
        r = c.get(BASE + path)
        assert r.status_code == 503 and 'your guests' in r.get_json()['error'], (path, r.data)
    assert not mgr.get_storage_list.called and not mgr._api_get.called
    r = _migrate(c, 'n3')
    assert r.status_code == 503 and not mgr.migrate_vm_manual.called, r.data
    # the whole cluster does not need the guest list for it
    assert _metrics_nodes(who['operator'].get(f'{BASE}/metrics')) == ALL
    assert who['operator'].get(f'{BASE}/nodes/n2/storage').status_code == 200


VOLID = 'local:backup/vzdump-qemu-100-2026_11_01-00_00_00.vma.zst'


def _restore(client, node):
    return client.post(f'{BASE}/vms/{node}/qemu/100/backups/restore',
                       json={'volid': VOLID, 'target_vmid': 555})


def test_a_restore_keeps_to_the_same_rule_and_says_when_it_could_not_read(who, mgr):
    """Restore and clone place a guest by the same rule (#1081): an unread guest list is a
    503 that says so, not a 403 that blames the node."""
    started = mgr._create_session.return_value.post.return_value
    started.status_code = 200
    started.json.return_value = {'data': 'UPID:n3:restore'}
    post = mgr._create_session.return_value.post
    c = who['acl_user']
    assert _restore(c, 'n2').status_code == 403
    mgr.get_vm_resources.return_value = UnreadList('timeout')
    r = _restore(c, 'n3')
    assert r.status_code == 503 and 'restore destination' in r.get_json()['error'], r.data
    assert not post.called
    mgr.get_vm_resources.return_value = list(GUESTS)
    assert _restore(c, 'n3').status_code == 200
    assert post.called


# --- cost: the polled reads of an operator read no guest, a confined one each node once -----

def test_the_node_reads_cost_what_they_have_to(api, seed, mgr, monkeypatch):
    """200 nodes, 10k guests. An operator's /metrics asks no guest at all. A confined caller
    asks the guests of a node until one is theirs, and takes the list the broadcast loop read
    a moment ago instead of walking the cluster again."""
    from pegaprox.api import helpers
    nodes = [f'pve{i:03d}' for i in range(200)]
    guests = [{'vmid': 1000 + i, 'node': nodes[i % 200], 'type': 'qemu'} for i in range(10000)]
    mgr.get_node_status.return_value = {n: {'status': 'online'} for n in nodes}
    mgr.get_vm_resources.return_value = guests
    seed.tenant('acme', clusters=[CID])
    seed.tenant('t_pool', clusters=[])
    seed.pool(CID, 'all', 'pooled', ['vm.view'])
    _pool_member({f"{g['vmid']}:qemu": 'all' for g in guests})
    calls = []
    real = rbac.user_can_access_vm

    def counted(*a, **kw):
        calls.append(a[2])
        return real(*a, **kw)
    monkeypatch.setattr(rbac, 'user_can_access_vm', counted)
    ops = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    pooled = api.as_user(seed.user('pooled', role='user', tenant_id='t_pool'))
    # an ACL user of another tenant: the guests without an ACL row are not theirs by role
    seed.tenant('globex', clusters=['other'])
    seed.vm_acl(CID, 1000, users=['portal'])
    portal = api.as_user(seed.user('portal', role='user', tenant_id='globex'))

    assert len(ops.get(f'{BASE}/metrics').get_json()) == 200
    assert calls == [] and not mgr.get_vm_resources.called

    t0 = time.monotonic()
    assert len(pooled.get(f'{BASE}/metrics').get_json()) == 200
    took = time.monotonic() - t0
    # every guest is theirs: one per node is asked, the other 9800 not
    assert len(calls) == 200, len(calls)
    assert mgr.get_vm_resources.call_args.kwargs.get('max_age') == helpers.GUEST_NODES_AGE > 0
    assert took < 5, took

    # one guest of their own among 10k: every guest of another node is asked once
    calls.clear()
    t0 = time.monotonic()
    assert set(portal.get(f'{BASE}/metrics').get_json()) == {'pve000'}
    took = time.monotonic() - t0
    assert len(calls) == 10000 - 49, len(calls)
    assert took < 10, took


# --- HA (#625): a standby serves /metrics itself and reads /node-progress on the active --------

from test_ha_members import group, _built  # noqa: F401,E402
from test_ha_forward import fwd, _forward_calls, FORWARD  # noqa: F401,E402


def test_the_cut_holds_on_a_standby_and_on_the_active_it_forwards_to(fwd, seed, api):
    g = fwd
    _built(g, seed, 'b')
    seed.tenant('acme', clusters=[CID])
    for vmid in (100, 101):
        seed.vm_acl(CID, vmid, users=['portal'])
    seed.vm_acl(CID, 200, users=['someone_else'])
    portal = api.as_user(seed.user('portal', role='user', tenant_id='acme'))
    ops = api.as_user(seed.user('ops', role='user', tenant_id='acme'))
    m = api.make_fake_manager(CID)
    m.is_connected = True
    m.get_node_status.return_value = _node_status()
    m.get_vm_resources.return_value = list(GUESTS)
    m.nodes_in_maintenance = {n: _task(n) for n in sorted(ALL)}
    m.nodes_updating = {}
    api.set_manager(CID, m)

    g.calls.clear()
    with g.at('b'):
        r = portal.get(f'{BASE}/node-progress')
        full = ops.get(f'{BASE}/node-progress')
    assert _forward_calls(g) == [('b', 'a', 'POST', FORWARD)] * 2
    assert r.status_code == 200 and set(r.get_json()['nodes']) == THEIRS, r.data
    assert 'secret' not in r.get_data(as_text=True)
    assert set(full.get_json()['nodes']) == ALL

    g.calls.clear()
    with g.at('b'):
        assert _metrics_nodes(portal.get(f'{BASE}/metrics')) == THEIRS
        assert _metrics_nodes(ops.get(f'{BASE}/metrics')) == ALL
    assert _forward_calls(g) == []


# --- the same nodes on the other routes that name them --------------------------------------
#
# A node read cut on /metrics is no cut while another route answers it whole: the node's
# migrate-all, the topology, the what-if report, the global search and summary, the group
# status, the health score, the storage content of a node, a node's maintenance and update,
# a ProxLB pin and the WebSocket's node actions (test_sse_frames_confine_1218.py).

def _migrate_all(client, target, node='n1'):
    return client.post(f'{BASE}/nodes/{node}/guests/migrateall', json={'vms': [100], 'target': target})


@pytest.mark.parametrize('kind', CONFINED)
def test_the_migrate_all_of_a_node_keeps_to_the_nodes_of_their_guests(who, mgr, kind):
    mgr.get_vm_resources.return_value = [dict(g, status='running') for g in GUESTS]
    mgr.node_guests_action.return_value = {'success': True, 'task': 'UPID:n1:migrateall'}
    # n9 is no node at all: the same answer, so the refusal tells nothing about n2
    for target in ('n2', 'n9'):
        r = _migrate_all(who[kind], target)
        assert r.status_code == 403 and 'none of your guests' in r.get_json()['error'], (kind, target, r.data)
    assert not mgr.node_guests_action.called and not mgr.get_node_status.called
    r = _migrate_all(who[kind], 'n3')
    assert r.status_code == 200, (kind, r.data)
    assert mgr.node_guests_action.call_args.kwargs['target'] == 'n3'


def test_the_migrate_all_of_an_operator_goes_anywhere(who, mgr):
    mgr.get_vm_resources.return_value = [dict(g, status='running') for g in GUESTS]
    mgr.node_guests_action.return_value = {'success': True, 'task': 'UPID:n1:migrateall'}
    r = _migrate_all(who['operator'], 'n2')
    assert r.status_code == 200, r.data
    assert _migrate_all(who['operator'], 'n9').get_json()['error'] == 'n9 is no node of this cluster'


def _topology_pve(mgr, guest_vnet='ownnet'):
    mgr.nodes = {n: {'status': 'online', 'cpu': 0.42, 'mem': 1, 'maxmem': 4, 'maxcpu': 8} for n in sorted(ALL)}

    def _get(url, *a, **kw):
        if url.endswith('/network'):
            node = url.split('/nodes/')[1].split('/')[0]
            return _resp(200, [{'iface': 'vmbr0', 'type': 'bridge', 'cidr': f'10.0.0.{node[-1]}/24',
                                'bridge_ports': 'bond0'}])
        if url.endswith('/cluster/sdn/vnets'):
            return _resp(200, [{'vnet': 'secretnet', 'zone': 'z1', 'tag': 42},
                               {'vnet': 'ownnet', 'zone': 'z1', 'tag': 7}])
        if '/qemu/100/config' in url:
            return _resp(200, {'net0': 'virtio,bridge=vmbr0', 'net1': f'virtio,bridge={guest_vnet}'})
        return _resp(200, {'net0': 'virtio,bridge=vmbr0'})
    mgr._api_get.side_effect = _get


def _topology_parts(r):
    body = r.get_json()
    return ({n['label'] for n in body['nodes'] if n['kind'] == 'node'},
            {n['id'] for n in body['nodes'] if n['kind'] == 'bridge'},
            {n['label'] for n in body['nodes'] if n['kind'] == 'sdn_vnet'})


@pytest.mark.parametrize('kind', CONFINED)
def test_the_topology_shows_the_nodes_of_their_guests_and_reads_only_those(who, mgr, kind):
    _topology_pve(mgr)
    r = who[kind].get(f'{BASE}/topology')
    assert r.status_code == 200, r.data
    nodes, bridges, vnets = _topology_parts(r)
    assert nodes == THEIRS and bridges == {f'br:{n}:vmbr0' for n in THEIRS}, (kind, nodes, bridges)
    # the vnet their own guest is attached to, not the others of the cluster
    assert vnets == {'ownnet'}, (kind, vnets)
    assert '10.0.0.2' not in r.get_data(as_text=True) and 'secretnet' not in r.get_data(as_text=True)
    asked = {c.args[0].split('/nodes/')[1].split('/')[0] for c in mgr._api_get.call_args_list
             if str(c.args[0]).endswith('/network')}
    assert asked == THEIRS, asked
    assert r.get_json()['counts']['nodes'] == len(THEIRS)


def test_the_topology_of_an_operator_is_whole(who, mgr):
    _topology_pve(mgr)
    nodes, bridges, vnets = _topology_parts(who['operator'].get(f'{BASE}/topology'))
    assert nodes == ALL and len(bridges) == 3 and vnets == {'secretnet', 'ownnet'}


def test_the_topology_says_when_it_could_not_read_their_guests(who, mgr):
    _topology_pve(mgr)
    mgr.get_vm_resources.return_value = UnreadList('timeout')
    r = who['acl_user'].get(f'{BASE}/topology')
    assert r.status_code == 503 and 'your guests' in r.get_json()['error'], r.data
    assert not mgr._api_get.called


def _whatif_cluster(mgr):
    ns = _node_status()
    for v in ns.values():
        v.update(mem_used=3 * 2**30, mem_total=64 * 2**30, cpu_percent=37.0)
    mgr.get_node_status.return_value = ns
    mgr.nodes = {n: {'node': n, 'status': 'online', 'maxcpu': 8, 'maxmem': 64 * 2**30} for n in sorted(ALL)}
    mgr.config.balance_cpu_weight = 1.0
    mgr.config.balance_mem_weight = 1.0
    mgr.config.balance_io_weight = 0.0
    mgr.get_vm_resources.return_value = [dict(g, status='running', maxmem=2**30, mem=2**29, cpu=0.1, maxcpu=2)
                                         for g in GUESTS]
    mgr.id = CID


SCENARIOS = {'node_failure': {'type': 'node_failure', 'nodes': ['n1']},
             'headroom': {'type': 'headroom', 'depth': 1}}


@pytest.mark.parametrize('scenario', sorted(SCENARIOS))
@pytest.mark.parametrize('kind', CONFINED)
def test_the_whatif_report_has_the_load_of_their_nodes_only(who, mgr, kind, scenario):
    _whatif_cluster(mgr)
    r = who[kind].post(f'{BASE}/whatif', json=SCENARIOS[scenario])
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert {row['node'] for row in body['nodes']} <= THEIRS and body['nodes'], (kind, body['nodes'])
    assert body['reserve'] is None
    if scenario == 'headroom':
        assert body['headroom']['combinations'] == [] and body['headroom']['checked'] > 0
    assert 'n2' not in json.dumps({k: body[k] for k in ('nodes', 'limits', 'headroom') if k in body})
    # the counts stay whole, as they do for the guests
    assert body['summary']['guests'] == len(GUESTS)


@pytest.mark.parametrize('scenario', sorted(SCENARIOS))
def test_the_whatif_report_of_an_operator_is_whole(who, mgr, scenario):
    _whatif_cluster(mgr)
    body = who['operator'].post(f'{BASE}/whatif', json=SCENARIOS[scenario]).get_json()
    assert 'n2' in {row['node'] for row in body['nodes']} and body['reserve']
    if scenario == 'headroom':
        assert body['headroom']['combinations']


def test_the_whatif_run_says_when_it_could_not_read_their_guests(who, mgr, monkeypatch):
    """The run reads the cluster fine; which of its nodes are the caller's is what failed."""
    from pegaprox.api import helpers

    def broken(*a, **kw):
        raise RuntimeError('cluster/resources broke off')
    _whatif_cluster(mgr)
    monkeypatch.setattr(helpers, 'guest_nodes_of', broken)
    r = who['acl_user'].post(f'{BASE}/whatif', json=SCENARIOS['node_failure'])
    assert r.status_code == 503 and 'your guests' in r.get_json()['error'], r.data
    assert who['operator'].post(f'{BASE}/whatif', json=SCENARIOS['node_failure']).status_code == 200


def _search_nodes(client, q='type:node'):
    r = client.get(f'/api/global/search?q={q}')
    assert r.status_code == 200, r.data
    return {x['name'] for x in r.get_json()['results'] if x.get('type') == 'node'}


def _nodes_attr(mgr):
    mgr.nodes = {n: {'node': n, 'status': 'online', 'cpu': 0.42, 'mem': 1111, 'maxmem': 9999, 'maxcpu': 8}
                 for n in sorted(ALL)}


def _default_tenant_confined(api, seed, how):
    """A default-tenant account confined to acme's cluster by a pool grant or a VM-ACL: the
    tenant gate lists every cluster for it, so only the confinement cuts."""
    if how == 'pool':
        seed.pool(CID, 'pool2', 'dpool', ['vm.view'])
        _pool_member({'100:qemu': 'pool2'})
    else:
        seed.vm_acl(CID, 100, users=['dpool'])
    return api.as_user(seed.user('dpool', role='user'))


@pytest.mark.parametrize('q', ['type:node', 'n2', 'node:n2'])
def test_the_global_search_finds_the_nodes_of_their_guests_only(api, seed, who, mgr, q):
    _nodes_attr(mgr)
    assert _search_nodes(who['acl_user'], q) <= THEIRS
    assert 'n2' in _search_nodes(who['operator'], q)
    assert _search_nodes(who['acl_user']) == THEIRS


@pytest.mark.parametrize('how', ['pool', 'acl'])
def test_the_global_search_of_a_default_tenant_confined_user(api, seed, who, mgr, how):
    _nodes_attr(mgr)
    dpool = _default_tenant_confined(api, seed, how)
    assert _search_nodes(dpool) == {'n1'}
    s = dpool.get('/api/global/summary').get_json()
    assert s['nodes']['total'] == 1 and [c['nodes'] for c in s['by_cluster'] if c['id'] == CID] == [1], s


def test_the_global_search_lists_no_node_when_their_guests_cannot_be_read(who, mgr):
    _nodes_attr(mgr)
    mgr.get_vm_resources.return_value = UnreadList('timeout')
    assert _search_nodes(who['acl_user']) == set()
    assert _search_nodes(who['operator']) == ALL


def test_an_api_token_of_a_confined_user_searches_the_same_nodes(api, who, mgr):
    from pegaprox.utils import auth as authmod
    _nodes_attr(mgr)
    res = authmod.create_api_token('portal', 'ci', role='viewer')
    r = api.anon().get('/api/global/search?q=type:node', headers={'Authorization': f"Bearer {res['token']}"})
    assert {x['name'] for x in r.get_json()['results'] if x['type'] == 'node'} == THEIRS


def test_the_global_summary_counts_the_nodes_of_their_guests(who, mgr):
    _nodes_attr(mgr)
    s = who['acl_user'].get('/api/global/summary').get_json()
    assert s['nodes'] == {'total': 2, 'online': 2, 'offline': 0}, s['nodes']
    assert s['resources']['mem_total'] == 2 * 9999 and s['resources']['cpu_total'] == 16
    assert [c['nodes'] for c in s['by_cluster'] if c['id'] == CID] == [2]
    full = who['operator'].get('/api/global/summary').get_json()
    assert full['nodes']['total'] == 3 and full['resources']['mem_total'] == 3 * 9999


def _group(seed):
    db = seed.db
    db.conn.execute("INSERT INTO cluster_groups (id, name, tenant_id) VALUES ('g1', 'acme-group', 'acme')")
    db.conn.execute("INSERT INTO clusters (id, name, host, user, pass_encrypted, group_id) "
                    "VALUES (?, ?, 'h', 'u', 'x', 'g1')", (CID, CID))
    db.conn.commit()


def test_the_group_status_counts_their_nodes_and_their_guests(who, mgr, seed):
    _group(seed)
    ns = _node_status()
    for v in ns.values():
        v.update(mem_used=100, mem_total=1000, disk_used=5, disk_total=50)
    mgr.get_node_status.return_value = ns
    mgr.get_vm_resources.return_value = [dict(g, status='running') for g in GUESTS] + [
        {'vmid': 300 + i, 'node': 'n2', 'type': 'qemu', 'status': 'running'} for i in range(40)]
    t = who['acl_user'].get('/api/cluster-groups/g1/status').get_json()['totals']
    assert t['nodes_online'] == 2 and t['mem_total'] == 2000, t
    assert t['vms_running'] == 2, t
    full = who['operator'].get('/api/cluster-groups/g1/status').get_json()['totals']
    assert full['nodes_online'] == 3 and full['vms_running'] == 43, full


def _health_cluster(mgr):
    ns = _node_status()
    ns['n2'].update(status='offline', offline=True)
    mgr.get_node_status.return_value = ns
    mgr.get_replication_status.return_value = [
        {'id': '200-0', 'guest': 200, 'type': 'local', 'fail_count': 3, 'error': 'broken'},
        {'id': '100-0', 'guest': 100, 'type': 'local', 'fail_count': 0}]
    mgr._api_get.return_value = _resp(200, [
        {'node': 'n1', 'storage': 'local', 'status': 'available', 'disk': 10, 'maxdisk': 100},
        {'node': 'n2', 'storage': 'secret-nfs', 'status': 'available', 'disk': 97, 'maxdisk': 100}])


@pytest.mark.parametrize('kind', CONFINED)
def test_the_health_score_names_their_nodes_only(who, mgr, kind):
    _health_cluster(mgr)
    body = who[kind].get(f'{BASE}/health').get_json()
    txt = json.dumps(body)
    assert 'secret-nfs' not in txt and 'n2' not in txt, (kind, txt)
    factors = {f['key']: f['value'] for f in body['factors']}
    assert factors['nodes'] == '2/2' and factors['storage'] == 'local @ n1 (10%)', factors
    # their replication job, not the failing one of guest 200
    assert factors['replication'] == '0 failing / 1 jobs', factors


def test_the_health_score_of_an_operator_is_whole(who, mgr):
    _health_cluster(mgr)
    body = who['operator'].get(f'{BASE}/health').get_json()
    factors = {f['key']: f['value'] for f in body['factors']}
    assert factors['nodes'] == '2/3' and factors['storage'] == 'secret-nfs @ n2 (97%)', factors
    assert factors['replication'] == '1 failing / 2 jobs'


def test_the_health_score_leaves_the_nodes_out_when_their_guests_cannot_be_read(who, mgr):
    _health_cluster(mgr)
    mgr.get_vm_resources.return_value = UnreadList('timeout')
    body = who['acl_user'].get(f'{BASE}/health').get_json()
    assert {f['key'] for f in body['factors']} & {'nodes', 'storage', 'replication'} == set(), body


CONTENT = [{'volid': 'local:iso/customer-b-installer.iso', 'content': 'iso', 'size': 123},
           {'volid': 'local:snippets/customer-b-userdata.yaml', 'content': 'snippets', 'size': 9},
           {'volid': 'local:200/vm-200-disk-0.qcow2', 'content': 'images', 'vmid': 200, 'size': 7}]


def _content_urls(mgr):
    return [str(c.args[0]) for c in mgr._create_session.return_value.get.call_args_list]


@pytest.mark.parametrize('kind', CONFINED)
def test_the_storage_content_of_a_node_is_theirs_to_list_on_their_nodes_only(who, mgr, kind):
    mgr._create_session.return_value.get.return_value = _resp(200, CONTENT)
    for path in (f'{BASE}/nodes/n2/storage/local/content', f'{BASE}/datastores/local/content?node=n2'):
        r = who[kind].get(path)
        assert r.status_code == 403 and 'customer-b' not in r.get_data(as_text=True), (kind, path, r.data)
    assert _content_urls(mgr) == []
    assert who[kind].get(f'{BASE}/nodes/n1/storage/local/content').status_code == 200
    # without a node, the first node of their guests, not the first of the cluster
    r = who[kind].get(f'{BASE}/datastores/local/content')
    assert r.status_code == 200 and {row['node'] for row in r.get_json()} == {'n1'}, r.data
    assert all('/nodes/n2/' not in u for u in _content_urls(mgr)), _content_urls(mgr)


def test_the_storage_content_of_any_node_for_an_operator(who, mgr):
    mgr._create_session.return_value.get.return_value = _resp(200, CONTENT)
    r = who['operator'].get(f'{BASE}/datastores/local/content?node=n2')
    assert r.status_code == 200 and 'customer-b-installer' in r.get_data(as_text=True)
    assert who['operator'].get(f'{BASE}/nodes/n2/storage/local/content').status_code == 200


@pytest.mark.parametrize('kind', CONFINED)
def test_the_maintenance_and_update_of_a_node_are_read_on_their_nodes_only(who, mgr, kind):
    from pegaprox.models.tasks import UpdateTask
    u = UpdateTask('n2')
    u.add_output('Setting up openssh-server (1:9.2p1-2+deb12u5) ...')
    mgr.get_maintenance_status.return_value = _task('n2').to_dict()
    mgr.get_update_status.return_value = {'is_updating': True, 'task': u.to_dict()}
    for what in ('maintenance', 'update'):
        r = who[kind].get(f'{BASE}/nodes/n2/{what}')
        assert r.status_code == 403 and 'openssh' not in r.get_data(as_text=True), (kind, what, r.data)
    assert not mgr.refresh_maintenance_status.called and not mgr.get_update_status.called
    for what in ('maintenance', 'update'):
        assert who[kind].get(f'{BASE}/nodes/n1/{what}').status_code == 200, (kind, what)
    assert mgr.refresh_maintenance_status.call_count == 1


def test_the_maintenance_and_update_of_any_node_for_an_operator(who, mgr):
    mgr.get_maintenance_status.return_value = _task('n2').to_dict()
    mgr.get_update_status.return_value = {'is_updating': False}
    for what in ('maintenance', 'update'):
        assert who['operator'].get(f'{BASE}/nodes/n2/{what}').status_code == 200, what


def _tags(client, tags):
    return client.put(f'{BASE}/vms/n1/qemu/100/config', json={'tags': tags})


@pytest.mark.parametrize('kind', ['acl_user', 'lowered_admin'])
def test_a_confined_caller_pins_a_guest_onto_a_node_of_their_guests_only(who, mgr, kind):
    """plb_pin_<node> with ProxLB pins set to migrate is a move the balancer makes for them."""
    mgr.update_vm_config.return_value = {'success': True, 'message': 'updated'}
    mgr.get_vm_config.return_value = {'success': True, 'config': {'tags': 'web'}}
    for tags in ('web;plb_pin_n2', 'PLB_PIN_N2', 'web,plb_pin_n9'):
        r = _tags(who[kind], tags)
        assert r.status_code == 403 and r.get_json()['code'] == 'PIN_OUT_OF_REACH', (kind, tags, r.data)
    assert not mgr.update_vm_config.called
    assert _tags(who[kind], 'web;plb_pin_n3').status_code == 200
    # a pin an administrator set already is no new placement: an edit of the other tags keeps it
    mgr.get_vm_config.return_value = {'success': True, 'config': {'raw': {'tags': 'plb_pin_n2'}}}
    assert _tags(who[kind], 'web;plb_pin_n2').status_code == 200


def test_an_operator_pins_a_guest_anywhere(who, mgr):
    mgr.update_vm_config.return_value = {'success': True, 'message': 'updated'}
    assert _tags(who['operator'], 'plb_pin_n2').status_code == 200
    assert mgr.update_vm_config.call_args[0][3] == {'tags': 'plb_pin_n2'}


# --- cost: the polled datastores read loads no users table ----------------------------------

def test_the_polled_datastores_read_loads_no_users_table(who, mgr, storage_state, db, monkeypatch):
    loads = []
    real = db.get_all_users
    monkeypatch.setattr(db, 'get_all_users', lambda *a, **k: loads.append(1) or real(*a, **k))
    for kind in WHOLE:
        assert who[kind].get(f'{BASE}/datastores').status_code == 200
    for kind in CONFINED:
        assert who[kind].get(f'{BASE}/datastores').status_code == 403
    assert loads == [], len(loads)


# --- the polled reads take a node set of the last seconds, placing a guest never does ---------

def _counted(monkeypatch):
    calls = []
    real = rbac.user_can_access_vm

    def counted(*a, **kw):
        calls.append(a[2])
        return real(*a, **kw)
    monkeypatch.setattr(rbac, 'user_can_access_vm', counted)
    return calls


def test_a_polled_read_takes_the_node_set_the_stream_found(who, mgr, monkeypatch):
    from pegaprox.utils import realtime
    realtime._note_node_scope(CID, 'portal', 'user', frozenset({'n1'}))
    calls = _counted(monkeypatch)
    assert _metrics_nodes(who['acl_user'].get(f'{BASE}/metrics')) == {'n1'}
    assert calls == []
    # the stream's "whole cluster" or "no resources pass yet" is no node set to take
    realtime._note_node_scope(CID, 'pooled', 'user', None)
    assert _metrics_nodes(who['pool_user'].get(f'{BASE}/metrics')) == THEIRS
    assert calls


def test_two_reads_in_the_window_ask_the_guests_once(who, mgr, monkeypatch):
    from pegaprox.api import helpers
    calls = _counted(monkeypatch)
    c = who['acl_user']
    assert _metrics_nodes(c.get(f'{BASE}/metrics')) == THEIRS
    first = len(calls)
    assert first
    assert _list_nodes(c.get(f'{BASE}/nodes-status')) == THEIRS
    assert len(calls) == first
    # older than the window: asked again, and a guest that moved meanwhile takes its node along
    for key, (t, nodes) in list(helpers._read_node_scope.items()):
        helpers._read_node_scope[key] = (t - helpers.GUEST_SCOPE_REUSE - 1, nodes)
    mgr.get_vm_resources.return_value = [dict(GUESTS[0], node='n2')] + GUESTS[1:]
    assert _metrics_nodes(c.get(f'{BASE}/metrics')) == {'n2', 'n3'}
    assert len(calls) > first


@pytest.mark.parametrize('kept_by', ['stream', 'read'])
def test_placing_a_guest_never_takes_a_kept_node_set(who, mgr, kept_by):
    from pegaprox.api import helpers
    from pegaprox.utils import realtime
    wide = frozenset(ALL)    # n2 hosts none of their guests
    if kept_by == 'stream':
        realtime._note_node_scope(CID, 'portal', 'user', wide)
    else:
        helpers._keep_node_scope((CID, 'portal', 'user'), wide)
    assert _metrics_nodes(who['acl_user'].get(f'{BASE}/metrics')) == ALL   # the read takes it
    r = _migrate(who['acl_user'], 'n2')
    assert r.status_code == 403, r.data
    assert not mgr.migrate_vm_manual.called


def test_an_account_without_a_name_never_shares_a_node_set():
    from pegaprox.api import helpers
    assert helpers._node_scope_key(CID, {'role': 'user'}) is None
    assert helpers._node_scope_key(CID, {'username': 'a', 'role': 'user'}) != \
        helpers._node_scope_key(CID, {'username': 'a', 'role': 'user', 'effective_role': 'viewer'})


def test_the_portal_case_at_scale_asks_its_guests_once_per_window(api, seed, mgr, monkeypatch):
    """One guest of their own among 10k on 200 nodes: the first read asks nearly every guest,
    the reads of the next seconds ask none."""
    nodes = [f'pve{i:03d}' for i in range(200)]
    guests = [{'vmid': 1000 + i, 'node': nodes[i % 200], 'type': 'qemu'} for i in range(10000)]
    mgr.get_node_status.return_value = {n: {'status': 'online'} for n in nodes}
    mgr.get_vm_resources.return_value = guests
    seed.tenant('globex', clusters=['other'])
    seed.tenant('acme', clusters=[CID])
    seed.vm_acl(CID, 1000, users=['portal'])
    portal = api.as_user(seed.user('portal', role='user', tenant_id='globex'))
    calls = _counted(monkeypatch)
    assert set(portal.get(f'{BASE}/metrics').get_json()) == {'pve000'}
    assert len(calls) == 10000 - 49, len(calls)
    calls.clear()
    t0 = time.monotonic()
    for path in ('/metrics', '/nodes-status', '/node-progress', '/metrics'):
        assert portal.get(f'{BASE}{path}').status_code == 200, path
    assert calls == [], len(calls)
    assert time.monotonic() - t0 < 2
