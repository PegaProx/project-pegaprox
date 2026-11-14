"""A node's maintenance names the guests in it: the one moving, the pending and the failed
ones, the ones placed off their pin, the templates moved or left behind, and the HA rules
held off over them. /node-progress cut some of that for a confined caller; /metrics, the
SSE 'metrics' frame and GET .../maintenance handed all of it to anyone who reaches the
cluster, a VM-ACL or pool grant on one guest being enough.

Confined: VM-ACL users (of the default tenant and of another one), a pool user of another
tenant, and an admin a tenant override lowers where they live who reaches the cluster
through an ACL. Not confined: the admin and
an operator of the owning tenant. Another tenant does not reach the cluster at all.

MK Oct 2026
"""
import json
import queue
from datetime import datetime

import pytest

import pegaprox.utils.realtime as rt
from pegaprox.models.tasks import MaintenanceTask

CID = 'cluster_1'
METRICS = f'/api/clusters/{CID}/metrics'
PROGRESS = f'/api/clusters/{CID}/node-progress'
MAINT = f'/api/clusters/{CID}/nodes/n1/maintenance'
UPDATES = f'/api/clusters/{CID}/updates/status'
REST_ROUTES = (METRICS, PROGRESS, MAINT)

# every guest of the maintenance below carries one of these, and nothing else does
NAME_MARK, VMID_MARK = 'secret', '98710'


def _task():
    t = MaintenanceTask('n1')
    t.started_at = datetime(2026, 10, 5, 1, 0, 0)
    t.status = 'evacuating'
    t.total_vms, t.migrated_vms = 5, 2
    t.current_vm = {'vmid': 987103, 'name': 'app-secret-03'}
    t.pending_vms = [{'vmid': 987105, 'name': 'web-secret-05'}]
    t.failed_vms = [{'vmid': 987104, 'name': 'db-secret-04', 'error': 'Migration failed'}]
    t.off_pin_vms = [{'vmid': 987106, 'name': 'pin-secret-06', 'target': 'n2', 'pinned_nodes': ['n3']}]
    t.templates_moved = [{'vmid': 987107, 'name': 'tpl-secret-07', 'to': 'n2'}]
    t.templates_left = [{'vmid': 987108, 'name': 'tpl-secret-08', 'reason': 'not shared'}]
    t.ha_rules_off = ['apart-secret-09']
    t.ha_rules_kept_on = ['apart-secret-10']
    t.note = '1 pinned guest(s) had to be evacuated off their plb_pin_ node.'
    return t


class _Cluster:
    """What the routes read of a Proxmox manager. get_node_status hands out one dict and
    keeps it, as the real one does with its short cache, so a route that writes into the
    answer writes into what the next caller gets.

    Every confined caller below has a guest on n1, the node in maintenance: VM 100 (the
    VM-ACL) and VM 101 (pool1). A confined caller sees the nodes its own guests run on."""
    cluster_type = 'proxmox'
    is_connected = True
    guests = [{'vmid': 100, 'node': 'n1', 'type': 'qemu', 'name': 'acl-vm', 'status': 'running'},
              {'vmid': 101, 'node': 'n1', 'type': 'qemu', 'name': 'pool-vm', 'status': 'running'},
              {'vmid': 200, 'node': 'n2', 'type': 'qemu', 'name': 'other-vm', 'status': 'running'}]

    def get_vm_resources(self, max_age=0.0):
        return [dict(g) for g in self.guests]

    def get_pools(self):
        return [{'poolid': 'pool1'}]

    def get_pool_members(self, pool_id):
        return {'members': [{'vmid': 101, 'type': 'qemu'}] if pool_id == 'pool1' else []}

    def __init__(self):
        self.nodes_in_maintenance = {'n1': _task()}
        self.nodes_updating = {}
        self.ha_node_status = {}
        self._ns = None
        self._last_update_check = None
        self._rolling_update = {
            'status': 'paused', 'current_node': 'n1', 'current_step': 'paused_evacuation',
            'logs': ['[01:00:00] Failed: db-secret-04 (VMID: 987104)'],
            'paused_reason': 'evacuation_failures',
            'paused_details': {'failed_vms': [{'vmid': 987104, 'name': 'db-secret-04'}]},
        }

    def get_node_status(self):
        if self._ns is None:
            self._ns = {}
            for name in ('n1', 'n2'):
                m = self.nodes_in_maintenance.get(name)
                self._ns[name] = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0,
                                  'maintenance_mode': m is not None,
                                  'maintenance_task': m.to_dict() if m else None,
                                  'maintenance_acknowledged': False,
                                  'is_updating': False, 'update_task': None, 'offline': False}
        return self._ns

    def refresh_maintenance_status(self):
        pass

    def get_maintenance_status(self, node):
        t = self.nodes_in_maintenance.get(node)
        return t.to_dict() if t else None


@pytest.fixture
def cluster(api):
    return api.set_manager(CID, _Cluster())


def _who(api, seed):
    """Name -> a client signed in as that caller."""
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['other'])
    seed.tenant('t_pool', clusters=[])
    seed.vm_acl(CID, 100, users=['portal', 'gx', 'dora'])
    seed.pool(CID, 'pool1', 'pooled', ['vm.view'])
    users = {
        'admin': seed.user('root', role='admin'),
        'operator': seed.user('ops', role='user', tenant_id='acme'),
        'acl_user': seed.user('portal', role='user', tenant_id='globex'),
        'default_acl_user': seed.user('dora', role='user'),
        'pool_user': seed.user('pooled', role='user', tenant_id='t_pool'),
        'lowered_admin': seed.user('gx', role='admin', tenant_id='globex',
                                   tenant_permissions={'globex': {'role': 'user'}}),
        'other_tenant': seed.user('milton', role='user', tenant_id='globex'),
    }
    return {k: api.as_user(u) for k, u in users.items()}


def _task_of(route, body):
    if route == METRICS:
        return body['n1']['maintenance_task']
    if route == PROGRESS:
        return body['nodes']['n1']['maintenance_task']
    return body


def _no_guests(text):
    return NAME_MARK not in text and VMID_MARK not in text


@pytest.mark.parametrize('kind', ['acl_user', 'default_acl_user', 'pool_user', 'lowered_admin'])
@pytest.mark.parametrize('route', REST_ROUTES)
def test_a_confined_caller_gets_the_progress_without_the_guests(api, seed, cluster, kind, route):
    c = _who(api, seed)[kind]
    r = c.get(route)
    assert r.status_code == 200, r.get_data(as_text=True)
    text = r.get_data(as_text=True)
    assert _no_guests(text), (kind, route, text)
    task = _task_of(route, r.get_json())
    # the progress stays
    assert task['status'] == 'evacuating' and task['migrated_vms'] == 2 and task['total_vms'] == 5
    assert task['note'].startswith('1 pinned guest')


@pytest.mark.parametrize('kind', ['admin', 'operator'])
@pytest.mark.parametrize('route', REST_ROUTES)
def test_the_admin_and_an_operator_of_the_cluster_still_get_every_guest(api, seed, cluster, kind, route):
    c = _who(api, seed)[kind]
    task = _task_of(route, c.get(route).get_json())
    assert task['current_vm']['name'] == 'app-secret-03'
    assert [v['vmid'] for v in task['pending_vms']] == [987105]
    assert [v['vmid'] for v in task['failed_vms']] == [987104]
    assert [v['vmid'] for v in task['off_pin_vms']] == [987106]
    assert [v['vmid'] for v in task['templates_moved']] == [987107]
    assert [v['vmid'] for v in task['templates_left']] == [987108]
    assert task['ha_rules_off'] == ['apart-secret-09'] and task['ha_rules_kept_on'] == ['apart-secret-10']


@pytest.mark.parametrize('route', REST_ROUTES + (UPDATES,))
def test_another_tenant_reaches_none_of_it(api, seed, cluster, route):
    c = _who(api, seed)['other_tenant']
    r = c.get(route)
    assert r.status_code == 403 and _no_guests(r.get_data(as_text=True))


def test_a_confined_answer_leaves_the_managers_cache_whole(api, seed, cluster):
    """get_node_status answers from the manager's cache, which the broadcast loop and the
    next caller share: cutting for one caller must not cut for everybody."""
    who = _who(api, seed)
    assert _no_guests(who['acl_user'].get(METRICS).get_data(as_text=True))
    assert cluster.get_node_status()['n1']['maintenance_task']['failed_vms']
    assert cluster._cached_metrics['n1']['maintenance_task']['templates_left']
    assert not _no_guests(who['admin'].get(METRICS).get_data(as_text=True))


def test_the_cached_metrics_are_cut_as_well(api, seed, cluster):
    who = _who(api, seed)
    who['admin'].get(METRICS)              # fills _cached_metrics
    cluster.is_connected = False
    assert _no_guests(who['acl_user'].get(METRICS).get_data(as_text=True))
    assert not _no_guests(who['admin'].get(METRICS).get_data(as_text=True))


def test_a_lowered_admin_does_not_get_the_rolling_update_log(api, seed, cluster):
    """updates/status cut the log and the pause details for a confined caller already; an
    admin a tenant override lowers, reaching the cluster through an ACL, got both."""
    who = _who(api, seed)
    for kind in ('lowered_admin', 'acl_user', 'default_acl_user', 'pool_user'):
        r = who[kind].get(UPDATES)
        assert r.status_code == 200 and _no_guests(r.get_data(as_text=True)), kind
        assert r.get_json()['rolling_update']['current_step'] == 'paused_evacuation'
    full = who['admin'].get(UPDATES).get_json()['rolling_update']
    assert full['paused_details']['failed_vms'][0]['vmid'] == 987104


def test_a_lowered_admin_in_a_cluster_of_their_own_tenant_sees_it_whole(api, seed, cluster):
    """Lowered to user where they live, and their tenant owns the cluster: an operator of
    it, like any user of that tenant."""
    seed.tenant('acme', clusters=[CID])
    c = api.as_user(seed.user('boss', role='admin', tenant_id='acme',
                              tenant_permissions={'acme': {'role': 'user'}}))
    task = c.get(PROGRESS).get_json()['nodes']['n1']['maintenance_task']
    assert task['failed_vms'][0]['name'] == 'db-secret-04'


# --- the live stream -----------------------------------------------------------------------
# A non-admin stream gets the nodes its own guests run on, as the resources pass found them
# (#1218): each test sends a resources frame first.

@pytest.fixture
def stream():
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()
    rt._sse_node_scope.clear()
    queues = {}

    def add(name, user, is_admin, effective_role, clusters=None):
        q = queues[name] = queue.Queue()
        rt.sse_clients[name] = {'queue': q, 'user': user, 'clusters': clusters,
                                'is_admin': is_admin, 'effective_role': effective_role}
    try:
        yield add, queues
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)
        rt._sse_node_scope.clear()


def _frame(q):
    msg = q.get_nowait()
    assert q.empty()
    return msg


def _resources_frame(cluster, queues):
    rt.broadcast_sse('resources', cluster.get_vm_resources(), CID)
    for q in queues.values():
        while not q.empty():
            q.get_nowait()


def test_the_metrics_frame_carries_the_guests_only_to_who_may_see_them(api, seed, cluster, stream):
    add, queues = stream
    _who(api, seed)
    # the stream subscribes a lowered admin to the clusters of their tenant and of their pools
    seed.pool(CID, 'pool2', 'gx', ['vm.view'])
    # as /api/sse/updates registers them: is_admin from the role, so the lowered admin too,
    # and the subscription get_user_clusters gives each
    add('admin', 'root', True, 'admin')
    add('operator', 'ops', False, 'user', clusters=[CID])
    add('default_acl_user', 'dora', False, 'user')
    add('pool_user', 'pooled', False, 'user', clusters=[CID])
    add('lowered_admin', 'gx', True, 'admin', clusters=['other', CID])
    add('other_tenant', 'milton', False, 'user', clusters=['other'])
    add('gone', 'nobody-here', False, 'user')
    _resources_frame(cluster, queues)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    for kind in ('admin', 'operator'):
        msg = _frame(queues[kind])
        assert json.loads(msg)['data']['n1']['maintenance_task']['failed_vms'], kind
    for kind in ('default_acl_user', 'pool_user', 'lowered_admin'):
        data = json.loads(_frame(queues[kind]))['data']
        # the data, not the frame: the frame's timestamp has digits of its own
        assert _no_guests(json.dumps(data)), kind
        task = data['n1']['maintenance_task']
        assert task['status'] == 'evacuating' and task['migrated_vms'] == 2, kind
    # an account that is not there gets no frame at all
    assert queues['gone'].empty()
    assert queues['other_tenant'].empty()
    # the manager's answer is the one the next frame is made from
    assert cluster.get_node_status()['n1']['maintenance_task']['off_pin_vms']


def test_a_quiet_cluster_costs_the_stream_no_user_read(api, seed, cluster, stream, monkeypatch):
    """Nothing to cut without a maintenance: the admin and an operator get the one shared
    frame, a confined client the nodes of its guests, and no account is read for it once a
    resources frame has gone out (the loop sends this once a second per cluster)."""
    add, queues = stream
    _who(api, seed)
    add('default_acl_user', 'dora', False, 'user')
    add('operator', 'ops', False, 'user', clusters=[CID])
    add('admin', 'root', True, 'admin')
    cluster.nodes_in_maintenance = {}
    _resources_frame(cluster, queues)
    reads = []
    monkeypatch.setattr(rt, '_sse_stored_user', lambda *a, **k: reads.append(a))
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert _frame(queues['operator']) == _frame(queues['admin'])
    assert sorted(json.loads(_frame(queues['default_acl_user']))['data']) == ['n1']
    assert reads == []


def test_every_field_of_a_maintenance_is_placed():
    """A new field on the task is either a guest list a confined caller does not get or one
    that names no guest. This fails until it is placed on one side."""
    from pegaprox.api.helpers import MAINTENANCE_GUEST_FIELDS
    no_guest = {'node', 'started_at', 'total_vms', 'migrated_vms', 'status', 'progress_percent',
                'error', 'acknowledged', 'native_ha', 'note'}
    fields = set(MaintenanceTask('n1').to_dict())
    assert fields == no_guest | set(MAINTENANCE_GUEST_FIELDS)
    assert not no_guest & set(MAINTENANCE_GUEST_FIELDS)
