"""The live stream named every node of a cluster to whoever reached it. The 'metrics' frame
went to each subscribed client with every node in it, a VM-ACL or a pool grant on one guest
being enough, and a role that withholds cluster.view got it all the same. 'node_status' and
'ha_status' went out with no node.view / ha.view asked and no node left out, the HA events
listing the vmids of guests the client cannot see.

A non-admin stream gets the nodes its own guests run on now, as the resources pass found
them; before one, a confined stream gets nothing. The admin and an operator of the owning
tenant keep the whole cluster.

Cluster: n1 runs VM 100 (VM-ACL), n2 runs VM 200 (pool1), n3 runs VM 300 (nobody's grant).

MK Nov 2026 (#1218)
"""
import collections
import json
import queue

import pytest

import pegaprox.globals as ppglobals
import pegaprox.utils.realtime as rt

CID = 'cluster_1'


class _Cluster:
    """What the broadcast and the per-VM gate read of a Proxmox manager."""
    cluster_type = 'proxmox'
    is_connected = True

    def __init__(self, nodes=('n1', 'n2', 'n3'), guests=None, pools=None):
        self.nodes = {n: {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0,
                          'maintenance_mode': False, 'maintenance_task': None, 'offline': False}
                      for n in nodes}
        self.guests = guests if guests is not None else [
            {'vmid': 100, 'node': 'n1', 'type': 'qemu', 'name': 'portal-vm', 'status': 'running'},
            {'vmid': 200, 'node': 'n2', 'type': 'qemu', 'name': 'pool-vm', 'status': 'running'},
            {'vmid': 300, 'node': 'n3', 'type': 'qemu', 'name': 'other-vm', 'status': 'running'},
        ]
        self.pools = pools if pools is not None else {'pool1': [200]}

    def get_node_status(self):
        return self.nodes

    def get_vm_resources(self):
        return [dict(g) for g in self.guests]

    def get_pools(self):
        return [{'poolid': p} for p in self.pools]

    def get_pool_members(self, pool_id):
        return {'members': [{'vmid': v, 'type': 'qemu'} for v in self.pools.get(pool_id, [])]}


@pytest.fixture
def cluster(db, monkeypatch):
    c = _Cluster()
    monkeypatch.setitem(ppglobals.cluster_managers, CID, c)
    return c


def _forget_scopes():
    # not there on a tree without the node scope
    getattr(rt, '_sse_node_scope', {}).clear()


@pytest.fixture
def stream():
    """add(name, user, clusters, is_admin, role): a client as /api/sse/updates registers it."""
    saved = dict(rt.sse_clients)
    rt.sse_clients.clear()
    _forget_scopes()
    queues = {}

    def add(name, user, clusters=None, is_admin=False, role='user'):
        q = queues[name] = queue.Queue()
        rt.sse_clients[name] = {'queue': q, 'user': user, 'clusters': clusters,
                                'is_admin': is_admin, 'effective_role': role}
    try:
        yield add, queues
    finally:
        rt.sse_clients.clear()
        rt.sse_clients.update(saved)
        _forget_scopes()


def _seed_callers(seed):
    seed.tenant('acme', clusters=[CID])
    seed.tenant('globex', clusters=['other'])
    seed.tenant('t_pool', clusters=[])
    seed.vm_acl(CID, 100, users=['portal', 'dora', 'gx'])
    seed.pool(CID, 'pool1', 'pooled', ['vm.view'])
    seed.user('root', role='admin')
    seed.user('ops', role='user', tenant_id='acme')
    seed.user('portal', role='user', tenant_id='acme')
    seed.user('dora', role='user')
    seed.user('pooled', role='user', tenant_id='t_pool')
    seed.user('gx', role='admin', tenant_id='globex', tenant_permissions={'globex': {'role': 'user'}})
    seed.user('blind', role='user', tenant_id='acme',
              denied=['cluster.view', 'node.view', 'ha.view'])
    seed.user('milton', role='user', tenant_id='globex')


CONFINED = ('portal', 'dora', 'pooled', 'gx')
WHOLE = ('root', 'ops')
NOTHING = ('blind', 'gone')


def _register(add):
    """Each caller with the subscription and admin flag the stream gives it."""
    add('root', 'root', None, True, 'admin')
    add('ops', 'ops', [CID])
    add('portal', 'portal', [CID])               # VM-ACL, its tenant owns the cluster
    add('dora', 'dora', None)                    # VM-ACL of the default tenant
    add('pooled', 'pooled', [CID])               # pool grant of another tenant
    # an admin a tenant override lowers where they live: not is_admin on the stream
    add('gx', 'gx', ['other', CID], False, 'admin')
    add('blind', 'blind', [CID])                 # an operator whose role withholds the views
    add('gone', 'nobody-here', None)
    add('milton', 'milton', ['other'])


def _frames(q, kind=None):
    out = []
    while not q.empty():
        f = json.loads(q.get_nowait())
        if kind is None or f['type'] == kind:
            out.append(f)
    return out


def _nodes(q):
    """The node names of the one metrics frame in the queue, None without one."""
    frames = _frames(q, 'metrics')
    assert len(frames) <= 1, frames
    return sorted(frames[0]['data']) if frames else None


def _drain(queues):
    for q in queues.values():
        _frames(q)


def _prime(cluster, queues):
    rt.broadcast_sse('resources', cluster.get_vm_resources(), CID)
    _drain(queues)


# --- metrics --------------------------------------------------------------------------------

def test_each_stream_gets_the_nodes_its_own_guests_run_on(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    _register(add)
    _prime(cluster, queues)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    got = {k: _nodes(q) for k, q in queues.items()}
    assert got['portal'] == ['n1'], got
    assert got['dora'] == ['n1'] and got['gx'] == ['n1'], got
    assert got['pooled'] == ['n2'], got
    for kind in WHOLE:
        assert got[kind] == ['n1', 'n2', 'n3'], (kind, got)
    for kind in NOTHING + ('milton',):
        assert got[kind] is None, (kind, got)


def test_the_unconfined_share_one_frame(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    add('root', 'root', None, True, 'admin')
    add('ops', 'ops', [CID])
    _prime(cluster, queues)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert queues['root'].get_nowait() == queues['ops'].get_nowait()


def test_before_a_resources_frame_a_confined_stream_gets_no_metrics(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    _register(add)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    got = {k: _nodes(q) for k, q in queues.items()}
    for kind in CONFINED + NOTHING:
        assert got[kind] is None, (kind, got)
    for kind in WHOLE:
        assert got[kind] == ['n1', 'n2', 'n3'], (kind, got)


def test_a_guest_that_moves_takes_the_frame_with_it(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    add('portal', 'portal', [CID])
    _prime(cluster, queues)
    cluster.guests[0]['node'] = 'n3'
    _prime(cluster, queues)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert _nodes(queues['portal']) == ['n3']


def test_a_maintenance_on_a_node_of_their_own_comes_without_its_guests(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    add('portal', 'portal', [CID])
    add('ops', 'ops', [CID])
    cluster.nodes['n1'].update(maintenance_mode=True, maintenance_task={
        'node': 'n1', 'status': 'evacuating', 'total_vms': 3, 'migrated_vms': 1,
        'failed_vms': [{'vmid': 98710, 'name': 'db-secret'}],
        'pending_vms': [{'vmid': 98711, 'name': 'web-secret'}]})
    _prime(cluster, queues)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    mine = _frames(queues['portal'], 'metrics')[0]['data']
    assert sorted(mine) == ['n1']
    assert mine['n1']['maintenance_task']['status'] == 'evacuating'
    assert 'secret' not in json.dumps(mine) and '98710' not in json.dumps(mine)
    full = _frames(queues['ops'], 'metrics')[0]['data']
    assert full['n1']['maintenance_task']['failed_vms'][0]['vmid'] == 98710
    # the manager's answer is what the next frame is made from
    assert cluster.get_node_status()['n1']['maintenance_task']['pending_vms']


def test_a_stale_scope_is_not_trusted(seed, cluster, stream, monkeypatch):
    add, queues = stream
    _seed_callers(seed)
    add('portal', 'portal', [CID])
    add('ops', 'ops', [CID])
    _prime(cluster, queues)
    monkeypatch.setattr(rt, '_SSE_SCOPE_TTL', 0, raising=False)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert _nodes(queues['portal']) is None
    assert _nodes(queues['ops']) == ['n1', 'n2', 'n3']


def test_another_role_of_the_same_account_does_not_ride_its_scope(seed, cluster, stream):
    """A stream opened with an API token carries the token's role, and its own scope."""
    add, queues = stream
    _seed_callers(seed)
    add('portal', 'portal', [CID])
    _prime(cluster, queues)
    add('portal-token', 'portal', [CID], False, 'viewer')
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert _nodes(queues['portal-token']) is None
    assert _nodes(queues['portal']) == ['n1']


def test_an_unread_guest_list_shows_no_node(seed, cluster, stream, monkeypatch):
    """The per-guest gate failing for every guest is no grant on any."""
    add, queues = stream
    _seed_callers(seed)
    add('portal', 'portal', [CID])
    monkeypatch.setattr('pegaprox.utils.rbac.get_vm_acls', lambda: {'__unavailable__': True})
    monkeypatch.setattr('pegaprox.utils.rbac.acls_unavailable', lambda acls: True)
    _prime(cluster, queues)
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert _nodes(queues['portal']) in (None, [])


def test_before_a_resources_frame_each_account_is_read_once_and_kept(seed, cluster, stream,
                                                                     monkeypatch):
    add, queues = stream
    _seed_callers(seed)
    for n in (1, 2):
        add(f'portal-{n}', 'portal', [CID])
        add(f'ops-{n}', 'ops', [CID])
    reads = []
    real = rt._sse_stored_user
    monkeypatch.setattr(rt, '_sse_stored_user', lambda *a, **k: reads.append(a) or real(*a, **k))
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    got = {k: _nodes(q) for k, q in queues.items()}
    assert got['portal-1'] is None and got['portal-2'] is None, got
    assert got['ops-1'] == got['ops-2'] == ['n1', 'n2', 'n3'], got
    assert sorted(a[0] for a in reads) == ['ops', 'portal']   # one per account, not per stream
    reads.clear()
    rt.broadcast_sse('metrics', cluster.get_node_status(), CID)
    assert reads == []


# --- node_status / ha_status ----------------------------------------------------------------

def _who_got(queues, kind):
    return sorted(k for k, q in queues.items() if _frames(q, kind))


def test_a_node_event_goes_to_who_may_see_that_node(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    _register(add)
    _prime(cluster, queues)
    rt.broadcast_sse('node_status', {'node': 'n1', 'status': 'offline', 'event': 'node_offline',
                                     'message': 'Node n1 is offline!', 'cluster_id': CID}, CID)
    assert _who_got(queues, 'node_status') == ['dora', 'gx', 'ops', 'portal', 'root']
    rt.broadcast_sse('node_status', {'node': 'n2', 'status': 'online', 'event': 'node_online',
                                     'message': 'Node n2 is back online', 'cluster_id': CID}, CID)
    assert _who_got(queues, 'node_status') == ['ops', 'pooled', 'root']
    # about the cluster, not a node of theirs
    rt.broadcast_sse('node_status', {'event': 'cluster_reconnected', 'cluster_id': CID,
                                     'message': 'Connection to cluster restored'}, CID)
    assert _who_got(queues, 'node_status') == ['ops', 'root']


def test_before_a_resources_frame_a_confined_stream_gets_no_node_event(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    _register(add)
    rt.broadcast_sse('node_status', {'node': 'n1', 'status': 'offline', 'event': 'node_offline',
                                     'message': 'Node n1 is offline!', 'cluster_id': CID}, CID)
    assert _who_got(queues, 'node_status') == ['ops', 'root']


def test_an_ha_event_that_lists_guests_is_not_for_a_confined_stream(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    _register(add)
    _prime(cluster, queues)
    for event in ('ha.recovery_left_guests', 'ha.recovery_node_back', 'ha.recovery_unclassified'):
        rt.broadcast_sse('ha_status', {'event': event, 'node': 'n1', 'cluster_id': CID,
                                       'message': 'n1: guests 300 (stopped) - start them by hand',
                                       'severity': 'critical'}, CID)
        assert _who_got(queues, 'ha_status') == ['ops', 'root'], event
    rt.broadcast_sse('ha_status', {'event': 'ha.recovery_refused', 'node': 'n1', 'cluster_id': CID,
                                   'message': 'n1 is not recovered', 'severity': 'critical'}, CID)
    assert _who_got(queues, 'ha_status') == ['dora', 'gx', 'ops', 'portal', 'root']
    rt.broadcast_sse('ha_status', {'event': 'quorum_restored', 'expected_votes': 3,
                                   'message': 'Quorum restored to 3 nodes', 'cluster_id': CID}, CID)
    assert _who_got(queues, 'ha_status') == ['ops', 'root']


def test_an_ha_event_for_many_clusters_asks_each_stream_about_its_own(seed, cluster, stream):
    add, queues = stream
    _seed_callers(seed)
    _register(add)
    _prime(cluster, queues)
    rt.broadcast_sse('ha_status', {'event': 'ha.forced_leader', 'message': 'forced', 'epoch': 4,
                                   'severity': 'critical'}, target_clusters=[CID, 'other'])
    # confined in cluster_1, an operator of 'other': gx's tenant owns it, dora's (the
    # default one) lists no clusters and so reaches every one
    assert _who_got(queues, 'ha_status') == ['dora', 'gx', 'milton', 'ops', 'root']


# --- scale ----------------------------------------------------------------------------------

def test_a_metrics_frame_costs_no_guest_and_no_account_at_scale(seed, stream, monkeypatch):
    """200 nodes, 10k guests, 50 confined and 50 unconfined streams of 100 accounts. Once a
    resources frame has gone out, the metrics frame reads no guest and no account, and is
    serialized once for the unconfined and once per distinct node set of the confined."""
    from pegaprox.utils import rbac
    import pegaprox.api.helpers as helpers
    add, queues = stream
    nodes = [f'pve{i:03d}' for i in range(200)]
    guests = [{'vmid': 10000 + i, 'node': nodes[i % 200], 'type': 'qemu', 'name': f'g{i}',
               'status': 'running'} for i in range(10_000)]
    big = _Cluster(nodes=nodes, guests=guests, pools={})
    monkeypatch.setitem(ppglobals.cluster_managers, CID, big)
    seed.tenant('acme', clusters=[CID])
    grants, want = {}, {}
    for k in range(50):
        # two guests each, on two nodes; ten node sets among the fifty
        s, m = k % 10, k // 10
        name = f'cust{k:02d}'
        grants[name] = {10000 + s + 200 * m, 10100 + s + 200 * m}
        want[name] = sorted({nodes[s], nodes[s + 100]})
        for vmid in grants[name]:
            seed.vm_acl(CID, vmid, users=[name])
        seed.user(name, role='user', tenant_id='acme')
        add(name, name, [CID])
    for k in range(50):
        name = f'oper{k:02d}'
        seed.user(name, role='user', tenant_id='acme')
        add(name, name, [CID])

    # The resources pass decides guest by guest, which costs that pass at this size, not this
    # frame: a stand-in decides there, checked against the real gate on a few guests.
    real_gate = rbac.user_can_access_vm
    for name, vmid in (('cust00', 10000), ('cust37', 10707), ('cust37', 10000), ('oper05', 10707)):
        user = rt._sse_stored_user(name, 'user')
        assert real_gate(user, CID, vmid, 'vm.view', 'qemu') == (vmid in grants.get(name, {vmid}))

    def stand_in(user, cluster_id, vmid, permission='vm.view', vm_type=None):
        mine = grants.get(user.get('username'))
        return mine is None or int(vmid) in mine
    monkeypatch.setattr(rbac, 'user_can_access_vm', stand_in)
    _prime(big, queues)

    calls = collections.Counter()

    def counted(what, fn):
        def wrapper(*a, **k):
            calls[what] += 1
            return fn(*a, **k)
        return wrapper
    monkeypatch.setattr(rbac, 'user_can_access_vm', counted('per-guest', real_gate))
    monkeypatch.setattr(rbac, 'has_permission', counted('permission', rbac.has_permission))
    monkeypatch.setattr(helpers, 'caller_is_scoped', counted('scoped', helpers.caller_is_scoped))
    monkeypatch.setattr(rt, '_sse_stored_user', counted('user read', rt._sse_stored_user))
    monkeypatch.setattr(seed.db, 'get_user', counted('db user', seed.db.get_user))
    monkeypatch.setattr(rt, '_serialize_sse_message',
                        counted('serialized', rt._serialize_sse_message))
    rt.broadcast_sse('metrics', big.get_node_status(), CID)

    for k in range(50):
        name = f'cust{k:02d}'
        assert _nodes(queues[name]) == want[name], name
    for k in range(50):
        assert _nodes(queues[f'oper{k:02d}']) == sorted(nodes)
    assert calls['per-guest'] == 0 and calls['user read'] == 0 and calls['db user'] == 0, calls
    assert calls['permission'] == 0 and calls['scoped'] == 0, calls
    assert calls['serialized'] == 1 + len({tuple(v) for v in want.values()}) == 11, calls


# --- the WebSocket's 'action' frames about a node -------------------------------------------

@pytest.fixture
def ws_clients():
    """add(name, user, clusters, is_admin): a client as /api/ws/updates registers it."""
    import threading
    from unittest.mock import MagicMock
    saved = dict(rt.ws_clients)
    rt.ws_clients.clear()
    socks = {}

    def add(name, user, clusters=None, is_admin=False, role='user'):
        socks[name] = MagicMock()
        rt.ws_clients[name] = {'ws': socks[name], 'lock': threading.Lock(), 'user': user,
                               'clusters': clusters, 'is_admin': is_admin, 'effective_role': role}
    try:
        yield add, socks
    finally:
        rt.ws_clients.clear()
        rt.ws_clients.update(saved)


def _ws_frames(sock):
    return [json.loads(c.args[0])['data'] for c in sock.send.call_args_list]


def test_a_node_action_goes_to_who_may_see_that_node_without_the_guests(seed, cluster, stream, ws_clients):
    """A node's maintenance, reboot and the start, stop or move of all its guests went to
    every WebSocket client of the cluster, with the operator and the vmids of the guests."""
    add, queues = stream
    add_ws, socks = ws_clients
    _seed_callers(seed)
    for name in ('portal', 'pooled'):
        add(name, name, [CID])            # their stream's resources pass keeps their nodes
    _prime(cluster, queues)
    add_ws('root', 'root', None, True, 'admin')
    add_ws('ops', 'ops', [CID])
    add_ws('portal', 'portal', [CID])     # VM 100 on n1
    add_ws('pooled', 'pooled', [CID])     # VM 200 on n2
    add_ws('blind', 'blind', [CID])       # no node.view
    add_ws('dora', 'dora', None)          # confined, no stream: no node scope known
    rt.broadcast_action('migrateall', 'node', 'n2', {'vms': [200, 300], 'target': 'n3'}, CID, 'ops')
    rt.broadcast_action('maintenance_enter', 'node', 'n1', {'status': 'evacuating'}, CID, 'ops')
    rt.broadcast_action('node_reboot', 'node', 'n3', {}, CID, 'ops')
    got = {k: [(f['action'], f['resource_id'], f['details']) for f in _ws_frames(s)] for k, s in socks.items()}
    whole = [('migrateall', 'n2', {'vms': [200, 300], 'target': 'n3'}),
             ('maintenance_enter', 'n1', {'status': 'evacuating'}), ('node_reboot', 'n3', {})]
    assert got['root'] == whole and got['ops'] == whole, got
    assert got['portal'] == [('maintenance_enter', 'n1', {'status': 'evacuating'})], got
    assert got['pooled'] == [('migrateall', 'n2', {})], got
    assert got['blind'] == [] and got['dora'] == [], got


def test_a_node_action_reads_each_account_once_per_frame(seed, cluster, stream, ws_clients, monkeypatch):
    add, queues = stream
    add_ws, socks = ws_clients
    _seed_callers(seed)
    add('portal', 'portal', [CID])
    _prime(cluster, queues)
    for i in range(20):
        add_ws(f'portal-tab{i}', 'portal', [CID])
        add_ws(f'ops-tab{i}', 'ops', [CID])
    reads = collections.Counter()
    real = rt._sse_stored_user
    monkeypatch.setattr(rt, '_sse_stored_user', lambda u, r=None: reads.update([u]) or real(u, r))
    rt.broadcast_action('maintenance_enter', 'node', 'n1', {'status': 'evacuating'}, CID, 'ops')
    assert reads == {'portal': 1, 'ops': 1}, reads
    assert all(len(_ws_frames(s)) == 1 for s in socks.values())
