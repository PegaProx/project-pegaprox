"""The diagnostics show what the event sources read on a cluster's nodes (ZFS pools, clocks,
QDevice votes, OSDs) only to a caller who gets that cluster's node alerts.

Their notes name the nodes asked and the slowest OSD with its latency. A caller confined to
pools or guests and a cluster-wide caller without node.view read them there, while
active-alerts, the push inbox and the rule lists keep a node's alerts from both. What the
other sources read (tasks, Ceph health, backups) stays as it was.
"""
import inspect
import re
import time
import types

import pytest

import pegaprox.utils.rbac as rbac
from pegaprox.api.helpers import caller_is_scoped
from pegaprox.background import alert_events as E

CID = 'cluster_1'
CONFINED = ('carol', 'erin', 'dflt')
NODE_NOTES = {
    'ceph_osd': '6 OSD(s) listed by pve-node-7, 0 without latency figures, slowest osd.3 at 40 ms',
    'clock': "2 of 3 online node(s) read, largest offset 0.4 s, unread: ['pve-node-9']",
    'zfs': "2 pool(s) on 1 of 2 online node(s), 2 of 2 pool status read(s), unread: ['pve-node-9']",
    'qdevice': '2 of 3 node(s) asked answered, 0 not reachable on an address of their own, no QDevice',
}


@pytest.fixture
def world(api, seed, monkeypatch):
    seed.tenant('tenant_x', clusters=[CID])
    manage = ['alert.manage']
    users = {
        'carol': seed.user('carol', role='viewer', tenant_id='tenant_x', permissions=manage),
        'erin': seed.user('erin', role='viewer', tenant_id='tenant_x', permissions=manage),
        'dflt': seed.user('dflt', role='viewer', permissions=manage),
        'nonode': seed.user('nonode', role='viewer', tenant_id='tenant_x', permissions=manage,
                            denied=['node.view']),
        'wide': seed.user('wide', role='viewer', tenant_id='tenant_x', permissions=manage),
        'root': seed.user('root', role='admin'),
    }
    for name in ('carol', 'dflt'):
        seed.pool(CID, 'pool_a', name, ['pool.view'])
    seed.vm_acl(CID, 100, ['erin'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_a', '200:qemu': 'pool_b'},
                                            'timestamp': time.time(), 'refreshing': False}
    mgr = api.make_fake_manager(cluster_id=CID)
    mgr.config = types.SimpleNamespace(name=CID, check_interval=300, host='h', enabled=True)
    api.set_manager(CID, mgr)
    monkeypatch.setattr(E, '_status', {})
    for source, note in NODE_NOTES.items():
        E._note(CID, source, True, note)
    E._note(CID, 'tasks', True, '12 listed, 3 in the window')
    E._note(CID, 'ceph', True, 'HEALTH_OK')
    return types.SimpleNamespace(users=users, clients={n: api.as_user(u) for n, u in users.items()})


def test_the_node_sources_are_the_ones_the_node_readers_write():
    written = set(re.findall(r"_note\(cid, '(\w+)'", inspect.getsource(E)))
    assert set(E.NODE_SOURCES) == set(NODE_NOTES) and set(E.NODE_SOURCES) <= written


@pytest.mark.parametrize('who', CONFINED + ('nonode', 'wide', 'root'))
def test_the_diagnostics_show_what_was_read_on_the_nodes_only_with_node_alerts(world, who):
    u = world.users[who]
    assert caller_is_scoped(u, CID) is (who in CONFINED)
    r = world.clients[who].get('/api/alerts/diagnostics')
    assert r.status_code == 200, r.get_data(as_text=True)
    seen = r.get_json()['event_sources'][CID]
    # the other sources stay for every caller who reaches the cluster
    assert seen['tasks']['note'] == '12 listed, 3 in the window' and seen['ceph']['note'] == 'HEALTH_OK'
    if who in ('wide', 'root'):
        assert {k: seen[k]['note'] for k in NODE_NOTES} == NODE_NOTES
    else:
        assert set(NODE_NOTES).isdisjoint(seen), sorted(seen)
        text = r.get_data(as_text=True)
        assert 'pve-node-7' not in text and 'pve-node-9' not in text
