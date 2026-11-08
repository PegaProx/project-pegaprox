"""A node's open incidents and their mutes are for callers with node.view, as the node pages are.

active-alerts and alert-mutes hid a node's incidents only from a caller confined to pools or
guests. A cluster-wide role without node.view (vm_operator and backup_operator as shipped, or
node.view denied) still read every node's ZFS pools with their devices, its OSDs, clock and
QDevice there, while the node routes answer that same caller 403.
MK Oct 2026
"""
import types

import pytest

from test_alert_events import _mute, _store
from test_alert_osd_rpo import _incident


@pytest.fixture
def routes(api, seed):
    api.set_manager('c1', api.make_fake_manager('c1'))
    seed.tenant('t_own', ['c1'])
    return types.SimpleNamespace(api=api, seed=seed, admin=api.as_user(seed.user('root', role='admin')))


NODE_OBJECTS = ('zfs:pve1:rpool', 'osd:pve1:3', 'qdevice:pve1', 'task:pve1:aptupdate:')
GUEST_OBJECTS = ('xcrepl:101:j1', 'task:pve2:vzdump:101')


def _fill(db):
    for obj in NODE_OBJECTS:
        _incident(db, 'zfs_health', obj, 'node', 'pve1')
    for obj in GUEST_OBJECTS:
        _incident(db, 'replication_rpo', obj, 'vm', '101')
    _incident(db, 'ceph_health', 'ceph', 'cluster', '')
    for obj in NODE_OBJECTS + GUEST_OBJECTS:
        _mute(db, object_key=obj)
    _mute(db, rule_id='r1')


def _seen(c):
    incidents = sorted(i['object_key'] for i in c.get('/api/clusters/c1/active-alerts').get_json()['active_alerts'])
    mutes = sorted(m['object_key'] or f"rule:{m['rule_id']}"
                   for m in c.get('/api/clusters/c1/alert-mutes').get_json()['mutes'])
    return incidents, mutes


@pytest.mark.parametrize('denied', [(), ('node.view',)])
def test_a_cluster_wide_caller_sees_a_nodes_incidents_only_with_node_view(routes, monkeypatch, db, denied):
    _store(monkeypatch)
    _fill(db)
    c = routes.api.as_user(routes.seed.user('op', role='user', tenant_id='t_own', denied=list(denied)))
    incidents, mutes = _seen(c)
    if denied:
        # the same caller on a node page: refused there before any manager is asked
        assert c.get('/api/clusters/c1/nodes/pve1/summary').status_code == 403
        assert incidents == sorted(GUEST_OBJECTS + ('ceph',))
        assert mutes == sorted(GUEST_OBJECTS + ('rule:r1',))
    else:
        assert incidents == sorted(NODE_OBJECTS + GUEST_OBJECTS + ('ceph',))
        assert mutes == sorted(NODE_OBJECTS + GUEST_OBJECTS + ('rule:r1',))


def test_the_admin_still_sees_everything(routes, monkeypatch, db):
    _store(monkeypatch)
    _fill(db)
    incidents, mutes = _seen(routes.admin)
    assert incidents == sorted(NODE_OBJECTS + GUEST_OBJECTS + ('ceph',))
    assert mutes == sorted(NODE_OBJECTS + GUEST_OBJECTS + ('rule:r1',))
