"""The node a rolling update just finished takes the next node's guests (#1387).

Two nodes: node1 left maintenance, and seconds later node2's evacuation said "completed"
with all its guests still on it, so the update went on to install. PVE's HA status still
named node1 for a while, the poll took that for maintenance set from outside, and with no
target left the evacuation took the single-node path. Now the exit is not undone by PVE
lagging behind, the rolling update waits for HA to let go of the node, and a cluster with
other nodes never calls a drain with no target done.
"""
import ast
import os
import threading
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mm
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask

GUEST = {'vmid': 100, 'node': 'n2', 'status': 'running', 'type': 'qemu', 'name': 'web', 'mem': 1}
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Clock:
    """sleep moves the clock on and returns at once; monotonic follows it."""
    def __init__(self):
        self.now = 0.0

    def __getattr__(self, name):
        return getattr(time, name)

    def sleep(self, seconds):
        self.now += seconds

    def time(self):
        return 1000.0 + self.now

    def monotonic(self):
        return 5000.0 + self.now


def _status(maint_n1):
    return {'n1': {'status': 'online', 'score': 1, 'maintenance_mode': maint_n1},
            'n2': {'status': 'online', 'score': 1, 'maintenance_mode': True}}


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(mm, 'time', c)
    return c


@pytest.fixture
def mgr(clock, monkeypatch):
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.config = MagicMock(proxlb_pins_strict=False, excluded_nodes=[])
    m.nodes_in_maintenance = {}
    m.maintenance_lock = threading.Lock()
    m._rolling_update = None
    m._evacuation_placement = lambda *a: ({}, {})
    m._evacuation_allowed_nodes = lambda vm, p: None
    m._derive_proxlb_tag_rules = lambda vms=None: {'pins': {}, 'rules': [], 'ignored': set(), 'unresolved': []}
    m._evacuate_templates = lambda *a, **k: None
    m.migrate_vm = MagicMock(return_value=True)
    m.id = 'c1'
    return m


def _evacuate(m):
    task = MaintenanceTask('n2')
    m.nodes_in_maintenance['n2'] = task
    m._evacuate_node('n2', task)
    return task


# the drain with other nodes in the cluster

def test_a_peer_that_never_takes_guests_is_an_error_not_done(mgr, clock):
    mgr.get_node_status = lambda: _status(maint_n1=True)
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    task = _evacuate(mgr)
    assert task.status == 'completed_with_errors', (task.status, task.note)
    assert [f['vmid'] for f in task.failed_vms] == [100]
    assert 'no other node could take it' in task.failed_vms[0]['error']
    assert 'still on n2' in task.note
    mgr.migrate_vm.assert_not_called()
    assert clock.now >= mm.EVACUATION_TARGET_WAIT


def test_a_peer_that_comes_free_during_the_wait_takes_the_guests(mgr, clock):
    reads = iter([_status(maint_n1=True), _status(maint_n1=True), _status(maint_n1=True)])
    mgr.get_node_status = lambda: next(reads, _status(maint_n1=False))
    on_n2 = [[dict(GUEST)]] * 3
    answers = iter(on_n2)
    mgr.get_vm_resources = lambda *a, **k: next(answers, [dict(GUEST, node='n1')])
    task = _evacuate(mgr)
    mgr.migrate_vm.assert_called()
    assert mgr.migrate_vm.call_args[0][1] == 'n1' or 'n1' in str(mgr.migrate_vm.call_args)
    assert task.status == 'completed', (task.status, task.failed_vms, task.note)
    assert clock.now < mm.EVACUATION_TARGET_WAIT


def test_a_cancel_during_the_wait_stops_it(mgr, clock):
    def status():
        if clock.now >= 10:
            mgr.nodes_in_maintenance.pop('n2', None)   # the admin left maintenance
        return _status(maint_n1=True)
    mgr.get_node_status = status
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    task = _evacuate(mgr)
    assert task.status == 'cancelled'
    mgr.migrate_vm.assert_not_called()
    assert clock.now < mm.EVACUATION_TARGET_WAIT


def test_a_real_single_node_still_flags_and_is_done(mgr, clock):
    mgr.get_node_status = lambda: {'n2': {'status': 'online', 'score': 1}}
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    task = _evacuate(mgr)
    assert task.status == 'completed' and 'Single node' in task.note
    assert clock.now == 0, 'a single node has nothing to wait for'


# the exit is not undone by PVE's HA status lagging behind

@pytest.fixture
def poll_mgr(mgr, monkeypatch):
    import pegaprox.core.manager as manager_mod
    monkeypatch.setattr(manager_mod, 'get_db', lambda: MagicMock())
    monkeypatch.setattr(manager_mod, 'maintenance_ha_owner', lambda n: 'owner', raising=False)
    mgr.current_host = 'h'
    mgr.config.api_port = 8006
    mgr._api_get = lambda *a, **k: None
    mgr._node_status_cache = (0.0, {'stale': True})
    ha = {'nodes': {'n1'}}

    def native():
        mgr._ha_maint_poll_ok = True
        return set(ha['nodes'])
    mgr._get_native_ha_maintenance_nodes = native
    mgr._ha = ha
    return mgr


def _left(m):
    t = MaintenanceTask('n1')
    t.native_ha = False
    m.nodes_in_maintenance['n1'] = t
    assert PegaProxManager.exit_maintenance_mode(m, 'n1') is True


def test_the_exit_drops_the_cached_node_status(poll_mgr):
    _left(poll_mgr)
    assert poll_mgr._node_status_cache is None


def test_pve_still_naming_the_node_does_not_put_it_back(poll_mgr):
    _left(poll_mgr)
    poll_mgr.refresh_maintenance_status()
    assert 'n1' not in poll_mgr.nodes_in_maintenance


def test_once_pve_lets_go_maintenance_from_outside_counts_again(poll_mgr):
    _left(poll_mgr)
    poll_mgr._ha['nodes'] = set()
    poll_mgr.refresh_maintenance_status()     # PVE caught up, the grace ends
    poll_mgr._ha['nodes'] = {'n1'}             # and someone switches it on by hand
    poll_mgr.refresh_maintenance_status()
    assert 'n1' in poll_mgr.nodes_in_maintenance


def test_the_grace_has_an_end(poll_mgr, clock):
    _left(poll_mgr)
    clock.now += mm.MAINT_LEFT_GRACE + 1
    poll_mgr.refresh_maintenance_status()
    assert 'n1' in poll_mgr.nodes_in_maintenance


def test_an_unread_ha_poll_ends_no_grace(poll_mgr):
    _left(poll_mgr)

    def unread():
        poll_mgr._ha_maint_poll_ok = False
        return set()
    poll_mgr._get_native_ha_maintenance_nodes = unread
    poll_mgr.refresh_maintenance_status()
    assert 'n1' in poll_mgr._maint_left_at


# the rolling update itself

def test_the_rolling_update_waits_for_ha_to_let_go_before_the_next_node():
    src = open(os.path.join(REPO, 'pegaprox', 'api', 'settings.py'), encoding='utf-8').read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'run_rolling_update')
    body = ast.get_source_segment(src, fn)
    finishing = body[body.index("if todo('finishing'):"):body.index("if todo('ceph'):")]
    assert '_get_native_ha_maintenance_nodes' in finishing
    assert finishing.index('mgr.exit_maintenance_mode(node_name)') < finishing.index('_get_native_ha_maintenance_nodes')
    assert 'idx < total - 1' in finishing, 'the last node has no next node to wait for'
