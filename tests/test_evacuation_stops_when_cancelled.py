"""A cancel or an exit of maintenance stops the evacuation.

Both take the task off the node, and the thread went on moving every remaining guest off a node that was no longer in maintenance.
"""
import threading
import time
import types
from unittest.mock import MagicMock

import pegaprox.core.manager as mm
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import MaintenanceTask


def _mgr():
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.config = MagicMock(proxlb_pins_strict=False, excluded_nodes=[])
    m.nodes_in_maintenance = {}
    m.maintenance_lock = threading.Lock()
    m._rolling_update = None
    m._evacuation_placement = lambda: ({}, {})
    m._evacuation_allowed_nodes = lambda vm, p: None
    m._derive_proxlb_tag_rules = lambda vms=None: {'pins': {}, 'rules': [], 'ignored': set(), 'unresolved': []}
    m.get_node_status = lambda: {'n2': {'status': 'online', 'score': 1}, 'n1': {'status': 'online', 'score': 1}}
    return m


def _guests(m, count=3):
    rows = [{'vmid': i, 'node': 'n1', 'status': 'running', 'type': 'qemu', 'name': f'v{i}', 'mem': i} for i in range(1, count + 1)]
    m.get_vm_resources = lambda *a, **k: [dict(r) for r in rows]
    return rows


def test_it_stops_at_the_next_guest(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    m = _mgr()
    rows = _guests(m)
    task = MaintenanceTask('n1')
    m.nodes_in_maintenance['n1'] = task
    moved = []

    def migrate(vm, target, dry_run=None, wait_timeout=0):
        moved.append(vm['vmid'])
        m.nodes_in_maintenance.pop('n1', None)
        rows[:] = [r for r in rows if r['vmid'] != vm['vmid']]
        return True
    m.migrate_vm = migrate
    m._evacuate_node('n1', task)
    assert moved == [1] and task.status == 'cancelled'


def test_all_of_them_move_while_it_stays_in_maintenance(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    m = _mgr()
    rows = _guests(m)
    task = MaintenanceTask('n1')
    m.nodes_in_maintenance['n1'] = task
    moved = []

    def migrate(vm, target, dry_run=None, wait_timeout=0):
        moved.append(vm['vmid'])
        rows[:] = [r for r in rows if r['vmid'] != vm['vmid']]
        return True
    m.migrate_vm = migrate
    m._evacuate_node('n1', task)
    assert moved == [1, 2, 3] and task.status == 'completed'


def _moving(m, rows, moved, on_move=None):
    def migrate(vm, target, dry_run=None, wait_timeout=0):
        moved.append(vm['vmid'])
        if on_move:
            on_move(vm)
        rows[:] = [r for r in rows if r['vmid'] != vm['vmid']]
        return True
    m.migrate_vm = migrate


def test_an_exit_before_the_thread_runs_stops_it(monkeypatch):
    # entering registers the task and then sets the Ceph flags and the HA flag over SSH before
    # the thread starts; an exit can land in that time
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    started = []

    class _Thread:
        def __init__(self, target=None, args=()):
            self.target, self.args, self.daemon = target, args, False

        def start(self):
            started.append(self)
    monkeypatch.setattr(mm, 'threading', types.SimpleNamespace(Thread=_Thread))
    monkeypatch.setattr(mm, 'get_db', lambda: MagicMock())
    m = _mgr()
    m.id = 'c1'
    m._set_ceph_maintenance_flags = lambda node: {}
    m._try_native_ha_maintenance = lambda node, task: False
    rows = _guests(m)
    moved = []
    _moving(m, rows, moved)
    task = m.enter_maintenance_mode('n1')
    assert len(started) == 1 and m.nodes_in_maintenance['n1'] is task
    m.nodes_in_maintenance.pop('n1')
    started[0].target(*started[0].args)
    assert moved == [] and task.status == 'cancelled'


def test_an_exit_during_the_first_read_stops_it(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    m = _mgr()
    rows = _guests(m)
    task = MaintenanceTask('n1')
    m.nodes_in_maintenance['n1'] = task

    def first_read(*a, **k):
        m.nodes_in_maintenance.pop('n1', None)
        return [dict(r) for r in rows]
    m.get_vm_resources = first_read
    moved = []
    _moving(m, rows, moved)
    m._evacuate_node('n1', task)
    assert moved == [] and task.status == 'cancelled'


def test_an_exit_while_the_target_is_picked_starts_no_move(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    m = _mgr()
    rows = _guests(m)
    task = MaintenanceTask('n1')
    m.nodes_in_maintenance['n1'] = task
    pick = PegaProxManager.get_best_target_node

    def picking(*a, **k):
        if k.get('vmid') is not None:
            m.nodes_in_maintenance.pop('n1', None)
        return pick(m, *a, **k)
    m.get_best_target_node = picking
    moved = []
    _moving(m, rows, moved)
    m._evacuate_node('n1', task)
    assert moved == [] and task.status == 'cancelled'


def test_an_exit_during_the_wait_ends_the_wait(monkeypatch):
    m = _mgr()
    rows = _guests(m, count=1)
    task = MaintenanceTask('n1')
    m.nodes_in_maintenance['n1'] = task
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        m.nodes_in_maintenance.pop('n1', None)
    monkeypatch.setattr(mm.time, 'sleep', sleep)
    moved = []
    # the move went through, the guest is still counted on the node
    m.migrate_vm = lambda vm, target, dry_run=None, wait_timeout=0: moved.append(vm['vmid']) or True
    m._evacuate_node('n1', task)
    assert moved == [1] and len(sleeps) == 1 and task.status == 'cancelled'


def _with_templates(m, rows, count):
    for i in range(count):
        rows.append({'vmid': 9000 + i, 'node': 'n1', 'status': 'stopped', 'type': 'qemu', 'name': f't{i}',
                     'template': 1, 'mem': 0})
    m.template_placement = lambda templates: [
        {'vmid': t['vmid'], 'name': t['name'], 'type': t['type'], 'reason': '', 'targets': ['n2']} for t in templates]
    m._wait_for_task = lambda node, upid, timeout=0: True


def test_no_template_moves_after_an_exit_during_the_last_guest(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    m = _mgr()
    rows = _guests(m, count=1)
    _with_templates(m, rows, 1)
    task = MaintenanceTask('n1')
    task.migrate_templates = True
    m.nodes_in_maintenance['n1'] = task
    moved = []
    _moving(m, rows, moved, on_move=lambda vm: m.nodes_in_maintenance.pop('n1', None))
    m.migrate_vm_manual = MagicMock(return_value={'success': True, 'task': 'UPID:n1:1'})
    m._evacuate_node('n1', task)
    assert moved == [1] and task.status == 'cancelled'
    m.migrate_vm_manual.assert_not_called()


def test_an_exit_during_a_template_stops_the_next_one(monkeypatch):
    monkeypatch.setattr(mm.time, 'sleep', lambda s: None)
    m = _mgr()
    rows = _guests(m, count=1)
    _with_templates(m, rows, 2)
    task = MaintenanceTask('n1')
    task.migrate_templates = True
    m.nodes_in_maintenance['n1'] = task
    moved = []
    _moving(m, rows, moved)
    sent = []

    def manual(node, vmid, vm_type, target, online=False):
        sent.append(vmid)
        m.nodes_in_maintenance.pop('n1', None)
        return {'success': True, 'task': 'UPID:n1:1'}
    m.migrate_vm_manual = manual
    m._evacuate_node('n1', task)
    assert moved == [1] and sent == [9000] and task.status == 'cancelled'
