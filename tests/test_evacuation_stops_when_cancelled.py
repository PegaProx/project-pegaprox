"""A cancel or an exit of maintenance stops the evacuation.

Both take the task off the node, and the thread went on moving every remaining guest off a node that was no longer in maintenance.
"""
import threading
import time
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
