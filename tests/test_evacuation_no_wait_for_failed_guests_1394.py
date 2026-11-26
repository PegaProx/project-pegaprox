"""Guests whose move failed do not keep the node in 'evacuating' (#1394).

Two containers with a bind mount cannot leave the node, PVE refuses them at once. The wait for a
node to empty out, meant for moves an HA manager is still finishing, then sat five minutes on
exactly those two before the task said completed with errors, and until then the node offered no
update or reboot.
"""
import pegaprox.core.manager as mm
from pegaprox.models.tasks import MaintenanceTask
from test_evacuation_proves_the_node_is_empty import mgr, _Clock  # noqa: F401  (fixture)


def _guests(**extra):
    rows = {
        100: {'vmid': 100, 'node': 'n1', 'status': 'running', 'type': 'qemu', 'name': 'web', 'mem': 1},
        201: {'vmid': 201, 'node': 'n1', 'status': 'running', 'type': 'lxc', 'name': 'backup-a', 'mem': 2},
        202: {'vmid': 202, 'node': 'n1', 'status': 'running', 'type': 'lxc', 'name': 'backup-b', 'mem': 3},
    }
    for vmid, fields in extra.items():
        rows[int(vmid[1:])].update(fields)
    return rows


def _run(m, rows, fails=(201, 202)):
    def migrate(vm, target, **kw):
        if vm['vmid'] in fails:
            return False
        rows[vm['vmid']]['node'] = target
        return True
    m.migrate_vm = migrate
    m.get_vm_resources = lambda *a, **k: [dict(r) for r in rows.values()]
    start = _Clock.now[0]
    task = MaintenanceTask('n1')
    m._evacuate_node('n1', task)
    return task, _Clock.now[0] - start


def test_failed_containers_finish_the_evacuation_at_once(mgr):
    task, waited = _run(mgr, _guests())
    assert task.status == 'completed_with_errors'
    assert sorted(f['vmid'] for f in task.failed_vms) == [201, 202]
    assert task.migrated_vms == 1
    assert waited < 60, waited


def test_a_guest_ha_may_still_move_keeps_the_wait(mgr):
    task, waited = _run(mgr, _guests(v201={'hastate': 'started'}))
    assert waited >= 300, waited
    assert task.status == 'completed_with_errors'


def test_a_guest_with_a_migrate_lock_keeps_the_wait(mgr):
    task, waited = _run(mgr, _guests(v202={'lock': 'migrate'}))
    assert waited >= 300, waited


def test_a_guest_nobody_tried_keeps_the_wait(mgr):
    # 202 never failed: it showed up on the node after the list was taken
    rows = _guests()
    first = {k: dict(v) for k, v in rows.items() if k != 202}
    calls = {'n': 0}

    def migrate(vm, target, **kw):
        if vm['vmid'] == 201:
            return False
        rows[vm['vmid']]['node'] = target
        return True
    mgr.migrate_vm = migrate

    def resources(*a, **k):
        calls['n'] += 1
        return [dict(r) for r in (first.values() if calls['n'] == 1 else rows.values())]
    mgr.get_vm_resources = resources
    start = _Clock.now[0]
    task = MaintenanceTask('n1')
    mgr._evacuate_node('n1', task)
    assert _Clock.now[0] - start >= 300
    assert {f['vmid'] for f in task.failed_vms} == {201, 202}
