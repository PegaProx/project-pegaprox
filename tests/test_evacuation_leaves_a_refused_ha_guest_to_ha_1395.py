"""A guest Proxmox HA moves off the node itself is not a failed move (#1395).

The evacuation asked ha-manager to take an HA guest to a node its node affinity rule did not
allow, and Proxmox refused. With the node in HA maintenance the CRM moved the guest off by
itself some 40 seconds later, to a node of its choosing, but the evacuation had counted it as
failed at once and showed it with Proceed Anyway until the end of the wait. Such a guest stays
pending now, and fails only when it is still on the node after the wait.
"""
import pegaprox.core.manager as mm  # noqa: F401
from pegaprox.models.tasks import MaintenanceTask
from test_evacuation_proves_the_node_is_empty import mgr, _Clock  # noqa: F401  (fixture)


def _rows():
    return {
        100: {'vmid': 100, 'node': 'n1', 'status': 'running', 'type': 'qemu', 'name': 'web', 'mem': 1},
        150: {'vmid': 150, 'node': 'n1', 'status': 'running', 'type': 'qemu', 'name': 'db',
              'mem': 2, 'hastate': 'started'},
    }


def _run(m, rows, ha_moves_after=None, native_ha=True):
    """150's move is refused; the CRM moves it to n2 `ha_moves_after` seconds into the run.
    What the task said about failures is recorded at every read of the guest list."""
    seen = []
    start = _Clock.now[0]

    def migrate(vm, target, **kw):
        if vm['vmid'] == 150:
            return False
        rows[vm['vmid']]['node'] = target
        return True

    def resources(*a, **k):
        if ha_moves_after is not None and _Clock.now[0] - start >= ha_moves_after:
            rows[150]['node'] = 'n2'
        seen.append([f['vmid'] for f in task.failed_vms])
        return [dict(r) for r in rows.values()]

    m.migrate_vm = migrate
    m.get_vm_resources = resources
    task = MaintenanceTask('n1')
    task.native_ha = native_ha
    m._evacuate_node('n1', task)
    return task, seen, _Clock.now[0] - start


def test_a_guest_ha_moves_itself_is_never_shown_as_failed(mgr):
    task, seen, waited = _run(mgr, _rows(), ha_moves_after=40)
    assert all(150 not in s for s in seen), seen
    assert task.status == 'completed' and task.failed_vms == []
    assert task.migrated_vms == task.total_vms == 2
    assert task.pending_vms == [] and task.left_to_ha == []
    # it waited for the CRM, and no longer than it took
    assert 40 <= waited < 120, waited


def test_a_guest_ha_does_not_move_fails_after_the_wait(mgr):
    task, seen, waited = _run(mgr, _rows())
    assert waited >= 300, waited
    assert task.status == 'completed_with_errors'
    [failed] = task.failed_vms
    assert failed['vmid'] == 150 and 'Proxmox HA refused the move' in failed['error']
    assert task.pending_vms == [] and task.migrated_vms == 1


def test_without_ha_maintenance_a_refused_guest_fails_at_once(mgr):
    # nothing moves it but us: failed as before
    task, seen, waited = _run(mgr, _rows(), native_ha=False)
    assert [f['vmid'] for f in task.failed_vms] == [150]
    assert task.failed_vms[0]['error'] == 'Migration failed'
    assert any(150 in s for s in seen[:-1]), seen
