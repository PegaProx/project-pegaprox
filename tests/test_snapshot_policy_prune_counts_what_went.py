"""A policy run counts as pruned only the snapshots that are gone.

_prune counted every delete it sent. The manager answers a refused one with
{'success': False} rather than raising, and PVE answers an accepted one with a task
(DELETE .../snapshot/{snapname} returns "the task ID"): the guest's lock is taken inside
that task (pve-guest-common AbstractConfig::snapshot_delete, set_lock with check_lock),
so a delete sent while the one before still ran was accepted and then died in its task
with 'VM is locked'. A run then took about one snapshot while the summary said all of
them went, and a surplus of more than one never shrank. Now each delete task is waited
for, the next one goes after it, and only a task that ended OK counts. What did not go
is in the run log.

MK Nov 2026
"""
import time

import pytest

from pegaprox.api import snapshots as sn
from pegaprox.core import ha

PID = 'abcdef012345'
PREFIX = f'pegaprox-{PID[:12]}-'
POLICY = {'id': PID, 'retention_count': 1, 'retention_days': 0}


class _Guest:
    """One guest as PVE runs snapshot deletes on it. The DELETE is answered at once with
    a task; the task takes the guest's lock, so one started while another still runs ends
    'VM is locked (snapshot-delete)' and removes nothing. A task runs until it is waited
    for, or until settle() lets the last one finish on its own."""

    def __init__(self, count=4, fail=()):
        now = time.time()
        self.fail = set(fail)        # their tasks end in an error of the storage
        self.snaps = [{'name': f'{PREFIX}{i}', 'snaptime': now - i * 86400} for i in range(count)]
        self.snaps.append({'name': 'by-hand', 'snaptime': now - 400 * 86400})
        self.tasks = {}
        self.running = None

    def list_snapshots(self, node, vmid, kind):
        return list(self.snaps)

    def delete_snapshot(self, node, vmid, kind, name):
        upid = f'UPID:{node}:{len(self.tasks):08X}:0001:6730AABB:qmdelsnapshot:{vmid}:root@pam:'
        locked = self.running is not None
        status = 'VM is locked (snapshot-delete)' if locked else (
            'rbd error: error setting snapshot context' if name in self.fail else 'OK')
        self.tasks[upid] = (name, status)
        if not locked:
            self.running = upid
        return {'success': True, 'task': upid}

    def _wait_for_task(self, node, upid, timeout=600):
        name, status = self.tasks[upid]
        if self.running == upid:
            self.settle()
        return status == 'OK'

    def settle(self):
        if self.running:
            name, status = self.tasks[self.running]
            if status == 'OK':
                self.snaps = [s for s in self.snaps if s['name'] != name]
            self.running = None

    def names(self):
        return sorted(s['name'] for s in self.snaps)


@pytest.fixture(autouse=True)
def _lease(monkeypatch):
    monkeypatch.setattr(ha, 'confirm_step', lambda what: True)


def test_a_surplus_of_three_is_gone_after_one_run():
    guest = _Guest()
    pruned = sn._prune(guest, 'pve1', 100, 'qemu', POLICY)
    guest.settle()
    assert guest.names() == ['by-hand', f'{PREFIX}0']
    assert pruned == 3


def test_a_delete_task_that_failed_is_not_counted(caplog):
    guest = _Guest(count=3)
    first = guest.delete_snapshot('pve1', 100, 'qemu', 'by-hand')['task']   # someone else's, still running
    assert sn._prune(guest, 'pve1', 100, 'qemu', POLICY) == 0
    assert caplog.text.count('the delete task did not end OK') == 2
    guest._wait_for_task('pve1', first)
    # the next run takes them
    assert sn._prune(guest, 'pve1', 100, 'qemu', POLICY) == 2
    assert guest.names() == [f'{PREFIX}0']


def test_a_refused_delete_is_not_counted():
    guest = _Guest()
    # what PegaProxManager.delete_snapshot answers on a non-200 from PVE
    guest.delete_snapshot = lambda *a: {'success': False, 'error': '{"data":null,"message":"VM is locked (backup)\\n"}'}
    assert sn._prune(guest, 'pve1', 100, 'qemu', POLICY) == 0
    errors = []
    sn._prune(guest, 'pve1', 100, 'qemu', POLICY, errors)
    assert len(errors) == 3 and 'VM is locked (backup)' in errors[0]


def test_a_delete_without_a_task_to_wait_for_counts_when_it_was_accepted():
    """An XCP-ng pool deletes the snapshot within the call and answers {'success': True}."""
    guest = _Guest()
    gone = []
    guest.delete_snapshot = lambda node, vmid, kind, name: gone.append(name) or {'success': True}
    assert sn._prune(guest, 'pve1', 100, 'qemu', POLICY) == 3 == len(gone)


def test_the_run_record_counts_what_went_and_logs_what_did_not(api, seed, db):
    seed.user('adm', role='admin')
    db.conn.execute("INSERT INTO snapshot_policies (id, cluster_id, name, target_type, target_value, schedule, enabled, "
                    "retention_count, prune_only, created_by, created_at) VALUES (?, 'c1', 'p', 'tag', 'prod', "
                    "'daily', 1, 1, 1, 'adm', '2026-01-01T00:00:00')", (PID,))
    db.conn.commit()
    guest = _Guest(fail=[f'{PREFIX}3'])
    m = api.make_fake_manager(cluster_id='c1')
    m.get_vm_resources.return_value = [{'vmid': 100, 'type': 'qemu', 'node': 'pve1', 'tags': 'prod'}]
    m.list_snapshots.side_effect = guest.list_snapshots
    m.delete_snapshot.side_effect = guest.delete_snapshot
    m._wait_for_task.side_effect = guest._wait_for_task
    api.set_manager('c1', m)
    sn._execute_policy(PID)
    run = db.conn.execute('SELECT snapshots_pruned, log FROM snapshot_runs WHERE policy_id=?', (PID,)).fetchone()
    assert run['snapshots_pruned'] == 2
    assert f'not pruned {PREFIX}3: the delete task did not end OK' in run['log']
    assert guest.names() == ['by-hand', f'{PREFIX}0', f'{PREFIX}3']
