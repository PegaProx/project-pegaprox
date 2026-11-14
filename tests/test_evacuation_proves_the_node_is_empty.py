"""An evacuation that cannot show the node is empty does not say it is.

A rolling update reboots the node once this says completed. A guest list that timed out read as no guests, a node list that failed read as a
single node, and guests still on the node after the five minute wait were only a log line, so the node went down with them.
"""
import threading
import time
from unittest.mock import MagicMock

import pytest

import pegaprox.core.manager as mm
from pegaprox.core.manager import PegaProxManager, UnreadList
from pegaprox.models.tasks import MaintenanceTask

GUEST = {'vmid': 100, 'node': 'n1', 'status': 'running', 'type': 'qemu', 'name': 'web', 'mem': 1}
NODES = {'n2': {'status': 'online', 'score': 1}, 'n1': {'status': 'online', 'score': 1}}


class _Clock:
    now = [0.0]

    def __getattr__(self, name):
        return getattr(time, name)

    def sleep(self, seconds):
        self.now[0] += seconds

    def time(self):
        return 1000.0 + self.now[0]


@pytest.fixture
def mgr(monkeypatch):
    monkeypatch.setattr(mm, 'time', _Clock())
    m = PegaProxManager.__new__(PegaProxManager)
    m.logger = MagicMock()
    m.config = MagicMock(proxlb_pins_strict=False, excluded_nodes=[])
    m.nodes_in_maintenance = {}
    m.maintenance_lock = threading.Lock()
    m._rolling_update = None
    m._evacuation_placement = lambda: ({}, {})
    m._evacuation_allowed_nodes = lambda vm, p: None
    m._derive_proxlb_tag_rules = lambda vms=None: {'pins': {}, 'rules': [], 'ignored': set(), 'unresolved': []}
    m.migrate_vm = MagicMock(return_value=True)
    m.get_node_status = lambda: dict(NODES)
    return m


def _evacuate(m):
    task = MaintenanceTask('n1')
    m._evacuate_node('n1', task)
    return task


def test_a_guest_list_that_was_not_read_fails(mgr):
    mgr.get_vm_resources = lambda *a, **k: UnreadList()
    task = _evacuate(mgr)
    assert task.status == 'failed' and 'could not be read' in task.error
    mgr.migrate_vm.assert_not_called()


def test_a_node_list_that_was_not_read_fails(mgr):
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    mgr.get_node_status = lambda: {}
    task = _evacuate(mgr)
    assert task.status == 'failed' and 'node list' in task.error


def test_a_real_single_node_is_still_nothing_to_move_to(mgr):
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    mgr.get_node_status = lambda: {'n1': {'status': 'online', 'score': 1}}
    task = _evacuate(mgr)
    assert task.status == 'completed' and 'Single node' in task.note


def test_an_empty_node_is_still_done(mgr):
    mgr.get_vm_resources = lambda *a, **k: []
    assert _evacuate(mgr).status == 'completed'


def test_a_guest_still_there_after_the_wait_is_an_error_by_name(mgr):
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    task = _evacuate(mgr)
    assert task.status == 'completed_with_errors'
    assert [f['vmid'] for f in task.failed_vms] == [100], task.failed_vms
    assert 'Still on the node' in task.failed_vms[0]['error']


def test_a_count_that_cannot_be_read_after_the_moves_is_an_error(mgr):
    reads = iter([[dict(GUEST)]])
    mgr.get_vm_resources = lambda *a, **k: next(reads, UnreadList())
    task = _evacuate(mgr)
    assert task.status == 'completed_with_errors'
    assert 'verify' in task.failed_vms[0]['error'], task.failed_vms


def test_a_guest_that_left_during_the_wait_is_fine(mgr):
    answers = iter([[dict(GUEST)], [dict(GUEST)], [dict(GUEST)], [dict(GUEST, node='n2')]])
    last = [dict(GUEST, node='n2')]
    mgr.get_vm_resources = lambda *a, **k: next(answers, last)
    task = _evacuate(mgr)
    assert task.status == 'completed' and task.failed_vms == []


def test_a_node_list_that_comes_back_on_a_second_read_still_fails(mgr):
    # the target pick read nothing, a second read recovered and the guests were called a single node's
    reads = iter([{}, dict(NODES)])
    mgr.get_node_status = lambda: next(reads, dict(NODES))
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    task = _evacuate(mgr)
    assert task.status == 'failed' and 'node list' in task.error, (task.status, task.error)
    mgr.migrate_vm.assert_not_called()


def test_a_node_list_without_the_node_itself_fails(mgr):
    # a node whose details ran out of time is left out of the list; its peer is offline
    mgr.get_node_status = lambda: {'n2': {'status': 'offline', 'score': 0}}
    mgr.get_vm_resources = lambda *a, **k: [dict(GUEST)]
    task = _evacuate(mgr)
    assert task.status == 'failed' and 'does not contain n1' in task.error, (task.status, task.error)
    mgr.migrate_vm.assert_not_called()


def test_the_target_comes_from_the_node_list_it_is_given(mgr):
    mgr.get_node_status = MagicMock(return_value={})
    got = PegaProxManager.get_best_target_node(mgr, exclude_nodes=['n1'], node_status=dict(NODES))
    assert got == 'n2'
    mgr.get_node_status.assert_not_called()


def test_an_unread_list_after_the_wait_is_no_proof_once_a_failed_move_lands(mgr):
    # web could not be moved and a second guest is counted on the node. The read that would name
    # it is unread, then the CRM finishes the move of web: the second guest is still there
    other = dict(GUEST, vmid=101, name='db')
    reads = iter([[dict(GUEST)], [dict(GUEST)], UnreadList(), [dict(GUEST, node='n2'), other]])
    mgr.get_vm_resources = lambda *a, **k: next(reads)
    mgr._count_vms_on_node = lambda node: 2
    mgr.migrate_vm = MagicMock(return_value=False)
    task = _evacuate(mgr)
    assert task.status == 'completed_with_errors', (task.status, task.error, task.failed_vms)
    assert [f['vmid'] for f in task.failed_vms] == [None] and 'verify' in task.failed_vms[0]['error']
