"""How the cluster task list (get_tasks, /api/clusters/<id>/tasks) reads the end of a task.

/cluster/tasks carries no exitstatus field: a finished task has its result in status
("OK", "WARNINGS: n", "job errors" or the error message) and an endtime, a running one
has neither. The check that should turn a failed task into status 'failed' asked
getattr() of the dict, which never finds a key, so it never ran: a backup that ended
with "job errors" was neither counted nor drawn as failed in the task bar.
NS Nov 2026
"""
import types

import pytest

from pegaprox.core.manager import PegaProxManager

UPID = 'UPID:pve1:0000A1B2:0012C3D4:6700{n:04d}:{kind}:{vmid}:root@pam:'


def _row(n, kind='vzdump', vmid='101', status=None, end=True):
    row = {'upid': UPID.format(n=n, kind=kind, vmid=vmid), 'node': 'pve1', 'type': kind,
           'id': vmid, 'user': 'root@pam', 'starttime': 1730000000 + n, 'pid': 41000 + n,
           'pstart': 1200000 + n}
    if end:
        row['endtime'] = 1730000060 + n
    if status is not None:
        row['status'] = status
    return row


class _Resp:
    def __init__(self, rows):
        self.status_code = 200
        self._rows = rows

    def json(self):
        return {'data': self._rows}


def _mgr(rows):
    mgr = object.__new__(PegaProxManager)
    mgr.is_connected = True
    mgr.session = object()
    mgr.current_host = 'pve1.lab'
    mgr.config = types.SimpleNamespace(host='pve1.lab', api_port=8006)
    mgr.id = 'c1'
    mgr._tasks_ttl = 0
    mgr.logger = types.SimpleNamespace(error=lambda *a, **k: None, debug=lambda *a, **k: None)
    mgr._create_session = lambda: types.SimpleNamespace(get=lambda url, timeout=None: _Resp(rows))
    return mgr


@pytest.fixture(autouse=True)
def _known_user(monkeypatch):
    # a known initiator keeps the audit-log lookup (a database read) out of these tests
    import pegaprox.api.helpers as helpers
    monkeypatch.setattr(helpers, 'get_task_user', lambda upid: 'alice')


def _one(row):
    out = _mgr([row]).get_tasks(limit=50)
    assert len(out) == 1
    return out[0]


@pytest.mark.parametrize('said', ['job errors', 'unexpected status',
                                  "command 'vma create' failed: exit code 1",
                                  'interrupted by signal'])
def test_a_task_that_ended_badly_is_failed_with_what_proxmox_said(said):
    t = _one(_row(1, status=said))
    assert t['status'] == 'failed'
    assert t['exitstatus'] == said
    assert t['error'] == said


def test_a_task_that_ended_well_stays_ok():
    t = _one(_row(2, kind='qmstart', status='OK'))
    assert t['status'] == 'OK'
    assert t['exitstatus'] == 'OK'
    assert 'error' not in t


def test_a_task_with_warnings_ended_and_is_no_failure():
    # Proxmox counts it as done (bulk_migrate, timeline and the alert rules do the same)
    t = _one(_row(3, status='WARNINGS: 2'))
    assert t['status'] == 'WARNINGS: 2'
    assert t['exitstatus'] == 'WARNINGS: 2'
    assert 'error' not in t


def test_a_running_task_has_no_result_yet():
    t = _one(_row(4, kind='qmigrate', end=False))
    assert t['status'] == 'running'
    assert 'exitstatus' not in t and 'error' not in t


def test_an_empty_status_is_no_failure():
    # nothing said is not "failed" (alert_events reads such a row as still running too)
    t = _one(_row(6, status=''))
    assert t['status'] != 'failed' and 'error' not in t


def test_a_stopped_row_without_exitstatus_is_left_alone():
    # 'stopped' only says the task ended; with no exitstatus nothing says it went wrong
    t = _one(_row(7, status='stopped'))
    assert t['status'] == 'stopped'
    assert 'error' not in t and not t.get('exitstatus')


@pytest.mark.parametrize('exit_said,want', [('OK', 'stopped'), ('job errors', 'failed'),
                                            ('some error: disk full', 'failed')])
def test_a_row_in_the_task_status_shape_reads_its_exitstatus(exit_said, want):
    # the per-task status endpoint says 'stopped' plus exitstatus; a row of that shape
    # takes the result from exitstatus, not from 'stopped'
    row = _row(5, status='stopped')
    row['exitstatus'] = exit_said
    t = _one(row)
    assert t['status'] == want
    assert t['exitstatus'] == exit_said


def test_the_task_bar_counts_what_the_list_says():
    # the classic task bar counts status 'failed' / 'error' (dashboard.js TaskBar)
    rows = [_row(10, status='OK'), _row(11, status='job errors'), _row(12, end=False),
            _row(13, status='WARNINGS: 1'), _row(14, kind='qmstart', status='start failed: QEMU exited')]
    out = _mgr(rows).get_tasks(limit=50)
    assert sum(t['status'] in ('failed', 'error') for t in out) == 2
    assert sum(t['status'] == 'running' for t in out) == 1


def test_the_timeline_keeps_the_words_of_a_failed_task():
    # the timeline reads the same list (api/timeline.py _tasks): a failed task says what
    # Proxmox said, not the word 'failed', and stays an anchor
    from datetime import datetime, timedelta, timezone
    from pegaprox.api import timeline as tl_api
    rows = [_row(20, status='job errors'), _row(21, kind='qmstart', vmid='102', status='OK'),
            _row(22, status='WARNINGS: 1'), _row(23, kind='qmigrate', vmid='103', end=False)]
    at = datetime.fromtimestamp(1730000000, timezone.utc)
    ask = types.SimpleNamespace(mgr=_mgr(rows), cid='c1', lo=at - timedelta(hours=1),
                                hi=at + timedelta(hours=1), scoped=False, sees=lambda g: True,
                                keeps=lambda g, nodes: True, guest_name=lambda g: '')
    out, _notes = tl_api._tasks(ask)
    ev = {e['source']['id']: e for e in out['task'] + out['backup']}
    failed = ev[rows[0]['upid']]
    assert failed['details'] == 'job errors' and failed['params']['status'] == 'job errors'
    assert failed['severity'] == 'critical' and failed['_anchor']
    assert ev[rows[1]['upid']]['severity'] == 'info'
    assert ev[rows[2]['upid']]['severity'] == 'warning' and not ev[rows[2]['upid']]['_anchor']
    assert ev[rows[3]['upid']]['params']['status'] == 'running'


# the waits that read this list after a clone, migration or restore: a task that ended
# with "WARNINGS: n" finished, as get_tasks says, and only an error is a failure

@pytest.mark.parametrize('said,ok', [('OK', True), ('WARNINGS: 2', True), ('job errors', False)])
def test_the_cross_cluster_wait_takes_warnings_as_done(said, ok):
    from pegaprox.api.vms import _wait_for_task
    row = _row(30, kind='qmclone', status=said)
    assert _wait_for_task(_mgr([row]), row['upid'], timeout=1, poll=1) == (ok, said)


@pytest.mark.parametrize('said,ok', [('OK', True), ('WARNINGS: 1', True), ('job errors', False)])
def test_the_restore_test_wait_takes_warnings_as_done(said, ok):
    from pegaprox.core import backup_verify
    row = _row(31, kind='qmrestore', status=said)
    # a manager without the per-task status read: the wait falls back to the task list
    lister = types.SimpleNamespace(get_tasks=_mgr([row]).get_tasks)
    assert backup_verify._wait_task(lister, row['upid'], timeout=5) is ok
