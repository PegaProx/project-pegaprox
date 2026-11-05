"""A rolling update a schedule starts is as careful as one started by hand.

The scheduler had a worker of its own, a second copy of the run loop that fell behind the
one of settings.run_rolling_update: a node whose update failed, or whose update never
started, was written down and the run went on with the next node; an evacuation that left
guests behind went on to the update (and the reboot) of that node with the guests still on
it; Ceph was never looked at; start_node_update was called with force=True; the schedule
row had no place for wait_for_reboot (the dialog sent it, the run always waited) nor for the
alert channels, and no start or end was announced. The end in the audit log named no
cluster.

Now the scheduler starts the worker of the run started by hand, with the options of the
schedule, in the same run table. A schedule saved before the new options existed runs with
the safe ones: it pauses on a failed node and on an evacuation that left guests behind, and
waits for a rebooted node.

NS Nov 2026
"""
from datetime import datetime

import pytest

from pegaprox.core import ha, rolling_runs
from pegaprox.models.tasks import MaintenanceTask
from test_rolling_runs_survive_restart import (CID, NODES, _a_fresh_process, _Cluster, _row,  # noqa: F401
                                               _until, _worker_gone, fast, root)

SLOT = datetime(2026, 11, 1, 3, 0)
SCHEDULE = f'/api/clusters/{CID}/updates/schedule'


class _Scheduled(_Cluster):
    """The cluster of the restart tests, with an update that fails or does not start, an
    evacuation that leaves a guest behind and a Ceph that is not healthy, on request."""

    def __init__(self, update_fails=(), update_none=(), evac_errors=(), ceph=None, **kw):
        super().__init__(**kw)
        self.update_fails = set(update_fails)
        self.update_none = set(update_none)
        self.evac_errors = set(evac_errors)
        self.ceph = ceph
        self.forces = []

    def enter_maintenance_mode(self, node, **kw):
        t = super().enter_maintenance_mode(node, **kw)
        if node in self.evac_errors:
            t.status, t.migrated_vms, t.total_vms = 'completed_with_errors', 1, 2
            t.failed_vms = [{'vmid': 101, 'name': 'db', 'error': 'no node has its local storage'}]
        return t

    def start_node_update(self, node, reboot=False, force=False):
        self.forces.append(force)
        if node in self.update_none:
            self.calls.append(('update', node))
            return None
        t = super().start_node_update(node, reboot=reboot, force=force)
        if node in self.update_fails:
            t.status, t.error = 'failed', 'dpkg was interrupted'
        return t

    def get_ceph_health_summary(self):
        return dict(self.ceph) if self.ceph else None


@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(ha, 'schedule_now', lambda: SLOT)
    monkeypatch.setattr(ha, 'schedule_fire_first', lambda: False)


@pytest.fixture
def sent(monkeypatch):
    """What went out to the alert channels: (event, channel ids)."""
    from pegaprox.utils import webhooks
    out = []
    monkeypatch.setattr(webhooks, 'send_to_channels',
                        lambda alert, ids: out.append((alert.get('event'), list(ids))))
    return out


def _arm(api, user, **body):
    r = api.as_user(user).post(SCHEDULE, json=dict({'enabled': True, 'day': 'daily', 'time': '03:00',
                                                    'include_reboot': False}, **body))
    assert r.status_code == 200, r.get_data(as_text=True)
    return r


def _tick():
    import pegaprox.api.schedules as sch
    sch.check_scheduled_updates([SLOT])


def _state(cluster):
    return rolling_runs.current(cluster) or {}


def _paused(cluster):
    return _until(lambda: _state(cluster).get('status') == 'paused')


def _resume(api, user):
    r = api.as_user(user).post(f'/api/clusters/{CID}/updates/rolling/resume')
    assert r.status_code == 200, r.get_data(as_text=True)


# -- a failed node --------------------------------------------------------------------------------

def test_a_failed_node_pauses_the_scheduled_run_until_someone_continues(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(update_fails={'pve1'}))
    _arm(api, root)
    _tick()
    assert _paused(cluster), _state(cluster).get('logs')
    state = _state(cluster)
    assert state['scheduled'] is True and state['paused_reason'] == 'node_failure', state['logs']
    assert state['failed_nodes'][0]['node'] == 'pve1'
    assert ('enter', 'pve2') not in cluster.calls, 'the run went on to the next node'
    assert _row(db)['status'] == 'paused'
    # it waits for a human like a run started by hand: its worker is still there
    assert rolling_runs.worker_here(CID, cluster)
    _resume(api, root)
    _worker_gone()
    state = _state(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == ['pve2'], state['logs']


def test_an_update_that_does_not_start_is_a_failed_node(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(update_none={'pve1'}))
    _arm(api, root)
    _tick()
    assert _paused(cluster), _state(cluster).get('logs')
    state = _state(cluster)
    assert state['paused_reason'] == 'node_failure'
    assert [f['node'] for f in state['failed_nodes']] == ['pve1']
    assert 'pve1' not in (state.get('completed_nodes') or [])
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200
    _worker_gone()
    assert _state(cluster)['status'] == 'cancelled'
    assert ('enter', 'pve2') not in cluster.calls


# -- an evacuation that left guests behind ----------------------------------------------------------

def test_an_evacuation_error_pauses_the_scheduled_run_before_the_update(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(evac_errors={'pve1'}))
    _arm(api, root, include_reboot=True)
    _tick()
    assert _paused(cluster), _state(cluster).get('logs')
    state = _state(cluster)
    assert state['paused_reason'] == 'evacuation_failures', state['logs']
    assert state['paused_details']['failed_vms'][0]['vmid'] == 101
    assert ('update', 'pve1') not in cluster.calls, 'the node was updated with a guest still on it'
    _resume(api, root)
    _worker_gone()
    state = _state(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == list(NODES), state['logs']


def test_a_schedule_that_says_so_goes_on_after_an_evacuation_error(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(evac_errors={'pve1'}))
    _arm(api, root, pause_on_evacuation_error=False)
    got = api.as_user(root).get(SCHEDULE).get_json()
    assert got['pause_on_evacuation_error'] is False
    _tick()
    _worker_gone()
    state = _state(cluster)
    assert state['status'] == 'completed' and state['completed_nodes'] == list(NODES), state['logs']
    assert any('Continuing despite failures' in line for line in state['logs'])


# -- no force, and the options of the schedule reach the run --------------------------------------

def test_no_force_reaches_the_update_of_a_node(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled())
    _arm(api, root, include_reboot=True)
    _tick()
    _worker_gone()
    assert _state(cluster)['status'] == 'completed', _state(cluster)['logs']
    assert cluster.forces == [False, False]


def test_wait_for_reboot_and_the_channels_of_the_schedule_reach_the_run(api, seed, db, root, fast, clock, sent):
    cluster = api.set_manager(CID, _Scheduled())
    _arm(api, root, include_reboot=True, wait_for_reboot=False, notify_channels=['ops-chat'])
    got = api.as_user(root).get(SCHEDULE).get_json()
    assert got['wait_for_reboot'] is False and got['notify_channels'] == ['ops-chat']
    _tick()
    _worker_gone()
    state = _state(cluster)
    assert state['status'] == 'completed', state['logs']
    assert state['wait_for_reboot'] is False and state['notify_channels'] == ['ops-chat']
    assert any('Not waiting for pve1 (wait_for_reboot=False)' in line for line in state['logs']), state['logs']
    assert sent == [('rolling_update.started', ['ops-chat']), ('rolling_update.finished', ['ops-chat'])]


def test_a_schedule_with_a_bad_channel_list_is_refused(api, seed, db, root):
    api.set_manager(CID, _Scheduled())
    for bad in ('ops-chat', [{'id': 'ops-chat'}], ['x' * 129]):
        r = api.as_user(root).post(SCHEDULE, json={'enabled': True, 'include_reboot': False,
                                                   'notify_channels': bad})
        assert r.status_code == 400 and 'notify_channels' in r.get_json()['error'], r.data
    import pegaprox.api.schedules as sch
    assert sch.load_all_update_schedules() == {}


def test_a_confined_caller_reads_the_schedule_without_its_channels(api, seed, db, root):
    from test_rolling_options_everywhere_763_954 import _pool_user
    api.set_manager(CID, _Scheduled())
    _arm(api, root, notify_channels=['ops-chat'])
    confined = _pool_user(seed, 'mallory', ['cluster.view', 'node.view'])
    got = api.as_user(confined).get(SCHEDULE)
    assert got.status_code == 200, got.data
    body = got.get_json()
    assert 'notify_channels' not in body and body['enabled'] is True
    assert rolling_runs.CONFINED_HIDDEN and 'notify_channels' in rolling_runs.CONFINED_HIDDEN
    assert api.as_user(root).get(SCHEDULE).get_json()['notify_channels'] == ['ops-chat']


def test_the_ceph_gate_of_the_schedule_holds_the_run(api, seed, db, root, fast, clock):
    ceph = {'status': 'HEALTH_WARN', 'osd_up': 5, 'osd_in': 6, 'pgs': '12 active+undersized+degraded',
            'warnings': ['OSD_DOWN']}
    cluster = api.set_manager(CID, _Scheduled(ceph=ceph))
    _arm(api, root, ceph_health_gate='degraded')
    _tick()
    assert _paused(cluster), _state(cluster).get('logs')
    state = _state(cluster)
    assert state['paused_reason'] == 'ceph_unhealthy' and state['ceph_health_gate'] == 'degraded', state['logs']
    assert ('enter', 'pve2') not in cluster.calls
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


def test_without_a_gate_the_scheduled_run_still_waits_for_ceph_and_says_so(api, seed, db, root, fast, clock):
    ceph = {'status': 'HEALTH_WARN', 'osd_up': 6, 'osd_in': 6, 'pgs': '128 active+clean', 'warnings': []}
    cluster = api.set_manager(CID, _Scheduled(ceph=ceph))
    _arm(api, root)
    _tick()
    _worker_gone()
    state = _state(cluster)
    assert state['status'] == 'completed' and state['ceph_health_gate'] == 'off', state['logs']
    logs = '\n'.join(state['logs'])
    assert 'Ceph: ⚠ HEALTH_WARN' in logs and 'Ceph after pve1: ⚠ HEALTH_WARN' in logs


# -- one run at a time ------------------------------------------------------------------------------

def test_a_scheduled_run_is_refused_while_a_run_by_hand_is_active(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(evac_errors={'pve1'}))
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling',
                               json={'include_reboot': False, 'skip_up_to_date': False})
    assert r.status_code == 200, r.data
    assert _paused(cluster)
    _arm(api, root)
    _tick()
    import pegaprox.api.schedules as sch
    sch.execute_scheduled_rolling_update(cluster, CID, {'config': {'include_reboot': False}})
    rows = db.get_rolling_runs(CID)
    assert len(rows) == 1 and rows[0]['started_by'] == 'root'
    assert _state(cluster).get('scheduled') is not True
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


def test_a_second_scheduled_start_is_refused_while_the_first_one_waits(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(update_fails={'pve1'}))
    _arm(api, root)
    _tick()
    assert _paused(cluster)
    first = _state(cluster)['run_id']
    _tick()
    import pegaprox.api.schedules as sch
    sch.execute_scheduled_rolling_update(cluster, CID, {'config': {'include_reboot': False}})
    assert [r['id'] for r in db.get_rolling_runs(CID)] == [first]
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


# -- a schedule saved before the options ------------------------------------------------------------

OLD_TABLE = ('CREATE TABLE update_schedules (cluster_id TEXT PRIMARY KEY, enabled INTEGER DEFAULT 0, '
             "schedule_type TEXT DEFAULT 'recurring', day TEXT DEFAULT 'sunday', time TEXT DEFAULT '03:00', "
             'include_reboot INTEGER DEFAULT 1, skip_evacuation INTEGER DEFAULT 0, skip_up_to_date INTEGER '
             'DEFAULT 1, evacuation_timeout INTEGER DEFAULT 1800, reboot_timeout INTEGER DEFAULT 600, '
             'last_run TEXT, next_run TEXT, created_by TEXT, created_at TEXT, updated_at TEXT, '
             'migrate_templates INTEGER DEFAULT 0, relax_anti_affinity INTEGER DEFAULT 0)')


def _old_row(db):
    c = db.conn
    c.execute('DROP TABLE update_schedules')
    c.execute(OLD_TABLE)
    c.execute("INSERT INTO update_schedules (cluster_id, enabled, day, time, include_reboot, created_by) "
              "VALUES (?, 1, 'daily', '03:00', 1, 'root')", (CID,))
    c.commit()


@pytest.mark.parametrize('migrated', [False, True])
def test_an_old_schedule_row_runs_with_the_safe_defaults(api, seed, db, root, fast, clock, migrated):
    _old_row(db)
    if migrated:
        db._init_db()
        cols = {r[1] for r in db.conn.execute('PRAGMA table_info(update_schedules)').fetchall()}
        assert {'wait_for_reboot', 'pause_on_evacuation_error', 'ceph_health_gate', 'notify_channels'} <= cols
    import pegaprox.api.schedules as sch
    row = sch.load_all_update_schedules()[CID]
    assert (row['wait_for_reboot'], row['pause_on_evacuation_error'], row['ceph_health_gate'],
            row['notify_channels']) == (True, True, 'off', [])
    cluster = api.set_manager(CID, _Scheduled(evac_errors={'pve1'}))
    _tick()
    assert _paused(cluster), _state(cluster).get('logs')
    state = _state(cluster)
    assert state['paused_reason'] == 'evacuation_failures'
    assert (state['pause_on_evacuation_error'], state['wait_for_reboot'], state['ceph_health_gate'],
            state['notify_channels'], state['force_all']) == (True, True, 'off', [], False)
    assert state['include_reboot'] is True and state['allow_local_disks'] is True
    assert True not in cluster.forces
    rolling_runs.change(cluster, status='cancelled')
    _worker_gone()


# -- history and audit ------------------------------------------------------------------------------

def _audit(db, action):
    return [tuple(r) for r in db.conn.execute(
        'SELECT user, details, cluster FROM audit_log WHERE action = ? ORDER BY id', (action,)).fetchall()]


def test_the_scheduled_run_is_in_the_history_as_scheduled_and_in_the_audit_log(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled())
    _arm(api, root)
    _tick()
    _worker_gone()
    assert _state(cluster)['status'] == 'completed', _state(cluster)['logs']
    runs = api.as_user(root).get(f'/api/clusters/{CID}/updates/rolling/history').get_json()['runs']
    assert len(runs) == 1
    assert runs[0]['scheduled'] is True and runs[0]['started_by'] == 'scheduler'
    assert runs[0]['status'] == 'completed' and runs[0]['completed'] == 2
    started = _audit(db, 'node.rolling_update_started')
    assert len(started) == 1 and started[0][0] == 'scheduler' and started[0][2] == 'Testi'
    ended = _audit(db, 'scheduled.rolling_update')
    assert ended == [('scheduler', 'Scheduled rolling update completed: 2 updated, 0 skipped, 0 failed [Testi]',
                      'Testi')]


def test_a_cancelled_scheduled_run_says_so_in_the_audit_log(api, seed, db, root, fast, clock):
    cluster = api.set_manager(CID, _Scheduled(update_fails={'pve1'}))
    _arm(api, root)
    _tick()
    assert _paused(cluster)
    assert api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling').status_code == 200
    _worker_gone()
    assert _state(cluster)['status'] == 'cancelled'
    ended = _audit(db, 'scheduled.rolling_update')
    assert ended == [('scheduler', 'Scheduled rolling update cancelled: 0 updated, 0 skipped, 1 failed [Testi]',
                      'Testi')]
    # a run started by hand writes no scheduled end
    assert _audit(db, 'node.rolling_update_cancelled')[0][0] == 'root'


def test_a_run_by_hand_writes_no_scheduled_end(api, seed, db, root, fast):
    cluster = api.set_manager(CID, _Scheduled())
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling', json={'include_reboot': False})
    assert r.status_code == 200
    _worker_gone()
    assert _state(cluster)['status'] == 'completed'
    assert _audit(db, 'scheduled.rolling_update') == []


# -- the update of an XCP-ng host in maintenance ----------------------------------------------------

def _xcpng(monkeypatch):
    import threading
    from pegaprox.core.xcpng import XcpngManager
    m = object.__new__(XcpngManager)
    m.nodes_in_maintenance, m.nodes_updating = {}, {}
    m.update_lock = threading.Lock()
    ran = []
    monkeypatch.setattr(m, '_perform_node_update', lambda node, task: ran.append(node), raising=False)
    return m, ran


def test_an_xcpng_host_in_maintenance_is_updated_without_force(monkeypatch):
    """The run puts the host into maintenance (disabled, its guests evacuated) and then
    updates it. The XCP-ng manager refused exactly that without force, so every run started
    by hand stopped at its first host; only the scheduled one, with force=True, went on."""
    m, ran = _xcpng(monkeypatch)
    t = MaintenanceTask('xcp1')
    t.status = 'completed'
    m.nodes_in_maintenance['xcp1'] = t
    task = m.start_node_update('xcp1', reboot=False)
    assert task is not None and task.node == 'xcp1'
    assert _until(lambda: ran == ['xcp1'], 5)
    # a host that is not in maintenance is not updated without force, as on Proxmox VE
    assert m.start_node_update('xcp2', reboot=False) is None
    assert m.start_node_update('xcp2', reboot=False, force=True) is not None
