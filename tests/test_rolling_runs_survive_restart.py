"""A rolling update outlives a restart of PegaProx and a switch to another instance (#625).

The run lived in mgr._rolling_update alone, so a restart lost it while a node sat in
maintenance with its guests moved away and the negative affinity rules of Proxmox HA
switched off. Every change of a run now goes through rolling_runs.change: the working copy
and its row in rolling_update_runs, a shared table. Here the process "dies" at a point of
the run (an exception no handler of the worker catches, so nothing after it runs), the
registry of this process is forgotten as a restart would, and a fresh manager reads the
run back: it is paused with the reason 'interrupted' and a log line that names the node
and its phase. Nothing goes on by itself. Continue looks at the node again and goes on
without repeating what is done; Cancel takes it out of maintenance and the rules back on
and says what it could not undo. A new start, by hand or by a schedule, is refused while
a run is running or paused, and finished runs stay as history.

MK Oct 2026
"""
import json
import os
import re
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.globals as g
from pegaprox.core import ha, rolling_runs
from pegaprox.models.tasks import MaintenanceTask, UpdateTask
from test_ha_core import env  # noqa: F401 (a fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CID = 'cluster_1'
NODES = ('pve1', 'pve2')
GUESTS = [{'vmid': 100, 'name': 'web', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
          {'vmid': 101, 'name': 'db', 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
          {'vmid': 200, 'name': 'mail', 'node': 'pve2', 'type': 'lxc', 'status': 'running'}]


class _Died(BaseException):
    """The process ends here: no handler of the worker catches it, nothing after it runs."""


class _FastTime:
    def __getattr__(self, name):
        return getattr(time, name)

    @staticmethod
    def sleep(_s):
        time.sleep(0.001)


class _DyingTask(MaintenanceTask):
    """An evacuation the process does not live through."""

    @property
    def status(self):
        raise _Died('evacuating')

    @status.setter
    def status(self, _value):
        pass


class _Cluster:
    """A Proxmox cluster as the worker sees it, with the point where the process ends."""
    cluster_type = 'proxmox'
    is_connected = True

    def __init__(self, die_at=None, pending=None, include_maintenance=(), offline=(), uptime=10 ** 6,
                 exit_ok=True, rules_left=()):
        self.id = CID
        self.config = types.SimpleNamespace(name='Testi')
        self.status = {n: {'status': 'offline' if n in offline else 'online', 'uptime': uptime} for n in NODES}
        self.nodes_in_maintenance = {}
        for n in include_maintenance:
            t = MaintenanceTask(n)
            t.status, t._restored = 'completed', True
            self.nodes_in_maintenance[n] = t
        self.maintenance_lock = threading.Lock()
        self._rolling_update = None
        self.calls = []
        self.die_at = die_at
        self.pending = dict({n: 2 for n in NODES}, **(pending or {}))
        self.exit_ok = exit_ok
        self.rules_left = list(rules_left)
        self.armed = None
        self.back_after = 0       # an offline node comes back after this many looks

    def _die(self, phase, node=None):
        if self.die_at == (phase, node) or (self.die_at and self.die_at[0] == phase and self.die_at[1] is None):
            self.die_at = None
            raise _Died(phase)

    def get_node_status(self):
        if self.armed == 'status':
            self.armed = None
            raise _Died('status')
        for n, row in self.status.items():
            if row['status'] != 'online' and self.back_after:
                self.back_after -= 1
                if not self.back_after:
                    row['status'], row['uptime'] = 'online', 5
        return {n: dict(v, maintenance_mode=n in self.nodes_in_maintenance) for n, v in self.status.items()}

    def get_ceph_health_summary(self):
        if self.armed == 'ceph':
            self.armed = None
            raise _Died('ceph')
        return None

    def get_vm_resources(self, *a, **k):
        out = []
        for g in GUESTS:
            g = dict(g)
            if g['node'] in self.nodes_in_maintenance and not getattr(self.nodes_in_maintenance[g['node']], '_restored', False):
                g['node'] = 'pve2' if g['node'] == 'pve1' else 'pve1'
            out.append(g)
        return out

    def refresh_node_apt(self, node):
        self.calls.append(('refresh', node))
        self._die('checking', node)

    def get_node_apt_updates(self, node):
        return [{'Package': f'p{i}'} for i in range(self.pending.get(node, 0))]

    def refresh_maintenance_status(self):
        pass

    def enter_maintenance_mode(self, node, **kw):
        self.calls.append(('enter', node))
        self._die('maintenance', node)
        if self.die_at == ('evacuating', node):
            self.die_at = None
            t = _DyingTask(node)
        else:
            t = MaintenanceTask(node)
            t.status = 'completed'
        with self.maintenance_lock:
            self.nodes_in_maintenance[node] = t
        return t

    def exit_maintenance_mode(self, node, who='system'):
        self.calls.append(('exit', node))
        self._die('finishing', node)
        if self.die_at == ('ceph', node):
            self.die_at, self.armed = None, 'ceph'
        if self.die_at == ('cleanup', None) and node == NODES[-1]:
            self.die_at, self.armed = None, 'status'
        if not self.exit_ok:
            return False
        return self.nodes_in_maintenance.pop(node, None) is not None

    def start_node_update(self, node, reboot=False, force=False):
        self.calls.append(('update', node))
        self._die('updating', node)
        t = UpdateTask(node, reboot=reboot)
        t.status, t.phase = 'completed', 'done'
        self.pending[node] = 0
        if reboot:
            t.reboot_issued = True
            if self.die_at == ('rebooting', node):
                self.die_at, self.armed = None, 'status'
        return t

    def suspend_negative_ha_rules(self, who='system'):
        self.calls.append(('rules off', who))
        return ['keep-apart'], []

    def restore_suspended_ha_rules(self, who='system'):
        self.calls.append(('rules on', who))
        return [r for r in ['keep-apart'] if r not in self.rules_left], list(self.rules_left)

    def held_ha_rules(self):
        return {}


@pytest.fixture(autouse=True)
def _a_fresh_process(monkeypatch):
    rolling_runs.reset_for_tests()
    # the worker that "dies" would print its exception: that is the point of it
    monkeypatch.setattr(threading, 'excepthook', lambda args: None)
    yield
    rolling_runs.reset_for_tests()


@pytest.fixture
def fast(monkeypatch):
    import pegaprox.api.settings as settings_mod
    import pegaprox.api.schedules as schedules_mod
    monkeypatch.setattr(settings_mod, 'time', _FastTime())
    monkeypatch.setattr(schedules_mod, 'time', _FastTime())


@pytest.fixture
def root(seed):
    return seed.user('root', role='admin')


def _start(api, root, **body):
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling',
                               json=dict({'include_reboot': False, 'skip_up_to_date': True}, **body))
    assert r.status_code == 200, r.get_data(as_text=True)
    return r


def _worker_gone(seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline and rolling_runs._live:
        time.sleep(0.01)
    assert not rolling_runs._live, 'the worker did not end'


def _until(pred, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline and not pred():
        time.sleep(0.01)
    return pred()


def _row(db):
    rows = db.get_rolling_runs(CID)
    assert rows, 'no run in the table'
    row = rows[0]
    return dict(row, state=json.loads(row['state']), logs=json.loads(row['logs']))


def _restart(cluster, active=True, monkeypatch=None):
    """A new process: the registry is gone, the manager starts and reads the table."""
    rolling_runs.reset_for_tests()
    if monkeypatch is not None:
        monkeypatch.setattr(ha, 'is_active', lambda: active)
    rolling_runs.restore(cluster)
    return cluster


def _age_phase(db, node, seconds):
    """The phase the node is in began `seconds` ago."""
    row = db.get_rolling_runs(CID)[0]
    state = json.loads(row['state'])
    state['node_state'][node]['phase_at'] -= seconds
    db.conn.execute('UPDATE rolling_update_runs SET state = ? WHERE id = ?', (json.dumps(state), row['id']))
    db.conn.commit()


def _die(api, root, db, die_at, **body):
    """Start a run and let the process end at die_at; the table as it was left."""
    cluster = api.set_manager(CID, _Cluster(die_at=die_at))
    _start(api, root, **body)
    _worker_gone()
    return cluster, _row(db)


# -- the run is in the table -------------------------------------------------------------

def test_every_phase_of_a_run_is_in_its_row_and_it_stays_as_history(api, seed, db, root, fast):
    cluster = api.set_manager(CID, _Cluster())
    _start(api, root, relax_anti_affinity=True)
    _worker_gone()
    row = _row(db)
    assert row['status'] == 'completed' and row['completed_at'], row['logs']
    state = row['state']
    assert state['started_by'] == 'root' and state['completed_nodes'] == list(NODES)
    assert {n: (s['phase'], s['result'], s['in_maintenance']) for n, s in state['node_state'].items()} == {
        'pve1': ('done', 'done', False), 'pve2': ('done', 'done', False)}
    # the guests the evacuation moved are counted; a finished node names none of them any more
    assert state['node_state']['pve1']['moved_count'] == 2 and state['node_state']['pve1']['moved'] == []
    assert state['ha_rules_held'] is False and state['ha_rules_off'] == ['keep-apart']
    assert any('Rolling update completed' in line for line in row['logs'])
    assert cluster.calls.count(('rules on', 'root')) == 1
    # the history route lists it
    runs = api.as_user(root).get(f'/api/clusters/{CID}/updates/rolling/history').get_json()['runs']
    assert [(r['status'], r['completed'], r['nodes'], r['started_by']) for r in runs] == [('completed', 2, 2, 'root')]


def test_the_end_of_a_run_leaves_a_node_someone_else_put_into_maintenance_alone(api, seed, db, root, fast):
    """The final sweep took every node in maintenance out of it, the ones an admin had put
    there for their own work included. It takes the run's own."""
    cluster = api.set_manager(CID, _Cluster())
    elsewhere = MaintenanceTask('pve9')
    elsewhere.status = 'completed'
    cluster.nodes_in_maintenance['pve9'] = elsewhere
    cluster.exit_ok = True
    orig = cluster.exit_maintenance_mode

    def stuck_once(node, who='system'):
        # pve2 does not come out at its own exit, only in the sweep
        if node == 'pve2' and ('exit', 'pve2') not in cluster.calls:
            cluster.calls.append(('exit', node))
            return False
        return orig(node, who)
    cluster.exit_maintenance_mode = stuck_once
    _start(api, root)
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed', state['logs']
    assert cluster.calls.count(('exit', 'pve2')) == 2, 'the sweep retries the run\'s own node'
    assert ('exit', 'pve9') not in cluster.calls and 'pve9' in cluster.nodes_in_maintenance
    assert '✓ pve2 maintenance cleared on retry' in '\n'.join(state['logs'])


def test_a_run_over_a_hundred_nodes_and_ten_thousand_guests_stays_small(api, seed, db, root, fast):
    """One guest list read per node and phase that needs it, never one call per guest, and a
    row that does not grow with the guests of the nodes that are done."""
    nodes = [f'n{i:03d}' for i in range(100)]
    guests = [{'vmid': 1000 + i, 'name': f'g{i}', 'node': nodes[i % 100], 'type': 'qemu', 'status': 'running'}
              for i in range(10000)]
    reads = []

    class _Big(_Cluster):
        def get_node_status(self):
            return {n: {'status': 'online', 'uptime': 10 ** 6} for n in nodes}

        def get_vm_resources(self, *a, **k):
            reads.append(1)
            return guests

    cluster = api.set_manager(CID, _Big())
    cluster.pending = {n: 1 for n in nodes}
    started = time.time()
    _start(api, root, skip_up_to_date=False)
    _worker_gone(seconds=120)
    state = rolling_runs.current(cluster)
    assert state['status'] == 'completed' and len(state['completed_nodes']) == 100, state['logs'][-5:]
    assert len(reads) <= 2 * len(nodes), len(reads)
    row = db.get_rolling_runs(CID)[0]
    assert len(row['state']) < 64 * 1024, len(row['state'])
    assert len(json.loads(row['logs'])) <= rolling_runs.HISTORY_LOG_KEEP
    assert sum(s['moved_count'] for s in json.loads(row['state'])['node_state'].values()) == 10000
    assert time.time() - started < 90


def test_a_log_line_alone_does_not_step_the_config_version():
    assert 'rolling_update_runs' in ha.SYNC_TABLES
    assert set(ha.VOLATILE_COLUMNS['rolling_update_runs']) == {'logs', 'updated_at'}


def test_the_history_keeps_the_last_twenty_of_each_cluster(db):
    for i in range(23):
        db.insert_rolling_run(f'r{i:02d}', CID, 'completed', '{}', '[]', 'root', f'2026-10-{1 + i:02d} 03:00:00')
    db.insert_rolling_run('other', 'cluster_2', 'completed', '{}', '[]', 'root', '2026-01-01 03:00:00')
    db.insert_rolling_run('open', CID, 'paused', '{}', '[]', 'root', '2026-01-01 03:00:00')
    mgr = types.SimpleNamespace(_rolling_update=None)
    assert rolling_runs.begin(mgr, CID, {'status': 'running', 'nodes': ['pve1']}, 'root') is None, \
        'a paused run lets no other one start'
    db.conn.execute("UPDATE rolling_update_runs SET status = 'cancelled' WHERE id = 'open'")
    db.conn.commit()
    run = rolling_runs.begin(mgr, CID, {'status': 'running', 'nodes': ['pve1']}, 'root')
    assert run is not None
    ids = [r['id'] for r in db.get_rolling_runs(CID)]
    finished = [i for i in ids if i != run['run_id']]
    assert len(finished) == rolling_runs.HISTORY_KEEP and 'r22' in finished and 'r02' not in finished
    assert [r['id'] for r in db.get_rolling_runs('cluster_2')] == ['other']


def test_nothing_writes_the_working_copy_but_the_one_function():
    """No scattered writes: every change of a run goes through rolling_runs.change."""
    pattern = re.compile(r"_rolling_update\[[^\]]+\]\s*(=|\.append|\.remove)|\['logs'\]\.append|"
                         r"_rolling_update\s*=\s*(?!=)")
    for rel in ('pegaprox/api/settings.py', 'pegaprox/api/schedules.py', 'pegaprox/api/helpers.py',
                'pegaprox/core/manager.py', 'pegaprox/core/xcpng.py'):
        with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
            src = fh.read()
        hits = [m.group(0) for m in pattern.finditer(src)]
        assert not hits, f'{rel} writes the run itself: {hits}'


# -- a restart in each phase -----------------------------------------------------------------

@pytest.mark.parametrize('phase,index', [
    ('checking', 0), ('maintenance', 0), ('evacuating', 0), ('updating', 0),
    ('rebooting', 0), ('finishing', 0), ('ceph', 0), ('cleanup', 2)])
def test_a_restart_in_each_phase_leaves_a_paused_run_that_says_where(api, seed, db, root, fast, monkeypatch,
                                                                      phase, index):
    body = {'include_reboot': phase == 'rebooting'}
    die = (phase, None) if phase == 'cleanup' else (phase, 'pve1')
    _cluster, row = _die(api, root, db, die, **body)
    assert row['status'] == 'running', 'the process ended mid-run: its row still says running'
    expected = phase
    assert row['state']['current_step'] == expected, row['logs']

    fresh = _restart(_Cluster(), monkeypatch=monkeypatch)
    state = rolling_runs.current(fresh)
    assert state['status'] == 'paused' and state['paused_reason'] == 'interrupted'
    assert state['resume_at'] == {'index': index, 'phase': phase}
    assert state['paused_details']['phase'] == expected
    line = state['logs'][-1]
    if phase == 'cleanup':
        assert 'INTERRUPTED' in line and 'taking the last nodes out of maintenance' in line, line
    else:
        assert f"INTERRUPTED - PegaProx stopped while pve1 (1/2) was in phase '{phase}'" in line, line
    stored = _row(db)
    assert stored['status'] == 'paused' and stored['state']['paused_reason'] == 'interrupted'
    # it waits: nothing runs on its own
    time.sleep(0.2)
    assert fresh.calls == [] and rolling_runs.current(fresh)['status'] == 'paused'
    audit = db.conn.execute("SELECT details FROM audit_log WHERE action = 'node.rolling_update_interrupted'").fetchall()
    assert len(audit) == 1


def test_a_run_that_was_paused_stays_paused_with_its_reason(api, seed, db, root, fast, monkeypatch):
    cluster = api.set_manager(CID, _Cluster())
    cluster.start_node_update = lambda node, reboot=False, force=False: None   # the update cannot start
    _start(api, root)
    assert _until(lambda: (rolling_runs.current(cluster) or {}).get('status') == 'paused')
    assert rolling_runs.current(cluster)['resume_at'] == {'index': 1, 'phase': 'checking'}
    waiting = rolling_runs._live[CID]['thread']
    fresh = _restart(_Cluster(), monkeypatch=monkeypatch)
    state = rolling_runs.current(fresh)
    assert state['status'] == 'paused' and state['paused_reason'] == 'node_failure'
    assert not any('INTERRUPTED' in line for line in state['logs'])
    assert _row(db)['status'] == 'paused'
    # the worker of the "old process" still waits in this one: let it go
    rolling_runs.change(cluster, status='cancelled')
    waiting.join(10)
    assert not waiting.is_alive()


def test_a_standby_shows_the_run_and_does_not_touch_it(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    standby = _restart(_Cluster(), active=False, monkeypatch=monkeypatch)
    monkeypatch.setattr(ha, 'acting_process', lambda: False)
    assert rolling_runs.current(standby)['status'] == 'running'
    assert _row(db)['status'] == 'running'
    assert not db.conn.execute("SELECT 1 FROM audit_log WHERE action = 'node.rolling_update_interrupted'").fetchall()


def test_a_leader_in_its_takeover_wait_pauses_the_run_once_it_may_act(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    later = []
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    monkeypatch.setattr(ha, 'acting_process', lambda: True)
    monkeypatch.setattr(ha, 'when_active', lambda fn, name: later.append((fn, name)))
    rolling_runs.reset_for_tests()
    leader = _Cluster()
    rolling_runs.restore(leader)
    assert [name for _fn, name in later] == ['rolling-update-recovery']
    assert rolling_runs.current(leader)['status'] == 'running'
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    later[0][0]()
    assert rolling_runs.current(leader)['paused_reason'] == 'interrupted'


def test_a_manager_built_again_mid_run_shares_the_live_run(api, seed, db, root, fast, monkeypatch):
    """A reconfigured cluster swaps its manager while the worker runs on with the old one:
    the new one shows that run and does not take it for interrupted."""
    cluster = api.set_manager(CID, _Cluster())
    gate = threading.Event()
    orig = cluster.start_node_update

    def slow(node, reboot=False, force=False):
        gate.wait(10)
        return orig(node, reboot, force)
    cluster.start_node_update = slow
    _start(api, root)
    assert _until(lambda: rolling_runs.current(cluster).get('current_step') == 'updating')
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    swapped = _Cluster()
    rolling_runs.restore(swapped)
    assert rolling_runs.current(swapped) is rolling_runs.current(cluster)
    assert rolling_runs.current(swapped)['status'] == 'running'
    gate.set()
    _worker_gone()
    assert rolling_runs.current(swapped)['status'] == 'completed'


# -- switching over: the row comes with the sync, only the active pauses it ------------------

def test_the_run_arrives_on_the_standby_and_the_new_active_pauses_it(env, db, seed, monkeypatch):
    from test_ha_core import _be_active, _be_standby, _wire
    _be_active()
    mgr = types.SimpleNamespace(_rolling_update=None)
    run = rolling_runs.begin(mgr, CID, {'status': 'running', 'nodes': list(NODES), 'current_index': 0,
                                        'current_node': 'pve1', 'current_step': 'starting',
                                        'relax_anti_affinity': True, 'logs': []}, 'root')
    rolling_runs.change(mgr, current_step='evacuating', node=('pve1', {'phase': 'evacuating', 'in_maintenance': True}),
                        ha_rules_held=True, log='Waiting for VM evacuation')
    snap = _wire(ha.build_snapshot())
    assert 'rolling_update_runs' in snap['tables']
    # the standby's own copy is older: the run is not in it yet
    db.conn.execute('DELETE FROM rolling_update_runs')
    db.conn.commit()
    _be_standby()
    ha.apply_snapshot(snap)
    row = _row(db)
    assert row['id'] == run['run_id'] and row['status'] == 'running'
    assert row['state']['node_state']['pve1']['phase'] == 'evacuating'

    rolling_runs.reset_for_tests()
    standby = _Cluster()
    rolling_runs.restore(standby)
    assert rolling_runs.current(standby)['status'] == 'running', 'a standby only shows the run'
    assert _row(db)['status'] == 'running'
    # the next sync changes nothing it holds of the run, the one after the run's end drops it
    assert rolling_runs.follow(standby, CID) == 0

    # promoted: the process restarts as the active and finds the run running
    _be_active(epoch=4)
    rolling_runs.reset_for_tests()
    active = _Cluster(include_maintenance=('pve1',))
    rolling_runs.restore(active)
    state = rolling_runs.current(active)
    assert state['status'] == 'paused' and state['paused_reason'] == 'interrupted'
    assert state['resume_at'] == {'index': 0, 'phase': 'evacuating'}
    assert state['ha_rules_held'] is True, 'the rules stay off for a run that is only paused'
    assert _row(db)['status'] == 'paused'


def test_a_standby_follows_the_run_after_each_sync(db, monkeypatch):
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    writer = types.SimpleNamespace(_rolling_update=None)
    rolling_runs.begin(writer, CID, {'status': 'running', 'nodes': ['pve1'], 'logs': []}, 'root')
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    standby = _Cluster()
    assert rolling_runs.follow(standby, CID) == 1 and rolling_runs.current(standby)['status'] == 'running'
    assert rolling_runs.follow(standby, CID) == 0
    rolling_runs.change(writer, status='completed')
    assert rolling_runs.follow(standby, CID) == 1 and rolling_runs.current(standby)['status'] == 'completed'
    # an active keeps its own
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    assert rolling_runs.follow(_Cluster(), CID) == 0


# -- Continue after an interruption ---------------------------------------------------------

def _continue(api, root, cluster):
    api.set_manager(CID, cluster)
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling/resume')
    assert r.status_code == 200, r.get_data(as_text=True)
    _worker_gone()
    return rolling_runs.current(cluster)


def test_continue_after_an_evacuation_evacuates_again_and_goes_on(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('evacuating', 'pve1'))
    fresh = _restart(_Cluster(include_maintenance=('pve1',)), monkeypatch=monkeypatch)
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed', state['logs']
    assert fresh.calls == [('enter', 'pve1'), ('update', 'pve1'), ('exit', 'pve1'),
                           ('refresh', 'pve2'), ('enter', 'pve2'), ('update', 'pve2'), ('exit', 'pve2')]
    logs = '\n'.join(state['logs'])
    assert 'Re-check of pve1: online, in maintenance' in logs
    assert 'pve1 is still in maintenance - its evacuation runs again for what is left on it' in logs
    assert '=== Continuing pve1 (1/2) from phase evacuating ===' in logs
    assert state['completed_nodes'] == list(NODES)
    audit = db.conn.execute("SELECT user FROM audit_log WHERE action = 'node.rolling_update_resumed'").fetchall()
    assert [a[0] for a in audit] == ['root']


def test_continue_while_updates_are_pending_updates_again_without_a_second_evacuation(api, seed, db, root, fast,
                                                                                      monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    fresh = _restart(_Cluster(include_maintenance=('pve1',)), monkeypatch=monkeypatch)
    # the node in progress names the guests its evacuation moved, and where to: one guest list
    # read for the node, none per guest
    moved = rolling_runs.current(fresh)['node_state']['pve1']['moved']
    assert {g['vmid']: g['to'] for g in moved} == {100: 'pve2', 101: 'pve2'}
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed', state['logs']
    assert fresh.calls[:3] == [('refresh', 'pve1'), ('update', 'pve1'), ('exit', 'pve1')]
    assert ('enter', 'pve1') not in fresh.calls
    assert 'pve1 still has 2 update(s) pending - the update runs again' in '\n'.join(state['logs'])


def test_continue_after_a_finished_update_skips_it(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    fresh = _restart(_Cluster(include_maintenance=('pve1',), pending={'pve1': 0}), monkeypatch=monkeypatch)
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed'
    assert fresh.calls[:2] == [('refresh', 'pve1'), ('exit', 'pve1')]
    assert ('update', 'pve1') not in fresh.calls and ('enter', 'pve1') not in fresh.calls
    assert 'pve1 has no update left - going on with taking it out of maintenance' in '\n'.join(state['logs'])


def test_continue_after_a_reboot_that_happened_meanwhile_finishes_the_node(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('rebooting', 'pve1'), include_reboot=True)
    # booted a few seconds ago, long after the phase began
    _age_phase(db, 'pve1', 3600)
    fresh = _restart(_Cluster(include_maintenance=('pve1',), uptime=5), monkeypatch=monkeypatch)
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed', state['logs']
    assert fresh.calls[0] == ('exit', 'pve1') and ('update', 'pve1') not in fresh.calls
    assert '✓ pve1 rebooted and is back online' in '\n'.join(state['logs'])
    # it was listed as rebooting when the process ended: a migration target again now
    assert state['rebooting_nodes'] == []


def test_continue_with_the_node_still_down_waits_for_it(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('rebooting', 'pve1'), include_reboot=True)
    fresh = _Cluster(include_maintenance=('pve1',), offline=('pve1',))
    fresh.back_after = 3
    _restart(fresh, monkeypatch=monkeypatch)
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed', state['logs']
    logs = '\n'.join(state['logs'])
    assert 'pve1 is down, most likely in its reboot - waiting for it to come back' in logs
    assert 'Waiting for pve1 to come back from its reboot' in logs and '✓ pve1 back online' in logs
    assert 'pve1 did not go offline' not in logs
    assert fresh.calls[0] == ('exit', 'pve1')


def test_continue_from_the_cleanup_only_winds_down(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('cleanup', None))
    fresh = _restart(_Cluster(), monkeypatch=monkeypatch)
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed' and fresh.calls == []
    assert state['completed_nodes'] == list(NODES)


def test_continue_needs_the_reboot_permission_of_a_rebooting_run(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'), include_reboot=True)
    _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve1',))), monkeypatch=monkeypatch)
    ops = seed.user('ops', role='user', permissions=['node.update', 'node.view', 'cluster.view'])
    r = api.as_user(ops).post(f'/api/clusters/{CID}/updates/rolling/resume')
    assert r.status_code == 403 and 'node.reboot' in r.get_json()['error']
    assert rolling_runs.current(g.cluster_managers[CID])['status'] == 'paused'


# -- Cancel after an interruption -------------------------------------------------------------

def test_cancel_after_an_interruption_takes_the_node_out_and_reports(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'), relax_anti_affinity=True)
    fresh = _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve1',), rules_left=['keep-apart'])),
                     monkeypatch=monkeypatch)
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert fresh.calls == [('exit', 'pve1'), ('rules on', 'root')]
    assert body['not_undone'] == [{'kind': 'ha_rules', 'rules': ['keep-apart']},
                                  {'kind': 'guests_stay', 'node': 'pve1', 'count': 2}]
    state = _row(db)['state']
    assert _row(db)['status'] == 'cancelled' and state['cancel_report'] == body['not_undone']
    assert state['cancelled_by'] == 'root' and state['rebooting_nodes'] == []
    logs = '\n'.join(_row(db)['logs'])
    assert 'Not undone: negative affinity rules still off: keep-apart' in logs
    assert 'Not undone: 2 guest(s) moved off pve1 stay on the nodes they were moved to' in logs
    # the next start is free again
    assert rolling_runs.busy(fresh, CID) == ''


def test_cancel_reports_a_node_that_stays_in_maintenance(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('finishing', 'pve1'))
    fresh = _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve1',), exit_ok=False)),
                     monkeypatch=monkeypatch)
    body = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling').get_json()
    assert {'kind': 'maintenance', 'node': 'pve1'} in body['not_undone']
    assert fresh.calls == [('exit', 'pve1')]
    state = rolling_runs.current(fresh)
    assert {'node': 'pve1', 'error': 'Stuck in maintenance after rolling update'} in state['failed_nodes']


def test_a_cancel_with_the_worker_here_lets_the_worker_wind_down(api, seed, db, root, fast):
    cluster = api.set_manager(CID, _Cluster())
    cluster.start_node_update = lambda node, reboot=False, force=False: None
    _start(api, root, relax_anti_affinity=True)
    assert _until(lambda: (rolling_runs.current(cluster) or {}).get('status') == 'paused')
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200 and r.get_json()['cleanup'] == 'running'
    _worker_gone()
    state = rolling_runs.current(cluster)
    assert state['status'] == 'cancelled', 'a cancelled run stays cancelled, it used to end as completed'
    assert ('rules on', 'root') in cluster.calls
    # the node that failed was taken out of maintenance; what its evacuation moved stays moved
    assert state['cancel_report'] == [{'kind': 'guests_stay', 'node': 'pve1', 'count': 2}]


# -- one run at a time, across restarts -------------------------------------------------------

def test_a_start_is_refused_while_a_run_is_paused_across_a_restart(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    _restart(_Cluster(), monkeypatch=monkeypatch)
    # a manager that never read the run: the table says it is open
    api.set_manager(CID, _Cluster())
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling', json={})
    assert r.status_code == 400 and 'paused' in r.get_json()['error'] and 'interrupted' in r.get_json()['error']
    assert len(db.get_rolling_runs(CID)) == 1


def test_a_start_is_refused_while_a_run_runs(api, seed, db, root, fast):
    cluster = api.set_manager(CID, _Cluster())
    gate = threading.Event()
    orig = cluster.start_node_update
    cluster.start_node_update = lambda node, reboot=False, force=False: (gate.wait(10), orig(node))[1]
    _start(api, root)
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling', json={})
    assert r.status_code == 400 and r.get_json()['error'] == 'Rolling update already in progress'
    gate.set()
    _worker_gone()


def test_two_starts_at_once_begin_one_run(db):
    mgr = types.SimpleNamespace(_rolling_update=None)
    got, barrier = [], threading.Barrier(4)

    def go():
        barrier.wait()
        got.append(rolling_runs.begin(mgr, CID, {'status': 'running', 'nodes': ['pve1']}, 'root'))
    threads = [threading.Thread(target=go) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for g in got if g is not None) == 1
    assert len(db.get_rolling_runs(CID)) == 1


# -- the scheduled start --------------------------------------------------------------------

def _scheduled(cluster):
    import pegaprox.api.schedules as sch
    sch.execute_scheduled_rolling_update(cluster, CID, {'cluster_id': CID, 'action': 'rolling_update',
                                                        'config': {'include_reboot': False}})


def test_a_scheduled_run_is_kept_like_one_started_by_hand(api, seed, db, fast):
    cluster = api.set_manager(CID, _Cluster())
    _scheduled(cluster)
    _worker_gone()
    row = _row(db)
    assert row['status'] == 'completed' and row['completed_at'], row['logs']
    state = row['state']
    assert state['scheduled'] is True and state['started_by'] == 'scheduler'
    assert state['allow_local_disks'] is True and state['pause_on_evacuation_error'] is False
    assert {n: s['result'] for n, s in state['node_state'].items()} == {'pve1': 'done', 'pve2': 'done'}


def test_a_scheduled_run_a_restart_interrupted_waits_and_continues(api, seed, db, root, fast, monkeypatch):
    cluster = api.set_manager(CID, _Cluster(die_at=('updating', 'pve2')))
    _scheduled(cluster)
    _worker_gone()
    fresh = _restart(_Cluster(include_maintenance=('pve2',)), monkeypatch=monkeypatch)
    state = rolling_runs.current(fresh)
    assert state['paused_reason'] == 'interrupted' and state['resume_at'] == {'index': 1, 'phase': 'updating'}
    # the next scheduled start waits for an admin
    _scheduled(_Cluster())
    assert len(db.get_rolling_runs(CID)) == 1
    state = _continue(api, root, fresh)
    assert state['status'] == 'completed', state['logs']
    assert fresh.calls == [('refresh', 'pve2'), ('update', 'pve2'), ('exit', 'pve2')]


def test_the_schedule_check_skips_a_cluster_with_a_paused_run(api, seed, db, monkeypatch):
    import pegaprox.api.schedules as sch
    from datetime import datetime
    db.insert_rolling_run('open', CID, 'paused', json.dumps({'paused_reason': 'interrupted'}), '[]', 'root',
                          '2026-10-01 03:00:00')
    monkeypatch.setattr(ha, 'schedule_now', lambda: datetime(2026, 10, 3, 3, 0))
    monkeypatch.setattr(sch, 'load_all_update_schedules', lambda: {CID: {
        'enabled': True, 'schedule_type': 'recurring', 'day': 'daily', 'time': '03:00'}})
    monkeypatch.setattr(sch, '_creator_may_update', lambda cid, s: True)
    cluster = _Cluster()
    cluster.is_connected = True
    api.set_manager(CID, cluster)
    ran = []
    monkeypatch.setattr(sch, 'execute_scheduled_rolling_update', lambda m, cid, a: ran.append(cid))
    sch.check_scheduled_updates()
    assert ran == []


# -- the Proxmox HA rules: off while the run is paused, on again with its cancel ----------------

def test_the_rules_stay_off_through_the_interruption_and_go_on_with_the_cancel(api, seed, db, root, monkeypatch):
    from test_rolling_templates_affinity_763_954 import _Pve, _manager
    db.save_suspended_ha_rules(CID, ['keep-apart'])
    db.insert_rolling_run('run1', CID, 'running', json.dumps({
        'nodes': ['pve5'], 'current_index': 0, 'current_node': 'pve5', 'current_step': 'evacuating',
        'relax_anti_affinity': True, 'ha_rules_held': True, 'ha_rules_off': ['keep-apart'],
        'node_state': {'pve5': {'phase': 'evacuating', 'in_maintenance': False}},
        'completed_nodes': [], 'skipped_nodes': [], 'failed_nodes': [], 'rebooting_nodes': []}),
        '[]', 'root', '2026-10-10 03:00:00')
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    pve = _Pve()
    mgr = _manager(pve)
    mgr._rolling_update = None
    del mgr._rolling_update      # a manager that starts fresh
    rolling_runs.restore(mgr)
    assert rolling_runs.current(mgr)['paused_reason'] == 'interrupted'
    # the daemon loop: a paused run still holds its rules
    mgr._restore_suspended_ha_rules_if_due()
    assert pve.puts == []
    api.set_manager(CID, mgr)
    r = api.as_user(root).delete(f'/api/clusters/{CID}/updates/rolling')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.puts == [('/cluster/ha/rules/keep-apart', {'type': 'resource-affinity', 'delete': 'disable'})]
    assert db.get_suspended_ha_rules(CID) == []
    assert r.get_json()['not_undone'] == []


def test_without_the_run_the_daemon_loop_switches_them_back_on(db, monkeypatch):
    """Counterproof: the rules stay off above because the run holds them, not by accident."""
    from test_rolling_templates_affinity_763_954 import _Pve, _manager
    db.save_suspended_ha_rules(CID, ['keep-apart'])
    db.insert_rolling_run('run1', CID, 'cancelled', json.dumps({'ha_rules_held': True}), '[]', 'root',
                          '2026-10-10 03:00:00')
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    pve = _Pve()
    mgr = _manager(pve)
    del mgr._rolling_update
    rolling_runs.restore(mgr)
    mgr._restore_suspended_ha_rules_if_due()
    assert pve.puts == [('/cluster/ha/rules/keep-apart', {'type': 'resource-affinity', 'delete': 'disable'})]


# -- who may: the routes ---------------------------------------------------------------------

def _pool_user(seed, name, perms):
    import pegaprox.utils.rbac as rbac
    seed.tenant('tenant_x', clusters=[CID])
    u = seed.user(name, role='viewer', tenant_id='tenant_x', permissions=perms)
    seed.pool(CID, 'pool_1', name, ['pool.view', 'vm.view'])
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[CID] = {'data': {'100:qemu': 'pool_1'}, 'timestamp': time.time(),
                                            'refreshing': False}
    return u


ROUTES = [('get', '/updates/rolling/history'), ('post', '/updates/rolling/resume'),
          ('delete', '/updates/rolling')]


@pytest.mark.parametrize('method,path', ROUTES)
def test_nobody_confined_elsewhere_or_without_the_permission_reaches_the_run(api, seed, db, fast, method, path,
                                                                             monkeypatch):
    db.insert_rolling_run('run1', CID, 'paused', json.dumps({'nodes': ['pve1'], 'paused_reason': 'interrupted'}),
                          '[]', 'root', '2026-10-10 03:00:00')
    cluster = api.set_manager(CID, _Cluster())
    seed.tenant('globex', clusters=['cluster_2'])
    api.set_manager('cluster_2', _Cluster())
    callers = {
        'confined admin': seed.user('gx', role='admin', tenant_id='globex',
                                    tenant_permissions={'globex': {'role': 'user'}}),
        'other tenant': seed.user('milton', role='user', tenant_id='globex',
                                  permissions=['node.update', 'node.view', 'cluster.view']),
        'pool-confined': _pool_user(seed, 'mallory', ['node.update', 'node.view', 'cluster.view']),
    }
    callers['no permission'] = seed.user('nou', role='user', permissions=['cluster.view'],
                                         denied=['node.view' if path.endswith('history') else 'node.update'])
    for who, user in callers.items():
        r = getattr(api.as_user(user), method)(f'/api/clusters/{CID}{path}')
        assert r.status_code == 403, (who, r.status_code, r.get_data(as_text=True))
    assert cluster.calls == [] and _row(db)['status'] == 'paused'
    # an admin of the cluster may
    admin = seed.user('boss', role='admin')
    r = getattr(api.as_user(admin), method)(f'/api/clusters/{CID}{path}')
    assert r.status_code == 200, r.get_data(as_text=True)
    _worker_gone()


@pytest.mark.parametrize('method,path', [('post', '/updates/rolling/resume'), ('delete', '/updates/rolling'),
                                         ('post', '/updates/rolling')])
def test_a_standby_does_not_act_on_the_run(api, seed, db, method, path, monkeypatch):
    db.insert_rolling_run('run1', CID, 'paused', json.dumps({'nodes': ['pve1'], 'paused_reason': 'interrupted'}),
                          '[]', 'root', '2026-10-10 03:00:00')
    cluster = api.set_manager(CID, _Cluster())
    monkeypatch.setattr(ha, 'is_standby', lambda: True)
    monkeypatch.setattr(ha, 'is_active', lambda: False)
    import pegaprox.api.ha as api_ha
    monkeypatch.setattr(api_ha, 'forward_to_active', lambda *a, **k: None)
    r = getattr(api.as_user(seed.user('boss', role='admin')), method)(f'/api/clusters/{CID}{path}', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY'
    assert cluster.calls == [] and _row(db)['status'] == 'paused'


def test_a_confined_caller_gets_the_progress_without_the_guests(api, seed, db, root, fast, monkeypatch):
    _die(api, root, db, ('updating', 'pve1'))
    fresh = _restart(api.set_manager(CID, _Cluster(include_maintenance=('pve1',))), monkeypatch=monkeypatch)
    assert rolling_runs.current(fresh)['node_state']['pve1']['moved']
    mallory = _pool_user(seed, 'mallory', ['node.view', 'cluster.view'])
    got = api.as_user(mallory).get(f'/api/clusters/{CID}/updates/status').get_json()['rolling_update']
    assert got['paused_reason'] == 'interrupted' and got['current_node'] == 'pve1'
    for key in rolling_runs.CONFINED_HIDDEN:
        assert key not in got, key
    full = api.as_user(root).get(f'/api/clusters/{CID}/updates/status').get_json()['rolling_update']
    assert full['node_state']['pve1']['moved'][0]['name'] == 'web'


def test_the_status_shows_an_open_run_the_manager_has_not_read(api, seed, db, root):
    db.insert_rolling_run('run1', CID, 'paused', json.dumps({'nodes': ['pve1'], 'paused_reason': 'interrupted',
                                                             'current_node': 'pve1'}), '["[03:00:00] x"]',
                          'root', '2026-10-10 03:00:00')
    api.set_manager(CID, _Cluster())
    got = api.as_user(root).get(f'/api/clusters/{CID}/updates/status').get_json()['rolling_update']
    assert got['status'] == 'paused' and got['paused_reason'] == 'interrupted' and got['run_id'] == 'run1'


@pytest.mark.parametrize('body,needle', [
    ([], 'JSON object'),
    ({'node_order': 'pve1'}, 'node_order'),
    ({'node_order': [1, 2]}, 'node_order'),
    ({'include_reboot': 'yes'}, 'include_reboot'),
    ({'evacuation_timeout': 'soon'}, 'evacuation_timeout'),
    ({'reboot_timeout': {'s': 1}}, 'reboot_timeout'),
    ({'notify_channels': ['x' * 500]}, 'notify_channels'),
])
def test_a_malformed_start_is_a_400(api, seed, root, body, needle):
    api.set_manager(CID, _Cluster())
    r = api.as_user(root).post(f'/api/clusters/{CID}/updates/rolling', json=body)
    assert r.status_code == 400 and needle in r.get_json()['error'], r.get_data(as_text=True)


# -- what came along ------------------------------------------------------------------------

def test_a_node_update_with_its_reboot_does_not_trip_over_a_cleared_run(monkeypatch):
    """The reboot alert read getattr(self, '_rolling_update', {}).get(...): with the run cleared
    (None) that raised, and the node update ended as failed right after its reboot."""
    import pegaprox.core.manager as mgrmod
    from pegaprox.core.manager import PegaProxManager
    from test_rolling_update_reboot_953 import _FastTime as _NoWait, _updating_manager
    monkeypatch.setattr(mgrmod, 'time', _NoWait())
    monkeypatch.setattr(mgrmod, '_read_capped', lambda s, *a, **k: '0')
    m = _updating_manager(True)
    m._rolling_update = None
    task = UpdateTask('blade1', reboot=True)
    PegaProxManager._perform_node_update(m, 'blade1', task)
    assert task.status == 'completed', task.error


def test_an_xcpng_pool_without_the_refresh_still_gets_its_maintenance(api, seed, db, root, fast):
    """The run called refresh_maintenance_status, which the XCP-ng manager does not have:
    every node of a pool ended as a node failure."""
    cluster = _Cluster()
    cluster.cluster_type = 'xcpng'
    cluster.refresh_maintenance_status = None
    api.set_manager(CID, cluster)
    _start(api, root)
    _worker_gone()
    assert rolling_runs.current(cluster)['status'] == 'completed', rolling_runs.current(cluster)['logs']
