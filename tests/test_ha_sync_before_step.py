"""What an automatic leader writes for a step it cannot take back reaches the members
before the step, and what only one instance knows is not turned into shared state
elsewhere (#625 stage 2).

  * site recovery: a failover writes the guest's mark (site_recovery_vms.failed_over)
    before its confirm round and sends it on, so a leader gone right after the start
    leaves the next one a mark that holds the guest's replication. A step that did not
    happen takes the mark back; a failback clears it only after its step. A replication
    run never stops, purges or writes into a replica that runs - a running one is a
    guest in use, whatever the marks say, and one that cannot read the target's guests
    writes nothing there
  * the marks of a database from before come from the failover events, a LOCAL table:
    only the instance that acts replays them, before its replication scheduler picks a job
  * the negative affinity rules a rolling update switches off are listed and sent on
    before the confirm round of the first switch-off
  * the balancer's cooldown after a change of leader: the guest migrations in the
    cluster's task list, one read per cluster

MK Oct 2026 (#625)
"""
import time

import pytest

import pegaprox.api.vms as vms_api
import pegaprox.background.site_recovery as srw
import pegaprox.core.incremental_repl as incr
import pegaprox.globals as ppglobals
from pegaprox.core import ha as _ha

from test_ha_members import group  # noqa: F401
from _ha_lease_harness import auto  # noqa: F401
from test_sr_per_guest_failover import SRC, TGT, _done, _event, _job, _mgr, _plan, _state, _tick
from test_rolling_templates_affinity_763_954 import RULES, _Pve, _manager as _rules_manager
from test_xcincr_replica_tag import BASE, OURS, FakeMgr, _R
from test_balancer_history import _guest, _manager as _bal_manager, _resp


class _Died(BaseException):
    """The process ends here: nothing after it runs, no except clause catches it."""


@pytest.fixture
def sites(db, monkeypatch):
    """Two clusters for plan p1, the reads of the worker answered: the source guest does not
    run, no VMID is in use on the way."""
    monkeypatch.setitem(ppglobals.cluster_managers, SRC, _mgr(SRC))
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, _mgr(TGT))
    monkeypatch.setattr(srw, '_source_vm_is_running', lambda mgr, vmid: (False, True))
    monkeypatch.setattr(srw, '_target_vmid_exists', lambda mgr, vmid: False)
    monkeypatch.setattr(srw, '_broadcast_progress', lambda *a, **kw: None)
    monkeypatch.setattr(srw, '_fire_webhook', lambda *a, **kw: None)


def _recorder(monkeypatch, db):
    """In order: what went to the members (the marks as cv_tick found them), each confirm
    round (the marks as they stood then) and each step."""
    events = []
    monkeypatch.setattr(_ha, 'cv_tick', lambda force=False: events.append(('sent', _state(db))) or 'stepped')
    real_confirm = _ha.confirm_step
    monkeypatch.setattr(_ha, 'confirm_step', lambda what, need=_ha.NEED_STEP:
                        events.append(('confirm', _state(db))) or real_confirm(what, need))
    monkeypatch.setattr(srw, '_start_replicated_vm', lambda mgr, vmid, vtype='qemu':
                        events.append(('start', vmid)) or (True, ''))
    monkeypatch.setattr(srw, '_migrate_vm_cross_cluster', lambda src, tgt, vmid, *a:
                        events.append(('migrate', vmid)) or (True, ''))
    return events


def _gone(events):
    def step(*a, **kw):
        events.append(('step went out',))
        raise _Died()
    return step


def _carry(db, marks):
    """The next leader's copy of the marks: what the last send-on carried."""
    for vmid, mark in marks.items():
        db.execute("UPDATE site_recovery_vms SET failed_over = ? WHERE plan_id = 'p1' AND vmid = ?", (mark, vmid))


# --- 1. the mark goes to the members before the step ----------------------------------------

@pytest.mark.parametrize('kind,step', [('emergency', 'start'), ('planned', 'migrate')])
def test_a_failover_marks_the_guest_and_sends_it_on_before_its_round_and_its_step(
        auto, seed, db, sites, monkeypatch, kind, step):
    auto.form(seed)
    _plan(db)
    events = _recorder(monkeypatch, db)
    with auto.at('a'):
        srw.execute_failover('p1', kind, only_vmids=[100])
    marked = {100: kind, 101: '', 102: ''}
    assert events == [('sent', marked), ('confirm', marked), (step, 100)]
    assert _state(db) == marked


@pytest.mark.parametrize('kind,step', [('emergency', '_start_replicated_vm'),
                                       ('planned', '_migrate_vm_cross_cluster')])
def test_a_leader_gone_right_after_the_step_leaves_a_mark_that_holds_the_replication(
        auto, seed, db, sites, monkeypatch, kind, step):
    """The start (or the migration) went out and the process ended before anything else
    ran. The next leader has the marks as far as the last send-on carried them: the guest
    is failed over there, so its replication job waits instead of stopping and purging
    the replica that runs as the guest now."""
    auto.form(seed)
    _plan(db)
    _job(db, 'j100', 100)
    _job(db, 'j101', 101)
    events = _recorder(monkeypatch, db)
    monkeypatch.setattr(srw, step, _gone(events))
    with auto.at('a'):
        with pytest.raises(_Died):
            srw.execute_failover('p1', kind, only_vmids=[100])
    sent = [e[1] for e in events if e[0] == 'sent']
    assert sent, 'nothing reached the members before the step went out'
    assert sent[-1] == {100: kind, 101: '', 102: ''}
    _carry(db, sent[-1])
    job = dict(db.query_one("SELECT * FROM cross_cluster_replications WHERE id = 'j100'"))
    assert srw.replication_held_by(job) == 'Plan p1'
    assert _tick(monkeypatch) == ['j101']


def test_a_failback_clears_the_mark_after_its_migration_and_sends_that_on(auto, seed, db, sites, monkeypatch):
    auto.form(seed)
    _plan(db, moved=(100,))
    events = _recorder(monkeypatch, db)
    with auto.at('a'):
        srw.execute_failover('p1', 'failback', only_vmids=[100])
    before, home = {100: 'emergency', 101: '', 102: ''}, {100: '', 101: '', 102: ''}
    assert events == [('confirm', before), ('migrate', 100), ('sent', home)]


def test_a_leader_gone_in_a_failback_leaves_the_mark_which_only_holds_the_replication(
        auto, seed, db, sites, monkeypatch):
    """The safe way round: cleared before the migration, a leader gone during it would
    leave the next one no mark while the guest still runs on the DR site, and the next
    replication run would stop and purge it there."""
    auto.form(seed)
    _plan(db, moved=(100,))
    _job(db, 'j100', 100)
    events = _recorder(monkeypatch, db)
    monkeypatch.setattr(srw, '_migrate_vm_cross_cluster', _gone(events))
    with auto.at('a'):
        with pytest.raises(_Died):
            srw.execute_failover('p1', 'failback', only_vmids=[100])
    assert [e[0] for e in events] == ['confirm', 'step went out']
    assert _state(db)[100] == 'emergency'
    assert _tick(monkeypatch) == []


@pytest.mark.parametrize('how', ['no lease', 'the start failed'])
def test_a_guest_that_did_not_move_loses_its_mark_again(db, sites, monkeypatch, how):
    """Outside an automatic group nothing is sent on, and the mark still comes first."""
    _plan(db)
    events = _recorder(monkeypatch, db)
    if how == 'no lease':
        monkeypatch.setattr(_ha, 'confirm_step', lambda what, need=_ha.NEED_STEP:
                            events.append(('confirm', _state(db))) or False)
    else:
        monkeypatch.setattr(srw, '_start_replicated_vm', lambda mgr, vmid, vtype='qemu':
                            events.append(('start', vmid)) or (False, 'no replica'))
    srw.execute_failover('p1', 'emergency', only_vmids=[100])
    marked = {100: 'emergency', 101: '', 102: ''}
    assert events == [('confirm', marked)] + ([('start', 100)] if how == 'the start failed' else [])
    assert _state(db) == {100: '', 101: '', 102: ''}
    ev = _done(db, 'emergency')
    assert ev['status'] == 'failed' and ev['details']['100']['success'] is False


@pytest.mark.parametrize('dr', [(False, True), (False, False)], ids=['stopped there', 'unread'])
def test_a_failback_does_not_call_the_copy_at_home_older_when_the_guest_does_not_run_on_the_dr_site(
        db, sites, monkeypatch, dr):
    """A mark can outlive a start that never happened (the leader gone in between). Then
    the copy at home may be the guest itself, and removing it is not the way back."""
    _plan(db, moved=(100,))
    monkeypatch.setattr(srw, '_target_vmid_exists', lambda mgr, vmid: mgr.cluster_id == SRC)
    monkeypatch.setattr(srw, '_source_vm_is_running', lambda mgr, vmid: dr if mgr.cluster_id == TGT else (True, True))
    srw.execute_failover('p1', 'failback')
    err = _done(db, 'failback')['details']['100']['error']
    assert 'Remove it on' not in err and 'Check which copy is current' in err, err
    assert _state(db)[100] == 'emergency'


# --- 1b. a replication run leaves a running replica alone ------------------------------------

class _Cluster:
    """One side of a full replication run of guest 100: GETs by path, writes recorded."""

    def __init__(self, node, guests, listed=True):
        self.host, self.api_port, self.is_connected = f'{node}.example', 8006, True
        self.node, self.guests, self.listed = node, guests, listed
        self.posts, self.deletes, self.migrations, self.tokens_deleted = [], [], [], []

    def _api_get(self, url, params=None, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/cluster/resources':
            if not self.listed:
                return _R(500)
            return _R(200, [{'vmid': v, 'node': self.node, 'type': 'qemu', 'status': s}
                            for v, s in self.guests.items()])
        if path == '/nodes':
            return _R(200, [{'node': self.node, 'status': 'online'}])
        if path == '/cluster/nextid':
            return _R(200, '9100')
        if path == '/storage':
            return _R(200, [{'storage': 'fast', 'type': 'lvmthin'}])
        if path.endswith('/config'):
            return _R(200, {'scsi0': 'fast:vm-9100-disk-0,size=8G'})
        return _R(404)

    def _api_post(self, url, data=None, **kw):
        self.posts.append(url.split('/api2/json', 1)[1])
        return _R(200, 'UPID:post')

    def _api_delete(self, url, params=None, **kw):
        self.deletes.append(url.split('/api2/json', 1)[1])
        return _R(200, 'UPID:delete')

    def _get_vm_storage(self, node, vmid, vm_type):
        return 'fast'

    def create_api_token(self, name):
        return {'success': True, 'token_id': 'root@pam!xcrepl', 'token_value': 'secret'}

    def delete_api_token(self, name):
        self.tokens_deleted.append(name)

    def get_cluster_fingerprint(self):
        return {'success': True, 'host': self.host, 'fingerprint': 'AA:BB'}

    def remote_migrate_vm(self, **kw):
        self.migrations.append(kw.get('vmid'))
        return {'success': True, 'task': 'UPID:migrate'}


@pytest.fixture
def full(db, monkeypatch):
    said, cleaned = [], []
    monkeypatch.setattr(vms_api, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    monkeypatch.setattr(vms_api, '_capture_vm_identity', lambda *a, **k: {})
    monkeypatch.setattr(vms_api, '_restore_vm_identity', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_is_replica_of_job', lambda *a, **k: True)
    monkeypatch.setattr(vms_api, '_tag_as_replica', lambda *a, **k: (True, ''))
    monkeypatch.setattr(vms_api, '_cleanup_snapshot', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_enforce_retention', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_cleanup_clone_and_snap', lambda *a, **k: cleaned.append(a[2]))
    monkeypatch.setattr(vms_api, '_update_repl_status', lambda _db, job_id, status, error='':
                        said.append((status, error)))

    def go(target_status, listed=True):
        src, tgt = _Cluster('s1', {100: 'running'}), _Cluster('t1', {100: target_status}, listed)
        monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
        monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
        vms_api._execute_replication({'id': 'j1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src',
                                      'target_cluster': 'tgt', 'target_storage': 'far', 'target_node': 't1',
                                      'mode': 'full'})
        return src, tgt, said, cleaned
    return go


def test_a_full_run_does_not_stop_or_purge_a_running_replica(full):
    src, tgt, said, cleaned = full('running')
    assert tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert status == 'error' and 'is running' in error and 'nothing was stopped' in error
    # the clone and the token of this run do not stay behind
    assert cleaned == [9100] and tgt.tokens_deleted


def test_a_full_run_still_replaces_its_stopped_replica(full):
    src, tgt, said, cleaned = full('stopped')
    assert tgt.posts == ['/nodes/t1/qemu/100/status/stop'] and tgt.deletes == ['/nodes/t1/qemu/100']
    assert src.migrations == [9100] and said == [('ok', '')]


def test_a_full_run_that_cannot_read_the_target_writes_nothing_there(full):
    """A guest list that did not answer is no empty one (#1051): the run cannot tell a
    replica that runs from none, so it ends in an error before any stop, removal or
    migration onto the VMID."""
    src, tgt, said, cleaned = full('running', listed=False)
    assert tgt.posts == [] and tgt.deletes == [] and src.migrations == []
    (status, error), = said
    assert status == 'error' and 'Cannot read the guests of the target cluster' in error
    assert cleaned == [9100] and tgt.tokens_deleted


class _Target(FakeMgr):
    """The target of an incremental run, its guests with a status."""

    def __init__(self, *a, status='stopped', **kw):
        super().__init__(*a, **kw)
        self.status, self.deletes = status, []

    def _api_get(self, url, params=None, **kw):
        if url.endswith('/cluster/resources'):
            return _R(200, [{'vmid': v, 'node': self.node, 'type': 'qemu', 'status': self.status}
                            for v in self.vms_here])
        return super()._api_get(url, params=params, **kw)

    def _api_delete(self, url, params=None, **kw):
        self.deletes.append(url)
        return _R(200, 'UPID:delete')


@pytest.fixture
def incremental(db, monkeypatch):
    seen = {'status': [], 'cleanup': [], 'shipped': [], 'built': []}
    monkeypatch.setattr(vms_api, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    monkeypatch.setattr(vms_api, '_update_repl_status', lambda _db, job_id, status, error='':
                        seen['status'].append((status, error)))
    monkeypatch.setattr(vms_api, '_cleanup_snapshot', lambda mgr, node, vmid, vt, snap:
                        seen['cleanup'].append((mgr.node, snap)))
    monkeypatch.setattr(vms_api, '_xcincr_rbd_pool', lambda ssh, storage: storage)
    monkeypatch.setattr(vms_api, '_capture_vm_identity', lambda *a, **k: {})
    monkeypatch.setattr(vms_api, '_restore_vm_identity', lambda *a, **k: None)
    monkeypatch.setattr(vms_api, '_tag_as_replica', lambda *a, **k: (True, ''))
    monkeypatch.setattr(vms_api, '_build_incremental_replica_vm', lambda *a, **k: seen['built'].append(a[2]))
    monkeypatch.setattr(incr, 'rbd_replicate_disk', lambda *a, base_snap=None, **k:
                        seen['shipped'].append(base_snap) or {'ok': True, 'bytes': 1, 'mode': 'x'})
    monkeypatch.setattr(incr, 'rbd_prune_snapshots', lambda *a, **k: None)

    def go(status, last_snapshot):
        src = FakeMgr('192.0.2.1', 's1', [100], {'fast': 'rbd'},
                      {100: {'name': 'web', 'scsi0': 'fast:vm-100-disk-0,size=8G'}})
        tgt = _Target('192.0.2.2', 't1', [100], {'far': 'rbd'}, {100: {'name': 'web', 'tags': OURS}},
                      status=status)
        monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
        monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
        job = {'id': 'job1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src', 'target_cluster': 'tgt',
               'target_storage': 'far', 'target_node': 't1', 'target_vmid': 100,
               'last_snapshot': last_snapshot, 'mode': 'incremental'}
        assert vms_api._execute_replication_incremental(job) is True
        return tgt, seen
    return go


@pytest.mark.parametrize('last_snapshot', [BASE, ''], ids=['delta', 'reseed'])
def test_an_incremental_run_does_not_write_into_or_remove_a_running_replica(incremental, last_snapshot):
    tgt, seen = incremental('running', last_snapshot)
    assert seen['shipped'] == [] and seen['built'] == []
    assert tgt.posts == [] and tgt.deletes == [] and tgt.puts == []
    (status, error), = seen['status']
    assert status == 'error' and 'is running' in error
    # the snapshot taken for this run goes again
    assert [c for c in seen['cleanup'] if c[0] == 's1' and c[1] != BASE]


@pytest.mark.parametrize('last_snapshot', [BASE, ''], ids=['delta', 'reseed'])
def test_an_incremental_run_still_writes_its_stopped_replica(incremental, last_snapshot):
    tgt, seen = incremental('stopped', last_snapshot)
    assert seen['status'] == [('ok', '')]
    if last_snapshot:
        assert seen['shipped'] == [BASE] and tgt.deletes == []
    else:
        # the old replica stops and goes, the seed builds a new one
        assert tgt.posts and tgt.posts[0][0].endswith('/qemu/100/status/stop') and len(tgt.deletes) == 1
        assert seen['shipped'] == [None] and seen['built'] == [100]


# --- 2. the marks of a database from before ----------------------------------------------------

def _old_database(db):
    """site_recovery_vms from before the failed_over columns; the failover events say 100
    is on the DR site."""
    c = db.conn
    c.execute('DROP TABLE site_recovery_vms')
    c.execute("CREATE TABLE site_recovery_vms (id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, vmid INTEGER NOT NULL, "
              "vm_name TEXT DEFAULT '', vm_type TEXT DEFAULT 'qemu', boot_group INTEGER DEFAULT 0, "
              "boot_delay INTEGER DEFAULT 30, replication_job_id TEXT DEFAULT '', target_vmid INTEGER, "
              "notes TEXT DEFAULT '')")
    c.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, status) "
              "VALUES ('p1', 'g1', 'Plan p1', ?, ?, 'completed')", (SRC, TGT))
    for vmid in (100, 101):
        c.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid) VALUES (?, 'p1', ?)", (f'r{vmid}', vmid))
    _event(db, 'e1', 'emergency', '2026-10-01T10:00:00', {'100': {'success': True}})
    c.commit()
    db._init_db()


def test_a_member_derives_no_marks_from_its_own_events(db, monkeypatch):
    """The events are per instance: a member's are not the active's, and the marks it would
    work out from them are not the group's."""
    monkeypatch.setattr(_ha, 'is_active', lambda: False)
    _old_database(db)
    srw.recover_orphan_runs()
    assert srw.replay_failover_state() is None
    assert _state(db) == {100: '', 101: ''}


def test_the_instance_that_acts_replays_them_at_its_start_and_sends_them_on(db, monkeypatch):
    sent = []
    monkeypatch.setattr(_ha, 'send_on', sent.append)
    _old_database(db)
    srw.recover_orphan_runs()
    assert _state(db) == {100: 'emergency', 101: ''}
    assert len(sent) == 1
    srw.recover_orphan_runs()
    assert len(sent) == 1


def test_the_replication_scheduler_replays_them_before_it_picks_a_job(db, monkeypatch):
    """An automatic leader replays them once it may act (when_active polls each second);
    its scheduler can tick first, and the job of a guest failed over still waits."""
    _old_database(db)
    _job(db, 'j100', 100)
    _job(db, 'j101', 101)
    assert _tick(monkeypatch) == ['j101']
    assert _state(db) == {100: 'emergency', 101: ''}


# --- 3. the HA rules a rolling update switches off ---------------------------------------------

def _rows(db):
    return sorted((r[0], r[3]) for r in db.get_suspended_ha_rules('cluster_1'))


def test_the_rules_reach_the_members_before_the_round_and_the_first_switch_off(auto, seed, db, monkeypatch):
    auto.form(seed)
    pve = _Pve({'/cluster/ha/rules': RULES})
    m = _rules_manager(pve)
    events = []
    monkeypatch.setattr(_ha, 'cv_tick', lambda force=False: events.append(('sent', _rows(db))) or 'stepped')
    real_confirm = _ha.confirm_step
    monkeypatch.setattr(_ha, 'confirm_step', lambda what, need=_ha.NEED_STEP:
                        events.append(('confirm', _rows(db))) or real_confirm(what, need))
    pve.on_put = lambda path, data: events.append(('put', path))
    with auto.at('a'):
        assert m.suspend_negative_ha_rules() == (['keep-apart', 'db-apart'], [])
    both = [('db-apart', 'rolling'), ('keep-apart', 'rolling')]
    assert events == [('sent', both), ('confirm', both), ('put', '/cluster/ha/rules/keep-apart'),
                      ('put', '/cluster/ha/rules/db-apart')]


def test_a_leader_gone_after_the_first_switch_off_leaves_the_next_one_the_list(auto, seed, db, monkeypatch):
    auto.form(seed)
    pve = _Pve({'/cluster/ha/rules': RULES})
    m = _rules_manager(pve)
    carried = []
    monkeypatch.setattr(_ha, 'cv_tick', lambda force=False: carried.append(_rows(db)) or 'stepped')

    def put(path, data):
        raise _Died()
    pve.on_put = put
    with auto.at('a'):
        with pytest.raises(_Died):
            m.suspend_negative_ha_rules()
    assert carried, 'the list did not reach the members before the first rule went off'
    assert carried[-1] == [('db-apart', 'rolling'), ('keep-apart', 'rolling')]
    # the next leader's daemon loop: nothing holds them there, so they go back on
    db.execute('DELETE FROM suspended_ha_rules')
    for rule, owner in carried[-1]:
        db.save_suspended_ha_rules('cluster_1', [rule], owner=owner)
    pve.on_put, pve.puts = None, []
    monkeypatch.setattr(_ha, 'is_active', lambda: True)
    monkeypatch.setattr(_ha, 'confirm_step', lambda *a, **k: True)
    _rules_manager(pve)._restore_suspended_ha_rules_if_due()
    assert sorted(p for p, _d in pve.puts) == ['/cluster/ha/rules/db-apart', '/cluster/ha/rules/keep-apart']
    assert db.get_suspended_ha_rules('cluster_1') == []


def test_rows_written_for_a_round_that_said_no_go_again_and_older_ones_stay(db, monkeypatch):
    db.save_suspended_ha_rules('cluster_1', ['keep-apart'], owner='rolling')
    db.save_suspended_ha_rules('cluster_1', ['already-off'], owner='maintenance:pve1')
    pve = _Pve({'/cluster/ha/rules': RULES})
    monkeypatch.setattr(_ha, 'confirm_step', lambda *a, **k: False)
    assert _rules_manager(pve).suspend_negative_ha_rules() == ([], ['keep-apart', 'db-apart'])
    assert pve.puts == []
    assert _rows(db) == [('already-off', 'maintenance:pve1'), ('keep-apart', 'rolling')]


# --- 4. the balancer's cooldown after a change of leader ----------------------------------------

def _tasks(now):
    return [
        {'type': 'qmigrate', 'id': '101', 'status': 'OK', 'endtime': int(now - 300)},
        # still running: the leader before started it
        {'type': 'vzmigrate', 'id': '102', 'starttime': int(now - 20)},
        {'type': 'qmigrate', 'id': '103', 'status': 'OK', 'endtime': int(now - 2000)},
        {'type': 'qmigrate', 'id': '104', 'status': 'migration aborted', 'endtime': int(now - 60)},
        {'type': 'qmstart', 'id': '105', 'status': 'OK', 'endtime': int(now - 60)},
        {'type': 'qmigrate', 'id': '106', 'status': 'WARNINGS: 1', 'endtime': int(now - 60)},
    ]


def _balancer(monkeypatch, role, answer):
    monkeypatch.setattr(_ha, 'role', lambda: role)
    m = _bal_manager([_guest(v) for v in range(101, 107)])
    m.reads = []

    def get(url, **kw):
        if url.endswith('/cluster/tasks'):
            m.reads.append(url)
            return answer()
        return _resp(404)
    m._api_get = get
    return m


def _candidates(m):
    picked = []
    while True:
        p = m.find_migration_candidate('pve1', 'pve2', exclude_vmids=list(picked))
        if not p:
            return sorted(picked)
        picked.append(p['vmid'])


def test_after_a_change_of_leader_the_cooldown_holds_the_moves_in_the_task_list(db, monkeypatch):
    m = _balancer(monkeypatch, _ha.ROLE_ACTIVE, lambda: _resp(200, _tasks(time.time())))
    assert _candidates(m) == [103, 104, 105]
    assert set(m._vm_migration_cooldown) == {101, 102, 106}
    # one read for the cluster, whatever the number of looks and guests
    assert len(m.reads) == 1


def test_an_instance_of_its_own_reads_no_task_list(db, monkeypatch):
    m = _balancer(monkeypatch, _ha.ROLE_STANDALONE, lambda: _resp(200, _tasks(time.time())))
    assert _candidates(m) == [101, 102, 103, 104, 105, 106]
    assert m.reads == []


def test_a_task_list_that_did_not_answer_is_asked_again_at_a_later_look(db, monkeypatch):
    answers = [_resp(500)]
    m = _balancer(monkeypatch, _ha.ROLE_ACTIVE, lambda: answers[-1])
    m.find_migration_candidate('pve1', 'pve2')
    m.find_migration_candidate('pve1', 'pve2')
    assert len(m.reads) == 1 and m._vm_migration_cooldown == {}
    # COOLDOWN_TASKS_RETRY later
    m._cooldown_tasks_retry = 0
    answers.append(_resp(200, _tasks(time.time())))
    assert _candidates(m) == [103, 104, 105]
    assert len(m.reads) == 2
