"""Site Recovery and the VMID a guest has on the DR site.

A replication job can keep a guest's replica under a VMID of its own (its target_vmid),
and a plan row can name one (site_recovery_vms.target_vmid). The emergency failover went
by the guest's own VMID all the same: on the DR site that is another guest, which it
started and reported as recovered, or none at all. Now:

  * the emergency failover starts the replica under its VMID: the plan row's target_vmid,
    else the linked job's, else the one the guest's jobs between the plan's clusters
    agree on, else the guest's own as before. Jobs that disagree refuse the guest instead
    of guessing, and the readiness check says so
  * a test failover clones that replica
  * the mark keeps where the guest is on the DR site (failed_over_vmid), and a failback
    brings it home from there under its own VMID, asking the DR site about that one
  * what concerns the source - whether the guest still runs there, its mark - keeps the
    guest's own VMID
MK Nov 2026
"""
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.background.site_recovery as srw
import pegaprox.globals as ppglobals

from test_sr_per_guest_failover import SRC, TGT, _done, _job, _mgr, _plan, _state


class _Site:
    """One cluster: its guests as /cluster/resources lists them, and what was started there."""

    def __init__(self, cid, guests, connected=True):
        self.cluster_id, self.is_connected = cid, connected
        self.host, self.api_port = f'{cid}.example', 8006
        self.guests = dict(guests)          # vmid -> status
        self.started = []

    def _api_get(self, url, params=None, **kw):
        assert url.endswith('/api2/json/cluster/resources'), url
        rows = [{'vmid': v, 'node': 'n1', 'type': 'qemu', 'status': s} for v, s in self.guests.items()]
        return types.SimpleNamespace(status_code=200, json=lambda: {'data': rows})

    def vm_action(self, node, vmid, vm_type, action, **kw):
        assert action == 'start'
        self.started.append(vmid)
        self.guests[vmid] = 'running'
        return {'success': True}

    def get_node_status(self):
        return {'n1': {'status': 'online'}}

    def get_storage_list(self, node):
        return []

    def get_network_list(self, node):
        return []


@pytest.fixture
def dr(db, monkeypatch):
    """Plan p1 (100, 101, 102) from cluster_1, which cannot be reached, to cluster_2. There
    100, 101, 102 and 9100 exist, all stopped."""
    home = _Site(SRC, {100: 'running', 101: 'running', 102: 'running'}, connected=False)
    far = _Site(TGT, {100: 'stopped', 101: 'stopped', 102: 'stopped', 9100: 'stopped'})
    monkeypatch.setitem(ppglobals.cluster_managers, SRC, home)
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, far)
    monkeypatch.setattr(srw, '_broadcast_progress', lambda *a, **kw: None)
    monkeypatch.setattr(srw, '_fire_webhook', lambda *a, **kw: None)
    _plan(db)
    moved = []

    def migrate(src, tgt, vmid, vm_type, storage_map, net_map, target_vmid=None):
        moved.append((src.cluster_id, vmid, tgt.cluster_id, target_vmid or vmid))
        return True, ''
    monkeypatch.setattr(srw, '_migrate_vm_cross_cluster', migrate)
    return types.SimpleNamespace(db=db, home=home, far=far, moved=moved)


def _pin_job(db, job_id, vmid, target_vmid, link=True, **kw):
    _job(db, job_id, vmid, **kw)
    if target_vmid:
        db.execute('UPDATE cross_cluster_replications SET target_vmid = ? WHERE id = ?', (target_vmid, job_id))
    if link:
        db.execute("UPDATE site_recovery_vms SET replication_job_id = ? WHERE plan_id = 'p1' AND vmid = ?",
                   (job_id, vmid))


def _dr_vmid(db, vmid):
    return db.query_one("SELECT failed_over_vmid FROM site_recovery_vms WHERE plan_id = 'p1' AND vmid = ?",
                        (vmid,))['failed_over_vmid']


# --- the emergency failover ---------------------------------------------------------------

def test_an_emergency_failover_starts_the_replica_the_plan_row_names(dr):
    dr.db.execute("UPDATE site_recovery_vms SET target_vmid = 9100 WHERE plan_id = 'p1' AND vmid = 100")
    srw.execute_failover('p1', 'emergency', only_vmids=[100])
    assert dr.far.started == [9100]
    assert dr.far.guests[100] == 'stopped'
    ev = _done(dr.db, 'emergency')
    assert ev['status'] == 'completed' and ev['details']['100']['dr_vmid'] == 9100


def test_an_emergency_failover_starts_the_replica_its_replication_job_keeps(dr, monkeypatch):
    """The common way to get one: the job pins the replica's VMID, the plan links the job."""
    _pin_job(dr.db, 'j100', 100, 9100)
    marks = []
    real_start = srw._start_replicated_vm
    monkeypatch.setattr(srw, '_start_replicated_vm', lambda mgr, vmid, vtype='qemu':
                        marks.append(_dr_vmid(dr.db, 100)) or real_start(mgr, vmid, vtype))
    srw.execute_failover('p1', 'emergency')
    assert sorted(dr.far.started) == [101, 102, 9100]
    assert dr.far.guests[100] == 'stopped'
    # the mark says where the guest is before its start goes out, for the next leader too
    assert marks[0] == 9100
    assert _state(dr.db) == {100: 'emergency', 101: 'emergency', 102: 'emergency'}
    assert (_dr_vmid(dr.db, 100), _dr_vmid(dr.db, 101)) == (9100, 101)
    assert _done(dr.db, 'emergency')['status'] == 'completed'


def test_an_unlinked_job_between_the_plan_clusters_counts_one_between_others_does_not(dr):
    _pin_job(dr.db, 'j100', 100, 9100, link=False)
    _pin_job(dr.db, 'j100-far', 100, 7100, link=False, tgt='cluster_9')
    srw.execute_failover('p1', 'emergency', only_vmids=[100])
    assert dr.far.started == [9100]


def test_without_a_pinned_replica_each_guest_starts_under_its_own_vmid_as_before(dr):
    _pin_job(dr.db, 'j101', 101, None)
    _pin_job(dr.db, 'j102', 102, None, link=False)
    srw.execute_failover('p1', 'emergency')
    assert sorted(dr.far.started) == [100, 101, 102]
    assert _done(dr.db, 'emergency')['status'] == 'completed'
    assert [_dr_vmid(dr.db, v) for v in (100, 101, 102)] == [100, 101, 102]


def test_jobs_that_disagree_on_the_replica_refuse_the_guest_instead_of_guessing(dr):
    _pin_job(dr.db, 'ja', 100, 9100, link=False)
    _pin_job(dr.db, 'jb', 100, None, link=False)
    srw.execute_failover('p1', 'emergency', only_vmids=[100, 101])
    assert dr.far.started == [101]
    ev = _done(dr.db, 'emergency')
    assert ev['status'] == 'failed'
    err = ev['details']['100']['error']
    assert err.startswith('not started:') and 'VMIDs 100, 9100' in err and 'link the one' in err, err
    assert _state(dr.db) == {100: '', 101: 'emergency', 102: ''}
    # the plan links one: that is the replica
    dr.db.execute("UPDATE site_recovery_vms SET replication_job_id = 'ja' WHERE plan_id = 'p1' AND vmid = 100")
    srw.execute_failover('p1', 'emergency', only_vmids=[100])
    assert dr.far.started == [101, 9100]


def test_a_job_table_that_cannot_be_read_starts_nothing_rather_than_the_guest_vmid(dr, monkeypatch):
    def unreadable(plan):
        raise RuntimeError('database is locked')
    # raising=False: before the change there was no read to fail
    monkeypatch.setattr(srw, '_replicas_kept', unreadable, raising=False)
    srw.execute_failover('p1', 'emergency', only_vmids=[100])
    assert dr.far.started == []
    assert 'could not be read' in _done(dr.db, 'emergency')['details']['100']['error']
    assert _state(dr.db)[100] == ''


def test_the_readiness_check_names_a_guest_whose_replica_is_open(api, seed):
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    _plan(seed.db)
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    _job(seed.db, 'ja', 100)
    _job(seed.db, 'jb', 100)
    seed.db.execute("UPDATE cross_cluster_replications SET target_vmid = 9100 WHERE id = 'ja'")
    c = api.as_user(seed.user('root', role='admin'))

    def open_ones():
        r = c.post('/api/site-recovery/plans/p1/readiness')
        assert r.status_code == 200, r.get_data(as_text=True)
        return [i for i in r.get_json()['issues'] if 'replication jobs keep replicas' in i['msg']]
    found = open_ones()
    assert [(i['severity'], i['msg'].split(':')[0]) for i in found] == [('error', 'VM 100')], found
    seed.db.execute("UPDATE site_recovery_vms SET replication_job_id = 'ja' WHERE plan_id = 'p1' AND vmid = 100")
    assert open_ones() == []


# --- the failback ---------------------------------------------------------------------------

def test_the_failback_brings_the_guest_home_from_the_replica_it_started(dr):
    _pin_job(dr.db, 'j100', 100, 9100)
    srw.execute_failover('p1', 'emergency', only_vmids=[100])
    assert dr.far.started == [9100]
    # the source is back and its old copy of 100 has been removed there
    dr.home.is_connected = True
    del dr.home.guests[100]
    srw.execute_failover('p1', 'failback')
    assert dr.moved == [(TGT, 9100, SRC, 100)]
    assert _state(dr.db)[100] == '' and _dr_vmid(dr.db, 100) is None
    assert _done(dr.db, 'failback')['details']['100']['dr_vmid'] == 9100


def test_a_failback_asks_the_dr_site_about_the_replica_not_about_the_guest_vmid(dr):
    """The old copy at home is in the way. Whether it is the older one depends on the guest
    running on the DR site, which there is 9100; 100 is another guest, stopped."""
    dr.db.execute("UPDATE site_recovery_vms SET failed_over = 'emergency', failed_over_vmid = 9100 "
                  "WHERE plan_id = 'p1' AND vmid = 100")
    dr.far.guests[9100] = 'running'
    dr.home.is_connected = True
    srw.execute_failover('p1', 'failback')
    err = _done(dr.db, 'failback')['details']['100']['error']
    assert "older than the guest running on 'cluster_2' as 9100" in err and 'Remove it on' in err, err
    assert dr.moved == []


def test_a_failback_does_not_look_for_the_dr_vmid_at_home(dr):
    """Under 9100 at home runs some other guest. That says nothing about the way back,
    which ends under 100."""
    dr.db.execute("UPDATE site_recovery_vms SET target_vmid = 9100, failed_over = 'emergency', "
                  "failed_over_vmid = 9100 WHERE plan_id = 'p1' AND vmid = 100")
    dr.far.guests[9100] = 'running'
    dr.home.is_connected = True
    dr.home.guests = {9100: 'running'}
    srw.execute_failover('p1', 'failback')
    assert dr.moved == [(TGT, 9100, SRC, 100)]
    assert _done(dr.db, 'failback')['status'] == 'completed'


def test_a_planned_failover_lands_under_the_guest_vmid_and_the_failback_takes_it_from_there(dr):
    """A planned failover migrates the guest itself, not its replica: it keeps its VMID on
    the DR site, whatever VMID the job keeps the replica under, and comes back from it."""
    _pin_job(dr.db, 'j100', 100, 9100)
    dr.home.is_connected = True
    del dr.far.guests[100]
    srw.execute_failover('p1', 'planned', only_vmids=[100])
    assert dr.moved == [(SRC, 100, TGT, 100)] and _dr_vmid(dr.db, 100) == 100
    dr.home.guests = {}
    dr.far.guests[100] = 'running'
    srw.execute_failover('p1', 'failback')
    assert dr.moved[1:] == [(TGT, 100, SRC, 100)]


@pytest.mark.parametrize('kind,pin', [('planned', 9100), ('emergency', None)])
def test_a_mark_from_before_the_column_brings_the_guest_home_from_its_own_vmid(dr, kind, pin):
    """Such a mark comes from a run that used the guest's own VMID on the DR site. A planned
    one moved the guest itself there, an emergency one started the replica the job kept
    under the guest's VMID."""
    _pin_job(dr.db, 'j100', 100, pin)
    dr.db.execute("UPDATE site_recovery_vms SET failed_over = ? WHERE plan_id = 'p1' AND vmid = 100", (kind,))
    dr.home.is_connected = True
    dr.home.guests = {}
    srw.execute_failover('p1', 'failback')
    assert dr.moved == [(TGT, 100, SRC, 100)]
    assert _done(dr.db, 'failback')['status'] == 'completed'


def _old_emergency_mark(dr, home):
    """100 failed over in an emergency before failed_over_vmid, while its job kept the replica
    as 9100: that run started the other guest 100 on the DR site, which runs now."""
    _pin_job(dr.db, 'j100', 100, 9100)
    dr.db.execute("UPDATE site_recovery_vms SET failed_over = 'emergency' WHERE plan_id = 'p1' AND vmid = 100")
    dr.far.guests[100] = 'running'
    dr.home.is_connected = True
    dr.home.guests = home


def test_an_old_emergency_mark_does_not_send_the_operator_to_remove_the_copy_at_home(dr):
    """Home 100 is the guest. What runs under 100 on the DR site says nothing about it being
    the older copy."""
    _old_emergency_mark(dr, {100: 'stopped'})
    srw.execute_failover('p1', 'failback', only_vmids=[100])
    err = _done(dr.db, 'failback')['details']['100']['error']
    assert 'Remove it on' not in err, err
    assert "VMID 100 on 'cluster_2' may be another guest" in err and 'kept as 9100' in err, err
    assert 'Check which copy is current' in err and dr.moved == []
    assert _state(dr.db)[100] == 'emergency'


def test_an_old_emergency_mark_does_not_bring_the_other_guest_home(dr):
    """Home 100 is gone. A migration would take the other guest 100 off the DR site."""
    _old_emergency_mark(dr, {})
    srw.execute_failover('p1', 'failback', only_vmids=[100])
    ev = _done(dr.db, 'failback')
    assert dr.moved == []
    assert ev['status'] == 'failed' and 'may be another guest' in ev['details']['100']['error']


def test_an_old_emergency_mark_with_jobs_that_disagree_goes_by_the_job_the_plan_links(dr):
    """One job keeps the replica as 100, one as 9100. Which one the old run started cannot be
    told until the plan links one."""
    _old_emergency_mark(dr, {})
    dr.db.execute("UPDATE site_recovery_vms SET replication_job_id = '' WHERE plan_id = 'p1' AND vmid = 100")
    _pin_job(dr.db, 'j100-own', 100, None, link=False)
    srw.execute_failover('p1', 'failback', only_vmids=[100])
    err = _done(dr.db, 'failback')['details']['100']['error']
    assert 'may be another guest' in err and 'VMIDs 100, 9100' in err and 'link the one' in err, err
    assert dr.moved == []
    dr.db.execute("UPDATE site_recovery_vms SET replication_job_id = 'j100-own' WHERE plan_id = 'p1' AND vmid = 100")
    srw.execute_failover('p1', 'failback', only_vmids=[100])
    assert dr.moved == [(TGT, 100, SRC, 100)]
    assert _done(dr.db, 'failback', n=2)['status'] == 'completed'


def test_a_plan_row_with_a_replica_vmid_that_is_none_refuses_that_guest_only(api, seed, dr):
    """Nothing writes site_recovery_vms.target_vmid; a hand edit can leave text there.
    (api first: it clears the managers dr sets.)"""
    dr.db.execute("UPDATE site_recovery_vms SET target_vmid = 'abc' WHERE plan_id = 'p1' AND vmid = 100")
    srw.execute_failover('p1', 'emergency')
    ev = _done(dr.db, 'emergency')
    assert ev['status'] == 'failed'
    assert ev['details']['100']['error'] == 'not started: the plan names no valid VMID for its replica'
    assert sorted(dr.far.started) == [101, 102]
    # and the readiness check says it rather than failing
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    r = api.as_user(seed.user('root', role='admin')).post('/api/site-recovery/plans/p1/readiness')
    assert r.status_code == 200, r.get_data(as_text=True)
    assert {'severity': 'error', 'msg': 'VM 100: the plan names no valid VMID for its replica'} in r.get_json()['issues']


def test_a_migration_takes_the_guest_from_one_vmid_to_another(monkeypatch):
    import gevent
    from pegaprox.core import transfer_net
    src, tgt = MagicMock(name='src'), MagicMock(name='tgt')
    src.get_node_status.return_value = {'n1': {}}
    src.get_vms.return_value = [{'vmid': 100}, {'vmid': 9100}]
    src.remote_migrate_vm.return_value = {'success': True, 'task': 'UPID:x'}
    tgt.host = '192.0.2.20'
    tgt.create_api_token.return_value = {'success': True, 'token_id': 'root@pam!t', 'token_value': 's'}
    tgt.get_cluster_fingerprint.return_value = {'success': True, 'fingerprint': 'AA:BB'}
    monkeypatch.setattr(transfer_net, 'migration_route', lambda mgr, node=None: None)
    # the run follows its task to the end and drops the token then: here it ended OK
    monkeypatch.setattr(transfer_net, 'drop_token_when_done', lambda *a, **kw: ('ok', 'OK'))
    monkeypatch.setattr(gevent, 'spawn', lambda *a, **kw: None)
    ok, err = srw._migrate_vm_cross_cluster(src, tgt, 9100, 'qemu', {}, {}, 100)
    assert ok, err
    kw = src.remote_migrate_vm.call_args.kwargs
    assert (kw['node'], kw['vmid'], kw['target_vmid']) == ('n1', 9100, 100)
    # no VMID for the target: it keeps its own
    srw._migrate_vm_cross_cluster(src, tgt, 100, 'qemu', {}, {})
    assert src.remote_migrate_vm.call_args.kwargs['target_vmid'] == 100


# --- the test failover and the database --------------------------------------------------------

def test_a_test_failover_clones_the_replica_its_job_keeps(db, monkeypatch):
    _plan(db, guests=((100, 'web01'), (101, 'db01')))
    _pin_job(db, 'j100', 100, 9100)
    tgt = MagicMock(name='tgt')
    tgt.get_node_status.return_value = {'n1': {'status': 'online'}}
    tgt.get_vms.return_value = [{'vmid': 100}, {'vmid': 101}, {'vmid': 9100}]
    tgt.clone_vm.return_value = {'success': True}
    tgt.vm_action.return_value = {'success': True}
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, tgt)
    monkeypatch.setattr(srw, '_broadcast_progress', lambda *a, **kw: None)
    srw.execute_test_failover('p1')
    cloned = sorted((c.args[1], c.kwargs['newid']) for c in tgt.clone_vm.call_args_list)
    assert cloned == [(101, 90101), (9100, 99100)]


def test_a_database_with_the_marks_gets_the_column_and_an_old_mark_reads_as_the_guest_vmid(db):
    c = db.conn
    c.execute('DROP TABLE site_recovery_vms')
    c.execute("CREATE TABLE site_recovery_vms (id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, vmid INTEGER NOT NULL, "
              "vm_name TEXT DEFAULT '', vm_type TEXT DEFAULT 'qemu', boot_group INTEGER DEFAULT 0, "
              "boot_delay INTEGER DEFAULT 30, replication_job_id TEXT DEFAULT '', target_vmid INTEGER, "
              "notes TEXT DEFAULT '', failed_over TEXT DEFAULT '', failed_over_at TEXT DEFAULT '')")
    c.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, failed_over) VALUES ('r100', 'p1', 100, 'planned')")
    c.commit()
    db._init_db()
    assert 'failed_over_vmid' in {r[1] for r in c.execute('PRAGMA table_info(site_recovery_vms)').fetchall()}
    row = dict(db.query_one("SELECT * FROM site_recovery_vms WHERE id = 'r100'"))
    assert row['failed_over'] == 'planned' and row['failed_over_vmid'] is None
    assert srw._dr_vmid_of(row) == 100
