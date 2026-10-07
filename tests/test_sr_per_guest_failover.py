"""Site Recovery guest by guest: an emergency failover or a failback of single guests.

POST /emergency and /failback take an optional body {"vmids": [...]}. Without it they
take the whole plan as before. Each guest of a plan records where it is
(site_recovery_vms.failed_over: '' at the source, else the failover that moved it), and
what runs later goes by that:

  * a failover passes over the guests failed over already, a failback the ones that are
    not; the plan shows 'none', 'partial' or 'all'
  * the replication job of a failed-over guest waits: its replica on the target is the
    running guest now, and the next run would replace it with the old source. The plan's
    other guests replicate as before, and the job runs again after the failback
  * the auto-failover heartbeat weighs only the guests still at the source, and a DR
    drill reads a held replication as a warning, not as an RPO breach
  * a database from before replays the state from its failover events once

The picks are validated (a list of the plan's guests, a body that is not JSON refused
rather than read as "every guest"), behind the same gates as before: admin, a user
without site_recovery.failover, a confined admin, another tenant, a pool user whose
pool does not hold the whole plan, and a standby.
MK Oct 2026
"""
import json
import time
import types
from unittest.mock import MagicMock

import gevent
import pytest

import pegaprox.api.site_recovery as srapi
import pegaprox.api.vms as vms_api
import pegaprox.background.cross_cluster_replication as xcr
import pegaprox.background.site_recovery as srw
import pegaprox.utils.rbac as rbac
from pegaprox.core import ha
from pegaprox.core.db import _replay_sr_failover_state

from test_ha_api import ha_env, _standby_of_active  # noqa: F401 (ha_env is a fixture)

SRC, TGT = 'cluster_1', 'cluster_2'
GUESTS = ((100, 'web01'), (101, 'db01'), (102, 'app01'))


def _mgr(cid, connected=True):
    m = MagicMock(name=f'mgr[{cid}]')
    m.cluster_id = cid
    m.is_connected = connected
    m.host, m.api_port = '192.0.2.10', 8006
    m.get_node_status.return_value = {'n1': {'status': 'online'}}
    m.get_storage_list.return_value = []
    m.get_network_list.return_value = []
    return m


def _plan(db, plan_id='p1', guests=GUESTS, status='ready', moved=(), links=None, **plan_cols):
    cols = {'auto_failover': 0, 'failover_timeout': 120}
    cols.update(plan_cols)
    db.execute("INSERT INTO site_recovery_plans (id, group_id, name, source_cluster, target_cluster, status, "
               "auto_failover, failover_timeout) VALUES (?, 'g1', ?, ?, ?, ?, ?, ?)",
               (plan_id, f'Plan {plan_id}', SRC, TGT, status, cols['auto_failover'], cols['failover_timeout']))
    for vmid, name in guests:
        db.execute("INSERT INTO site_recovery_vms (id, plan_id, vmid, vm_name, vm_type, boot_group, boot_delay, "
                   "replication_job_id, failed_over, failed_over_at) VALUES (?, ?, ?, ?, 'qemu', 0, 0, ?, ?, ?)",
                   (f'{plan_id}-{vmid}', plan_id, vmid, name, (links or {}).get(vmid, ''),
                    'emergency' if vmid in moved else '', '2026-10-07T08:00:00' if vmid in moved else ''))


def _state(db, plan_id='p1'):
    return {r['vmid']: r['failed_over'] for r in db.query(
        'SELECT vmid, failed_over FROM site_recovery_vms WHERE plan_id = ?', (plan_id,))}


@pytest.fixture
def site(api, seed, monkeypatch):
    """Plan p1 (100, 101, 102) from cluster_1 to cluster_2 of tenant_a, and a recorder for
    what the worker would do on the clusters."""
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    seed.tenant('tenant_b', clusters=['cluster_9'])
    _plan(seed.db)
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    did = types.SimpleNamespace(started=[], migrated=[])
    monkeypatch.setattr(srw, '_source_vm_is_running', lambda mgr, vmid: (False, True))
    monkeypatch.setattr(srw, '_start_replicated_vm',
                        lambda mgr, vmid, vtype='qemu': did.started.append(vmid) or (True, ''))
    monkeypatch.setattr(srw, '_migrate_vm_cross_cluster',
                        lambda src, tgt, vmid, *a: did.migrated.append((src.cluster_id, vmid)) or (True, ''))
    monkeypatch.setattr(srw, '_target_vmid_exists', lambda mgr, vmid: False)
    monkeypatch.setattr(srw, '_broadcast_progress', lambda *a, **kw: None)
    monkeypatch.setattr(srw, '_fire_webhook', lambda *a, **kw: None)
    seed.did = did
    return seed


def _admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _done(db, kind, plan_id='p1', n=1, timeout=10):
    """The latest event of this kind once the worker finished the n-th one."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = db.query('SELECT * FROM site_recovery_events WHERE plan_id = ? AND event_type = ? '
                        'ORDER BY started_at DESC', (plan_id, kind))
        if len(rows) >= n and rows[0]['status'] != 'running':
            ev = dict(rows[0])
            ev['details'] = json.loads(ev['details'] or '{}')
            return ev
        gevent.sleep(0.05)
    raise AssertionError(f'the {kind} run did not finish')


def _audit(db, action):
    return [r['details'] for r in db.query('SELECT details FROM audit_log WHERE action = ?', (action,))]


# --- the main scenario ---------------------------------------------------------------------

def test_one_guest_fails_over_and_back_while_the_others_stay_and_replicate(api, site):
    c = _admin(api, site)

    r = c.post('/api/site-recovery/plans/p1/emergency', json={'vmids': [100]})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['vmids'] == [100]
    ev = _done(site.db, 'emergency')
    assert ev['status'] == 'completed'
    assert site.did.started == [100]
    assert sorted(ev['details']) == ['100'] and ev['details']['100']['success'] is True
    assert _state(site.db) == {100: 'emergency', 101: '', 102: ''}
    assert any('(guests 100)' in d for d in _audit(site.db, 'site_recovery.emergency'))

    detail = c.get('/api/site-recovery/plans/p1').get_json()
    assert (detail['failover_state'], detail['failed_over_count']) == ('partial', 1)
    rows = {v['vmid']: v for v in detail['vms']}
    assert rows[100]['failed_over'] == 'emergency' and rows[100]['failed_over_at']
    assert rows[101]['failed_over'] == ''
    listed, = c.get('/api/site-recovery/plans').get_json()
    assert (listed['failover_state'], listed['failed_over_count'], listed['vm_count']) == ('partial', 1, 3)

    # the replication of 100 waits, 101 and 102 replicate on
    jobs = {vmid: {'id': f'j{vmid}', 'vmid': vmid, 'source_cluster': SRC, 'target_cluster': TGT}
            for vmid, _ in GUESTS}
    assert srw.replication_held_by(jobs[100]) == 'Plan p1'
    assert srw.replication_held_by(jobs[101]) is None and srw.replication_held_by(jobs[102]) is None

    # failback with no body takes the guests that are failed over, here 100 alone
    r = c.post('/api/site-recovery/plans/p1/failback', json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _done(site.db, 'failback')
    assert ev['status'] == 'completed', ev
    assert site.did.migrated == [(TGT, 100)]
    assert ev['details']['101']['skipped'] is True and ev['details']['101']['reason'] == 'not failed over'
    assert _state(site.db) == {100: '', 101: '', 102: ''}
    assert c.get('/api/site-recovery/plans/p1').get_json()['failover_state'] == 'none'
    assert srw.replication_held_by(jobs[100]) is None


def test_the_rest_of_the_plan_fails_over_after_one_guest_and_the_first_is_not_started_again(api, site):
    c = _admin(api, site)
    assert c.post('/api/site-recovery/plans/p1/emergency', json={'vmids': ['101']}).status_code == 200
    _done(site.db, 'emergency')
    assert site.did.started == [101]
    # no body: the whole plan, which is the two still at the source
    r = c.post('/api/site-recovery/plans/p1/emergency')
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _done(site.db, 'emergency', n=2)
    assert site.did.started == [101, 100, 102]
    assert ev['details']['101'] == {'success': True, 'skipped': True, 'error': '', 'vm_name': 'db01',
                                    'reason': 'failed over already'}
    assert ev['status'] == 'completed'
    assert c.get('/api/site-recovery/plans/p1').get_json()['failover_state'] == 'all'
    # nothing left to fail over
    r = c.post('/api/site-recovery/plans/p1/emergency')
    assert r.status_code == 409 and 'failed over already' in r.get_json()['error']
    assert c.post('/api/site-recovery/plans/p1/failover').status_code == 409


def test_a_picked_guest_that_is_failed_over_already_is_refused(api, site):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'emergency' WHERE vmid = 100")
    r = _admin(api, site).post('/api/site-recovery/plans/p1/emergency', json={'vmids': [101, 100]})
    assert r.status_code == 409 and r.get_json()['error'] == 'Failed over already: 100'
    assert site.did.started == []
    assert site.db.query_one("SELECT status FROM site_recovery_plans WHERE id = 'p1'")['status'] == 'ready'


def test_failback_of_a_guest_that_is_not_failed_over_is_refused(api, site):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'planned' WHERE vmid = 100")
    c = _admin(api, site)
    r = c.post('/api/site-recovery/plans/p1/failback', json={'vmids': [100, 102]})
    assert r.status_code == 409 and r.get_json()['error'] == 'Not failed over: 102'
    site.db.execute("UPDATE site_recovery_vms SET failed_over = ''")
    r = c.post('/api/site-recovery/plans/p1/failback')
    assert r.status_code == 409 and r.get_json()['error'] == 'No guest of this plan is failed over'
    assert site.did.migrated == []


def test_failback_of_single_guests(api, site):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'planned' WHERE vmid IN (100, 101)")
    r = _admin(api, site).post('/api/site-recovery/plans/p1/failback', json={'vmids': [101]})
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _done(site.db, 'failback')
    assert site.did.migrated == [(TGT, 101)]
    assert sorted(ev['details']) == ['101']
    assert _state(site.db) == {100: 'planned', 101: '', 102: ''}
    assert any('(guests 101)' in d for d in _audit(site.db, 'site_recovery.failback'))


def test_a_failed_guest_keeps_its_place(api, site, monkeypatch):
    monkeypatch.setattr(srw, '_start_replicated_vm',
                        lambda mgr, vmid, vtype='qemu': (vmid != 101, '' if vmid != 101 else 'no replica'))
    assert _admin(api, site).post('/api/site-recovery/plans/p1/emergency',
                                  json={'vmids': [100, 101]}).status_code == 200
    ev = _done(site.db, 'emergency')
    assert ev['status'] == 'failed'
    assert _state(site.db) == {100: 'emergency', 101: '', 102: ''}


def test_failback_after_an_emergency_says_the_old_source_copy_is_in_the_way(api, site, monkeypatch):
    """An emergency failover leaves the source guest; it is not dropped on its own."""
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'emergency' WHERE vmid = 100")
    monkeypatch.setattr(srw, '_target_vmid_exists', lambda mgr, vmid: mgr.cluster_id == SRC)
    assert _admin(api, site).post('/api/site-recovery/plans/p1/failback').status_code == 200
    ev = _done(site.db, 'failback')
    err = ev['details']['100']['error']
    assert 'still exists on' in err and 'emergency failover' in err and 'then fail this guest back' in err
    assert site.did.migrated == []
    assert _state(site.db)[100] == 'emergency'


def test_a_planned_failover_passes_over_the_guests_failed_over(api, site):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'emergency' WHERE vmid = 100")
    r = _admin(api, site).post('/api/site-recovery/plans/p1/failover')
    assert r.status_code == 200, r.get_data(as_text=True)
    ev = _done(site.db, 'planned')
    assert site.did.migrated == [(SRC, 101), (SRC, 102)]
    assert ev['details']['100']['skipped'] is True
    assert _state(site.db) == {100: 'emergency', 101: 'planned', 102: 'planned'}


def test_readiness_says_which_guests_are_failed_over(api, site):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'emergency' WHERE vmid = 100")
    issues = _admin(api, site).post('/api/site-recovery/plans/p1/readiness').get_json()['issues']
    msgs = [i['msg'] for i in issues]
    assert 'VM 100: failed over (emergency), replication waits for its failback' in msgs
    assert not any(m.startswith('VM 100: no replication') for m in msgs)
    assert 'VM 101: no replication job linked' in msgs


# --- the body ------------------------------------------------------------------------------

@pytest.mark.parametrize('body', [
    {'vmids': []}, {'vmids': 100}, {'vmids': '100'}, {'vmids': ['abc']}, {'vmids': [True]},
    {'vmids': [100.5]}, {'vmids': [-100]}, {'vmids': [0]}, {'vmids': ['１００']}, {'vmids': [None]},
    {'vmids': [{'vmid': 100}]}, {'vmids': [10 ** 12]}, [100], 'x',
])
@pytest.mark.parametrize('route', ['emergency', 'failback'])
def test_a_malformed_pick_is_a_400_and_starts_nothing(api, site, body, route):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'planned' WHERE vmid = 100")
    r = _admin(api, site).post(f'/api/site-recovery/plans/p1/{route}', json=body)
    assert r.status_code == 400, (body, r.get_data(as_text=True))
    assert site.db.query_one("SELECT status FROM site_recovery_plans WHERE id = 'p1'")['status'] == 'ready'
    assert site.db.query_one('SELECT COUNT(*) AS n FROM site_recovery_events')['n'] == 0


@pytest.mark.parametrize('route', ['emergency', 'failback'])
def test_a_body_that_is_not_json_is_refused_not_read_as_every_guest(api, site, route):
    c = _admin(api, site)
    for raw, ctype in (('{"vmids": [100', 'application/json'), ('vmids=100', 'application/x-www-form-urlencoded')):
        r = c.post(f'/api/site-recovery/plans/p1/{route}', data=raw, headers={'Content-Type': ctype})
        assert r.status_code == 400, r.get_data(as_text=True)
    assert site.did.started == [] and site.did.migrated == []


def test_a_guest_of_another_plan_is_not_picked(api, site):
    _plan(site.db, 'p2', guests=((200, 'other'),))
    r = _admin(api, site).post('/api/site-recovery/plans/p1/emergency', json={'vmids': [100, 200]})
    assert r.status_code == 400 and r.get_json()['error'] == 'Not a guest of this plan: 200'
    assert site.did.started == []


def test_a_pick_listed_twice_runs_once(api, site):
    r = _admin(api, site).post('/api/site-recovery/plans/p1/emergency', json={'vmids': [102, '102', 102]})
    assert r.status_code == 200 and r.get_json()['vmids'] == [102]
    _done(site.db, 'emergency')
    assert site.did.started == [102]


def test_the_worker_holds_to_the_pick_and_to_the_approval(db, site):
    """A guest picked but never approved is not touched, nor one approved but not picked."""
    srw.execute_failover('p1', 'emergency', [100, 101], [101, 102])
    assert site.did.started == [101]
    assert _state(db) == {100: '', 101: 'emergency', 102: ''}


# --- who may ---------------------------------------------------------------------------------

def _pool_membership(cluster_id, mapping):
    data = {f"{vmid}:qemu": pool for vmid, pool in mapping.items()}
    with rbac._pool_cache_lock:
        rbac._pool_membership_cache[cluster_id] = {'data': data, 'timestamp': time.time(), 'refreshing': False}


@pytest.mark.parametrize('route', ['emergency', 'failback'])
def test_who_may_fail_over_single_guests(api, site, route):
    site.db.execute("UPDATE site_recovery_vms SET failed_over = 'planned' WHERE vmid = 100")
    body = {'vmids': [100]}
    viewer = site.user('viewer1', role='viewer', tenant_id='tenant_a')
    capped = site.user('tadmin', role='admin', tenant_id='tenant_b',
                       tenant_permissions={'tenant_b': {'role': 'viewer'}})
    bob = site.user('bob', role='user', tenant_id='tenant_b', permissions=['site_recovery.failover'])
    mallory = site.user('mallory', role='viewer', tenant_id='tenant_a', permissions=['site_recovery.failover'])
    site.pool(SRC, 'pool_1', 'mallory', ['pool.view', 'vm.view', 'vm.start'])
    _pool_membership(SRC, {100: 'pool_1'})
    _pool_membership(TGT, {})
    for user in (viewer, capped, bob, mallory):
        r = api.as_user(user).post(f'/api/site-recovery/plans/p1/{route}', json=body)
        assert r.status_code == 403, (user['username'], r.status_code, r.get_data(as_text=True))
        # the gates come before the body: a stranger learns nothing from a bad one
        r = api.as_user(user).post(f'/api/site-recovery/plans/p1/{route}', json={'vmids': [999]})
        assert r.status_code == 403, (user['username'], r.get_data(as_text=True))
    assert site.did.started == [] and site.did.migrated == []
    assert _state(site.db) == {100: 'planned', 101: '', 102: ''}
    # positive control: the admin
    r = _admin(api, site).post(f'/api/site-recovery/plans/p1/{route}',
                               json={'vmids': [101] if route == 'emergency' else [100]})
    assert r.status_code == 200, r.get_data(as_text=True)
    _done(site.db, route)


@pytest.mark.parametrize('route', ['emergency', 'failback'])
def test_a_standby_fails_over_and_back_nothing(ha_env, seed, monkeypatch, route):  # noqa: F811
    api = ha_env.api
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    _plan(seed.db, moved=(100,))
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    spawned = []
    monkeypatch.setattr(srapi, '_safe_spawn_failover', lambda *a: spawned.append(a))
    c = api.as_user(seed.user('root', role='admin'))
    _standby_of_active(ha_env)
    r = c.post(f'/api/site-recovery/plans/p1/{route}', json={'vmids': [101] if route == 'emergency' else [100]})
    assert r.status_code == 409 and r.get_json()['code'] == 'HA_STANDBY', r.get_data(as_text=True)
    assert spawned == []
    assert _state(seed.db) == {100: 'emergency', 101: '', 102: ''}


# --- replication of a failed-over guest ------------------------------------------------------

def _job(db, job_id, vmid, src=SRC, tgt=TGT, mode='full'):
    db.execute("INSERT INTO cross_cluster_replications (id, source_cluster, target_cluster, vmid, enabled, "
               "schedule, last_run, mode, created_at) VALUES (?, ?, ?, ?, 1, '0 */6 * * *', '', ?, '2026-10-01')",
               (job_id, src, tgt, vmid, mode))


class _Stop(Exception):
    pass


def _tick(monkeypatch):
    """One pass of the replication scheduler; returns the ids of the jobs it started."""
    started = []

    class _Thread:
        def __init__(self, target=None, args=(), daemon=None):
            self.job = args[1]

        def start(self):
            started.append(self.job['id'])
            xcr._release_job(self.job['id'])

    def nap(seconds):
        raise _Stop()
    monkeypatch.setattr(xcr, 'time', types.SimpleNamespace(sleep=nap, time=time.time))
    monkeypatch.setattr(xcr, 'threading', types.SimpleNamespace(Thread=_Thread))
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **kw: True)
    monkeypatch.setattr(xcr, '_xcrepl_running', False)
    with pytest.raises(_Stop):
        xcr._xcrepl_loop()
    return sorted(started)


def test_the_scheduler_holds_only_the_job_of_the_failed_over_guest(db, monkeypatch):
    _plan(db, moved=(100,), links={101: 'jlinked'})
    _job(db, 'j100', 100)
    _job(db, 'j101', 101)
    _job(db, 'j102', 102)
    # the same VMID between other clusters is another guest
    _job(db, 'j100-elsewhere', 100, tgt='cluster_9')
    # linked by id: held whatever its clusters say
    _job(db, 'jlinked', 101, tgt='cluster_8')
    assert _tick(monkeypatch) == ['j100-elsewhere', 'j101', 'j102', 'jlinked']

    db.execute("UPDATE site_recovery_vms SET failed_over = 'planned' WHERE vmid = 101")
    db.execute("UPDATE cross_cluster_replications SET last_run = ''")
    assert _tick(monkeypatch) == ['j100-elsewhere', 'j102']

    # failed back: both run again
    db.execute("UPDATE site_recovery_vms SET failed_over = ''")
    db.execute("UPDATE cross_cluster_replications SET last_run = ''")
    assert _tick(monkeypatch) == ['j100', 'j100-elsewhere', 'j101', 'j102', 'jlinked']


def test_a_replication_run_of_a_failed_over_guest_touches_nothing(db, monkeypatch):
    _plan(db, moved=(100,))
    ran = []
    monkeypatch.setattr(vms_api, '_execute_replication_incremental', lambda job: ran.append(job['id']) or True)
    for vmid in (100, 101):
        _job(db, f'j{vmid}', vmid, mode='incremental')
        job = dict(db.query_one('SELECT * FROM cross_cluster_replications WHERE id = ?', (f'j{vmid}',)))
        vms_api._execute_replication(job)
    assert ran == ['j101']
    held = db.query_one("SELECT last_run, last_status FROM cross_cluster_replications WHERE id = 'j100'")
    assert (held['last_run'], held['last_status']) == ('', '')


def test_running_the_job_of_a_failed_over_guest_by_hand_is_refused(api, seed, monkeypatch):
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    _plan(seed.db, moved=(100,))
    _job(seed.db, 'j100', 100)
    _job(seed.db, 'j101', 101)
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    monkeypatch.setattr(xcr, '_claim_job', lambda job_id: False)
    c = _admin(api, seed)
    r = c.post('/api/cross-cluster-replications/j100/run', json={})
    assert r.status_code == 409 and r.get_json()['code'] == 'SR_FAILED_OVER', r.get_data(as_text=True)
    # the other guest only meets the in-flight guard the test put in its way
    r = c.post('/api/cross-cluster-replications/j101/run', json={})
    assert r.status_code == 409 and 'code' not in r.get_json()


def test_deleting_the_plan_switches_off_what_it_held(api, seed):
    """Without the plan nothing holds the job of a failed-over guest, and its next run would
    replace the guest running on the target with the old source."""
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    _plan(seed.db, moved=(100, 101), links={101: 'jlinked'})
    _job(seed.db, 'j100', 100)
    _job(seed.db, 'jlinked', 101, tgt='cluster_8')
    _job(seed.db, 'j102', 102)
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    r = _admin(api, seed).delete('/api/site-recovery/plans/p1')
    assert r.status_code == 200 and r.get_json()['replications_disabled'] == 2, r.get_data(as_text=True)
    enabled = {row['id']: row['enabled'] for row in seed.db.query('SELECT id, enabled FROM cross_cluster_replications')}
    assert enabled == {'j100': 0, 'jlinked': 0, 'j102': 1}
    assert any('2 replication job(s) of failed-over guests disabled' in d
               for d in _audit(seed.db, 'site_recovery.plan_deleted'))


def test_taking_a_failed_over_guest_out_of_the_plan_switches_its_job_off(api, seed):
    seed.tenant('tenant_a', clusters=[SRC, TGT])
    _plan(seed.db, moved=(100,))
    _job(seed.db, 'j100', 100)
    _job(seed.db, 'j101', 101)
    api.set_manager(SRC, _mgr(SRC))
    api.set_manager(TGT, _mgr(TGT))
    c = _admin(api, seed)
    assert c.delete('/api/site-recovery/plans/p1/vms/p1-101').status_code == 200
    assert c.delete('/api/site-recovery/plans/p1/vms/p1-100').status_code == 200
    enabled = {row['id']: row['enabled'] for row in seed.db.query('SELECT id, enabled FROM cross_cluster_replications')}
    assert enabled == {'j100': 0, 'j101': 1}


# --- the heartbeat --------------------------------------------------------------------------

@pytest.fixture
def heartbeat(db, monkeypatch):
    import pegaprox.globals as ppglobals
    monkeypatch.setattr(srw, '_last_fail_times', {})
    monkeypatch.setattr(srw, '_cooldowns', {})
    monkeypatch.setitem(ppglobals.cluster_managers, SRC, _mgr(SRC, connected=False))
    monkeypatch.setitem(ppglobals.cluster_managers, TGT, _mgr(TGT))
    spawned = []
    monkeypatch.setattr(srapi, '_safe_spawn_failover', lambda func, plan_id, *a: spawned.append((plan_id,) + a))
    return spawned


def _beat(times=2):
    for _ in range(times):
        srw._heartbeat_check()


def test_the_heartbeat_weighs_only_the_guests_still_at_the_source(db, heartbeat):
    _plan(db, guests=((100, 'web01'), (101, 'db01')), moved=(100,), links={100: 'j100', 101: 'j101'},
          auto_failover=1, failover_timeout=0)
    _job(db, 'j100', 100)
    _job(db, 'j101', 101)
    # held since the failover, so its last word is whatever it was then
    db.execute("UPDATE cross_cluster_replications SET last_status = 'error' WHERE id = 'j100'")
    db.execute("UPDATE cross_cluster_replications SET last_status = 'ok' WHERE id = 'j101'")
    _beat()
    assert heartbeat == [('p1', 'emergency')]


def test_the_heartbeat_leaves_a_plan_with_every_guest_failed_over(db, heartbeat):
    _plan(db, guests=((100, 'web01'),), moved=(100,), links={100: 'j100'}, auto_failover=1, failover_timeout=0)
    _job(db, 'j100', 100)
    _beat(3)
    assert heartbeat == []
    assert db.query_one("SELECT status FROM site_recovery_plans WHERE id = 'p1'")['status'] == 'ready'


# --- a DR drill -------------------------------------------------------------------------------

def test_a_drill_does_not_read_a_held_replication_as_an_rpo_breach(db):
    from datetime import datetime
    import pegaprox.api.dr_drill as drill
    _plan(db, guests=((100, 'web01'), (101, 'db01')), moved=(100,), links={100: 'j100', 101: 'j101'})
    _job(db, 'j100', 100)
    _job(db, 'j101', 101)
    db.execute("UPDATE cross_cluster_replications SET last_status = 'error', last_run = '2026-09-01T00:00:00' "
               "WHERE id = 'j100'")
    db.execute("UPDATE cross_cluster_replications SET last_status = 'ok', last_run = ? WHERE id = 'j101'",
               (datetime.now().isoformat(),))
    db.execute("INSERT INTO dr_drills (id, plan_id, plan_name, started_at, status, started_by) "
               "VALUES ('d1', 'p1', 'Plan p1', ?, 'running', 'root')", (datetime.now().isoformat(),))
    drill._execute_drill('d1')
    row = db.query_one("SELECT status, detail FROM dr_drill_checks WHERE drill_id = 'd1' "
                       "AND name = 'freshness_per_vm'")
    assert row['status'] == 'warn', dict(row)
    assert 'vmid 100: failed over, replication waits for its failback' in row['detail']
    assert 'vmid 101: last sync 0 min ago' in row['detail']


# --- a database from before -------------------------------------------------------------------

def _event(db, event_id, kind, started, results, completed=True):
    db.execute("INSERT INTO site_recovery_events (id, plan_id, event_type, status, started_at, completed_at, "
               "details) VALUES (?, 'p1', ?, 'completed', ?, ?, ?)",
               (event_id, kind, started, started if completed else None, json.dumps(results)))


def test_the_state_is_replayed_from_the_failover_events(db):
    _plan(db, guests=((100, 'a'), (101, 'b'), (102, 'c'), (103, 'd')))
    ok = {'success': True, 'error': ''}
    _event(db, 'e1', 'emergency', '2026-10-01T10:00:00', {'100': ok, '101': ok, '102': {'success': False}})
    _event(db, 'e2', 'failback', '2026-10-02T10:00:00', {'100': ok, '101': {'success': False}})
    _event(db, 'e3', 'test', '2026-10-03T10:00:00', {'results': {'103': ok}})
    _event(db, 'e4', 'planned', '2026-10-04T10:00:00', {'preflight_issues': [], 'aborted': 'before any VM moved'})
    _event(db, 'e5', 'planned', '2026-10-05T10:00:00', {'103': ok})
    # still running when the process went: moved nobody yet
    _event(db, 'e6', 'emergency', '2026-10-06T10:00:00', {'102': ok}, completed=False)
    cur = db.conn.cursor()
    assert _replay_sr_failover_state(cur) == 2
    db.conn.commit()
    assert _state(db) == {100: '', 101: 'emergency', 102: '', 103: 'planned'}
    at = db.query_one("SELECT failed_over_at FROM site_recovery_vms WHERE vmid = 101")['failed_over_at']
    assert at == '2026-10-01T10:00:00'


def test_an_old_database_gets_the_columns_and_its_state_once(db):
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
    _event(db, 'e1', 'emergency', '2026-10-01T10:00:00', {'100': {'success': True}, '101': {'success': False}})
    c.commit()

    db._init_db()
    cols = {r[1] for r in c.execute('PRAGMA table_info(site_recovery_vms)').fetchall()}
    assert {'failed_over', 'failed_over_at'} <= cols
    assert _state(db) == {100: 'emergency', 101: ''}
    # a second start replays nothing: the failback the operator ran since stays
    c.execute("UPDATE site_recovery_vms SET failed_over = '' WHERE vmid = 100")
    c.commit()
    db._init_db()
    assert _state(db) == {100: '', 101: ''}
