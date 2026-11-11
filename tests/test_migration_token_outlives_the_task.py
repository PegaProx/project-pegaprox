"""The temporary token of a cross-cluster migration lives as long as the migration.

A remote migrate authenticates at the target with a token PegaProx creates there and
deletes afterwards. The source node presents it again when it opens the tunnels of the
migration, so a token deleted while the task runs ends the migration with

    tunnel: ... failed - server didn't upgrade: 401 Unauthorized

The thread that deletes it looked for the task in the last 100 tasks of the source
cluster. After five minutes (two for the cross-cluster balancer) a task missing from
that list counted as finished, when a guest with the source or target VMID existed on
the target - any guest, so two clusters that both have a VM 105 were enough. A list
read that failed came back empty and counted the same. And after two hours the token
went whatever the task was doing.

Now the status of the task itself is read, and only its end takes the token away. A
status nobody can read for two hours in a row gives up on the task, with a warning, and
so does a task that still reports running after a week.

Both places that start such a thread are driven here up to the thread, which then runs
in place on a clock of its own.
"""
import logging
import re
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

import pegaprox.api.vms as vms
import pegaprox.background.cross_cluster_lb as xclb
import pegaprox.background.site_recovery as sr
import pegaprox.globals as ppglobals
from pegaprox.core import transfer_net
from test_transfer_network import CID, TGT, _fresh_caches, _source, _target  # noqa: F401

# the task of a PegaProx that logs in with an API token, as Proxmox names it
UPID = 'UPID:pve1:0000ABCD:00000001:6700AAAA:qmigrate:105:root@pam!pegaprox:'
EVER = float('inf')
HOUR = 3600
SETTLE = 30


class _Horizon(BaseException):
    """The clock ran out: the thread was still waiting."""


class _Clock:
    def __init__(self):
        self.t, self.end = 0, 0

    def sleep(self, seconds):
        self.t += seconds
        if self.t > self.end:
            raise _Horizon()


def _threads(monkeypatch, module):
    """The threads `module` starts, kept instead of started."""
    kept = []
    fake = types.SimpleNamespace(**{k: getattr(threading, k) for k in dir(threading) if not k.startswith('__')})
    fake.Thread = lambda *a, **k: kept.append(k) or types.SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(module, 'threading', fake)
    return kept


def _token_in(endpoint):
    return re.search(r'root@pam!([^=]+)=', endpoint).group(1)


class _Migration:
    """A started migration: its source, its target, its token and the thread that follows it."""

    def __init__(self, src, tgt, job, token, monkeypatch, expire=None, again=None, kept=()):
        self.src, self.tgt, self.job, self.token, self.expire = src, tgt, job, token, expire
        self.again, self.kept = again, kept
        self.clock, self.deleted, self.delete_answer = _Clock(), [], {'success': True}
        self.script, self.waiting, self.result = [(EVER, 'running')], False, None
        src.cluster_type = 'proxmox'
        src.get_tasks = self._tasks
        src.get_task_status = self._status
        tgt.delete_api_token = self._delete
        # another guest of the same number lives on the target, as on two clusters that
        # each number their guests from 100
        tgt.get_vm_resources = lambda *a, **k: [{'vmid': 105, 'type': 'qemu', 'node': 'pve2'}]
        # the cleanup's own sleeps only: another thread of the process that sleeps meanwhile
        # neither moves this clock nor runs into its end
        monkeypatch.setattr(transfer_net, 'time', types.SimpleNamespace(**{**vars(time), 'sleep': self.clock.sleep}))

    def _state(self):
        for until, state in self.script:
            if self.clock.t < until:
                if state == 'raises':
                    raise ConnectionError('source cluster unreachable')
                return state

    def _tasks(self, limit=50, **kw):
        state = self._state()
        if state in ('unlisted', 'blind'):
            return []
        return [{'upid': UPID, 'status': state}]

    def _status(self, node, upid):
        state = self._state()
        if state == 'blind':
            return None
        if state in ('running', 'unlisted'):
            return {'status': 'running'}
        return {'status': 'stopped', 'exitstatus': state}

    def _delete(self, name):
        self.deleted.append((name, self.clock.t))
        return self.delete_answer

    def follow(self, script, hours=3):
        """Run the thread for `hours`: what the source says until when. When its own
        token was deleted, and `waiting` says whether the thread was still at it."""
        self.script, self.clock.end = script, hours * HOUR
        try:
            self.result = self.job['target'](*self.job.get('args', ()), **self.job.get('kwargs', {}))
        except _Horizon:
            self.waiting = True
        assert [name for name, _t in self.deleted] == [self.token] * len(self.deleted)
        return [t for _name, t in self.deleted]

    def keeps_its_token(self, script, hours=3):
        return self.follow(script, hours) == [] and self.waiting


@pytest.fixture
def by_hand(api, seed, monkeypatch):
    kept = _threads(monkeypatch, vms)
    src = api.set_manager(CID, _source())
    src.remote_migrate_vm.return_value = {'success': True, 'task': UPID}
    tgt = _target(api)
    created, create = [], tgt.create_api_token
    tgt.create_api_token = lambda name, **kw: created.append(kw) or create(name, **kw)
    admin = api.as_user(seed.user('root', role='admin'))

    def start(status=200):
        r = admin.post('/api/cross-cluster-migrate', json={
            'source_cluster': CID, 'target_cluster': TGT, 'vmid': 105, 'vm_type': 'qemu', 'source_node': 'pve1',
            'target_node': 'pve2', 'target_storage': 'local-lvm', 'delete_source': False})
        assert r.status_code == status, r.get_data(as_text=True)
        return _token_in(src.remote_migrate_vm.call_args[0][3])
    token = start()
    (job,) = kept
    assert job['daemon'] is True
    return _Migration(src, tgt, job, token, monkeypatch, expire=created[0].get('expire'), again=start,
                      kept=kept)


@pytest.fixture
def balancer(monkeypatch):
    kept = _threads(monkeypatch, xclb)
    hi, lo = MagicMock(), MagicMock()
    hi.logger = logging.getLogger('test.migration_token.source')
    hi.find_migration_candidate.return_value = {'vmid': 105, 'name': 'db', 'type': 'qemu'}
    hi.remote_migrate_vm.return_value = {'success': True, 'task': UPID}
    lo.create_api_token.side_effect = lambda name, **kw: {'success': True, 'token_id': 'root@pam!' + name,
                                                    'token_value': 'secret'}
    lo.get_cluster_fingerprint.return_value = {'success': True, 'host': '10.0.0.11', 'fingerprint': 'AB:CD'}

    class _DB:
        def query(self, *a, **kw):
            return [{'id': 'hi'}, {'id': 'lo'}]

        def execute(self, *a, **kw):
            pass
    monkeypatch.setattr(xclb, 'cluster_managers', {'hi': hi, 'lo': lo})
    monkeypatch.setattr(xclb, 'compute_cluster_score', lambda m: 90.0 if m is hi else 10.0)
    monkeypatch.setattr(xclb, '_pick_node', lambda m, highest: 'hi1' if m is hi else 'lo1')
    monkeypatch.setattr(xclb, 'get_db', lambda: _DB())
    monkeypatch.setattr(xclb, 'log_audit', lambda *a, **kw: None)
    monkeypatch.setattr(xclb.transfer_net, 'migration_route', lambda mgr, node=None: None)

    def start(status=None):
        """status: what the route answers by hand; the balancer answers nobody"""
        xclb.run_cross_cluster_balance_check({
            'id': 'g1', 'name': 'group', 'cross_cluster_threshold': 5, 'cross_cluster_dry_run': 0,
            'cross_cluster_include_containers': 0})
        return _token_in(hi.remote_migrate_vm.call_args[1]['target_endpoint'])
    token = start()
    (job,) = kept
    assert job['daemon'] is True
    return _Migration(hi, lo, job, token, monkeypatch,
                      expire=lo.create_api_token.call_args.kwargs.get('expire'), again=start, kept=kept)


@pytest.fixture(params=['by_hand', 'balancer'])
def migration(request):
    return request.getfixturevalue(request.param)


@pytest.fixture
def failover(monkeypatch):
    """A Site Recovery migration of VM 105. The run waits for its migration itself, so
    the run is what goes on the clock here, and its result is the failover's verdict."""
    src, tgt = MagicMock(), MagicMock()
    src.logger = logging.getLogger('test.migration_token.source')
    src.get_node_status.return_value = {'pve1': {}}
    src.get_vms.return_value = [{'vmid': 105}]
    src.remote_migrate_vm.return_value = {'success': True, 'task': UPID}
    tgt.host = '10.0.0.11'
    tgt.create_api_token.side_effect = lambda name, **kw: {'success': True, 'token_id': 'root@pam!' + name,
                                                           'token_value': 'secret'}
    tgt.get_cluster_fingerprint.return_value = {'success': True, 'fingerprint': 'AB:CD'}
    monkeypatch.setattr(sr.transfer_net, 'migration_route', lambda mgr, node=None: None)
    monkeypatch.setattr(sr, 'uuid', types.SimpleNamespace(uuid4=lambda: types.SimpleNamespace(hex='5a5a5a5a0000')))
    job = {'target': sr._migrate_vm_cross_cluster, 'args': (src, tgt, 105, 'qemu', {}, {})}
    migration = _Migration(src, tgt, job, 'pegaprox-sr-5a5a5a5a', monkeypatch)
    # what the run leaves to the background runs in place, and every wait of it, wherever
    # it sleeps, goes by the same clock
    import gevent
    monkeypatch.setattr(gevent, 'spawn', lambda fn, *a, **kw: fn(*a, **kw))
    for module in (sr, vms):
        monkeypatch.setattr(module, 'time', types.SimpleNamespace(**{**vars(time), 'sleep': migration.clock.sleep}))
    return migration


class _R:
    def __init__(self, status, data=None):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class _Side:
    """One cluster of a full replication run of VM 100 through its clone 9100."""

    def __init__(self, node, guests):
        self.host, self.api_port, self.is_connected = f'{node}.example', 8006, True
        self.node, self.guests = node, guests
        self.logger = logging.getLogger('test.migration_token.' + node)
        self.create_api_token = MagicMock(side_effect=lambda name, **kw: {
            'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'})

    def _api_get(self, url, params=None, **kw):
        path = url.split('/api2/json', 1)[1]
        if path == '/cluster/resources':
            return _R(200, [{'vmid': v, 'node': self.node, 'type': 'qemu', 'status': 'running'} for v in self.guests])
        if path == '/cluster/nextid':
            return _R(200, '9100')
        if path == '/storage':
            return _R(200, [{'storage': 'fast', 'type': 'lvmthin'}])
        if path.endswith('/config'):
            return _R(200, {'scsi0': 'fast:vm-9100-disk-0,size=8G'})
        return _R(404)

    def _api_post(self, url, data=None, **kw):
        return _R(200, 'UPID:post')

    def _get_vm_storage(self, node, vmid, vm_type):
        return 'fast'

    def get_cluster_fingerprint(self):
        return {'success': True, 'host': self.host, 'fingerprint': 'AB:CD'}

    def remote_migrate_vm(self, **kw):
        return {'success': True, 'task': UPID}


@pytest.fixture
def replication(db, monkeypatch):
    """A full cross-cluster replication run of VM 100. The run waits for the migration of
    its clone itself, so the run goes on the clock, and what it records is its verdict."""
    said, wait = [], vms._wait_for_task
    # the snapshot and the clone are done at once, a wait for the migration is a real one
    monkeypatch.setattr(vms, '_wait_for_task',
                        lambda mgr, upid, **kw: wait(mgr, upid, **kw) if upid == UPID else (True, 'OK'))
    for name in ('_capture_vm_identity', '_restore_vm_identity', '_cleanup_snapshot', '_enforce_retention',
                 '_cleanup_clone_and_snap'):
        monkeypatch.setattr(vms, name, lambda *a, **kw: None)
    monkeypatch.setattr(vms, '_tag_as_replica', lambda *a, **kw: (True, ''))
    monkeypatch.setattr(vms, '_update_repl_status', lambda _db, job_id, status, error='': said.append((status, error)))
    monkeypatch.setattr(transfer_net, 'migration_route', lambda mgr, node=None: None)
    src, tgt = _Side('s1', [100]), _Side('t1', [])
    monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
    monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
    job = {'target': vms._execute_replication,
           'args': ({'id': 'j1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src', 'target_cluster': 'tgt',
                     'target_storage': 'far', 'target_node': 't1', 'mode': 'full'},)}
    # the token is named by the second the run started: xcrepl-j1-0
    migration = _Migration(src, tgt, job, 'xcrepl-j1-0', monkeypatch)
    monkeypatch.setattr(vms, 'time', types.SimpleNamespace(**{**vars(time), 'sleep': migration.clock.sleep,
                                                               'time': lambda: 1794400000.0}))
    migration.said = said
    return migration


def _warned(caplog, about):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING and about in r.getMessage()]


def test_a_running_task_missing_from_the_task_list_keeps_its_token(migration):
    """What ended three migrations of one guest after 315, 319 and 661 seconds."""
    assert migration.keeps_its_token([(EVER, 'unlisted')])


@pytest.mark.parametrize('silence', ['blind', 'raises'])
def test_a_source_that_stops_answering_for_a_while_keeps_the_token(migration, silence):
    assert migration.keeps_its_token([(600, 'running'), (1500, silence), (EVER, 'running')])


def test_a_migration_of_more_than_two_hours_keeps_its_token(migration):
    """Two terabytes over a slow link take a day or more."""
    assert migration.keeps_its_token([(EVER, 'running')], hours=6 * 24)


@pytest.mark.parametrize('exit_status', ['OK', 'WARNINGS: 1', 'migration aborted'])
def test_the_token_goes_once_the_task_has_ended(migration, exit_status):
    """And not at once: the source node may still be closing its tunnels."""
    end = 3 * HOUR
    assert migration.follow([(end, 'running'), (EVER, exit_status)], hours=4) == [end + SETTLE]
    assert not migration.waiting


@pytest.mark.parametrize('exit_status, warns', [('OK', False), ('WARNINGS: 1', True), ('migration aborted', True)])
def test_a_migration_that_did_not_end_clean_is_a_warning(migration, caplog, exit_status, warns):
    """The route answered long ago: this line is where the operator learns how it ended."""
    caplog.set_level(logging.INFO)
    migration.follow([(600, 'running'), (EVER, exit_status)], hours=1)
    said = [r.getMessage() for r in caplog.records if 'ended' in r.getMessage()]
    assert len(said) == 1 and exit_status in said[0], said
    assert bool(_warned(caplog, 'ended')) is warns


def test_a_task_nobody_can_read_for_two_hours_loses_its_token(migration, caplog):
    caplog.set_level(logging.INFO)
    assert migration.follow([(EVER, 'blind')]) == [2 * HOUR]
    assert _warned(caplog, migration.token)


def test_the_two_hours_count_in_a_row(migration):
    """One answer in between and the count starts again."""
    script = [(HOUR, 'blind'), (HOUR + 100, 'running'), (HOUR + 100 + 5400, 'blind'), (EVER, 'running')]
    assert migration.keeps_its_token(script, hours=6)


def test_a_task_still_running_after_a_week_is_stuck_and_loses_its_token(migration, caplog):
    caplog.set_level(logging.INFO)
    assert migration.follow([(EVER, 'running')], hours=8 * 24) == [7 * 24 * HOUR]
    assert _warned(caplog, migration.token)


@pytest.mark.parametrize('upid', [None, '', 'not a task id'])
def test_a_migration_without_a_task_id_keeps_its_token_two_hours(monkeypatch, caplog, upid):
    """Nothing to read the end from: the token stays for the two hours of a task nobody
    can read, where it used to go after five minutes."""
    caplog.set_level(logging.INFO)
    src, tgt = MagicMock(), MagicMock()
    src.logger = logging.getLogger('test.migration_token.source')
    job = {'target': transfer_net.drop_token_when_done, 'args': (tgt, src, 'pegaprox-migrate-1', upid, 'qemu/105')}
    migration = _Migration(src, tgt, job, 'pegaprox-migrate-1', monkeypatch)
    assert migration.follow([(EVER, 'running')]) == [2 * HOUR]
    assert _warned(caplog, migration.token)


@pytest.mark.parametrize('answer', [{'success': False, 'error': 'no lease'}, ConnectionError('no lease')])
def test_a_token_that_could_not_be_deleted_is_not_reported_as_deleted(migration, caplog, answer):
    caplog.set_level(logging.INFO)
    if isinstance(answer, Exception):
        def refuse(name):
            migration.deleted.append((name, migration.clock.t))
            raise answer
        migration.tgt.delete_api_token = refuse
    else:
        migration.delete_answer = answer
    # tried three times, minutes apart
    tried = migration.follow([(EVER, 'OK')])
    assert len(tried) == 3 and tried[0] == SETTLE and tried[2] - tried[1] == tried[1] - tried[0] >= 60, tried
    said = [r.getMessage() for r in caplog.records if migration.token in r.getMessage()]
    assert [m for m in _warned(caplog, migration.token) if 'no lease' in m], said
    assert not [m for m in said if 'eleted migration token' in m], said


def test_pve_refuses_the_token_by_itself_a_day_after_the_longest_wait(migration):
    """A restart or a lost lease during the migration leaves the token on the target, with
    the rights of its user: Proxmox ends it then, nobody has to find it."""
    longest = transfer_net.TOKEN_MAX_SECONDS + 86400
    expire = migration.expire or 0
    assert time.time() + longest - 60 <= expire <= time.time() + longest



def test_two_migrations_in_the_same_second_get_a_token_each(migration, monkeypatch):
    """create_api_token replaces a token of the same name. The name was the second of the
    start by hand and group plus VMID in the balancer, which picks a guest that is still
    moving again on its next cycle: the second migration revoked the token the first one
    was copying with, and the first one's cleanup deleted the second one's."""
    now = time.time()
    monkeypatch.setattr(time, 'time', lambda: now)
    # the other guest 105 on the target is there for the cleanup; the preflight would refuse the VMID
    migration.tgt.get_vm_resources = lambda *a, **k: []
    first, second = migration.again(), migration.again()
    assert first != second
    assert all(name.startswith(('pegaprox-migrate-', 'xclb-g1-105-')) for name in (first, second))


def test_a_started_migration_keeps_its_token_when_a_later_step_fails(migration, monkeypatch):
    """Once remote_migrate_vm has started the task, the audit line, the task user and the
    live update still ran in the try whose except deleted the token: the migration copied
    on without its access to the target."""
    def unavailable(*a, **kw):
        raise RuntimeError('audit log unavailable')
    monkeypatch.setattr(vms, 'log_audit', unavailable)
    monkeypatch.setattr(xclb, 'log_audit', unavailable)
    migration.tgt.get_vm_resources = lambda *a, **k: []
    token = migration.again(status=500)
    assert migration.deleted == []
    assert [job['args'][2] for job in migration.kept] == [migration.token, token]


def test_a_delete_the_target_did_not_take_is_tried_again(migration, caplog):
    """A single refused delete, a short outage of the target or the lease between two
    leaders, left the token there for good."""
    caplog.set_level(logging.INFO)
    answers = [{'success': False, 'error': 'no lease'}, {'success': True}]

    def flaky(name):
        migration.deleted.append((name, migration.clock.t))
        return answers.pop(0)
    migration.tgt.delete_api_token = flaky
    tried = migration.follow([(EVER, 'OK')])
    assert len(tried) == 2 and tried[0] == SETTLE < tried[1], tried
    assert not _warned(caplog, migration.token)
    assert [r for r in caplog.records if 'Deleted migration token ' + migration.token in r.getMessage()]


# --- Site Recovery: the run follows its migration ----------------------------------------

def test_a_failover_of_hours_keeps_its_token_and_moves_the_guest(failover):
    """The token went an hour after the start, and the run gave up on the task at the same
    hour: a guest that copied on was reported failed, and its failover mark taken back."""
    end = 3 * HOUR
    assert failover.follow([(end, 'running'), (EVER, 'OK')], hours=4) == [end + SETTLE]
    assert failover.result == (True, '')
    assert failover.tgt.create_api_token.call_args.kwargs['expire'] > time.time() + 7 * 24 * HOUR


@pytest.mark.parametrize('exit_status', ['migration aborted', "VM 105 already exists on node 'pve2'"])
def test_a_failover_says_how_its_task_ended_and_its_token_goes_then(failover, exit_status):
    """A short one left its token on the target for the rest of the hour."""
    assert failover.follow([(600, 'running'), (EVER, exit_status)], hours=2) == [600 + SETTLE]
    ok, err = failover.result
    assert not ok and err.startswith(f'Migration task aborted on PVE: {exit_status}'), err


def test_a_failover_that_did_not_start_drops_its_token_at_once(failover):
    failover.src.remote_migrate_vm.return_value = {'success': False, 'error': 'VM is locked (backup)'}
    assert failover.follow([(EVER, 'running')]) == [0]
    assert failover.result == (False, 'VM is locked (backup)')


def test_a_failover_whose_task_cannot_be_read_gives_up_on_it(failover):
    assert failover.follow([(EVER, 'blind')]) == [2 * HOUR]
    ok, err = failover.result
    assert not ok and 'could not be read' in err, err


def test_a_failover_without_a_task_id_leaves_the_token_to_the_cleanup(failover):
    """Nothing to follow: the token stays the two hours of a task nobody can read."""
    failover.src.remote_migrate_vm.return_value = {'success': True, 'task': None}
    assert failover.follow([(EVER, 'running')]) == [2 * HOUR]
    assert failover.result == (True, '')


# --- cross-cluster replication: the run follows the migration of its clone ------------------

def test_a_first_full_copy_of_hours_keeps_its_token_and_the_replica_is_kept(replication):
    """The run gave up on the migration after an hour, marked the job failed and deleted
    the token in its finally, under the copy still running."""
    end = 3 * HOUR
    assert replication.follow([(end, 'running'), (EVER, 'OK')], hours=4) == [end + SETTLE]
    assert replication.said == [('ok', '')]
    assert replication.tgt.create_api_token.call_args.kwargs['expire'] > time.time() + 7 * 24 * HOUR


def test_a_replication_run_says_how_its_migration_ended_and_its_token_goes_then(replication):
    assert replication.follow([(600, 'running'), (EVER, 'migration aborted')], hours=1) == [600 + SETTLE]
    assert replication.said == [('error', 'Migration task failed: migration aborted')]

@pytest.mark.parametrize('expire, sent', [(None, 0), (1893456000, 1893456000)])
def test_the_token_is_created_with_the_expire_it_is_given(expire, sent):
    from pegaprox.core.manager import PegaProxManager
    posted = []
    answer = types.SimpleNamespace(status_code=200, text='',
                                   json=lambda: {'data': {'value': 'v', 'full-tokenid': 'root@pam!t'}})
    mgr = types.SimpleNamespace(is_connected=True, host='10.0.0.11', api_port=8006,
                                config=types.SimpleNamespace(user='root@pam'),
                                logger=logging.getLogger('test.migration_token.target'),
                                _api_post=lambda url, data=None, **kw: posted.append((url, data)) or answer)
    kw = {} if expire is None else {'expire': expire}
    assert PegaProxManager.create_api_token(mgr, 't', **kw)['success']
    [(url, data)] = posted
    assert url.endswith('/access/users/root@pam/token/t')
    assert data['expire'] == sent and data['privsep'] == 0
