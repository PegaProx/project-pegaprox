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

    def __init__(self, src, tgt, job, token, monkeypatch, expire=None):
        self.src, self.tgt, self.job, self.token, self.expire = src, tgt, job, token, expire
        self.clock, self.deleted, self.delete_answer = _Clock(), [], {'success': True}
        self.script, self.waiting = [(EVER, 'running')], False
        src.cluster_type = 'proxmox'
        src.get_tasks = self._tasks
        src.get_task_status = self._status
        tgt.delete_api_token = self._delete
        # another guest of the same number lives on the target, as on two clusters that
        # each number their guests from 100
        tgt.get_vm_resources = lambda *a, **k: [{'vmid': 105, 'type': 'qemu', 'node': 'pve2'}]
        monkeypatch.setattr(time, 'sleep', self.clock.sleep)

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
            self.job['target'](*self.job.get('args', ()), **self.job.get('kwargs', {}))
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
    r = admin.post('/api/cross-cluster-migrate', json={
        'source_cluster': CID, 'target_cluster': TGT, 'vmid': 105, 'vm_type': 'qemu', 'source_node': 'pve1',
        'target_node': 'pve2', 'target_storage': 'local-lvm', 'delete_source': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    (job,) = kept
    assert job['daemon'] is True
    return _Migration(src, tgt, job, _token_in(src.remote_migrate_vm.call_args[0][3]), monkeypatch,
                      expire=created[0].get('expire'))


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
    xclb.run_cross_cluster_balance_check({
        'id': 'g1', 'name': 'group', 'cross_cluster_threshold': 5, 'cross_cluster_dry_run': 0,
        'cross_cluster_include_containers': 0})
    (job,) = kept
    assert job['daemon'] is True
    return _Migration(hi, lo, job, _token_in(hi.remote_migrate_vm.call_args[1]['target_endpoint']), monkeypatch,
                      expire=lo.create_api_token.call_args.kwargs.get('expire'))


@pytest.fixture(params=['by_hand', 'balancer'])
def migration(request):
    return request.getfixturevalue(request.param)


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
    assert migration.follow([(EVER, 'OK')]) == [SETTLE]
    said = [r.getMessage() for r in caplog.records if migration.token in r.getMessage()]
    assert [m for m in _warned(caplog, migration.token) if 'no lease' in m], said
    assert not [m for m in said if 'eleted migration token' in m], said


def test_pve_refuses_the_token_by_itself_a_day_after_the_longest_wait(migration):
    """A restart or a lost lease during the migration leaves the token on the target, with
    the rights of its user: Proxmox ends it then, nobody has to find it."""
    longest = transfer_net.TOKEN_MAX_SECONDS + 86400
    expire = migration.expire or 0
    assert time.time() + longest - 60 <= expire <= time.time() + longest


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
