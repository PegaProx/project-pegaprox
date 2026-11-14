"""A remote migration whose POST is answered late.

Proxmox answers the remote_migrate POST only once the source node has checked the target
cluster (its version, its guests, its storages) and forked the task. Over a slow link
between the clusters that took longer than the general 10 s read timeout: the migration
that would have started was given up on with the raw urllib3 message, which names the host
PegaProx talks to and points at the wrong side, and the caller deleted its token on the
target while the node could still start the task with it.

Now the POST waits REMOTE_MIGRATE_TIMEOUT for its answer. One that does not come in time,
or pveproxy's own 596 'Connection timed out', is followed by a look at the node's task
list: a migration task of the guest that the node started after the POST, by the node's
own clock, is the answer, and the caller follows it as any started migration. Without one
the error says what did not answer, and only then does the token go.

The manager method runs for real here, its API calls answered by a fake source node. The
migration by hand, the replication run and the Site Recovery migration are driven up to it.
"""
import logging
import threading
import time
import types
from unittest.mock import MagicMock

import pytest
import requests

import pegaprox.api.vms as vms
import pegaprox.background.site_recovery as sr
import pegaprox.core.manager as manager_mod
import pegaprox.globals as ppglobals
from pegaprox.core import transfer_net
from pegaprox.core.manager import PegaProxManager
from test_transfer_network import CID, TGT, _fresh_caches, _source, _target  # noqa: F401

WALL = 1794400000
VMID = 105
ENDPOINT = 'apitoken=PVEAPIToken=root@pam!pegaprox-migrate-1=s3cret,host=10.0.0.11,fingerprint=AB:CD'
SAID = ("the source node pve1 did not answer the remote migration request within {s} s; check that the "
        "source nodes reach the target cluster's API at {host}")


class _Clock:
    """sleep, time and monotonic of the manager, one clock for all three"""

    def __init__(self):
        self.t = 0.0

    def sleep(self, seconds):
        self.t += seconds

    def time(self):
        return WALL + self.t

    def monotonic(self):
        return self.t


class _R:
    def __init__(self, status=200, data=None, reason='', text=''):
        self.status_code, self._data, self.reason, self.text = status, data, reason, text
        self.headers = {}

    def json(self):
        return {'data': self._data}


class _Node:
    """The source node pve1 behind the API PegaProx talks to: the remote_migrate POST, the
    node's clock (skew seconds off PegaProx's) and its migration tasks, each listed from the
    moment the node starts it."""

    def __init__(self, clock, answer='timeout', skew=0):
        self.clock, self.answer, self.skew = clock, answer, skew
        self.posts, self.reads = [], []
        self.tasks = []
        self.listable = True

    def now(self):
        return int(WALL + self.skew + self.clock.t)

    def task(self, at, vmid=VMID, kind='qmigrate', started=None, ended=False):
        """a migration task the node lists from clock time `at` on, started then (or at
        `started`, by the node's clock)"""
        start = int(WALL + self.skew + at) if started is None else started
        upid = f'UPID:pve1:0000{len(self.tasks):04X}:00000001:{start:08X}:{kind}:{vmid}:root@pam!pegaprox:'
        entry = {'upid': upid, 'node': 'pve1', 'type': kind, 'id': str(vmid), 'starttime': start,
                 'user': 'root@pam!pegaprox'}
        if ended:
            entry.update(endtime=start + 4, status='OK')
        self.tasks.append((at, entry))
        return upid

    def post(self, url, data=None, timeout=None, **kw):
        self.posts.append({'url': url, 'data': data, 'timeout': timeout})
        if self.answer == 'timeout':
            read = timeout[1] if isinstance(timeout, tuple) else (timeout or 10)
            self.clock.t += read
            raise requests.exceptions.ReadTimeout(
                f"_GuardedHTTPSPool(host='10.0.0.1', port=8006): Read timed out. (read timeout={read})")
        if self.answer == 'connect':
            raise requests.exceptions.ConnectTimeout("_GuardedHTTPSPool(host='10.0.0.1', port=8006): "
                                                     "Max retries exceeded (connect timeout=10)")
        if self.answer == 596:
            # pveproxy's own wait for the node ran out
            self.clock.t += 30
            return _R(596, None, reason='Connection timed out')
        status, text = self.answer
        if status == 200:
            return _R(200, text)
        return _R(status, None, text=text)

    def get(self, url, params=None, **kw):
        path = url.split('/api2/json', 1)[1]
        self.reads.append((path, self.clock.t))
        if path == '/nodes/pve1/time':
            return _R(200, {'time': self.now(), 'localtime': self.now()})
        if path == '/nodes/pve1/tasks':
            if not self.listable:
                return _R(500, None)
            return _R(200, [entry for at, entry in self.tasks if self.clock.t >= at])
        return _R(404)

    def task_reads(self):
        return [t for p, t in self.reads if p == '/nodes/pve1/tasks']


def _manager(node):
    """A PegaProxManager without its constructor that talks to node."""
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host='10.0.0.1', api_port=8006, user='root@pam')
    m.current_host = None
    m.is_connected = True
    m.api_timeout = 10
    m._consecutive_failures = 0
    m.logger = logging.getLogger('test.remote_migrate.source')
    session = types.SimpleNamespace(get=node.get, post=node.post)
    m._create_session = lambda: session
    return m


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(manager_mod, 'time', types.SimpleNamespace(
        **{**vars(time), 'sleep': c.sleep, 'time': c.time, 'monotonic': c.monotonic}))
    return c


@pytest.fixture
def node(clock):
    return _Node(clock)


def _migrate(node, vmid=VMID, vm_type='qemu'):
    return _manager(node).remote_migrate_vm('pve1', vmid, vm_type, ENDPOINT, 'local-lvm:far', 'vmbr0', vmid,
                                            True, True)


# --- the POST ------------------------------------------------------------------------------

def test_the_post_waits_longer_than_the_general_timeout(node):
    node.answer = (200, 'UPID:pve1:00000001:00000001:6AF5E100:qmigrate:105:root@pam!pegaprox:')
    assert _migrate(node)['success']
    (post,), timeout = node.posts, node.posts[0]['timeout']
    read = timeout[1] if isinstance(timeout, tuple) else timeout
    assert read and read >= 60, timeout
    # a host that does not take the connection is still given up on after the usual time
    assert isinstance(timeout, tuple) and timeout[0] == 10, timeout
    assert post['url'].endswith('/nodes/pve1/qemu/105/remote_migrate')


def test_an_answer_in_time_reads_no_task_list(node):
    node.answer = (200, 'UPID:pve1:00000001:00000001:6AF5E100:qmigrate:105:root@pam!pegaprox:')
    _migrate(node)
    assert node.reads == []


# --- no answer in time: the node may have started it all the same -------------------------

def test_a_task_the_node_started_while_the_post_waited_is_the_answer(node):
    upid = node.task(at=3)
    assert _migrate(node) == {'success': True, 'task': upid}


def test_a_task_the_node_starts_a_little_after_the_timeout_is_found(node):
    """pvedaemon goes on with its checks when nobody waits for the answer any more."""
    upid = node.task(at=60 + 17)
    assert _migrate(node) == {'success': True, 'task': upid}
    assert node.clock.t < 60 + 30


def test_pveproxys_own_timeout_is_looked_after_too(node):
    node.answer = 596
    upid = node.task(at=40)
    assert _migrate(node) == {'success': True, 'task': upid}


def test_the_task_is_found_by_the_nodes_own_clock(node):
    """The node runs five minutes behind PegaProx: its task started after the POST by its
    clock, and before it by PegaProx's."""
    node.skew = -300
    upid = node.task(at=8)
    assert _migrate(node) == {'success': True, 'task': upid}


@pytest.mark.parametrize('skew', [0, 300])
def test_an_earlier_migration_of_the_guest_is_not_taken_for_this_one(node, skew):
    """Two minutes before the POST by the node's clock, which runs five minutes ahead of
    PegaProx's in the second case: no answer, whatever its end."""
    node.skew = skew
    node.task(at=0, started=int(WALL + skew - 120), ended=True)
    result = _migrate(node)
    assert result['success'] is False


@pytest.mark.parametrize('other', [{'vmid': 106}, {'kind': 'vzmigrate'}, {'kind': 'qmstart'}])
def test_a_task_of_another_guest_or_kind_is_not_the_answer(node, other):
    node.task(at=5, **other)
    assert _migrate(node)['success'] is False


# --- no answer and no task -----------------------------------------------------------------

def test_the_error_says_what_did_not_answer(node):
    result = _migrate(node)
    assert result == {'success': False, 'error': SAID.format(s=60, host='10.0.0.11')}
    assert 'Read timed out' not in result['error'] and "host='10.0.0.1'" not in result['error']
    # the token secret of the endpoint stays out of it
    assert 's3cret' not in result['error']


def test_the_node_is_asked_for_half_a_minute_and_not_longer(node):
    _migrate(node)
    reads = node.task_reads()
    assert len(reads) >= 3 and reads[0] == 60 and 60 + 25 <= reads[-1] <= 60 + 30, reads
    assert node.clock.t <= 60 + 30


def test_after_pveproxys_timeout_the_error_names_the_time_it_waited(node):
    node.answer = 596
    assert _migrate(node) == {'success': False, 'error': SAID.format(s=30, host='10.0.0.11')}


def test_a_task_list_that_cannot_be_read_is_not_taken_for_none(node):
    node.listable = False
    result = _migrate(node)
    assert result['success'] is False
    assert result['error'].startswith(SAID.format(s=60, host='10.0.0.11'))
    assert 'whether pve1 started the task could not be read' in result['error']


# --- what stays as it was ------------------------------------------------------------------

def test_a_refused_start_is_reported_as_proxmox_said_it(node):
    node.answer = (500, "VM 105 already exists on the target")
    assert _migrate(node) == {'success': False, 'error': 'VM 105 already exists on the target'}
    assert node.reads == []


def test_a_host_that_did_not_take_the_connection_is_not_asked_for_a_task(node):
    node.answer = 'connect'
    result = _migrate(node)
    assert result['success'] is False and 'connect timeout' in result['error']
    assert node.reads == []


# --- the callers ---------------------------------------------------------------------------

@pytest.fixture
def by_hand(api, seed, monkeypatch, node):
    """The migration by hand; the thread that follows a started task is kept, not started."""
    kept = []
    fake = types.SimpleNamespace(**{k: getattr(threading, k) for k in dir(threading) if not k.startswith('__')})
    fake.Thread = lambda *a, **k: kept.append(k) or types.SimpleNamespace(start=lambda: None)
    monkeypatch.setattr(vms, 'threading', fake)
    src = api.set_manager(CID, _source())
    src.remote_migrate_vm = _manager(node).remote_migrate_vm
    tgt = _target(api)
    created, deleted = [], []
    tgt.create_api_token = lambda name, **kw: created.append(name) or {
        'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}
    tgt.delete_api_token = lambda name: deleted.append(name) or {'success': True}
    admin = api.as_user(seed.user('root', role='admin'))

    def start():
        return admin.post('/api/cross-cluster-migrate', json={
            'source_cluster': CID, 'target_cluster': TGT, 'vmid': VMID, 'vm_type': 'qemu', 'source_node': 'pve1',
            'target_node': 'pve2', 'target_storage': 'local-lvm', 'delete_source': False})
    return types.SimpleNamespace(start=start, kept=kept, created=created, deleted=deleted, node=node)


def test_by_hand_the_error_names_what_did_not_answer_and_the_token_goes(by_hand):
    r = by_hand.start()
    assert r.status_code == 500
    # the target node pve2 is dialled at its transfer address
    assert r.get_json()['error'] == SAID.format(s=60, host='10.20.0.12')
    assert by_hand.deleted == by_hand.created and len(by_hand.created) == 1
    assert by_hand.kept == []


def test_by_hand_a_task_found_after_the_timeout_keeps_its_token(by_hand):
    upid = by_hand.node.task(at=70)
    r = by_hand.start()
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['task'] == upid
    assert by_hand.deleted == []
    (job,) = by_hand.kept
    assert job['args'][2:4] == (by_hand.created[0], upid)


class _Side:
    """A cluster of a full replication run of VM 100 through its clone 9100."""

    def __init__(self, node, guests):
        self.host, self.api_port, self.is_connected = f'{node}.example', 8006, True
        self.node, self.guests = node, guests
        self.logger = logging.getLogger('test.remote_migrate.' + node)
        self.created, self.deleted = [], []

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

    def _api_delete(self, url, params=None, **kw):
        return _R(200, None)

    def _get_vm_storage(self, node, vmid, vm_type):
        return 'fast'

    def create_api_token(self, name, **kw):
        self.created.append(name)
        return {'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}

    def delete_api_token(self, name):
        self.deleted.append(name)
        return {'success': True}

    def get_cluster_fingerprint(self):
        return {'success': True, 'host': '10.0.0.11', 'fingerprint': 'AB:CD'}


@pytest.fixture
def replication(db, monkeypatch, node):
    said, followed = [], []
    monkeypatch.setattr(vms, '_wait_for_task', lambda mgr, upid, **kw: (True, 'OK'))
    for name in ('_capture_vm_identity', '_restore_vm_identity', '_cleanup_snapshot', '_enforce_retention',
                 '_cleanup_clone_and_snap'):
        monkeypatch.setattr(vms, name, lambda *a, **kw: None)
    monkeypatch.setattr(vms, '_tag_as_replica', lambda *a, **kw: (True, ''))
    monkeypatch.setattr(vms, '_update_repl_status', lambda _db, job_id, status, error='': said.append((status, error)))
    monkeypatch.setattr(transfer_net, 'migration_route', lambda mgr, node=None: None)
    monkeypatch.setattr(transfer_net, 'drop_token_when_done',
                        lambda tgt, src, token, upid, what, **kw: followed.append((token, upid)) or ('ok', 'OK'))
    src, tgt = _Side('pve1', [100]), _Side('t1', [])
    # the clone's migration goes through the manager method, to the fake node
    node.answer = 'timeout'
    src.remote_migrate_vm = _manager(node).remote_migrate_vm
    monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
    monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)

    def go():
        vms._execute_replication({'id': 'j1', 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src',
                                  'target_cluster': 'tgt', 'target_storage': 'far', 'target_node': 't1',
                                  'mode': 'full'})
        return said
    return types.SimpleNamespace(go=go, tgt=tgt, node=node, followed=followed)


def test_a_replication_run_says_what_did_not_answer_and_its_token_goes(replication):
    assert replication.go() == [('error', 'Migration failed: ' + SAID.format(s=60, host='10.0.0.11'))]
    assert replication.tgt.deleted == replication.tgt.created and len(replication.tgt.created) == 1
    assert replication.followed == []


def test_a_replication_run_follows_a_task_found_after_the_timeout(replication):
    upid = replication.node.task(at=75, vmid=9100)
    assert replication.go() == [('ok', '')]
    assert replication.followed == [(replication.tgt.created[0], upid)]
    assert replication.tgt.deleted == []


@pytest.fixture
def failover(monkeypatch, node):
    src, tgt = MagicMock(), MagicMock()
    src.logger = logging.getLogger('test.remote_migrate.sr')
    src.get_node_status.return_value = {'pve1': {}}
    src.get_vms.return_value = [{'vmid': VMID}]
    src.remote_migrate_vm = _manager(node).remote_migrate_vm
    tgt.host = '10.0.0.11'
    created, deleted, followed = [], [], []
    tgt.create_api_token.side_effect = lambda name, **kw: created.append(name) or {
        'success': True, 'token_id': 'root@pam!' + name, 'token_value': 'secret'}
    tgt.delete_api_token.side_effect = lambda name: deleted.append(name) or {'success': True}
    tgt.get_cluster_fingerprint.return_value = {'success': True, 'fingerprint': 'AB:CD'}
    monkeypatch.setattr(sr.transfer_net, 'migration_route', lambda mgr, node=None: None)
    monkeypatch.setattr(sr.transfer_net, 'drop_token_when_done',
                        lambda t, s, token, upid, what, **kw: followed.append((token, upid)) or ('ok', 'OK'))

    def go():
        return sr._migrate_vm_cross_cluster(src, tgt, VMID, 'qemu', {}, {})
    return types.SimpleNamespace(go=go, created=created, deleted=deleted, followed=followed, node=node)


def test_a_failover_says_what_did_not_answer_and_its_token_goes(failover):
    assert failover.go() == (False, SAID.format(s=60, host='10.0.0.11'))
    assert failover.deleted == failover.created and len(failover.created) == 1
    assert failover.followed == []


def test_a_failover_follows_a_task_found_after_the_timeout(failover):
    upid = failover.node.task(at=64)
    assert failover.go() == (True, '')
    assert failover.followed == [(failover.created[0], upid)]
    assert failover.deleted == []
