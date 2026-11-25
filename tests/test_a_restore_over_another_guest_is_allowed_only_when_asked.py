"""A restore over a guest the backup does not belong to goes through only when the caller asks.

Proxmox VE 9.3 (pve-manager 9.2.33 on) gives every guest a uid and refuses, inside the restore
task, a backup with another uid over an existing guest: 'force' alone no longer does it, the
create call needs 'allow-identity-mismatch'. PegaProx could not send it, so such a restore
failed with "backup belongs to another guest ... use 'allow-identity-mismatch'" and had to be
finished on the command line.

The restore routes and a batch now take allow_identity_mismatch (default false) and send the
option only with it, only over an existing VMID and only to a node of 9.2.33 or newer: an
older node knows no such parameter and refused the whole call for it. A node whose version
cannot be read gets the restore as before. Asked for and not sent, the answer (a batch: the
row) says why in identity_warning, and the audit names the option only where it went out. A
batch row Proxmox refused for this reason fails with code IDENTITY_MISMATCH, so the dialog can
offer it again with the option.

MK Nov 2026
"""
import json
import threading
import time
import types

import pytest

from pegaprox.core import batch_restore as batch
from pegaprox.core.manager import PegaProxManager

CID = 'cluster_1'
VMA = 'local:backup/vzdump-qemu-100-2026_11_20-00_00_00.vma.zst'
PBS_VM = 'pbs:backup/vm/100/2026-11-20T00:00:00Z'
PBS_CT = 'pbs:backup/ct/200/2026-11-20T00:00:00Z'
# what pve-guest-common's prepare_restore dies with, the task's exit status
REFUSED = ("backup belongs to another guest: its uid 'backupbackupbackupba' differs from uid "
           "'existingexistingexis' of the existing VM 100 - use 'allow-identity-mismatch' to "
           "overwrite the VM anyway")


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body) if not isinstance(body, Exception) else ''

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _Pve:
    """The calls a restore makes: GET /nodes/<n>/version, POST /nodes/<n>/qemu|lxc, the task"""

    def __init__(self, api, version='9.2.33', guests=(), answer=None):
        self.lock = threading.Lock()
        self.version = version
        self.answer = answer
        self.posts, self.version_reads, self.tasks = [], [], {}
        m = api.make_fake_manager(CID)
        m.is_connected = True
        m.host, m.api_port = '192.0.2.10', 8006
        m.config.name = CID
        m.get_node_status.return_value = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}}
        m.get_vm_resources.side_effect = lambda max_age=0: [dict(g) for g in guests]
        m._api_get.side_effect = self._get
        m._api_post.side_effect = self._post
        m._create_session.return_value.post.side_effect = self._post
        m.get_task_status.side_effect = self._status
        # the real read of the node's version, against the answers above
        m.get_node_pve_version = types.MethodType(PegaProxManager.get_node_pve_version, m)
        self.mgr = api.set_manager(CID, m)

    def _get(self, url, **kw):
        if url.endswith('/version'):
            self.version_reads.append(url.split('/api2/json', 1)[1])
            if isinstance(self.version, Exception):
                raise self.version
            if self.version is None:
                return _Resp(500, {'data': None, 'message': 'proxy error'})
            return _Resp(200, {'data': {'version': self.version, 'release': self.version[:3],
                                        'repoid': 'abcdef12'}})
        return _Resp(404, {'data': None})

    def _post(self, url, data=None, **kw):
        path = url.split('/api2/json', 1)[1]
        node, kind = path.split('/')[2], path.split('/')[3]
        with self.lock:
            self.posts.append((node, kind, dict(data)))
            if self.answer is not None:
                return self.answer
            vmid = int(data['vmid'])
            upid = f'UPID:{node}:{vmid:08X}:00000001:6740AAAA:qmrestore:{vmid}:root@pam:'
            self.tasks[upid] = {'vmid': vmid, 'status': 'running'}
        return _Resp(200, {'data': upid})

    def _status(self, node, upid):
        with self.lock:
            t = self.tasks.get(upid)
            if t is None:
                return None
            if t['status'] == 'running':
                return {'status': 'running'}
            return {'status': 'stopped', 'exitstatus': t['exitstatus']}

    def finish(self, vmid, exitstatus='OK'):
        with self.lock:
            t = next(t for t in self.tasks.values() if t['vmid'] == vmid and t['status'] == 'running')
            t['status'], t['exitstatus'] = 'stopped', exitstatus

    def running(self):
        with self.lock:
            return sorted(t['vmid'] for t in self.tasks.values() if t['status'] == 'running')


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _audit(seed, action):
    return [r[0] for r in seed.db.conn.execute(
        'SELECT details FROM audit_log WHERE action = ? ORDER BY id', (action,)).fetchall()]


# --- the restore of one guest's vzdump backup ------------------------------------------------

def _single(client, **body):
    return client.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/backups/restore', json={'volid': VMA, **body})


def test_asked_for_over_the_same_vmid_a_node_of_9_2_33_gets_the_option(api, seed, admin):
    pve = _Pve(api, version='9.2.33')
    r = _single(admin, allow_identity_mismatch=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    ((node, kind, sent),) = pve.posts
    assert (node, kind) == ('pve1', 'qemu')
    assert sent['force'] == 1 and sent['allow-identity-mismatch'] == 1
    assert pve.version_reads == ['/nodes/pve1/version']
    assert 'identity_warning' not in r.get_json()
    assert 'to VMID 100 (allow-identity-mismatch)' in _audit(seed, 'backup.restored')[-1]


def test_never_on_its_own(api, seed, admin):
    """A 9.3 node and the same VMID, nobody asked: force as before, nothing more, and the
    version is not even read."""
    pve = _Pve(api, version='9.3.1')
    for body in ({}, {'allow_identity_mismatch': False}, {'allow_identity_mismatch': 'true'}):
        r = _single(admin, **body)
        assert r.status_code == 200 and 'identity_warning' not in r.get_json()
    assert [sent for _n, _k, sent in pve.posts] == [{'vmid': 100, 'force': 1, 'archive': VMA}] * 3
    assert pve.version_reads == []


@pytest.mark.parametrize('version', ['9.2.32', '9.1.4', '8.4.14', '7.4-3', 'garbled', None,
                                     ConnectionError('no route to host')])
def test_a_node_that_does_not_know_it_or_cannot_say_gets_the_restore_as_before(api, seed, admin, version):
    pve = _Pve(api, version=version)
    r = _single(admin, allow_identity_mismatch=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert [sent for _n, _k, sent in pve.posts] == [{'vmid': 100, 'force': 1, 'archive': VMA}]
    # not dropped without a word: the answer says it was not sent, and why
    said = r.get_json()['identity_warning']
    assert said.startswith('allow-identity-mismatch was not sent: ')
    unreadable = version in ('garbled', None) or isinstance(version, Exception)
    assert ('version of pve1 could not be read' in said) is unreadable, said
    assert ('pve1 runs pve-manager ' in said) is not unreadable, said
    assert 'allow-identity-mismatch' not in _audit(seed, 'backup.restored')[-1]


def test_into_another_vmid_there_is_nothing_to_overwrite(api, seed, admin):
    pve = _Pve(api, version='9.3.1')
    r = _single(admin, target_vmid=555, allow_identity_mismatch=True)
    assert r.status_code == 200 and 'identity_warning' not in r.get_json()
    assert [sent for _n, _k, sent in pve.posts] == [{'vmid': 555, 'force': 0, 'archive': VMA}]


# --- POST /backup-restore and the batch, through start_restore -------------------------------

def _pbs(client, **body):
    return client.post(f'/api/clusters/{CID}/backup-restore', json={
        'volid': PBS_CT, 'target_node': 'pve2', 'target_vmid': 200, 'mode': 'overwrite', **body})


def test_the_pbs_restore_sends_it_on_overwrite_when_asked(api, seed, admin):
    pve = _Pve(api, version='9.2.34')
    assert _pbs(admin, allow_identity_mismatch=True).status_code == 200
    assert _pbs(admin).status_code == 200
    assert pve.posts == [
        ('pve2', 'lxc', {'vmid': 200, 'ostemplate': PBS_CT, 'restore': 1, 'force': 1, 'allow-identity-mismatch': 1}),
        ('pve2', 'lxc', {'vmid': 200, 'ostemplate': PBS_CT, 'restore': 1, 'force': 1})]
    said = _audit(seed, 'backup.restored')
    assert 'allow-identity-mismatch' in said[0] and 'allow-identity-mismatch' not in said[1]


def test_the_pbs_restore_says_why_when_it_was_asked_for_and_not_sent(api, seed, admin):
    pve = _Pve(api, version='9.2.32')
    r = _pbs(admin, allow_identity_mismatch=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()['identity_warning'] == ('allow-identity-mismatch was not sent: pve2 runs '
                                               'pve-manager 9.2.32, which has neither that option '
                                               'nor the check it lifts')
    assert pve.posts == [('pve2', 'lxc', {'vmid': 200, 'ostemplate': PBS_CT, 'restore': 1, 'force': 1})]
    assert 'identity_warning' not in _pbs(admin).get_json()


@pytest.mark.parametrize('route', ['single', 'pbs'])
def test_a_restore_pve_refuses_says_it_as_well(api, seed, admin, route):
    _Pve(api, version=None, answer=_Resp(500, {'data': None, 'message': 'storage full\n'}))
    r = (_single if route == 'single' else _pbs)(admin, allow_identity_mismatch=True)
    body = r.get_json()
    assert r.status_code == 500 and 'storage full' in body['error'], body
    assert 'could not be read' in body['identity_warning']


def test_the_pbs_restore_into_a_new_guest_never_sends_it(api, seed, admin):
    pve = _Pve(api, version='9.3.1')
    r = _pbs(admin, mode='new', target_vmid=900, allow_identity_mismatch=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.posts == [('pve2', 'lxc', {'vmid': 900, 'ostemplate': PBS_CT, 'restore': 1})]


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(batch, 'POLL_SECONDS', 0.02)
    batch.reset_for_tests()
    yield
    for run in batch.runs():
        batch.cancel(run, 'teardown')
    deadline = time.time() + 5
    while time.time() < deadline and any(r.state == 'running' for r in batch.runs()):
        time.sleep(0.02)
    batch.reset_for_tests()


def _wait(cond, what, seconds=5.0):
    deadline = time.time() + seconds
    while time.time() < deadline and not cond():
        time.sleep(0.01)
    assert cond(), f'timed out waiting for {what}'


def _batch(client, **body):
    r = client.post(f'/api/clusters/{CID}/backup-restore/batch', json={
        'items': [{'volid': PBS_VM}], 'mode': 'overwrite', 'confirm': True, 'target_node': 'pve1', **body})
    assert r.status_code == 202, r.get_data(as_text=True)
    return r.get_json()['run']


def test_a_batch_row_pve_refused_for_another_guest_says_so_and_a_second_batch_can_allow_it(api, seed, admin, quick):
    pve = _Pve(api, version='9.2.33', guests=[{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}])
    run = _batch(admin)
    assert run['allow_identity_mismatch'] is False
    _wait(lambda: pve.running() == [100], 'the first restore')
    pve.finish(100, REFUSED)
    _wait(lambda: batch.get(run['id']).state != 'running', 'the end of the first batch')
    (row,) = admin.get(f"/api/batch-restores/{run['id']}").get_json()['run']['rows']
    assert row['state'] == 'failed' and row['code'] == batch.IDENTITY_MISMATCH
    assert row['note'] == REFUSED
    assert pve.posts[0][2] == {'vmid': 100, 'archive': PBS_VM, 'force': 1}

    again = _batch(admin, allow_identity_mismatch=True)
    assert again['allow_identity_mismatch'] is True
    _wait(lambda: pve.running() == [100], 'the second restore')
    pve.finish(100)
    _wait(lambda: batch.get(again['id']).state != 'running', 'the end of the second batch')
    assert pve.posts[1][2] == {'vmid': 100, 'archive': PBS_VM, 'force': 1, 'allow-identity-mismatch': 1}
    (row,) = admin.get(f"/api/batch-restores/{again['id']}").get_json()['run']['rows']
    assert row['state'] == 'done' and 'code' not in row


def test_a_batch_row_that_failed_otherwise_has_no_code(api, seed, admin, quick):
    pve = _Pve(api, version='9.2.33', guests=[{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}])
    run = _batch(admin, allow_identity_mismatch=True)
    _wait(lambda: pve.running() == [100], 'the restore')
    pve.finish(100, 'command failed: exit code 133')
    _wait(lambda: batch.get(run['id']).state != 'running', 'the end of the batch')
    (row,) = admin.get(f"/api/batch-restores/{run['id']}").get_json()['run']['rows']
    assert row['state'] == 'failed' and 'code' not in row


def test_a_batch_names_the_option_only_for_the_restores_it_went_out_for(api, seed, admin, quick):
    """The batch's audit lines name allow-identity-mismatch only where a restore was sent it;
    a row it was asked for and not sent for says why."""
    pve = _Pve(api, version='9.2.32', guests=[{'vmid': 100, 'node': 'pve1', 'type': 'qemu'}])
    ended = lambda n: len(_audit(seed, 'backup.batch_restore_finished')) == n

    # asked for, over an older node: not sent
    old = _batch(admin, allow_identity_mismatch=True)
    _wait(lambda: pve.running() == [100], 'the restore on the older node')
    pve.finish(100)
    _wait(lambda: ended(1), 'the end of the first batch')
    (row,) = admin.get(f"/api/batch-restores/{old['id']}").get_json()['run']['rows']
    assert row['state'] == 'done' and 'identity_override' not in row
    assert row['identity_warning'].startswith('allow-identity-mismatch was not sent: pve1 runs pve-manager 9.2.32')

    # asked for, into a new VMID: nothing to overwrite, nothing sent
    pve.version = '9.2.33'
    new = _batch(admin, mode='new', first_vmid=700, allow_identity_mismatch=True)
    _wait(lambda: pve.running() == [700], 'the restore into a new guest')
    pve.finish(700)
    _wait(lambda: ended(2), 'the end of the second batch')
    (row,) = admin.get(f"/api/batch-restores/{new['id']}").get_json()['run']['rows']
    assert 'identity_override' not in row and 'identity_warning' not in row

    # asked for, over a node that takes it: sent, and said so
    sent = _batch(admin, allow_identity_mismatch=True)
    _wait(lambda: pve.running() == [100], 'the restore on the newer node')
    pve.finish(100)
    _wait(lambda: ended(3), 'the end of the third batch')
    (row,) = admin.get(f"/api/batch-restores/{sent['id']}").get_json()['run']['rows']
    assert row['identity_override'] is True and 'identity_warning' not in row

    assert [p[2].get('allow-identity-mismatch') for p in pve.posts] == [None, None, 1]
    assert not any('allow-identity-mismatch' in a for a in _audit(seed, 'backup.batch_restore'))
    finished = _audit(seed, 'backup.batch_restore_finished')
    assert [old['id'] in finished[0], new['id'] in finished[1], sent['id'] in finished[2]] == [True] * 3
    assert 'allow-identity-mismatch' not in finished[0] and 'allow-identity-mismatch' not in finished[1]
    assert 'allow-identity-mismatch sent for 100' in finished[2]
