"""A single restore Proxmox VE refuses because the backup belongs to another guest says so.

Proxmox VE 9.3 (pve-manager 9.2.33 on) checks the identity of a guest in the restore task, not
in the call that starts it. The call answers with the task, the task ends a moment later with
"backup belongs to another guest ... use 'allow-identity-mismatch'". A batch follows its tasks
and marks such a row IDENTITY_MISMATCH, but the restore of the Backups tab and of the PBS restore
wizard answered 200 and closed: the refusal stood only in the task, the dialogs never offered
their "Allow restoring a backup of another guest" hint.

Now such a restore - over a guest that is there, without the override, on a node that has the
check - is followed for a few seconds. Refused in that time it answers 409 with code
IDENTITY_MISMATCH and PVE's words; anything else (still running, done, failed for another
reason) is answered as before. A restore that cannot meet the check (an older node or one whose
version cannot be read, a new VMID, a guest that is not there, the override asked for) is not
followed at all.

MK Nov 2026
"""
import time

import pytest

from pegaprox.core import batch_restore as batch
from test_a_restore_over_another_guest_is_allowed_only_when_asked import (CID, PBS_CT, REFUSED, VMA, _Pve,
                                                                          _audit)

GUEST_100 = {'vmid': 100, 'node': 'pve1', 'type': 'qemu'}
GUEST_200 = {'vmid': 200, 'node': 'pve2', 'type': 'lxc'}


class _Pve93(_Pve):
    """The fake PVE of the restore tests; its restore task ends with `ends` once its status was
    read `after` times (never when ends is None)"""

    def __init__(self, api, ends=None, after=1, **kw):
        self.ends, self.after, self.status_reads = ends, after, []
        super().__init__(api, **kw)

    def _status(self, node, upid):
        with self.lock:
            self.status_reads.append((node, upid))
            t = self.tasks.get(upid)
            if (t is not None and t['status'] == 'running' and self.ends is not None
                    and len(self.status_reads) >= self.after):
                t['status'], t['exitstatus'] = 'stopped', self.ends
        return super()._status(node, upid)


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    monkeypatch.setattr(batch, 'IDENTITY_WATCH_STEP', 0.01, raising=False)
    monkeypatch.setattr(batch, 'IDENTITY_WATCH_SECONDS', 0.5, raising=False)


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _single(client, **body):
    return client.post(f'/api/clusters/{CID}/vms/pve1/qemu/100/backups/restore', json={'volid': VMA, **body})


def _pbs(client, **body):
    return client.post(f'/api/clusters/{CID}/backup-restore', json={
        'volid': PBS_CT, 'target_node': 'pve2', 'target_vmid': 200, 'mode': 'overwrite', **body})


# --- refused in the task: 409 with the code the dialogs read ---------------------------------

def test_the_backups_tab_restore_refused_in_its_task_answers_409_identity_mismatch(api, seed, admin):
    pve = _Pve93(api, ends=REFUSED, after=2, version='9.2.33', guests=[GUEST_100])
    r = _single(admin)
    body = r.get_json()
    assert r.status_code == 409, r.get_data(as_text=True)
    assert body['code'] == batch.IDENTITY_MISMATCH == 'IDENTITY_MISMATCH'
    # PVE's words, which the dialog shows next to its hint
    assert body['error'] == REFUSED
    ((node, kind, sent),) = pve.posts
    assert (node, kind) == ('pve1', 'qemu')
    assert sent == {'vmid': 100, 'force': 1, 'archive': VMA}
    assert body['task'].startswith('UPID:pve1:') and body['vmid'] == 100
    assert {n for n, _u in pve.status_reads} == {'pve1'}
    # the audit says it was refused, not that it was restored
    assert _audit(seed, 'backup.restored') == []
    (said,) = _audit(seed, 'backup.restore_refused')
    assert VMA in said and 'VMID 100' in said and 'belongs to another guest' in said


def test_the_pbs_wizard_restore_refused_in_its_task_answers_409_identity_mismatch(api, seed, admin):
    pve = _Pve93(api, ends=REFUSED, version='9.3.1', guests=[GUEST_200])
    r = _pbs(admin)
    body = r.get_json()
    assert r.status_code == 409, r.get_data(as_text=True)
    assert body['code'] == 'IDENTITY_MISMATCH' and body['error'] == REFUSED
    assert body['upid'].startswith('UPID:pve2:') and body['target_vmid'] == 200 and body['mode'] == 'overwrite'
    assert pve.posts == [('pve2', 'lxc', {'vmid': 200, 'ostemplate': PBS_CT, 'restore': 1, 'force': 1})]
    assert _audit(seed, 'backup.restored') == []
    (said,) = _audit(seed, 'backup.restore_refused')
    assert PBS_CT in said and 'lxc/200 on pve2' in said and 'belongs to another guest' in said


@pytest.mark.parametrize('route', ['single', 'pbs'])
def test_ticked_after_the_refusal_the_option_goes_out_and_the_task_is_not_waited_for(api, seed, admin, route):
    pve = _Pve93(api, ends=REFUSED, version='9.2.33', guests=[GUEST_100, GUEST_200])
    call = _single if route == 'single' else _pbs
    assert call(admin).status_code == 409
    reads = len(pve.status_reads)
    r = call(admin, allow_identity_mismatch=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.posts[-1][2]['allow-identity-mismatch'] == 1
    assert len(pve.status_reads) == reads


# --- anything else is answered as before ------------------------------------------------------

@pytest.mark.parametrize('route', ['single', 'pbs'])
@pytest.mark.parametrize('ends', [None, 'OK', 'WARNINGS: 1', 'command failed: exit code 133'])
def test_a_restore_that_runs_on_ends_well_or_fails_otherwise_answers_as_before(api, seed, admin, route, ends):
    pve = _Pve93(api, ends=ends, after=3, version='9.2.33', guests=[GUEST_100, GUEST_200])
    began = time.monotonic()
    r = (_single if route == 'single' else _pbs)(admin)
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['success'] is True and 'code' not in body
    assert (body['task'] if route == 'single' else body['upid']).startswith('UPID:')
    assert pve.status_reads, 'the task was not looked at'
    if ends is None:
        # a task still running is let go once the watch is over
        assert 0.4 <= time.monotonic() - began < 5
    else:
        assert len(pve.status_reads) == 3
    assert len(_audit(seed, 'backup.restored')) == 1 and _audit(seed, 'backup.restore_refused') == []


# --- a restore that cannot meet the check is not followed -------------------------------------

@pytest.mark.parametrize('route', ['single', 'pbs'])
@pytest.mark.parametrize('version', ['9.2.32', '8.4.14', 'garbled', None])
def test_a_node_without_the_check_or_that_cannot_say_is_not_waited_for(api, seed, admin, route, version):
    pve = _Pve93(api, ends=REFUSED, version=version, guests=[GUEST_100, GUEST_200])
    r = (_single if route == 'single' else _pbs)(admin)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.status_reads == []


@pytest.mark.parametrize('route', ['single', 'pbs'])
def test_over_a_guest_that_is_not_there_nothing_is_read_at_all(api, seed, admin, route):
    pve = _Pve93(api, ends=REFUSED, version='9.2.33', guests=())
    r = (_single if route == 'single' else _pbs)(admin)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.status_reads == [] and pve.version_reads == []


def test_into_a_new_guest_nothing_is_read_at_all(api, seed, admin):
    pve = _Pve93(api, ends=REFUSED, version='9.2.33', guests=[GUEST_100, GUEST_200,
                                                             {'vmid': 555, 'node': 'pve1', 'type': 'qemu'}])
    assert _single(admin, target_vmid=555).status_code == 200
    assert _pbs(admin, mode='new', target_vmid=555).status_code == 200
    assert pve.status_reads == [] and pve.version_reads == []


@pytest.mark.parametrize('route', ['single', 'pbs'])
@pytest.mark.parametrize('version', ['9.2.33', '9.2.32'])
def test_the_override_asked_for_is_not_waited_for_sent_or_not(api, seed, admin, route, version):
    pve = _Pve93(api, ends=REFUSED, version=version, guests=[GUEST_100, GUEST_200])
    r = (_single if route == 'single' else _pbs)(admin, allow_identity_mismatch=True)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert pve.status_reads == []
    assert len(pve.version_reads) == 1


def test_the_watch_is_bounded_and_reads_the_task_on_its_own_node(api, seed, admin, monkeypatch):
    monkeypatch.setattr(batch, 'IDENTITY_WATCH_STEP', 0.05, raising=False)
    monkeypatch.setattr(batch, 'IDENTITY_WATCH_SECONDS', 0.3, raising=False)
    pve = _Pve93(api, ends=None, version='9.2.33', guests=[GUEST_200])
    r = _pbs(admin)
    assert r.status_code == 200
    assert 1 <= len(pve.status_reads) <= 8
    assert {n for n, _u in pve.status_reads} == {'pve2'}
    # the production window is a few seconds, not a wait on the restore
    monkeypatch.undo()
    assert 0 < batch.IDENTITY_WATCH_SECONDS <= 10 and 0 < batch.IDENTITY_WATCH_STEP <= batch.IDENTITY_WATCH_SECONDS


# --- the helper -------------------------------------------------------------------------------

class _Mgr:
    def __init__(self, version, states):
        self.version, self.states, self.reads = version, list(states), 0

    def get_node_pve_version(self, node):
        if isinstance(self.version, Exception):
            raise self.version
        return self.version

    def get_task_status(self, node, upid):
        self.reads += 1
        return self.states.pop(0) if self.states else {'status': 'running'}


UPID = 'UPID:pve1:00000064:00000001:6740AAAA:qmrestore:100:root@pam:'


@pytest.mark.parametrize('states,said', [
    ([{'status': 'running'}, {'status': 'stopped', 'exitstatus': REFUSED}], REFUSED),
    ([None, {'status': 'stopped', 'exitstatus': REFUSED}], REFUSED),
    ([{'status': 'stopped', 'exitstatus': 'OK'}], ''),
    ([{'status': 'stopped', 'exitstatus': "unable to restore VM 100 - VM is running"}], ''),
    ([], ''),
])
def test_identity_refusal_in_task(states, said):
    assert batch.identity_refusal_in_task(_Mgr((9, 2, 33), states), 'pve1', UPID) == said


@pytest.mark.parametrize('version', [(9, 2, 32), None, 'x', ConnectionError('down')])
def test_identity_refusal_in_task_never_waits_on_a_node_without_the_check(version):
    m = _Mgr(version, [{'status': 'stopped', 'exitstatus': REFUSED}])
    assert batch.identity_refusal_in_task(m, 'pve1', UPID) == '' and m.reads == 0


@pytest.mark.parametrize('upid', ['', None, 'OK', 12, {'data': 'x'}])
def test_identity_refusal_in_task_without_a_task(upid):
    m = _Mgr((9, 3, 1), [{'status': 'stopped', 'exitstatus': REFUSED}])
    assert batch.identity_refusal_in_task(m, 'pve1', upid) == '' and m.reads == 0
