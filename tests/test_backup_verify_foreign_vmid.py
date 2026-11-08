"""A backup verification cleans up only the test guest its own restore created (#1018).

The test VMID comes from /cluster/nextid, which names a free id without reserving it.
When another create takes that id first, the restore (force=0) is refused, and the
error path's emergency cleanup then stopped and purged the guest that did take it -
somebody else's VM. Purge only once our restore was accepted.

NS Oct 2026
"""
import threading
import time
import types

import pytest

import pegaprox.core.backup_verify as bv

TEST_VMID = 105


class _Resp:
    def __init__(self, status, data=None, text=''):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return {'data': self._data}


class _PVE:
    host, api_port = '10.0.0.1', 8006

    def __init__(self, restore_ok=True):
        self.restore_ok = restore_ok
        self.calls = []
        self.restored = None

    def _api_get(self, url, **kw):
        self.calls.append(('GET', url))
        if url.endswith('/cluster/nextid'):
            return _Resp(200, str(TEST_VMID))
        if url.endswith('/vzdump/extractconfig'):
            return _Resp(200, 'name: web01\nnet0: virtio=BC:24:11:00:00:01,bridge=vmbr0\n')
        if url.endswith('/cluster/ha/resources'):
            # Proxmox answers a list, an empty one without HA
            return _Resp(200, [])
        if url.endswith(f'/qemu/{TEST_VMID}/config') and self.restored:
            # the guest our restore made: what the restore call set on top of the backup
            return _Resp(200, {k: v for k, v in self.restored.items() if k not in ('vmid', 'archive', 'force')})
        return _Resp(200, {})

    def _api_post(self, url, data=None, **kw):
        self.calls.append(('POST', url))
        if url.endswith('/nodes/pve1/qemu'):
            if self.restore_ok:
                self.restored = dict(data)
                return _Resp(200, 'UPID:restore')
            return _Resp(500, None, f'unable to restore VM {TEST_VMID} - VM {TEST_VMID} already exists')
        if url.endswith('/status/start'):
            return _Resp(500, None, 'start failed')
        return _Resp(200, 'UPID:other')

    def _api_delete(self, url, **kw):
        self.calls.append(('DELETE', url))
        return _Resp(200, 'UPID:delete')

    def get_tasks(self, limit=50):
        return [{'upid': 'UPID:restore', 'status': 'OK'}]

    def touched_test_vm(self):
        guest = f'/qemu/{TEST_VMID}'
        return [c for c in self.calls if c[0] in ('POST', 'DELETE') and guest in c[1]]


_SAVED = []


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    # no waiting, and the result row is what the run hands to the database
    monkeypatch.setattr(bv, 'time', types.SimpleNamespace(
        time=time.time, strftime=time.strftime, sleep=lambda s: None))
    monkeypatch.setattr(bv, '_save_result', lambda status: _SAVED.append(dict(status)))


def _verify(pve):
    task_id = bv.start_verification(pve, {
        'cluster_id': 'cluster_1', 'node': 'pve1', 'vmid': 100,
        'backup_volid': 'pbs:backup/vm/100/2026-10-01T00:00:00Z', 'storage': 'local-lvm'})
    for t in threading.enumerate():
        if t.name == f'verify-{task_id}':
            t.join(10)
    # the run is on record before its restore; the result is its last row
    return [row for row in _SAVED if row['id'] == task_id][-1]


def test_a_refused_restore_leaves_the_guest_on_that_vmid_alone():
    pve = _PVE(restore_ok=False)

    status = _verify(pve)

    assert status['status'] == 'error'
    assert pve.touched_test_vm() == [], \
        f'the emergency cleanup stopped or purged a guest this run did not create: {pve.calls}'


def test_a_test_guest_from_an_accepted_restore_is_still_cleaned_up():
    """The mirror: our restore went through, the boot failed - that guest must go."""
    pve = _PVE(restore_ok=True)

    status = _verify(pve)

    assert status['status'] == 'error' and status['restore_ok'] is True
    assert ('DELETE', f'https://10.0.0.1:8006/api2/json/nodes/pve1/qemu/{TEST_VMID}') in pve.calls
