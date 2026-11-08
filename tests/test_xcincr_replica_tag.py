"""An incremental replication run writes only onto this job's own replica (#1051).

Once a job has a base snapshot, the run went straight to shipping the delta whenever any
guest held the target VMID. When the replica had been removed and the id taken by another
guest since, rbd_replicate_disk / zfs_replicate_dataset found no base on that guest's disk
and fell back to a seed, which on RBD removes the image first and on ZFS receives with -F:
the other guest lost its disk and got the source VM's data in its place. The reseed path
and the full path already refused a target that does not carry the job's tag.
"""
import pytest

import pegaprox.api.vms as vms
import pegaprox.core.incremental_repl as incr
import pegaprox.globals as ppglobals

JOB = 'job1'
BASE = 'xcincr-job1-1000'
OURS = f'pegaprox-replica;{vms._job_tag(JOB)}'


class _R:
    def __init__(self, status, data=None):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class _Ssh:
    def close(self):
        pass


class FakeMgr:
    def __init__(self, ip, node, vms_here, storages, configs):
        self.host, self.api_port, self.is_connected = ip, 8006, True
        self.node, self.ip = node, ip
        self.vms_here, self.storages, self.configs = vms_here, storages, configs
        self.posts, self.puts = [], []
        self.resources_status = 200

    def _api_get(self, url, params=None, **kw):
        if url.endswith('/cluster/resources'):
            if self.resources_status != 200:
                return _R(self.resources_status)
            return _R(200, [{'vmid': v, 'node': self.node, 'type': 'qemu'} for v in self.vms_here])
        if url.endswith('/cluster/status'):
            return _R(200, [{'type': 'node', 'name': self.node, 'ip': self.ip}])
        if url.endswith('/api2/json/storage'):
            return _R(200, [{'storage': s, 'type': t} for s, t in self.storages.items()])
        for vmid, cfg in self.configs.items():
            if url.endswith(f'/nodes/{self.node}/qemu/{vmid}/config'):
                return _R(200, cfg) if cfg is not None else _R(500)
        return _R(404)

    def _api_post(self, url, data=None, **kw):
        self.posts.append((url, data))
        return _R(200, 'UPID:task')

    def _api_put(self, url, data=None, **kw):
        self.puts.append((url, data))
        return _R(200)

    def _ssh_connect(self, ip):
        return _Ssh()


@pytest.fixture
def run(db, monkeypatch):
    seen = {'status': [], 'cleanup': [], 'rbd': [], 'zfs': []}
    monkeypatch.setattr(vms, '_wait_for_task', lambda *a, **k: (True, 'OK'))
    monkeypatch.setattr(vms, '_update_repl_status', lambda _db, job_id, status, error='':
                        seen['status'].append((status, error)))
    monkeypatch.setattr(vms, '_cleanup_snapshot', lambda mgr, node, vmid, vt, snap:
                        seen['cleanup'].append((mgr.node, vmid, snap)))
    monkeypatch.setattr(vms, '_xcincr_rbd_pool', lambda ssh, storage: storage)
    monkeypatch.setattr(vms, '_xcincr_zfs_pool', lambda ssh, storage: storage)

    def rbd(src_ssh, tgt_ssh, src_pool, src_image, tgt_pool, tgt_image, new_snap, base_snap=None, log=None):
        seen['rbd'].append((tgt_pool, tgt_image, base_snap))
        return {'ok': True, 'bytes': 1, 'mode': 'incremental' if base_snap else 'seed'}

    def zfs(src_ssh, tgt_ssh, src_ds, tgt_ds, new_snap, base_snap=None, log=None):
        seen['zfs'].append((tgt_ds, base_snap))
        return {'ok': True, 'bytes': 1, 'mode': 'incremental' if base_snap else 'seed'}
    monkeypatch.setattr(incr, 'rbd_replicate_disk', rbd)
    monkeypatch.setattr(incr, 'zfs_replicate_dataset', zfs)
    monkeypatch.setattr(incr, 'rbd_prune_snapshots', lambda *a, **k: None)
    monkeypatch.setattr(incr, 'zfs_prune_snapshots', lambda *a, **k: None)

    def go(target_tags, kind='rbd', target_vms=(100,), last_snapshot=BASE, resources_status=200):
        src = FakeMgr('192.0.2.1', 's1', [100], {'fast': kind if kind == 'rbd' else 'zfspool'},
                      {100: {'name': 'web', 'scsi0': 'fast:vm-100-disk-0,size=8G'}})
        tgt = FakeMgr('192.0.2.2', 't1', list(target_vms),
                      {'far': kind if kind == 'rbd' else 'zfspool'},
                      {100: None if target_tags is None else {'name': 'someone', 'tags': target_tags}})
        tgt.resources_status = resources_status
        monkeypatch.setitem(ppglobals.cluster_managers, 'src', src)
        monkeypatch.setitem(ppglobals.cluster_managers, 'tgt', tgt)
        job = {'id': JOB, 'vmid': 100, 'vm_type': 'qemu', 'source_cluster': 'src',
               'target_cluster': 'tgt', 'target_storage': 'far', 'target_node': 't1',
               'target_vmid': 100, 'last_snapshot': last_snapshot, 'mode': 'incremental'}
        assert vms._execute_replication_incremental(job) is True
        return src, tgt
    return go, seen


@pytest.mark.parametrize('kind', ['rbd', 'zfs'])
def test_a_guest_that_took_the_vmid_since_is_not_written_over(run, kind):
    go, seen = run
    src, tgt = go('prod;billing', kind=kind)
    assert seen['rbd'] == [] and seen['zfs'] == []
    (status, error), = seen['status']
    assert status == 'error' and vms._job_tag(JOB) in error and 'refusing to overwrite' in error
    # the snapshot taken for this run is not left behind on the source
    assert [c for c in seen['cleanup'] if c[2] != BASE and c[0] == 's1']
    # and nothing was written to the target's config either
    assert tgt.puts == [] and tgt.posts == []


def test_a_target_whose_config_cannot_be_read_counts_as_foreign(run):
    go, seen = run
    go(None)
    assert seen['rbd'] == []
    assert seen['status'][0][0] == 'error'


@pytest.mark.parametrize('kind', ['rbd', 'zfs'])
def test_this_jobs_own_replica_still_gets_the_delta(run, kind):
    go, seen = run
    go(OURS, kind=kind)
    shipped = seen['rbd'] if kind == 'rbd' else seen['zfs']
    assert len(shipped) == 1 and shipped[0][-1] == BASE
    assert seen['status'] == [('ok', '')]


def test_no_guest_at_the_vmid_is_still_a_reseed(run):
    go, seen = run
    go(OURS, target_vms=())
    assert len(seen['rbd']) == 1 and seen['rbd'][0][-1] is None
    assert seen['status'] == [('ok', '')]


@pytest.mark.parametrize('last_snapshot', [BASE, ''])
@pytest.mark.parametrize('kind', ['rbd', 'zfs'])
def test_a_target_guest_list_that_cannot_be_read_is_no_free_vmid(run, kind, last_snapshot):
    """An unread list is not an empty one: read as 'nobody there' it sent a seed onto the
    VMID, and a seed replaces whatever disk carries that name."""
    go, seen = run
    src, tgt = go('prod;billing', kind=kind, last_snapshot=last_snapshot, resources_status=500)
    assert seen['rbd'] == [] and seen['zfs'] == []
    (status, error), = seen['status']
    assert status == 'error' and 'target' in error.lower(), error
    assert [c for c in seen['cleanup'] if c[0] == 's1']
    assert tgt.puts == [] and tgt.posts == []
