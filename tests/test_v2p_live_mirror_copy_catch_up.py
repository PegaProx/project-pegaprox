"""The copies Live Mirror makes without a mirror are brought up to date before they are attached.

When drive-mirror does not start, Live Mirror copies the source disks with the guest still
running on them over SSH (the background copy of the QEMU SSH boot, the qemu-img copy of the
SSHFS boot, importdisk), then stops the VM and attaches the copies. The guest kept writing
during the copy, also to blocks that were copied already: a lab Windows guest ran 28 minutes on
the source while its 40 GB disk was copied, and the copy was attached as it was, a torn disk.
With the VM stopped, what differs now goes over from the source files on ESXi first; copies that
cannot be brought up to date are never attached. The guest also gets 5 minutes to shut down, as
in the snapshot modes, instead of 30 seconds before a hard stop.

MK Nov 2026
"""
import inspect

import pegaprox.core.v2p as v2p

import test_v2p_tpm_and_folder_copy as farm


def _no_mirror(monkeypatch, catch_up_ok=True):
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')
    synced = []
    monkeypatch.setattr(v2p, '_drive_mirror_to_local', lambda *a, **k: False)

    def delta(pve_mgr, task, host, user, pw, esxi_flat, vol_path, size, di, pve_checksums=None):
        synced.append((di, esxi_flat, vol_path, size))
        r.log.append(('delta_sync', di))
        return catch_up_ok
    monkeypatch.setattr(v2p, '_delta_sync_blocks', delta)
    return r, synced


def _attaches(r):
    return [i for i, e in enumerate(r.log) if e[0] == 'node' and 'qm set' in e[2] and '--scsi0 ' in e[2]]


def test_the_background_copy_is_brought_up_to_date_from_the_source_before_it_is_attached(monkeypatch):
    r, synced = _no_mirror(monkeypatch)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert [s[0] for s in synced] == [0, 1], synced
    for di, esxi_flat, vol_path, size in synced:
        assert esxi_flat.startswith('/vmfs/volumes/') and esxi_flat.endswith('-flat.vmdk'), esxi_flat
        assert vol_path.startswith('/dev/') and size == r.task.disk_progress[f'disk{di}']['total']
    assert _attaches(r) and min(_attaches(r)) > r.log.index(('delta_sync', 0)), \
        'a copy was attached before it was brought up to date'


def test_a_copy_that_cannot_be_brought_up_to_date_is_not_attached(monkeypatch):
    r, synced = _no_mirror(monkeypatch, catch_up_ok=False)
    r.go()
    assert synced, 'the catch-up did not run'
    assert r.task.status == 'failed' and 'could not be brought up to what the guest wrote' in r.task.error
    assert 'the source disks on ESXi hold the guest' in r.task.error
    assert not _attaches(r)
    assert not any('RESTARTED on local storage' in ln for ln in r.task.log_lines)


class _Task:
    def __init__(self, sizes):
        self.target_node, self.log_lines = 'pve1', []
        self.disk_progress = {f'disk{i}': {'total': s} for i, s in enumerate(sizes)}

    def kept_disks(self, n):
        return [i for i in range(n)]

    def log(self, msg):
        self.log_lines.append(msg)


def test_the_helper_reads_the_path_of_an_imported_volume_and_stops_at_the_first_failure(monkeypatch):
    calls, sent = [], []

    def node(mgr, n, cmd, timeout=600, **kw):
        sent.append(cmd)
        if cmd.startswith('pvesm path'):
            return 0, '/dev/pve/vm-120-disk-7\n', ''
        if cmd.startswith('test -b'):
            return 0, 'BLK\n', ''
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, '_delta_sync_blocks',
                        lambda *a, **k: calls.append((a[5], a[6], a[7], a[8])) or a[8] == 0)
    task = _Task([4 << 30, 2 << 30, 1 << 30])
    vols = [('local-lvm:vm-120-disk-7', ''), ('local-lvm:vm-120-disk-8', '/dev/pve/vm-120-disk-8'), ('', '')]
    ok = v2p._catch_up_live_copies(None, task, 'esx1', 'root', 'pw', 'datastore1', 'app01',
                                   ['app01.vmdk', 'app01_1.vmdk', 'app01_2.vmdk'], vols)
    assert ok is False
    assert calls == [('/vmfs/volumes/datastore1/app01/app01-flat.vmdk', '/dev/pve/vm-120-disk-7', 4 << 30, 0),
                     ('/vmfs/volumes/datastore1/app01/app01_1-flat.vmdk', '/dev/pve/vm-120-disk-8', 2 << 30, 1)]
    assert sent[0] == 'sync' and "pvesm path local-lvm:vm-120-disk-7 2>/dev/null" in sent


def _imported(monkeypatch, path, block=True, is_file=False):
    """the node of an imported volume whose `pvesm path` says `path`"""
    import time
    monkeypatch.setattr(time, 'sleep', lambda s: None)
    sent, synced = [], []

    def node(mgr, n, cmd, timeout=600, **kw):
        sent.append(cmd)
        if cmd.startswith('pvesm path'):
            return 0, path + '\n', ''
        if cmd.startswith('test -b'):
            return 0, ('BLK\n' if block else 'NOBLK\n'), ''
        if cmd.startswith('test -f'):
            return (0, 'FILE\n', '') if is_file else (1, '', '')
        return 0, '', ''
    monkeypatch.setattr(v2p, '_pve_node_exec', node)
    monkeypatch.setattr(v2p, '_delta_sync_blocks', lambda *a, **k: synced.append(a[6]) or True)
    task = _Task([1 << 30])
    ok = v2p._catch_up_live_copies(None, task, 'esx1', 'root', 'pw', 'ds', 'vm', ['vm.vmdk'],
                                   [('store:vm-120-disk-1', '')])
    return ok, synced, sent, task


def test_a_librbd_volume_is_mapped_like_an_allocation_and_handed_to_the_teardown(monkeypatch):
    mapped = []
    monkeypatch.setattr(v2p, '_map_rbd_uri_to_device', lambda mgr, node, vol, uri: mapped.append(uri) or '/dev/rbd0')
    ok, synced, _sent, task = _imported(monkeypatch, 'rbd:pool/vm-120-disk-1:conf=/etc/pve/ceph.conf')
    assert ok is True and synced == ['/dev/rbd0']
    assert mapped == ['rbd:pool/vm-120-disk-1:conf=/etc/pve/ceph.conf'] and task._mapped_rbd_devs == ['/dev/rbd0']


def test_a_stale_device_path_is_never_written(monkeypatch):
    # importdisk deactivated the thick LV: activation is tried, and a path that is still no block
    # device gets no dd, which would write a regular file in /dev that its read-back passes
    ok, synced, sent, _task = _imported(monkeypatch, '/dev/vgsan/vm-120-disk-1', block=False)
    assert ok is False and synced == []
    assert 'lvchange -aly vgsan/vm-120-disk-1 2>&1' in sent


def test_a_raw_file_of_a_directory_storage_is_compared_a_qcow2_one_is_not(monkeypatch):
    ok, synced, _s, _t = _imported(monkeypatch, '/var/lib/vz/images/120/vm-120-disk-1.raw', is_file=True)
    assert ok is True and synced == ['/var/lib/vz/images/120/vm-120-disk-1.raw']
    ok, synced, _s, _t = _imported(monkeypatch, '/var/lib/vz/images/120/vm-120-disk-1.qcow2', is_file=True)
    assert ok is False and synced == []


def test_a_volume_without_a_readable_path_is_no_copy_brought_up_to_date(monkeypatch):
    monkeypatch.setattr(v2p, '_pve_node_exec', lambda mgr, n, cmd, timeout=600, **kw: (2, '', 'no such volume'))
    monkeypatch.setattr(v2p, '_delta_sync_blocks', lambda *a, **k: True)
    task = _Task([1 << 30])
    assert v2p._catch_up_live_copies(None, task, 'esx1', 'root', 'pw', 'ds', 'vm', ['vm.vmdk'],
                                     [('local-lvm:vm-120-disk-1', '')]) is False


def test_the_sshfs_copy_catches_up_before_it_attaches_and_imports_again_when_it_cannot():
    src = inspect.getsource(v2p._do_sshfs_boot_migration)
    block = src[src.index('=== ALL DISKS COPIED - switching to local storage'):]
    block = block[:block.index('vm_running_on_ssh = False  # VM was stopped and restarted on local storage')]
    stop = block.index('Graceful shutdown timed out')
    catch = block.index('_catch_up_live_copies(')
    assert stop < catch < block.index('# Reconfigure: remove SSH args, set local disks, set boot order')
    assert 'copy_ok = False' in block[catch:block.index('# Reconfigure')]
    # five minutes for the guest, in both switch blocks
    assert "data={'timeout': 300}" in block[:stop] and 'for _w in range(150):' in block[:stop]
    shared = src[src.index('task.log("Switching VM from SSH to local storage (brief restart)...")'):]
    shared = shared[:shared.index('Graceful shutdown timed out')]
    assert "data={'timeout': 300}" in shared and 'for attempt in range(150):' in shared


def test_a_guest_on_the_qemu_ssh_backend_gets_its_disks_copied_when_the_mirror_fails(monkeypatch):
    # neither SSHFS fallback has files to read on this backend: nothing copied the disks,
    # "ALL DISKS COPIED" followed and the empty volumes were attached as a completed run
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')
    monkeypatch.setattr(v2p, '_drive_mirror_to_local', lambda *a, **k: False)
    r.go()
    assert r.task.status == 'completed', r.task.error
    assert any('QEMU SSH driver: connection OK' in ln for ln in r.task.log_lines)
    assert r.node.copied_from == {'/dev/local-lvm/vm-120-disk-1': 'app01-flat.vmdk',
                                  '/dev/local-lvm/vm-120-disk-2': 'app01_1-flat.vmdk'}, r.node.copied_from
    assert any('copying the disks from ESXi while the VM keeps running' in ln for ln in r.task.log_lines)
