"""A restore test puts a container back on the storages its backup names (#1168).

Two things sent it elsewhere. The Verify Backup button sent the first storage of the node
that takes 'images', from a list Proxmox orders differently on every read, so each run of
the same guest went somewhere else, and 'images' is no content type for a container at
all. Without that, pct restore given no storage puts every volume on 'local', which as
installed holds no container volumes. Now the button sends no storage, the test storage
of the recovery settings wins when there is one, and otherwise rootfs and each volume
mount point are restored to the storage the backup's config names, as a VM's disks are.
NS Oct 2026
"""
import json
import time

import pytest

import pegaprox.core.backup_verify as bv
from test_restore_test_isolation import _PVE, _params, _plan, clock  # noqa: F401

CT_BACKUP = {
    'hostname': 'ct1', 'onboot': 1, 'tags': 'db',
    'net0': 'name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:03,ip=10.0.0.5/24,type=veth',
    'rootfs': 'data-pool:subvol-100-disk-0,size=8G',
    'mp0': '/srv/shared,mp=/shared',
    'mp1': 'vm-pool:vm-100-disk-1,mp=/var/lib/db,backup=1,size=512M',
    'dev0': '/dev/ttyUSB0',
}


@pytest.mark.parametrize('size,gib', [('8G', '8'), ('512M', '0.5'), ('1T', '1024'), ('1.5G', '1.5'),
                                      ('1073741824', '1'), ('100K', '0.0009765625'), ('4m', '0.00390625'),
                                      ('0T', '0'), ('0', '0')])
def test_a_size_as_proxmox_writes_it_in_gib(size, gib):
    assert bv._gib(size) == gib


@pytest.mark.parametrize('size', [None, '', 'big', '-1G', '8X', 'G'])
def test_what_is_no_size(size):
    assert bv._gib(size) is None


def test_each_volume_goes_back_to_its_own_storage():
    assert bv.lxc_volumes(CT_BACKUP) == {
        'rootfs': 'data-pool:8',
        'mp1': 'vm-pool:0.5,mp=/var/lib/db,backup=1',
    }


@pytest.mark.parametrize('rootfs', ['data-pool:subvol-100-disk-0', '/srv/root', 'size=8G'])
def test_a_rootfs_that_cannot_be_placed_leaves_it_to_proxmox(rootfs):
    assert bv.lxc_volumes(dict(CT_BACKUP, rootfs=rootfs)) is None
    assert bv.lxc_volumes({'hostname': 'ct1'}) is None


def test_a_volume_without_a_size_leaves_it_to_proxmox():
    assert bv.lxc_volumes(dict(CT_BACKUP, mp1='vm-pool:vm-100-disk-1,mp=/var/lib/db')) is None


def test_a_subvolume_without_a_size_limit_goes_back_to_its_own_pool():
    # made as 'data-pool:0', Proxmox writes its size as 0T; pct restore would make it 'local:0'
    vols = bv.lxc_volumes(dict(CT_BACKUP, rootfs='data-pool:subvol-100-disk-0,size=0T'))
    assert vols['rootfs'] == 'data-pool:0'


def _restore(pve):
    return pve.calls[pve.index('POST', '/nodes/pve1/lxc')][2]


def test_the_run_restores_a_container_to_the_storages_of_its_backup(clock, db, monkeypatch):
    from pegaprox.utils import ssh
    monkeypatch.setattr(ssh, '_pve_node_exec', lambda m, n, cmd, timeout=600, **k: (0, '', ''))
    pve = _PVE(kind='lxc', config=CT_BACKUP)
    st = bv.run_verification(pve, _params('lxc'))
    assert st['status'] == 'passed', st['logs']
    restore = _restore(pve)
    assert 'storage' not in restore
    assert restore['rootfs'] == 'data-pool:8'
    assert restore['mp1'] == 'vm-pool:0.5,mp=/var/lib/db,backup=1'
    # the bind mount and the device are not asked for, and isolation still takes them off
    assert 'mp0' not in restore and 'dev0' not in restore
    assert not {'mp0', 'dev0'} & set(pve.config_at_start)


def test_the_run_restores_an_unlimited_subvolume_to_its_own_pool(clock, db, monkeypatch):
    from pegaprox.utils import ssh
    monkeypatch.setattr(ssh, '_pve_node_exec', lambda m, n, cmd, timeout=600, **k: (0, '', ''))
    pve = _PVE(kind='lxc', config=dict(CT_BACKUP, rootfs='data-pool:subvol-100-disk-0,size=0T'))
    st = bv.run_verification(pve, _params('lxc'))
    assert st['status'] == 'passed', st['logs']
    restore = _restore(pve)
    assert 'storage' not in restore
    assert restore['rootfs'] == 'data-pool:0'


def test_the_room_check_looks_at_the_pool_an_unlimited_subvolume_goes_to(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(bv, '_backup_config', lambda *a: dict(CT_BACKUP, rootfs='data-pool:subvol-100-disk-0,size=0T'))
    assert bv.restore_storages(SimpleNamespace(host='pve1', api_port=8006), 'pve1', 'pbs1:backup/ct/100', 'lxc', {}) \
        == ['data-pool', 'vm-pool']


def test_the_test_storage_of_the_recovery_settings_wins(clock, db, monkeypatch):
    from pegaprox.utils import ssh
    monkeypatch.setattr(ssh, '_pve_node_exec', lambda m, n, cmd, timeout=600, **k: (0, '', ''))
    pve = _PVE(kind='lxc', config=CT_BACKUP)
    st = bv.run_verification(pve, _params('lxc', plan=_plan(test_storage='scratch')))
    assert st['status'] == 'passed', st['logs']
    restore = _restore(pve)
    assert restore['storage'] == 'scratch'
    assert 'rootfs' not in restore and 'mp1' not in restore


def test_a_vm_still_keeps_the_storages_of_its_backup(clock, db):
    pve = _PVE()
    st = bv.run_verification(pve, _params())
    assert st['status'] == 'passed', st['logs']
    restore = pve.calls[pve.index('POST', '/nodes/pve1/qemu')][2]
    assert 'storage' not in restore and 'scsi0' not in restore


# --- the button, at runtime -----------------------------------------------------------------

from test_ha_ui import browser  # noqa: E402,F401
from test_backup_file_restore_ui import open_app, BACKUP  # noqa: E402,F401
from test_lxc_features_passthrough_ui import _open_config, _tab, CT  # noqa: E402

VERIFY = '/api/clusters/c1/backup-verify'


def _verify_body(app):
    page = app.page
    app.server.extra[('POST', VERIFY)] = (200, {'success': True, 'task_id': 't1168'})
    app.server.extra[('GET', f'{VERIFY}/t1168')] = (200, {'id': 't1168', 'status': 'running', 'phase': 'restoring'})
    # what the old code picked from (or 'local-lvm' while it was not loaded yet): VM disk storages
    app.server.extra[('GET', '/api/clusters/c1/nodes/pve1/storage')] = (200, [
        {'storage': 'local', 'content': 'iso,vztmpl,backup,images'},
        {'storage': 'vm-pool', 'content': 'images,rootdir'},
    ])
    page.on('dialog', lambda d: d.accept())
    _tab(app, 'Backups').click()
    button = page.locator('button[title="Verify Backup"]').first
    button.wait_for(timeout=5000)
    button.click()
    deadline = time.time() + 5
    while time.time() < deadline and not app.server.bodies.get(VERIFY):
        page.wait_for_timeout(100)
    return app.server.bodies.get(VERIFY, [])


def test_runtime_the_verify_button_names_no_storage(open_app):
    backup = dict(BACKUP, volid='pbs1:backup/ct/101/2026-10-01T02:00:00Z', filename='ct/101/2026-10-01T02:00:00Z')
    app = open_app(guest=CT, backup=backup)
    _open_config(app, 'ct101')
    bodies = _verify_body(app)
    assert len(bodies) == 1, bodies
    body = bodies[0]
    assert body['vmid'] == 101 and body['node'] == 'pve1' and body['backup_volid'] == backup['volid']
    assert 'storage' not in body, json.dumps(body)
    assert not app.errors, app.errors
