"""Discard and SSD emulation of the migration dialog reach the migrated disks (#1246).

Both were read into the task and never used again, so every disk came out without
discard=on and ssd=1 whatever the Advanced tab said, and on thin storage the whole disk
stayed allocated. PVE takes discard on every bus and ssd on IDE, SATA and SCSI only, not on
VirtIO Block. Both land in a root `qm set`, so discard is one of PVE's two tokens or nothing.

The migrations run against the ESXi host and Proxmox node of test_v2p_tpm_and_folder_copy.
"""
import pytest

import pegaprox.core.v2p as v2p
from test_v2p_disk_options_1270 import _attach_opts, _run

MODES = [dict(mode='offline'), dict(mode='vmkfstools_clone'),
         dict(mode='auto', clone_snap_fails=True), dict(mode='snapshot_zero'),
         dict(mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed')]


@pytest.mark.parametrize('kw', MODES, ids=lambda kw: kw['mode'])
def test_every_transfer_mode_attaches_with_discard_and_ssd(monkeypatch, kw):
    r = _run(monkeypatch, {'disk_discard': 'on', 'disk_ssd': True}, **kw)
    assert _attach_opts(r) == {'scsi0': ['discard=on', 'ssd=1'],
                               'scsi1': ['discard=on', 'ssd=1']}


@pytest.mark.parametrize('bus', ['sata', 'ide'])
def test_sata_and_ide_take_both(monkeypatch, bus):
    r = _run(monkeypatch, {'disk_bus': bus, 'disk_discard': 'on', 'disk_ssd': True})
    assert _attach_opts(r, bus) == {f'{bus}0': ['discard=on', 'ssd=1'],
                                    f'{bus}1': ['discard=on', 'ssd=1']}


def test_virtio_block_takes_discard_but_no_ssd(monkeypatch):
    r = _run(monkeypatch, {'disk_bus': 'virtio', 'disk_iothread': False,
                           'disk_discard': 'on', 'disk_ssd': True})
    assert _attach_opts(r, 'virtio') == {'virtio0': ['discard=on'], 'virtio1': ['discard=on']}


def test_both_switched_off_leave_the_disk_as_pve_makes_it(monkeypatch):
    r = _run(monkeypatch, {'disk_discard': 'ignore', 'disk_ssd': False})
    assert _attach_opts(r) == {'scsi0': [], 'scsi1': []}


def _opts(**cfg):
    task = v2p.V2PMigrationTask('t1', 'vw1', 'vm-42', 'pve-cl', 'pve1', 'local-lvm',
                                config={'disk_iothread': False, **cfg})
    task._attach_bus = cfg.pop('bus', 'scsi')
    return task._disk_attach_opts()


@pytest.mark.parametrize('discard,want', [
    ('on', ',discard=on'), ('ON ', ',discard=on'), ('ignore', ''), ('', ''), (None, ''),
    ('on;reboot', ''), ('on,ssd=1', ''), (['on'], ''), (True, ''),
], ids=repr)
def test_discard_is_a_pve_token_or_nothing(discard, want):
    assert _opts(disk_discard=discard) == want


@pytest.mark.parametrize('ssd,want', [
    (True, ',ssd=1'), ('true', ',ssd=1'), ('1', ',ssd=1'), ('on', ',ssd=1'),
    (False, ''), ('false', ''), ('0', ''), (None, ''), ('', ''), ('1;reboot', ''),
], ids=repr)
def test_ssd_is_on_or_off(ssd, want):
    assert _opts(disk_discard='ignore', disk_ssd=ssd) == want


def test_a_task_without_a_choice_keeps_the_dialogs_default():
    # the dialog starts on discard=on and SSD off, and so does a request that says nothing
    assert _opts() == ',discard=on'
