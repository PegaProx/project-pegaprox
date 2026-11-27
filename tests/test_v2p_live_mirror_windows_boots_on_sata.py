"""Live Mirror boots a Windows guest prepared in ESXi with its boot disk on SATA first.

Seen on a lab run of Windows Server 2025 with the in-guest preparation: the drivers were in
the Driver Store and vioscsi at boot start, Live Mirror booted the guest with the boot disk on
VirtIO SCSI, and Windows stopped with INACCESSIBLE_BOOT_DEVICE until the recovery screen came
up. The run said COMPLETED and "ZERO downtime". By hand: the boot disk on SATA with VirtIO
SCSI next to it, Windows booted and bound vioscsi; the next start from scsi0 came up.

Now the boot disk of such a guest is on port 0 of the q35 AHCI controller for the boot from
the ESXi datastore, the other disks stay on VirtIO SCSI. After the mirror the run asks the
guest agent: vioscsi bound and at boot start, the boot disk is scsi0 from the next start on;
otherwise it stays sata0, with a warning. A guest whose agent never answers is a warning too.
"""
import json
import re

import pytest

import pegaprox.core.v2p as v2p
from pegaprox.core import v2p_twostage as ts

import test_v2p_tpm_and_folder_copy as farm
from test_v2p_two_stage_boot import lab, _task  # noqa: F401 (lab: a fixture)

FB = {'version': 1, 'run': 't1', 'platform': 'kvm', 'state': 'applied', 'boots': 1, 'tools': 'removed',
      'devices': 'removed', 'adapters': [{'n': 1, 'ip': '10.0.0.5', 'index': '12', 'by': 'mac', 'applied': True}]}
FB_PATH = r'C:\ProgramData\KVMMigration\firstboot.json'


# --------------------------------------------------------------------------- the device of a disk

def test_the_boot_disk_goes_on_ahci_port_0_the_others_on_virtio_scsi():
    t = _task()
    t._live_boot_di = 0
    assert v2p._live_device_spec(t, 'sshfs-disk0', 0, 'scsi') == 'ide-hd,drive=sshfs-disk0,bus=ide.0,unit=0,bootindex=0'
    assert v2p._live_device_spec(t, 'sshfs-disk1', 1, 'scsi').startswith('scsi-hd,bus=scsihw0.0,scsi-id=1,')


def test_without_the_sata_boot_every_disk_keeps_its_bus():
    t = _task()
    t._live_boot_di = None
    assert v2p._live_device_spec(t, 'sshfs-disk0', 0, 'scsi') == v2p._qemu_device_spec('sshfs-disk0', 0, 'scsi')


# --------------------------------------------------------------------------- when it applies

def _prepared(windows=True, state='shut_down'):
    t = _task()
    t._winprep = {'windows': windows, 'on': True, 'state': 'planned'}
    t._guest_prep = {'on': True, 'state': state}
    return t


@pytest.mark.parametrize('t,prefix,want', [
    (_prepared(), '-device virtio-scsi-pci,id=scsihw0 ', True),
    (_prepared(), '-device pvscsi,id=scsihw0 ', False),          # the source's controller kept
    (_prepared(), '', False),                                      # no SCSI at all
    (_prepared(state='fell_back'), '-device virtio-scsi-pci,id=scsihw0 ', False),
    (_prepared(windows=False), '-device virtio-scsi-pci,id=scsihw0 ', False),
], ids=['prepared-virtio', 'pvscsi', 'no-scsi', 'not-prepared', 'not-windows'])
def test_only_a_windows_guest_prepared_in_esxi_on_virtio_scsi_boots_on_sata(t, prefix, want):
    assert ts.live_first_sata(t, prefix) is want


def test_the_in_guest_preparation_readies_storahci_for_live_mirror_too():
    t = _task()
    t._two_stage = {'on': False}
    t.transfer_mode = 'sshfs_boot'
    assert ts.sata_first_boot_planned(t) is True
    t.transfer_mode = 'offline'
    assert ts.sata_first_boot_planned(t) is False
    t._two_stage = {'on': True}
    assert ts.sata_first_boot_planned(t) is True


# --------------------------------------------------------------------------- the check after the mirror

def _running(lb, t):
    lb.pve.running = True
    lb.pve.boots = ['order=sata0']
    return t


def test_bound_and_at_boot_start_moves_the_boot_disk_to_virtio_scsi(lab):
    lb = lab(files={FB_PATH: json.dumps(FB)})
    t = _running(lb, _prepared())
    assert ts.live_switch(lb.pve, t) == 'scsi'
    assert any('vioscsi is bound and starts at boot' in ln for ln in t.log_lines)
    assert any('static IPv4 10.0.0.5 is on interface 12' in ln for ln in t.log_lines)
    assert t.warnings == []


def test_a_guest_whose_agent_never_answers_keeps_sata_and_says_so(lab):
    lb = lab(agent_boots=())
    t = _running(lb, _prepared())
    assert ts.live_switch(lb.pve, t) == 'sata'
    assert any('did not answer' in w and 'open its console' in w and 'sata0' in w for w in t.warnings)


def test_vioscsi_not_bound_keeps_sata(lab):
    lb = lab(bound=0, files={FB_PATH: json.dumps(FB)})
    t = _running(lb, _prepared())
    assert ts.live_switch(lb.pve, t) == 'sata'
    assert any('vioscsi is not bound to any device' in w and 'sata0' in w for w in t.warnings)


def test_vioscsi_bound_on_demand_is_set_to_boot_start_first(lab):
    lb = lab(start=3, files={FB_PATH: json.dumps(FB)})
    t = _running(lb, _prepared())
    assert ts.live_switch(lb.pve, t) == 'scsi'
    assert ['sc.exe', 'config', 'vioscsi', 'start=', 'boot'] in lb.pve.execs


def test_a_first_boot_that_never_reports_is_a_warning(lab):
    lb = lab()
    t = _running(lb, _prepared())
    assert ts.live_switch(lb.pve, t) == 'scsi'
    assert any('first boot task did not report' in w for w in t.warnings)


# --------------------------------------------------------------------------- a whole Live Mirror run

def _mirror_run(monkeypatch, switch):
    # a guest prepared in ESXi: the run keeps the VirtIO SCSI controller (not_with_live_mirror)
    monkeypatch.setattr(ts, 'not_with_live_mirror', lambda pve, task: None)
    monkeypatch.setattr(v2p, '_scsi_controller_args', lambda *a: '-device virtio-scsi-pci,id=scsihw0 ')
    monkeypatch.setattr(ts, 'live_first_sata', lambda task, prefix: 'virtio-scsi' in prefix)
    monkeypatch.setattr(ts, 'live_switch', lambda pve, task: switch)
    orig = v2p.V2PMigrationTask

    def task(*a, config=None, **k):
        return orig(*a, config={**config, 'scsihw': 'virtio-scsi-single', 'disk_discard': 'ignore'}, **k)
    monkeypatch.setattr(v2p, 'V2PMigrationTask', task)
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'completed', r.task.error
    return r


def _args_lines(r):
    return [c for c in r.nodecmds() if "echo 'args:" in c]


def _final_slots(r):
    """{slot: volume} of the disks the run wrote after the mirror, and the boot order"""
    slots, boot = {}, None
    for c in r.nodecmds():
        m = re.search(r"echo '((?:scsi|sata)\d+): (\S+?),size=", c) or \
            re.search(r'qm set \d+ --((?:scsi|sata)\d+) (\S+?)[ ,]', c)
        if m:
            slots[m.group(1)] = m.group(2).strip("'")
        b = re.search(r"boot: order=(\w+)|--boot order=(\w+)", c)
        if b:
            boot = b.group(1) or b.group(2)
    return slots, boot


@pytest.mark.parametrize('switch,boot', [('scsi', 'scsi0'), ('sata', 'sata0')])
def test_the_mirror_boots_on_sata_and_ends_where_the_check_said(monkeypatch, switch, boot):
    r = _mirror_run(monkeypatch, switch)
    args = _args_lines(r)
    assert args and all('bus=ide.0,unit=0,bootindex=0' in a for a in args), args
    assert all(re.search(r'scsi-hd,bus=scsihw0\.0,scsi-id=1,lun=0,drive=\S+disk1', a) for a in args), args
    assert all('-device virtio-scsi-pci,id=scsihw0' in a for a in args), args
    slots, order = _final_slots(r)
    assert boot in slots and 'scsi1' in slots, slots
    assert order == boot
    assert not any('ZERO downtime' in ln for ln in r.task.log_lines)


def test_a_mirror_without_the_sata_boot_is_as_before(monkeypatch):
    monkeypatch.setattr(ts, 'live_first_sata', lambda task, prefix: False)
    r = farm.Run(monkeypatch, mode='sshfs_boot', ssh_key='/tmp/v2p-key-fixed').go()
    assert r.task.status == 'completed', r.task.error
    assert not any('ide-hd' in a for a in _args_lines(r))
    slots, order = _final_slots(r)
    assert 'sata0' not in slots and order == 'scsi0'
