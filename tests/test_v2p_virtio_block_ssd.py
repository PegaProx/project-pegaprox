"""SSD emulation on a migration to VirtIO Block, and Discard sent as a bool.

VirtIO Block has no ssd option, so the attaches leave it out (test_v2p_discard_ssd_1246.py),
and nothing told the operator that the box they ticked did nothing. The log says so once.
The create dialog sends Discard as a bool, which the task read as unset, so a request in
that shape got no discard=on.

The migrations run against the ESXi host and Proxmox node of test_v2p_tpm_and_folder_copy.
"""
from test_v2p_disk_options_1270 import _attach_opts, _run

LINE = 'SSD emulation left out: VirtIO Block has no SSD option'


def _migrated(monkeypatch, extra):
    # one fresh set of fakes per migration, _run wraps the task class it finds
    with monkeypatch.context() as mp:
        return _run(mp, extra)


def _said(r):
    return [ln for ln in r.task.log_lines if 'SSD emulation left out' in ln]


def test_the_log_says_once_that_virtio_block_got_no_ssd(monkeypatch):
    r = _migrated(monkeypatch, {'disk_bus': 'virtio', 'disk_iothread': False, 'disk_ssd': True})
    assert _attach_opts(r, 'virtio') == {'virtio0': [], 'virtio1': []}
    assert len(_said(r)) == 1 and _said(r)[0].endswith(LINE), r.task.log_lines
    # only when the box was ticked and only on VirtIO Block
    assert _said(_migrated(monkeypatch, {'disk_bus': 'virtio', 'disk_iothread': False, 'disk_ssd': False})) == []
    assert _said(_migrated(monkeypatch, {'disk_bus': 'scsi', 'disk_ssd': True})) == []


def test_discard_as_a_bool_counts(monkeypatch):
    r = _migrated(monkeypatch, {'disk_discard': True, 'disk_ssd': True})
    assert _attach_opts(r) == {'scsi0': ['discard=on', 'ssd=1'], 'scsi1': ['discard=on', 'ssd=1']}
    r = _migrated(monkeypatch, {'disk_discard': False})
    assert _attach_opts(r) == {'scsi0': [], 'scsi1': []}
