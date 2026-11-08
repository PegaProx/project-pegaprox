# The VirtIO injection read the target storage type as "the second column of the line after
# pvesm's header". On a node where pvesm prints warnings to stdout first - here a volume group
# of a third-party storage plugin, "unsupported storage of vg 'Proxmox-01'" - that line IS the
# header, the type came out as "type", and every injection ended with
# UNSUPPORTED_STORAGE_TYPE. The disk allocation had the same habit with "the second word of
# everything pvesm printed", so a dir or nfs storage could lose its file extension.
# Both now take the row that names the storage in its first column. MK Oct 2026

from types import SimpleNamespace
from unittest.mock import MagicMock

import pegaprox.core.v2p as v2p

# what `pvesm status --storage local-lvm 2>/dev/null` printed on the test node
PVE1_STDOUT = (
    "unsupported storage of vg 'Proxmox-01'\n"
    "Name             Type     Status     Total (KiB)      Used (KiB) Available (KiB)        %\n"
    "local-lvm     lvmthin     active       927924224       761269033       166655190   82.04%\n"
)


def _status_only(output):
    calls = []

    def fake(pve_mgr, node, cmd, timeout=30):
        calls.append(cmd)
        if cmd.startswith('pvesm status'):
            return 0, output, ''
        return 0, '', ''
    return fake, calls


def test_a_warning_ahead_of_the_header_does_not_become_the_type(monkeypatch):
    fake, _ = _status_only(PVE1_STDOUT)
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    assert v2p._pve_storage_type(MagicMock(), 'pve1', 'local-lvm') == 'lvmthin'


def test_plain_output_still_reads(monkeypatch):
    fake, _ = _status_only(PVE1_STDOUT.split('\n', 1)[1])
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    assert v2p._pve_storage_type(MagicMock(), 'pve1', 'local-lvm') == 'lvmthin'


def test_no_row_for_the_storage_is_unknown_not_a_guess(monkeypatch):
    fake, _ = _status_only("unsupported storage of vg 'x'\nName Type Status\n")
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    assert v2p._pve_storage_type(MagicMock(), 'pve1', 'local-lvm') == ''


def test_the_storage_name_is_quoted_for_the_shell(monkeypatch):
    fake, calls = _status_only('')
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    v2p._pve_storage_type(MagicMock(), 'pve1', 'odd name')
    assert calls == ["pvesm status --storage 'odd name' 2>/dev/null"]


def test_a_dir_storage_keeps_its_file_extension_behind_warnings(monkeypatch):
    allocs = []

    def fake(pve_mgr, node, cmd, timeout=30):
        if cmd.startswith('pvesm status'):
            return 0, ("Plugin \"PVE::Storage::Custom::X\" is implementing an older storage API\n"
                       "Name   Type  Status  Total  Used  Available  %\n"
                       "images dir   active  100    1     99         1%\n"), ''
        if cmd.startswith('pvesm alloc'):
            allocs.append(cmd)
            name = cmd.split()[4]
            return 0, f"successfully created 'images:117/{name}'", ''
        if cmd.startswith('pvesm path'):
            return 0, '/var/lib/vz/images/117/vm-117-disk-0.raw\n', ''
        return 0, '', ''

    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    mgr = MagicMock(host='pve1', api_port=8006)
    mgr._api_post.return_value = MagicMock(status_code=500)
    v2p._pvesm_alloc_disk(mgr, 'pve1', 'images', 117, 0, 2 * 1024 ** 3)
    assert allocs and ' vm-117-disk-0.raw ' in allocs[0], allocs


def test_the_injection_script_gets_the_real_type(monkeypatch):
    seen = []

    def fake(pve_mgr, node, cmd, timeout=30):
        seen.append(cmd)
        if cmd.startswith('pvesm path'):
            return 0, '/dev/pve/vm-116-disk-0\n', ''
        if cmd.startswith('pvesm status'):
            return 0, PVE1_STDOUT, ''
        return 0, '', ''

    written = []
    monkeypatch.setattr(v2p, '_pve_node_exec', fake)
    if hasattr(v2p, '_write_node_script'):
        monkeypatch.setattr(v2p, '_write_node_script',
                            lambda mgr, node, text, tag, timeout=10: written.append(text) or f'/run/{tag}.sh')
    task = SimpleNamespace(target_node='pve1', target_storage='local-lvm', proxmox_vmid=116,
                           virtio_iso_path='/var/lib/vz/template/iso/virtio-win.iso', id='t1',
                           install_virtio_drivers=True, log=lambda *a, **k: None,
                           boot_volume=lambda: 'local-lvm:vm-116-disk-0')
    mgr = MagicMock(host='pve1', api_port=8006)
    mgr._api_get.return_value = MagicMock(status_code=200, json=lambda: {'data': {'status': 'stopped'}})
    try:
        v2p._inject_virtio_drivers(mgr, task)
    except Exception:
        pass  # the fake node answers nothing useful after the script; only the script matters
    text = '\n'.join(written + seen)
    assert 'STYPE=lvmthin' in text, 'the injection script did not get the storage type'
    assert 'STYPE=type' not in text
