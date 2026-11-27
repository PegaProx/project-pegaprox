"""The VirtIO injection leaves the Windows volume as clean as Windows left it.

Seen on a lab migration of Windows Server 2025: the guest had shut down cleanly on ESXi
(event 1074, then 13), its C: had been healthy at every boot there, and at the first boot
on Proxmox VE Windows logged "Volume C: requires an Online Scan", fsutil said dirty. The
injection ran ntfsfix on every volume before it mounted it, and ntfsfix sets the dirty
flag: that is how it asks Windows for a check. Now a volume ntfs-3g opens for writing as
it is gets no ntfsfix; one left by Fast Startup, hibernation or a power off still does,
and the run says so.
"""
import os
import pathlib
import shutil
import subprocess
import textwrap

import pytest

from test_virtio_injection_node_prereqs_824 import _injection_node_script
from test_v2p_windows_auto import Win, _injection_out

_START = 'echo "WIN_PART=$WIN_PART"\n'
_END = "{ echo 'NTFS_NOT_RW'; exit 6; }\n"


def _ntfs_section():
    script = _injection_node_script()
    a = script.index(_START)
    b = script.index(_END, a) + len(_END)
    return script[a:b]


_FAKES = {
    # each fake counts its calls, logs its arguments and answers what the case asks for
    'mount': '''
        n=$(( $(cat "$STATE/mount" 2>/dev/null || echo 0) + 1 )); echo $n > "$STATE/mount"
        echo "mount $*" >> "$STATE/calls"
        eval rc=\\${MOUNT_RC$n:-0}; eval err=\\${MOUNT_ERR$n:-}
        [ -n "$err" ] && echo "$err" >&2
        exit $rc''',
    'touch': '''
        n=$(( $(cat "$STATE/touch" 2>/dev/null || echo 0) + 1 )); echo $n > "$STATE/touch"
        echo "touch $*" >> "$STATE/calls"
        eval rc=\\${TOUCH_RC$n:-0}
        exit $rc''',
    'umount': 'echo "umount $*" >> "$STATE/calls"',
    'ntfsfix': 'echo "ntfsfix $*" >> "$STATE/calls"',
}


@pytest.fixture
def node(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name, body in _FAKES.items():
        f = bin_dir / name
        f.write_text('#!/bin/sh\n' + textwrap.dedent(body).strip() + '\n')
        f.chmod(0o755)
    state = tmp_path / 'state'
    state.mkdir()
    (tmp_path / 'win').mkdir()
    script = tmp_path / 'ntfs.sh'
    script.write_text('set -u\n'
                      f'TMP={tmp_path}; WIN_MNT={tmp_path}/win; WIN_PART=/dev/loop9p3\n'
                      + _ntfs_section() + 'echo REACHED_WINDOWS_DIR\n')

    def run(**env):
        e = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', STATE=str(state))
        e.update({k: str(v) for k, v in env.items()})
        p = subprocess.run(['bash', str(script)], capture_output=True, text=True, env=e, timeout=30)
        calls = (state / 'calls').read_text().splitlines() if (state / 'calls').exists() else []
        return p.returncode, p.stdout, calls
    return run


def test_ntfsfix_runs_only_in_the_branch_for_a_volume_ntfs3g_would_not_open():
    script = _injection_node_script()
    branch = script[script.index('if [ -n "$NTFS_FIX" ]; then'):script.index("else echo 'NTFS_CLEAN'; fi")]
    calls = [ln for ln in script.splitlines() if ln.lstrip().startswith('ntfsfix ') or '; ntfsfix ' in ln
             or '&& ntfsfix ' in ln]
    assert len(calls) == 1 and calls[0] in branch, calls


def test_a_clean_volume_is_mounted_as_it_is_without_ntfsfix(node):
    rc, out, calls = node()
    assert rc == 0 and 'REACHED_WINDOWS_DIR' in out
    assert 'NTFS_CLEAN' in out and 'NTFS_CHECK_SCHEDULED' not in out
    assert not [c for c in calls if c.startswith('ntfsfix')], calls
    mounts = [c for c in calls if c.startswith('mount')]
    assert len(mounts) == 1 and 'norecover' in mounts[0] and 'remove_hiberfile' in mounts[0]


def test_a_volume_ntfs3g_refuses_goes_through_ntfsfix_and_says_why(node):
    rc, out, calls = node(MOUNT_RC1=14, MOUNT_ERR1='The disk contains an unclean file system (0, 0).')
    assert rc == 0 and 'REACHED_WINDOWS_DIR' in out
    assert 'NTFS_CHECK_SCHEDULED The disk contains an unclean file system (0, 0).' in out
    assert 'NTFS_CLEAN' not in out
    order = [c.split()[0] for c in calls if c.split()[0] in ('mount', 'ntfsfix')]
    assert order == ['mount', 'ntfsfix', 'mount'], calls
    assert ',recover,' in [c for c in calls if c.startswith('mount')][1]


def test_a_volume_mounted_read_only_is_unmounted_then_repaired(node):
    # ntfs-3g falls back to a read-only mount for a Fast Startup volume and still exits 0
    rc, out, calls = node(MOUNT_ERR1='Falling back to read-only mount because the NTFS partition is in an '
                                     'unsafe state.', TOUCH_RC1=1)
    assert rc == 0 and 'REACHED_WINDOWS_DIR' in out
    assert 'NTFS_CHECK_SCHEDULED Falling back to read-only mount' in out
    seq = [c.split()[0] for c in calls]
    assert seq.index('umount') < seq.index('ntfsfix') < len(seq) - 1 - seq[::-1].index('mount'), calls


def test_a_volume_that_mounts_neither_way_stops_the_injection(node):
    rc, out, calls = node(MOUNT_RC1=14, MOUNT_RC2=14)
    assert rc == 6 and 'NTFS_MOUNT_FAILED' in out and 'REACHED_WINDOWS_DIR' not in out


def test_a_read_only_mount_after_ntfsfix_is_still_refused(node):
    rc, out, _calls = node(TOUCH_RC1=1, TOUCH_RC2=1)
    assert rc == 6 and 'NTFS_NOT_RW' in out


def test_the_run_logs_a_clean_volume(monkeypatch):
    out = _injection_out().replace('INJECTION_OK', 'NTFS_CLEAN\nINJECTION_OK')
    w = Win(monkeypatch, inject=out).go()
    assert w.task.status == 'completed'
    assert any('Windows volume closed cleanly, written as it was' in x for x in w.task.log_lines)
    assert not any('ntfsfix' in x for x in w.task.warnings)


def test_the_run_warns_when_windows_will_check_its_volume(monkeypatch):
    out = _injection_out().replace('INJECTION_OK', 'NTFS_CHECK_SCHEDULED Windows is hibernated\nINJECTION_OK')
    w = Win(monkeypatch, inject=out).go()
    assert w.task.status == 'completed'
    assert any('was not closed cleanly (Windows is hibernated)' in x and 'checks the volume at its next boot' in x
               for x in w.task.log_lines)
    assert any('repaired with ntfsfix' in x for x in w.task.warnings)


@pytest.mark.skipif(not (shutil.which('mkntfs') or os.path.exists('/usr/sbin/mkntfs')) or not shutil.which('ntfsfix')
                    or not shutil.which('ntfsinfo'), reason='ntfs-3g tools not installed')
def test_ntfsfix_is_what_sets_the_dirty_flag(tmp_path):
    """the premise, on a real NTFS image: ntfsfix leaves the flag Windows reads as dirty"""
    img = tmp_path / 'v.img'
    with open(img, 'wb') as f:
        f.truncate(64 << 20)
    mkntfs = shutil.which('mkntfs') or '/usr/sbin/mkntfs'
    subprocess.run([mkntfs, '-F', '-Q', '-q', str(img)], capture_output=True, check=True)

    def flags():
        p = subprocess.run(['ntfsinfo', '-f', '-m', str(img)], capture_output=True, text=True)
        return next((ln.split(':', 1)[1].strip() for ln in p.stdout.splitlines() if 'Volume Flags' in ln), '')
    assert flags().startswith('0x0000')
    subprocess.run(['ntfsfix', str(img)], capture_output=True)
    assert 'DIRTY' in flags()
