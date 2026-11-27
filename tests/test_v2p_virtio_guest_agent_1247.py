"""#1247 - "Prepare VirtIO drivers" promised the guest agent and did not install it.

The first boot service only ran virtio-win-gt-x64.msi, and a comment assumed that brings qemu-ga along.
It does not: the agent is a package of its own, guest-agent/qemu-ga-x86_64.msi on the same ISO.

The script is the one that reaches the node. The staging part runs in bash against a folder that stands
in for the ISO. MK Nov 2026 - the first boot service runs firstboot.cmd now (core/v2p_firstboot.cmd,
staged in ProgramData\\KVMMigration with the packages); what it does with the two packages is read from
that script. It does not run on Windows here. The bash part only picks the packages on the ISO; the
node helper copies them into the folder it checked (test_v2p_winprep_node.py).
"""
import re
import subprocess

import pytest

from test_virtio_injection_node_prereqs_824 import _injection_node_script
from pegaprox.core import v2p_winprep


def _firstboot():
    return v2p_winprep.firstboot_bytes().decode('ascii')


def _stage(tmp_path, with_agent):
    iso, win = tmp_path / 'iso', tmp_path / 'win'
    (iso / 'guest-agent').mkdir(parents=True)
    (win / 'Windows').mkdir(parents=True)
    (iso / 'virtio-win-gt-x64.msi').write_text('drivers')
    if with_agent:
        (iso / 'guest-agent' / 'qemu-ga-x86_64.msi').write_text('agent')
    script = _injection_node_script()
    start = script.index("MSI_SRC=''")
    part = script[start:script.index('SYSTEM_HIVE=', start)] + 'echo "SRC=$MSI_SRC|$AGENT_SRC"\n'
    out = subprocess.run(['bash', '-c', part], capture_output=True, text=True, timeout=30,
                         env={'PATH': '/usr/bin:/bin', 'WIN_MNT': str(win), 'WDIR': 'Windows', 'ISO_MNT': str(iso)})
    assert out.returncode == 0, out.stderr
    src = [ln for ln in out.stdout.splitlines() if ln.startswith('SRC=')][0][4:].split('|')
    return win, iso, src, out.stdout


def test_the_agent_package_is_handed_on_beside_the_drivers(tmp_path):
    win, iso, src, out = _stage(tmp_path, True)
    assert src == [str(iso / 'virtio-win-gt-x64.msi'), str(iso / 'guest-agent' / 'qemu-ga-x86_64.msi')]
    # bash writes nothing into the guest: a folder a user made there could point anywhere
    assert sorted(p.name for p in win.rglob('*')) == ['Windows']
    assert 'MISSING' not in out


def test_an_iso_without_it_still_hands_on_the_drivers_and_says_so(tmp_path):
    _win, iso, src, out = _stage(tmp_path, False)
    assert src == [str(iso / 'virtio-win-gt-x64.msi'), '']
    assert 'GUEST_AGENT_MSI_MISSING' in out


def test_the_first_boot_service_installs_it_after_the_drivers_and_cleans_up():
    fb = _firstboot()
    drivers = fb.index('set "MSIARGS=/i "%W%\\%KM_DRIVER_MSI%"')
    agent = fb.index('set "MSIARGS=/i "%W%\\%KM_AGENT_MSI%"')
    gone = fb.index('sc delete PegaProxFirstBoot')
    assert drivers < agent < gone
    # each install waits for msiexec, so the second one does not fail while the first still runs
    assert 'start "" /wait msiexec.exe %MSIARGS%' in fb
    # an ISO without the package is no error, and its log is kept
    assert 'if not defined KM_AGENT_MSI (' in fb and 'if not exist "%W%\\%KM_AGENT_MSI%" (' in fb
    assert '/l*v "%W%\\qemu-ga-install.log"' in fb
    # both packages go once the first boot is through, each only when it is named
    assert 'if defined KM_DRIVER_MSI if exist "%W%\\%KM_DRIVER_MSI%" del /q "%W%\\%KM_DRIVER_MSI%"' in fb
    assert 'if defined KM_AGENT_MSI if exist "%W%\\%KM_AGENT_MSI%" del /q "%W%\\%KM_AGENT_MSI%"' in fb


def test_the_injection_hands_both_packages_to_the_node_helper():
    script = _injection_node_script()
    assert 'MSI_SRC="$ISO_MNT/$cand"' in script
    assert 'AGENT_SRC="$ISO_MNT/guest-agent/qemu-ga-x86_64.msi"' in script
    assert '--driver-msi "$MSI_SRC" --agent-msi "$AGENT_SRC"' in script
    # nothing else writes into ProgramData of the guest
    assert 'PEGADIR' not in script and 'KVMMigration' not in script.split("MSI_SRC=''", 1)[1].split('INJECTION_OK')[0]


@pytest.mark.parametrize('needle', ['ADDLOCAL=ALL', 'for %%s in (vioscsi viostor) do (', 'sc config %%s start= boot'])
def test_what_the_service_did_before_is_still_there(needle):
    assert needle in _firstboot()
