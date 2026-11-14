"""#1247 - "Prepare VirtIO drivers" promised the guest agent and did not install it.

The first boot service only ran virtio-win-gt-x64.msi, and a comment assumed that brings qemu-ga along.
It does not: the agent is a package of its own, guest-agent/qemu-ga-x86_64.msi on the same ISO.

The script is the one that reaches the node. The staging part runs in bash against a folder that stands
in for the ISO, and the service line is taken from the embedded Python as it would be registered. It does
not run on Windows here.
"""
import re
import subprocess

import pytest

from test_virtio_injection_node_prereqs_824 import _injection_node_script

AGENT = r'C:\PegaProx\qemu-ga-x86_64.msi'
DRIVERS = r'C:\PegaProx\virtio-win-gt-x64.msi'


def _service_line():
    src = re.search(r'^cmdline = \(\n.*?^\)$', _injection_node_script(), re.S | re.M).group(0)
    found = {}
    exec(src, {}, found)
    return found['cmdline']


def _stage(tmp_path, with_agent):
    iso, win = tmp_path / 'iso', tmp_path / 'win'
    (iso / 'guest-agent').mkdir(parents=True)
    (win / 'Windows').mkdir(parents=True)
    (iso / 'virtio-win-gt-x64.msi').write_text('drivers')
    if with_agent:
        (iso / 'guest-agent' / 'qemu-ga-x86_64.msi').write_text('agent')
    script = _injection_node_script()
    start = script.index('PEGADIR=')
    part = script[start:script.index('SYSTEM_HIVE=', start)]
    out = subprocess.run(['bash', '-c', part], capture_output=True, text=True, timeout=30,
                         env={'PATH': '/usr/bin:/bin', 'WIN_MNT': str(win), 'WDIR': 'Windows', 'ISO_MNT': str(iso)})
    assert out.returncode == 0, out.stderr
    return win / 'PegaProx', out.stdout


def test_the_agent_package_is_staged_beside_the_drivers(tmp_path):
    folder, out = _stage(tmp_path, True)
    assert (folder / 'qemu-ga-x86_64.msi').read_text() == 'agent'
    assert (folder / 'virtio-win-gt-x64.msi').read_text() == 'drivers'
    assert 'MSI_STAGED qemu-ga-x86_64.msi' in out


def test_an_iso_without_it_still_stages_the_drivers_and_says_so(tmp_path):
    folder, out = _stage(tmp_path, False)
    assert not (folder / 'qemu-ga-x86_64.msi').exists()
    assert (folder / 'virtio-win-gt-x64.msi').exists()
    assert 'GUEST_AGENT_MSI_MISSING' in out


def test_the_first_boot_service_installs_it_after_the_drivers_and_cleans_up():
    line = _service_line()
    drivers = line.index(f'msiexec /i "{DRIVERS}"')
    agent = line.index(f'msiexec /i "{AGENT}"')
    gone = line.index('sc delete PegaProxFirstBoot')
    assert drivers < agent < gone, line
    # the second install fails while the first still runs, and an ISO without the package is no error
    assert line.count('start "" /wait msiexec') == 2, line
    assert f'if exist "{AGENT}"' in line, line
    assert r'/l*v "C:\PegaProx\qemu-ga.log"' in line, line
    assert re.search(r'del "[^"]+virtio-win-gt-x64\.msi" "[^"]+qemu-ga-x86_64\.msi"', line), line


@pytest.mark.parametrize('needle', ['ADDLOCAL=ALL', 'sc config vioscsi start= boot', 'sc config viostor start= boot'])
def test_what_the_service_did_before_is_still_there(needle):
    assert needle in _service_line()
