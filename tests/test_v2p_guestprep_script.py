"""The PowerShell script of the in-guest Windows preparation (core/v2p_guestprep.ps1).

MK Nov 2026 - PegaProx runs it in the source guest over the ESXi guest operations when a Windows
login is given, and an admin can download it (GET /api/vmware/guest-prep-script) and run it by
hand: the same bytes both ways. It does not run here (no PowerShell on the test hosts; when pwsh
is on PATH, it is parsed). These pin what it must and must never do.
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

from pegaprox.core import v2p_guestprep as gp

ROOT = pathlib.Path(__file__).resolve().parent.parent
PS = (ROOT / 'pegaprox' / 'core' / 'v2p_guestprep.ps1').read_text(encoding='ascii')


def _fn(name):
    m = re.search(rf'^function {re.escape(name)}\b.*?^}}', PS, re.M | re.S)
    assert m, name
    return m.group(0)


def test_the_automatic_run_and_the_download_are_the_same_bytes():
    assert gp.script_bytes() == (ROOT / 'pegaprox' / 'core' / 'v2p_guestprep.ps1').read_bytes()
    assert gp.SCRIPT_FILE.endswith('v2p_guestprep.ps1')


def test_it_ships_with_the_updater():
    files = json.loads((ROOT / 'version.json').read_text())['update_files']
    for f in ('pegaprox/core/v2p_guestprep.ps1', 'pegaprox/core/v2p_firstboot.cmd', 'pegaprox/core/v2p_guestprep.py',
              'pegaprox/core/v2p_winprep.py', 'pegaprox/core/v2p_winprep_node.py', 'pegaprox/core/v2p_twostage.py',
              'pegaprox/core/esxi_guestops.py'):
        assert f in files, f


def test_the_modes_and_the_log():
    assert "[ValidateSet('Probe', 'Start', 'Run', 'Manual', 'ToolsMedia')]" in PS
    assert "(Join-Path $env:ProgramData 'KVMMigration')" in PS and "'migrate.log'" in PS


def test_nothing_is_run_from_text():
    low = PS.lower()
    for bad in ('invoke-expression', 'iex ', '-encodedcommand', 'downloadstring', 'downloadfile', 'start-bitstransfer',
                'invoke-webrequest', 'net.webclient'):
        assert bad not in low, bad
    assert 'ConvertFrom-Json' in PS


def test_the_work_folder_is_locked_by_sid():
    init = _fn('Initialize-WorkDir')
    assert "*{0}:(OI)(CI)F' -f $SID_SYSTEM" in init and "'/inheritance:r', '/grant:r'" in init
    assert "$SID_SYSTEM = 'S-1-5-18'" in PS and "$SID_ADMINS = 'S-1-5-32-544'" in PS
    assert 'Administrators:' not in init and 'SYSTEM:' not in init
    assert 'ReparsePoint' in init


def test_the_drivers_go_into_the_driver_store_both_ways():
    stage1 = _fn('Invoke-Stage1')
    assert "'/add-driver', (Join-Path $root '*.inf'), '/subdirs', '/install'" in stage1
    assert "@('-i', '-a', $inf.FullName)" in stage1


def test_the_tasks_run_as_system_and_the_first_boot_one_runs_firstboot_cmd():
    assert PS.count("New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest") == 2
    fb = _fn('Register-FirstBootTask')
    assert 'New-ScheduledTaskTrigger -AtStartup' in fb and "'firstboot.cmd'" in fb and 'auto' in fb
    assert 'cmd.exe' in fb and 'powershell' not in fb.lower()
    assert 'FirstBoot' not in re.search(r"ValidateSet\([^)]*\)", PS).group(0)


def test_the_guest_tools_are_found_through_the_service_folder_not_their_name():
    find = _fn('Find-GuestToolsUninstall')
    assert 'Get-GuestToolsProgram' in find and 'InstallLocation' in find and 'WindowsInstaller' in find
    assert "Name='VMTools'" in _fn('Get-GuestToolsProgram')
    assert 'DisplayName' not in find


def test_stage_two_releases_the_address_before_the_uninstall_and_then_marks_the_release():
    s2 = _fn('Invoke-Stage2')
    rel = s2.index('Clear-StaticIPv4')
    unin = s2.index('Uninstall-GuestTools')
    reg = s2.index('Clear-InterfaceRegistry')
    flag = s2.index("'released.flag'")
    assert rel < unin < reg < flag < s2.index('shutdown.exe')


def test_the_run_waits_for_go_or_abort_within_its_deadline():
    run = _fn('Invoke-Run')
    assert "'go.flag'" in run and "'abort.flag'" in run and 'go_wait_seconds' in run
    assert run.index("Write-Status 'ready'") < run.index('Invoke-Stage2')
    # the abort and the deadline take the tasks away and change nothing destructive
    ab = run[run.index('if ($why) {'):run.index("Write-Status 'stage2'")]
    assert 'Remove-PegaTask $TASK_FIRSTBOOT' in ab and 'Invoke-Stage2' not in ab


def test_the_network_saved_in_stage_one_is_tagged_with_the_run_and_the_device():
    s1 = _fn('Invoke-Stage1')
    assert "source = 'guest'; run = $Cfg.run" in s1
    assert 'PNPDeviceID' in _fn('Get-Adapters') and 'instance =' in _fn('Get-Adapters')


def test_an_automatic_gateway_metric_stays_automatic():
    # GatewayCostMetric is 0 for the automatic metric: kept as 0, firstboot.cmd then gives netsh
    # no gwmetric. A truthiness test turned it into an explicit 1.
    ad = _fn('Get-Adapters')
    assert '$metric = 0' in ad and '$null -ne $m[$i]' in ad
    assert '-and $m[$i])' not in ad and '$metric = 1' not in ad


def test_the_files_the_node_trusts_belong_to_the_administrators():
    # the node takes netconfig.json and released.flag of the copied disk only when SYSTEM or the
    # Administrators own them; a run by hand on a client writes them as the admin's own account
    s1, s2 = _fn('Invoke-Stage1'), _fn('Invoke-Stage2')
    assert s1.index("Write-JsonFile (Join-Path $WorkDir 'netconfig.json')") < \
        s1.index("Set-AdminOwner (Join-Path $WorkDir 'netconfig.json')")
    assert s2.index("'released.flag'), 'released'") < s2.index("Set-AdminOwner (Join-Path $WorkDir 'released.flag')")
    own = _fn('Set-AdminOwner')
    assert "'/setowner', ('*' + $SID_ADMINS)" in own and 'throw' in own


def test_stage_one_saves_the_signer_of_the_guest_tools_through_their_service():
    s1 = _fn('Invoke-Stage1')
    step = s1[s1.index("'signer of the ESXi guest tools'"):s1.index("'first boot task'")]
    assert 'Get-GuestToolsProgram' in step and 'Get-SignerOrg' in step and "'tools-signer.txt'" in step
    assert '-BestEffort' in step
    prog = _fn('Get-GuestToolsProgram')
    assert "Name='VMTools'" in prog and 'DisplayName' not in prog
    sig = _fn('Get-SignerOrg')
    assert "$sig.Status -ne 'Valid'" in sig and 'Get-AuthenticodeSignature -FilePath $Path' in sig
    assert "'tools-signer.txt', 'tools-setup.exe'" in _fn('Remove-StaleFiles')


def test_the_tools_media_mode_takes_only_a_signed_installer_from_a_cd_drive_and_checks_its_copy():
    tm = _fn('Invoke-ToolsMedia')
    assert "[string]$d.DriveType -ne 'CDRom'" in tm and '[IO.DriveInfo]::GetDrives()' in tm
    assert "'tools-signer.txt'" in tm and 'exit 3' in tm
    first = tm.index('(Get-SignerOrg $src) -ne $want')
    copy = tm.index('Copy-Item -LiteralPath $src -Destination $dest -Force')
    again = tm.index('(Get-SignerOrg $dest) -eq $want')
    assert first < copy < again < tm.index('exit 0')
    assert "$dest = Join-Path $WorkDir 'tools-setup.exe'" in tm
    # the copy goes when the check of the copy fails, and nothing here starts an installer
    assert 'Remove-Item -LiteralPath $dest' in tm and 'Start-Process' not in tm and 'Invoke-Installer' not in tm
    assert "'ToolsMedia' { Invoke-ToolsMedia }" in PS


def test_the_tools_media_mode_takes_setup_exe_on_64_bit_when_there_is_no_setup64_exe():
    # the guest tools ISO of ESXi 8.0.3 holds setup.exe alone, a 64-bit installer: a lab
    # rollback that looked for setup64.exe only left the guest without its tools and network
    tm = _fn('Invoke-ToolsMedia')
    assert "if ($arch -ne 'x86') { $names = @('setup64.exe', 'setup.exe') }" in tm
    assert "$names = @('setup.exe')" in tm
    pick = tm[tm.index('foreach ($n in $names)'):tm.index('if (-not $src) { continue }')]
    assert 'Test-Path -LiteralPath $p -PathType Leaf' in pick and 'break' in pick


def test_the_config_from_pegaprox_is_typed_data():
    rc = _fn('Read-Config')
    assert "$run -notmatch '^[A-Za-z0-9-]{1,64}$'" in rc and '$NAME_RE' in rc and '-is [bool]' in rc


@pytest.mark.skipif(not shutil.which('pwsh'), reason='no PowerShell on this host')
def test_powershell_parses_it():
    path = ROOT / 'pegaprox' / 'core' / 'v2p_guestprep.ps1'
    cmd = ("$e=$null; [System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$null,[ref]$e) | Out-Null; "
           "if ($e) { $e | ForEach-Object { $_.Message }; exit 1 }" % path)
    out = subprocess.run(['pwsh', '-NoProfile', '-Command', cmd], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stdout + out.stderr
