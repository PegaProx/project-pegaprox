"""firstboot.cmd, the first boot of a Windows guest moved from ESXi (core/v2p_firstboot.cmd).

MK Nov 2026 - the one-shot SYSTEM service PegaProxFirstBoot (offline preparation) or the scheduled
task of the in-guest preparation start it. It runs at a boot nobody watches, so it uses console
tools only: no PowerShell an execution policy (AllSigned, RemoteSigned by group policy) could stop,
except the one signature check back on ESXi that nothing else on Windows can do.
cmd does not run here; these pin what the script does, in which order, and that every value it
reads is one data_cmd() writes. The naming rule of the project is checked over every new file of
the feature.
"""
import pathlib
import re

import pytest

from pegaprox.core import v2p_winprep, v2p_winprep_node as nh

ROOT = pathlib.Path(__file__).resolve().parent.parent
CMD = (ROOT / 'pegaprox' / 'core' / 'v2p_firstboot.cmd').read_text(encoding='ascii')
LINES = CMD.splitlines()
NEW_FILES = ['pegaprox/core/v2p_firstboot.cmd', 'pegaprox/core/v2p_winprep.py', 'pegaprox/core/v2p_winprep_node.py',
             'pegaprox/core/v2p_twostage.py', 'pegaprox/core/v2p_guestprep.py', 'pegaprox/core/v2p_guestprep.ps1',
             'pegaprox/core/esxi_guestops.py', 'docs/esxi-windows-prep.md']


def _label(name):
    m = re.search(rf'^:{re.escape(name)}\s*$', CMD, re.M)
    assert m, f'no label :{name}'
    return m.start()


def _section(start, end):
    return CMD[_label(start):_label(end)]


# --------------------------------------------------------------------------- the file

# the words of the project's naming rule, spelled so this file does not carry them
VENDOR, MGMT = 'vm' + 'ware', 'vc' + 'enter'
# identifiers and paths that keep the word on purpose
_KEPT = ('_mgr', 'manager', '_managers', '_id', '.py', '_vms', '_bulk', '.vm.', 'api')


@pytest.mark.parametrize('rel', NEW_FILES)
def test_the_new_files_keep_the_naming_rule_and_have_no_em_dash(rel):
    text = (ROOT / rel).read_text(encoding='utf-8')
    assert '\u2014' not in text
    low = text.lower()
    for m in re.finditer(VENDOR, low):
        around = low[max(0, m.start() - 12):m.end() + 12]
        assert any(k in around for k in _KEPT), f'{rel} names the vendor: {around!r}'
    assert MGMT not in low


@pytest.mark.parametrize('rel', ['pegaprox/core/v2p_firstboot.cmd', 'pegaprox/core/v2p_guestprep.ps1'])
def test_the_guest_scripts_are_ascii(rel):
    (ROOT / rel).read_bytes().decode('ascii')


def test_the_guest_gets_crlf_line_ends_and_the_same_lines():
    raw = v2p_winprep.firstboot_bytes()
    assert raw.count(b'\r\n') == raw.count(b'\n') and raw.endswith(b'\r\n')
    assert raw.decode('ascii').splitlines() == LINES


def test_every_goto_and_call_target_exists():
    targets = set(re.findall(r'\b(?:goto|call)\s+:(\w+)', CMD, re.I)) - {'eof'}
    for t in targets:
        _label(t)


def test_the_parentheses_of_every_block_close():
    depth = 0
    for n, line in enumerate(LINES, 1):
        s = line.strip()
        if s.lower().startswith('rem') or s.startswith('::'):
            continue
        s = re.sub(r'"[^"]*"', '""', s)
        s = s.replace('(OI)(CI)', '').replace('echo(', 'echo ')
        depth += s.count('(') - s.count(')')
        assert depth >= 0, f'line {n} closes a block nobody opened: {line}'
    assert depth == 0


def test_powershell_only_for_the_signature_check_on_esxi_and_no_console_input():
    code = '\n'.join(ln for ln in LINES if not ln.lstrip().lower().startswith('rem'))
    back = _section('tools_back', 'network')
    outside = code.replace('\n'.join(ln for ln in back.splitlines() if not ln.lstrip().lower().startswith('rem')), '')
    assert 'powershell' not in outside.lower()
    runs = [ln for ln in back.splitlines() if '"!PSX!"' in ln]
    assert len(runs) == 1 and '-ExecutionPolicy Bypass' in runs[0] and '-NoProfile -NonInteractive' in runs[0]
    assert r'-File "%W%\Prepare-KvmMigration.ps1" -Mode ToolsMedia -WorkDir "%W%"' in runs[0]
    low = CMD.lower()
    # timeout.exe fails without a console (session 0), ping waits instead
    assert not re.search(r'^\s*timeout\b', CMD, re.M | re.I) and 'ping -n ' in CMD
    assert '%cd%' not in low, 'CD is cmd\'s current folder'


def test_the_folder_is_locked_by_sid_before_anything_in_it_runs():
    lock = CMD.index('icacls "%W%" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F')
    data = CMD.index('call "%W%\\firstboot-data.cmd"')
    assert lock < data
    assert 'icacls "%W%" /setowner *S-1-5-32-544' in CMD
    # the grants a file written on Linux carries (Everyone) or a user of the guest left go too:
    # /grant:r only replaces the grants of the SIDs it names. On the folder /remove:g takes them,
    # every file in it is reset to what it inherits from the folder (no explicit grant stays)
    strip = CMD.index('icacls "%W%" /remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545 *S-1-5-4 /C /Q')
    reset = CMD.index('icacls "%W%\\*" /reset /T /C /Q')
    assert lock < strip < reset < data
    code = [ln for ln in LINES if not ln.lstrip().lower().startswith('rem')]
    assert not [ln for ln in code if 'icacls' in ln and ('Administrators' in ln or 'SYSTEM:' in ln)]


# --------------------------------------------------------------------------- on Proxmox VE

def test_the_steps_on_kvm_run_in_order_and_the_service_goes_last():
    kvm = _section('kvm', 'source')
    order = ['set "MSIARGS=/i "%W%\\%KM_DRIVER_MSI%"', 'set "MSIARGS=/i "%W%\\%KM_AGENT_MSI%"',
             'sc config %%s start= boot', 'call :network', 'pnputil /remove-device', 'set "MSIARGS=/x %KM_TOOLS_CODE%',
             'call :report kvm', 'schtasks /delete /tn PegaProxKvmFirstBoot /f', 'sc delete PegaProxFirstBoot']
    at = [kvm.index(x) for x in order]
    assert at == sorted(at), list(zip(order, at))


def test_each_step_runs_once():
    for marker in ('drivers.done', 'agent.done', 'net.done', 'devices.done', 'tools.done'):
        assert f'if exist "%W%\\{marker}"' in CMD and f'"%W%\\{marker}"' in CMD.replace('(echo done>', '')


def test_the_old_interface_loses_its_address_before_the_new_one_gets_it_and_only_on_kvm():
    apply = _section('apply', 'report')
    clear = apply.index('reg add "!K!" /v EnableDHCP /t REG_DWORD /d 1 /f')
    assert apply.index('if "%TARGET%"=="MAC" (') < clear < apply.index('netsh interface ipv4 set address name=!IDX!')
    for v in ('IPAddress', 'SubnetMask', 'DefaultGateway', 'DefaultGatewayMetric'):
        assert v in apply
    assert 'reg add "!K!" /v NameServer /t REG_SZ /d "" /f' in apply
    assert r'Services\Tcpip\Parameters\Interfaces\!KM_NIC%N%_GUID!' in apply


def test_the_address_goes_by_mac_first_then_by_order_and_carries_gateways_and_dns():
    assign = _section('assign', 'apply')
    assert assign.index('set "NBY%%n=mac"') < assign.index('set "NBY%%n=order"')
    apply = _section('apply', 'report')
    assert 'netsh interface ipv4 add address name=!IDX! address=!KM_NIC%N%_IP%%k! mask=!KM_NIC%N%_MASK%%k!' in apply
    assert 'gateway=!KM_NIC%N%_GW%%k!' in apply and 'gwmetric=' in apply
    assert 'netsh interface ipv4 set dnsservers name=!IDX! source=static address=%%d register=primary validate=no' in apply
    assert 'netsh interface ipv4 add dnsservers name=!IDX! address=%%d index=!D!' in apply


def test_the_interface_list_of_route_print_gives_index_and_mac():
    # the format the scan relies on (the same in every display language)
    sample = ['===========================================================================',
              'Interface List',
              ' 12...bc 24 11 aa bb cc ......Red Hat VirtIO Ethernet Adapter',
              '  7...bc 24 11 00 00 02 ......Red Hat VirtIO Ethernet Adapter #2',
              '  1...........................Software Loopback Interface 1',
              ' 14...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter']
    pattern = '^ *[0-9][0-9]*\\.\\.\\.[0-9a-f][0-9a-f] .. .. .. .. .. \\.'
    assert f'findstr /r /i /c:"{pattern}"' in CMD
    # findstr's . is any character as in Python; the scan then wants exactly 12 characters
    pat = re.compile(pattern, re.I)
    got = []
    for line in sample:
        if pat.search(line):
            toks = [t for t in line.split('.') if t != '']   # tokens=1,2 delims=.
            mac = toks[1].replace(' ', '')
            if len(mac) == 12:
                got.append((toks[0].replace(' ', ''), mac))
    assert got == [('12', 'bc2411aabbcc'), ('7', 'bc2411000002')]


def test_the_esxi_guest_tools_go_only_without_a_device_on_their_drivers():
    tools = _section('tools', 'finish')
    uninstall = tools.index('set "MSIARGS=/x %KM_TOOLS_CODE% /qn /norestart REBOOT=ReallySuppress')
    assert tools.index('if not "%KM_TOOLS_UNINSTALL%"=="1" (') < uninstall
    assert tools.index('call :bound pvscsi') < uninstall and tools.index('call :bound vmxnet3ndis6') < uninstall
    # when it fails the service is disabled, never left spinning
    assert 'sc config VMTools start= disabled' in tools
    assert 'call :okcode 0 1605 1641 3010' in tools


def test_old_devices_are_removed_only_where_pnputil_can():
    dev = _section('devices', 'tools')
    assert dev.index('if not "%KM_REMOVE_DEVICES%"=="1" (') < dev.index('pnputil /remove-device "!KM_OLDDEV%%n!"')
    assert nh.REMOVE_DEVICE_BUILD == 19041


def test_a_package_name_that_is_empty_never_deletes_the_folder():
    for line in LINES:
        if 'del /q' in line and 'MSI%' in line:
            assert line.lstrip().startswith('if defined KM_'), line


def test_an_address_that_did_not_go_back_is_tried_again_at_the_next_boots():
    fin = _section('finish', 'source')
    assert 'set "STATE=partial"' in fin and 'if !BOOTS! geq 3 set "STATE=failed"' in fin
    assert fin.index('if "!STATE!"=="partial" (') < fin.index('sc delete PegaProxFirstBoot')


# --------------------------------------------------------------------------- back on ESXi

def test_on_esxi_it_acts_only_after_the_guest_was_released():
    src = _section('source', 'tools_back')
    assert src.index('if not exist "%W%\\released.flag" exit /b 0') < src.index('call :boots')
    assert 'set "TARGET=SRCMAC"' in src
    assert src.index('call :tools_back') < src.index('call :network')
    assert 'sc delete PegaProxFirstBoot' not in src


def test_a_folder_that_is_a_link_runs_nothing_and_writes_nothing():
    head = CMD[:_label('nodata')]
    check = head.index('if not "!WATTR:l=!"=="!WATTR!" exit /b 1')
    assert head.index('for %%I in ("%W%") do set "WATTR=%%~aI"') < check
    # before the log, the icacls walk and the data: all of them would go through the link
    assert check < head.index('icacls "%W%"') and check < head.index('call "%W%\\firstboot-data.cmd"')
    assert 'call :log' not in head[:check]


def test_the_tools_come_back_silently_and_only_from_a_checked_copy():
    back = _section('tools_back', 'network')
    assert 'set "TCD=%W%\\tools-setup.exe"' in back
    assert 'start "" /wait "!TCD!" /s /v"/qn REBOOT=R"' in back
    # nothing found on a drive is started: no drive letters, no file name of the CD here
    assert 'for %%d in' not in back and 'setup64.exe' not in back and ':\\' not in back.replace('%W%\\', '')
    assert back.index('-Mode ToolsMedia') < back.index('if not errorlevel 1 if exist "!TCD!" set "FOUND=1"') < \
        back.index('start "" /wait "!TCD!"')
    assert back.count('set "TCD=') == 1, 'the path run is never anything but the copy'
    assert back.index('start "" /wait "!TCD!"') < back.rindex('del /q "!TCD!"')


def test_the_script_name_is_the_one_the_in_guest_preparation_copies_there():
    from pegaprox.core import v2p_guestprep
    ps = (ROOT / 'pegaprox' / 'core' / 'v2p_guestprep.ps1').read_text(encoding='ascii')
    assert "$SCRIPT_NAME = 'Prepare-KvmMigration.ps1'" in ps and v2p_guestprep.SCRIPT_NAME == 'Prepare-KvmMigration.ps1'
    assert CMD.count('Prepare-KvmMigration.ps1') >= 2


def test_auto_mode_tells_kvm_from_esxi_and_leaves_kvm_to_the_service():
    head = CMD[:_label('nodata')]
    assert 'if /i "%MODE%"=="auto" if not "%PLATFORM%"=="kvm" goto :source' in head
    assert 'sc query PegaProxFirstBoot' in head
    plat = _section('platform', 'boots')
    assert 'QEMU' in plat and 'Standard PC' in plat


# --------------------------------------------------------------------------- the data contract

def test_every_value_the_script_reads_is_one_the_data_holds():
    read = set()
    for name in re.findall(r'KM_(?:[A-Z0-9_]|%%[a-z]|%N%|%TARGET%)+', CMD):
        if '%TARGET%' in name:
            continue        # KM_NICn_MAC on Proxmox, KM_NICn_SRCMAC on ESXi: asserted below
        read.add(re.sub(r'\d+', 'n', re.sub(r'%%[a-z]|%N%', 'n', name)).rstrip('_'))
    moved = [{'guid': '{11111111-2222-3333-4444-555555555555}', 'mac': '005056aabbcc', 'target_mac': 'bc2411000001',
              'instance': r'PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\FF565000CCBBAAFE00',
              'ipv4': [{'ip': '10.0.0.5', 'prefix': 24}, {'ip': '10.0.0.6', 'prefix': 24}],
              'gateway': [{'ip': '10.0.0.1', 'metric': 1}, {'ip': '10.0.0.2', 'metric': 0}], 'dns': ['1.1.1.1']}]
    data = nh.data_cmd('t1', 20348, moved, 'a.msi', 'b.msi', '{ABCDEF01-2345-6789-ABCD-EF0123456789}', True,
                       [moved[0]['instance']]).decode()
    written = {re.sub(r'\d+', 'n', k) for k in re.findall(r'set "(KM_[A-Z0-9_]+)=', data)}
    # KM_NICn_<TARGET> is KM_NICn_MAC on Proxmox and KM_NICn_SRCMAC on ESXi
    missing = {r for r in read if r not in written and r not in ('KM_NICn', 'KM_NICn_n')}
    assert not missing, missing
    assert {'KM_NICn_MAC', 'KM_NICn_SRCMAC'} <= written
