<#
PegaProx: prepares a Windows guest on ESXi for its move to Proxmox VE (KVM)

MK Nov 2026 - PegaProx prepares every Windows guest on its own after the copy, without a
login. With a Windows login it runs this script first, through the guest operations of the
ESXi host, so the drivers are in place before the first boot; an administrator can also run
it by hand (-Mode Manual) with the virtio-win ISO in a CD drive:

  1. the VirtIO drivers for this Windows from virtio-win into the Driver Store, the
     virtio-win guest tools installed, vioscsi and viostor as boot start drivers
  2. the static IPv4 configuration saved, and a task for the first boot (firstboot.cmd of
     PegaProx, console tools only): it puts the address back on KVM, or on ESXi when the
     migration was given up
  3. the static IPv4 released from the old ESXi adapter
  4. the ESXi guest tools uninstalled
  5. shut down: migrate the guest then, do not power it on again on ESXi

Log: <WorkDir>\migrate.log (C:\ProgramData\KVMMigration\migrate.log)

By hand, as administrator, with virtio-win.iso mounted in the guest:
  powershell -ExecutionPolicy Bypass -File Prepare-KvmMigration.ps1
  (-NoShutdown leaves the shutdown to you)

Modes: Probe (checks, run by PegaProx), Start (registers the SYSTEM task that does the
work), Run (that task), Manual, ToolsMedia (firstboot.cmd back on ESXi: the guest tools
installer from a CD drive, checked and copied into the work folder).

ASCII only: Windows PowerShell 5.1 reads a file without BOM in the ANSI code page. Values
from the JSON files beside it are checked for their type and only used as arguments.
#>
param(
    [ValidateSet('Probe', 'Start', 'Run', 'Manual', 'ToolsMedia')][string]$Mode = 'Manual',
    [string]$WorkDir = (Join-Path $env:ProgramData 'KVMMigration'),
    [switch]$NoShutdown
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$SID_SYSTEM = 'S-1-5-18'
$SID_ADMINS = 'S-1-5-32-544'
$TASK_PREPARE = 'PegaProxKvmPrepare'
$TASK_FIRSTBOOT = 'PegaProxKvmFirstBoot'
$SCRIPT_NAME = 'Prepare-KvmMigration.ps1'
$NAME_RE = '^[A-Za-z0-9._-]{1,128}$'
$IPV4_RE = '^\d{1,3}(\.\d{1,3}){3}$'
$OK_INSTALL = @(0, 1641, 3010)

$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Steps = New-Object System.Collections.ArrayList
$script:LogReady = $false
$script:RunId = ''

# ---------------------------------------------------------------------------- helpers

function Write-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    if ($script:LogReady) {
        try { [IO.File]::AppendAllText((Join-Path $WorkDir 'migrate.log'), $line + "`r`n", $script:Utf8) } catch { }
    }
    if ($Mode -eq 'Manual') { Write-Host $line }
}

function Write-JsonFile([string]$Path, $Data) {
    $json = ConvertTo-Json -InputObject $Data -Depth 8
    [IO.File]::WriteAllText($Path, $json, $script:Utf8)
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Path))
}

function Get-JsonProp($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# console programs: wait, log what they print, hand back the exit code
function Invoke-Native([string]$File, [string[]]$Arguments) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $File @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    foreach ($l in @($out)) {
        if ($l -and $l.Trim()) { Write-Log ('    ' + $l.Trim()) }
    }
    return [int]$code
}

# msiexec and setup programs are windows programs: the call operator would not wait
function Invoke-Installer([string]$File, [string]$Arguments) {
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    return [int]$p.ExitCode
}

function Add-Step([string]$Name, [bool]$Ok, [string]$Detail) {
    [void]$script:Steps.Add(@{ name = $Name; ok = $Ok; detail = $Detail })
    if ($Ok) { Write-Log ("  ok: {0}: {1}" -f $Name, $Detail) } else { Write-Log ("  FAILED: {0}: {1}" -f $Name, $Detail) }
}

function Invoke-Step([string]$Name, [scriptblock]$Body, [switch]$BestEffort) {
    Write-Log ("step: {0}" -f $Name)
    try {
        $detail = (& $Body | Out-String).Trim()
        Add-Step $Name $true $detail
        return $true
    } catch {
        $why = $_.Exception.Message
        Add-Step $Name $false $why
        if ($BestEffort) { return $false }
        throw ("{0}: {1}" -f $Name, $why)
    }
}

function Write-Status([string]$Stage, [string]$ErrorText) {
    $data = @{
        run = $script:RunId; stage = $Stage; ok = (-not $ErrorText); steps = $script:Steps.ToArray()
        error = $ErrorText; at = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-JsonFile (Join-Path $WorkDir 'status.json') $data
}

function ConvertTo-Prefix([string]$Mask) {
    if ($Mask -match '^\d{1,2}$') { return [int]$Mask }
    $bits = 0
    foreach ($o in $Mask.Split('.')) {
        $n = [int]$o
        while ($n -band 0x80) { $bits++; $n = ($n -shl 1) -band 0xFF }
    }
    return $bits
}

# ---------------------------------------------------------------------------- the work folder

# The SYSTEM tasks run the script from the work folder. A folder in ProgramData that a normal
# user made first would let that user swap it, so the folder belongs to the Administrators and
# only they and SYSTEM may touch it (by SID, any display language).
function Initialize-WorkDir {
    if (Test-Path -LiteralPath $WorkDir) {
        $item = Get-Item -LiteralPath $WorkDir -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw ("{0} is no plain folder (a file or a link): remove it and run this again" -f $WorkDir)
        }
        $owner = (Get-Acl -LiteralPath $WorkDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -ne $SID_ADMINS -and $owner -ne $SID_SYSTEM) {
            # made by somebody else before the first run: taken over and emptied
            Invoke-Native 'icacls.exe' @($WorkDir, '/setowner', ('*' + $SID_ADMINS), '/T', '/C', '/Q') | Out-Null
            Invoke-Native 'icacls.exe' @($WorkDir, '/grant', ('*{0}:(OI)(CI)F' -f $SID_ADMINS), '/T', '/C', '/Q') | Out-Null
            Remove-Item -LiteralPath $WorkDir -Recurse -Force
        }
    }
    if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
    $rc1 = Invoke-Native 'icacls.exe' @($WorkDir, '/setowner', ('*' + $SID_ADMINS), '/T', '/C', '/Q')
    $rc2 = Invoke-Native 'icacls.exe' @($WorkDir, '/inheritance:r', '/grant:r', ('*{0}:(OI)(CI)F' -f $SID_SYSTEM),
                                        ('*{0}:(OI)(CI)F' -f $SID_ADMINS), '/T', '/C', '/Q')
    if ($rc1 -ne 0 -or $rc2 -ne 0) { throw ("icacls could not lock {0} (exit codes {1}, {2})" -f $WorkDir, $rc1, $rc2) }
    $acl = Get-Acl -LiteralPath $WorkDir
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($sid -ne $SID_ADMINS -and $sid -ne $SID_SYSTEM) { throw ("{0} still grants access to {1}" -f $WorkDir, $sid) }
    }
}

function Remove-StaleFiles {
    foreach ($n in 'go.flag', 'abort.flag', 'status.json', 'probe.json', 'released.flag', 'firstboot.json',
                  'firstboot.nics', 'firstboot-data.cmd', 'boots.txt', 'drivers.done', 'agent.done', 'net.done',
                  'devices.done', 'tools.done', 'tools-signer.txt', 'tools-setup.exe') {
        $p = Join-Path $WorkDir $n
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
    }
}

# ---------------------------------------------------------------------------- what the guest has

# MK Nov 2026 - the same table as driver_folders() in v2p_guestprep.py: the client and the
# server build of one number take different folders of the ISO
function Get-DriverFolders([int]$Build, [bool]$Server) {
    if ($Build -ge 22000) { if ($Server) { return '2k25', '2k22', 'w11' } else { return 'w11', '2k25', '2k22' } }
    if ($Build -ge 20348) { if ($Server) { return '2k22', 'w11' } else { return 'w11', '2k22' } }
    if ($Build -ge 17763) { if ($Server) { return '2k19', 'w10', '2k16' } else { return 'w10', '2k19', 'w11' } }
    if ($Build -ge 14393) { if ($Server) { return '2k16', 'w10', '2k19' } else { return 'w10', '2k16' } }
    if ($Build -ge 10240) { if ($Server) { return '2k16', 'w10' } else { return 'w10', '2k19', 'w11' } }
    if ($Build -ge 9600) { if ($Server) { return '2k12R2', 'w8.1' } else { return 'w8.1', '2k12R2' } }
    if ($Build -ge 9200) { if ($Server) { return '2k12', 'w8' } else { return 'w8', '2k12' } }
    if ($Server) { return '2k8R2' } else { return 'w7' }
}

# The uninstall entry of the ESXi guest tools, found without their product name: the folder
# of the program the VMTools service runs is the InstallLocation of its uninstall entry
function Get-GuestToolsProgram {
    $svc = Get-WmiObject -Class Win32_Service -Filter "Name='VMTools'" -ErrorAction SilentlyContinue
    if (-not $svc -or -not $svc.PathName) { return $null }
    $exe = ([string]$svc.PathName).Trim()
    if ($exe.StartsWith('"')) {
        $end = $exe.IndexOf('"', 1)
        if ($end -lt 2) { return $null }
        $exe = $exe.Substring(1, $end - 1)
    } else {
        $i = $exe.ToLowerInvariant().IndexOf('.exe')
        if ($i -gt 0) { $exe = $exe.Substring(0, $i + 4) }
    }
    return $exe
}

function Find-GuestToolsUninstall {
    $exe = Get-GuestToolsProgram
    if (-not $exe) { return $null }
    $folder = (Split-Path -Parent $exe).TrimEnd('\')
    if (-not $folder) { return $null }
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            $loc = [string](Get-JsonProp $p 'InstallLocation')
            $msi = Get-JsonProp $p 'WindowsInstaller'
            if (-not $loc -or $null -eq $msi -or [int]$msi -ne 1) { continue }
            if ($loc.TrimEnd('\') -ieq $folder -and $key.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') {
                return $key.PSChildName
            }
        }
    }
    return $null
}

# MK Nov 2026 - the organization in the certificate of a file with a valid Authenticode
# signature, $null for anything else
function Get-SignerOrg([string]$Path) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $null }
    if ($sig.SignerCertificate.Subject -match '(?:^|,\s*)O=("[^"]+"|[^,]+)') { return $Matches[1].Trim('"').Trim() }
    return $null
}

# whoever wrote it, the file belongs to the Administrators: PegaProx trusts netconfig.json and
# released.flag on the copied disk only then (a user can never make a file theirs)
function Set-AdminOwner([string]$Path) {
    $rc = Invoke-Native 'icacls.exe' @($Path, '/setowner', ('*' + $SID_ADMINS), '/C', '/Q')
    if ($rc -ne 0) { throw ('icacls could not give {0} to the Administrators (exit code {1})' -f $Path, $rc) }
}

function Test-PendingReboot {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    return [bool](Get-JsonProp $sm 'PendingFileRenameOperations')
}

# every adapter with IPv4 on it: MAC, static or DHCP, addresses with prefix, gateways, DNS
function Get-Adapters {
    $list = New-Object System.Collections.ArrayList
    $pnp = @{}
    foreach ($n in @(Get-WmiObject -Class Win32_NetworkAdapter)) { $pnp[[int]$n.Index] = [string]$n.PNPDeviceID }
    foreach ($c in @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE')) {
        $ips = New-Object System.Collections.ArrayList
        $addrs = @($c.IPAddress)
        $masks = @($c.IPSubnet)
        for ($i = 0; $i -lt $addrs.Count; $i++) {
            if ([string]$addrs[$i] -match $IPV4_RE -and $i -lt $masks.Count) {
                [void]$ips.Add(@{ ip = [string]$addrs[$i]; prefix = (ConvertTo-Prefix ([string]$masks[$i])) })
            }
        }
        $gws = New-Object System.Collections.ArrayList
        $g = @($c.DefaultIPGateway)
        $m = @($c.GatewayCostMetric)
        for ($i = 0; $i -lt $g.Count; $i++) {
            if ([string]$g[$i] -match $IPV4_RE) {
                # 0 is the automatic metric and stays automatic on KVM (no gwmetric for netsh)
                $metric = 0
                if ($i -lt $m.Count -and $null -ne $m[$i]) { $metric = [int]$m[$i] }
                [void]$gws.Add(@{ ip = [string]$g[$i]; metric = $metric })
            }
        }
        $dns = New-Object System.Collections.ArrayList
        foreach ($d in @($c.DNSServerSearchOrder)) { if ([string]$d -match $IPV4_RE) { [void]$dns.Add([string]$d) } }
        [void]$list.Add(@{
            mac = [string]$c.MACAddress; setting_id = [string]$c.SettingID; index = [int]$c.InterfaceIndex
            instance = [string]$pnp[[int]$c.Index]
            dhcp = [bool]$c.DHCPEnabled; ipv4 = $ips.ToArray(); gateway = $gws.ToArray(); dns = $dns.ToArray()
        })
    }
    return ,$list.ToArray()
}

function Get-ProbeData {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ubr = Get-JsonProp $cv 'UBR'
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    $drive = New-Object IO.DriveInfo($env:SystemDrive)
    $machine = [string](Get-ExecutionPolicy -Scope MachinePolicy)
    $adapters = New-Object System.Collections.ArrayList
    foreach ($a in (Get-Adapters)) {
        $ips = New-Object System.Collections.ArrayList
        foreach ($ip in $a.ipv4) { [void]$ips.Add(('{0}/{1}' -f $ip.ip, $ip.prefix)) }
        $gws = New-Object System.Collections.ArrayList
        foreach ($gw in $a.gateway) { [void]$gws.Add($gw.ip) }
        [void]$adapters.Add(@{ mac = $a.mac; static = (-not $a.dhcp); ipv4 = $ips.ToArray(); gateway = $gws.ToArray(); dns = $a.dns })
    }
    return @{
        ok = $true; elevated = $true; build = [int]$os.BuildNumber; ubr = [int]$ubr
        product = [string]$os.Caption; product_type = [int]$os.ProductType; arch = [string]$arch
        ps_version = $PSVersionTable.PSVersion.ToString(); free_mb = [int64]($drive.AvailableFreeSpace / 1MB)
        execution_policy = [string](Get-ExecutionPolicy); execution_policy_blocked = ($machine -eq 'AllSigned')
        tools_uninstall = [bool](Find-GuestToolsUninstall); pending_reboot = (Test-PendingReboot)
        adapters = $adapters.ToArray()
    }
}

# ---------------------------------------------------------------------------- the settings PegaProx left

function Read-Config {
    $path = Join-Path $WorkDir 'pegaprox.json'
    $cfg = @{ version = 1; run = 'manual'; drivers = @(); installer = $null; agent_msi = $null
              go_wait_seconds = 0; sata_first_boot = $true; preserve_mac = $true }
    $j = Read-JsonFile $path
    if ($null -eq $j) {
        if ($Mode -eq 'Manual') { return $cfg }
        throw 'pegaprox.json is missing'
    }
    $v = Get-JsonProp $j 'version'
    if (-not ($v -is [int] -or $v -is [long]) -or $v -ne 1) { throw 'pegaprox.json: version must be 1' }
    $run = Get-JsonProp $j 'run'
    if (-not ($run -is [string]) -or $run -notmatch '^[A-Za-z0-9-]{1,64}$') { throw 'pegaprox.json: run is no run id' }
    $cfg.run = $run
    $drivers = New-Object System.Collections.ArrayList
    foreach ($d in @(Get-JsonProp $j 'drivers')) {
        if ($null -eq $d) { continue }
        if (-not ($d -is [string]) -or $d -notmatch $NAME_RE) { throw 'pegaprox.json: drivers holds no driver name' }
        [void]$drivers.Add($d)
    }
    $cfg.drivers = $drivers.ToArray()
    foreach ($k in 'installer', 'agent_msi') {
        $x = Get-JsonProp $j $k
        if ($null -ne $x -and (-not ($x -is [string]) -or $x -notmatch $NAME_RE)) { throw ("pegaprox.json: {0} is no file name" -f $k) }
        $cfg[$k] = $x
    }
    $w = Get-JsonProp $j 'go_wait_seconds'
    if (-not ($w -is [int] -or $w -is [long]) -or $w -lt 60 -or $w -gt 3456000) { throw 'pegaprox.json: go_wait_seconds is out of range' }
    $cfg.go_wait_seconds = [int64]$w
    foreach ($k in 'sata_first_boot', 'preserve_mac') {
        $x = Get-JsonProp $j $k
        if (-not ($x -is [bool])) { throw ("pegaprox.json: {0} must be true or false" -f $k) }
        $cfg[$k] = $x
    }
    return $cfg
}

# ---------------------------------------------------------------------------- stage 1

function Import-DriverSigners {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine')
    $store.Open('ReadWrite')
    $seen = @{}
    try {
        $root = Join-Path $WorkDir 'drivers'
        if (-not (Test-Path -LiteralPath $root)) { return 0 }
        foreach ($cat in @(Get-ChildItem -LiteralPath $root -Filter '*.cat' -Recurse -File)) {
            $sig = Get-AuthenticodeSignature -FilePath $cat.FullName
            if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { continue }
            $t = $sig.SignerCertificate.Thumbprint
            if ($seen.ContainsKey($t)) { continue }
            $seen[$t] = $true
            $store.Add($sig.SignerCertificate)
        }
    } finally {
        $store.Close()
    }
    return $seen.Count
}

function Set-BootDriver([string]$Name, [int]$BusType) {
    $sys = Join-Path $env:SystemRoot ('System32\drivers\{0}.sys' -f $Name)
    if (-not (Test-Path -LiteralPath $sys)) {
        $from = Join-Path $WorkDir ('drivers\' + $Name)
        if (-not (Test-Path -LiteralPath $from)) { return $false }
        $src = @(Get-ChildItem -LiteralPath $from -Filter ($Name + '.sys') -Recurse -File) | Select-Object -First 1
        if (-not $src) { return $false }
        Copy-Item -LiteralPath $src.FullName -Destination $sys -Force
    }
    $base = 'SYSTEM\CurrentControlSet\Services\' + $Name
    $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($base)
    try {
        $k.SetValue('Type', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $k.SetValue('Start', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $k.SetValue('ErrorControl', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $k.SetValue('Group', 'SCSI miniport', [Microsoft.Win32.RegistryValueKind]::String)
        $k.SetValue('ImagePath', ('System32\drivers\{0}.sys' -f $Name), [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally { $k.Close() }
    # BusType as each driver's own INF writes it: viostor 1, vioscsi 0x0A
    $p = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($base + '\Parameters')
    try { $p.SetValue('BusType', $BusType, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $p.Close() }
    $i = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($base + '\Parameters\PnpInterface')
    try { $i.SetValue('5', 1, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $i.Close() }
    return $true
}

function Register-PegaTask([string]$Name, [string]$TaskMode) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $file = Join-Path $WorkDir $SCRIPT_NAME
    $arg = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode {1} -WorkDir "{2}"' -f $file, $TaskMode, $WorkDir
    $action = New-ScheduledTaskAction -Execute $ps -Argument $arg -WorkingDirectory $WorkDir
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
}

# MK Nov 2026 - firstboot.cmd runs with console tools only, so no execution policy stops it at
# a boot nobody watches; "auto" lets it tell KVM from ESXi
function Register-FirstBootTask {
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $file = Join-Path $WorkDir 'firstboot.cmd'
    $action = New-ScheduledTaskAction -Execute $cmd -Argument ('/d /c ""{0}" auto"' -f $file) -WorkingDirectory $WorkDir
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT30S'
    Register-ScheduledTask -TaskName $TASK_FIRSTBOOT -Action $action -Principal $principal -Settings $settings `
        -Trigger $trigger -Force | Out-Null
}

function Remove-PegaTask([string]$Name) {
    try { Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue } catch { }
}

function Invoke-Stage1($Cfg, [int]$Build) {
    Invoke-Step 'trusted publishers of the drivers' {
        $n = Import-DriverSigners
        '{0} signer certificate(s)' -f $n
    } | Out-Null

    Invoke-Step 'virtio-win guest tools' {
        if (-not $Cfg.installer) { return 'no installer, the drivers come from the Driver Store step' }
        $path = Join-Path $WorkDir $Cfg.installer
        if (-not (Test-Path -LiteralPath $path)) { throw ('{0} is not in {1}' -f $Cfg.installer, $WorkDir) }
        $log = Join-Path $WorkDir 'virtio-win-install.log'
        if ($Cfg.installer -like '*.msi') {
            $code = Invoke-Installer 'msiexec.exe' ('/i "{0}" ADDLOCAL=ALL /qn /norestart /l*v "{1}"' -f $path, $log)
        } else {
            $code = Invoke-Installer $path ('/install /quiet /norestart /log "{0}"' -f $log)
        }
        if ($OK_INSTALL -notcontains $code) { throw ('exit code {0}, see {1}' -f $code, $log) }
        'exit code {0}' -f $code
    } | Out-Null

    Invoke-Step 'drivers into the Driver Store' {
        $root = Join-Path $WorkDir 'drivers'
        if (-not (Test-Path -LiteralPath $root)) { throw 'no drivers folder' }
        if ($Build -ge 14393) {
            $code = Invoke-Native 'pnputil.exe' @('/add-driver', (Join-Path $root '*.inf'), '/subdirs', '/install')
            # 259: no device of this kind here, which is what ESXi looks like
            if (@(0, 259, 3010) -notcontains $code) { throw ('pnputil exit code {0}' -f $code) }
            'pnputil exit code {0}' -f $code
        } else {
            $n = 0
            foreach ($inf in @(Get-ChildItem -LiteralPath $root -Filter '*.inf' -Recurse -File)) {
                $code = Invoke-Native 'pnputil.exe' @('-i', '-a', $inf.FullName)
                if (@(0, 259, 3010) -notcontains $code) { Write-Log ('    pnputil -i -a {0}: exit code {1}' -f $inf.Name, $code) }
                $n++
            }
            'pnputil -i -a for {0} INF file(s)' -f $n
        }
    } | Out-Null

    Invoke-Step 'guest agent' {
        if (Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue) { return 'installed' }
        if (-not $Cfg.agent_msi) { return 'no agent package on the ISO, PegaProx cannot talk to the guest after the move' }
        $msi = Join-Path $WorkDir $Cfg.agent_msi
        $log = Join-Path $WorkDir 'qemu-ga-install.log'
        $code = Invoke-Installer 'msiexec.exe' ('/i "{0}" /qn /norestart /l*v "{1}"' -f $msi, $log)
        if ($OK_INSTALL -notcontains $code) { throw ('msiexec exit code {0}, see {1}' -f $code, $log) }
        'msiexec exit code {0}' -f $code
    } | Out-Null

    Invoke-Step 'boot start storage drivers' {
        $done = @()
        if (Set-BootDriver 'vioscsi' 0x0A) { $done += 'vioscsi' }
        if (Set-BootDriver 'viostor' 1) { $done += 'viostor' }
        if (-not $done.Count) { throw 'neither vioscsi.sys nor viostor.sys is there' }
        if ($Cfg.sata_first_boot) {
            # the documented switch to AHCI: storahci starts at boot, so the first boot on
            # SATA does not depend on luck
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\storahci', $true)
            if ($k) {
                try {
                    $k.SetValue('Start', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
                    $k.DeleteSubKeyTree('StartOverride', $false)
                } finally { $k.Close() }
                $done += 'storahci'
            }
        }
        'Start 0: {0}' -f ($done -join ', ')
    } | Out-Null

    # Windows Server keeps a disk on a new controller offline and read-only (SAN policy
    # OfflineShared); every data disk is on a new controller under KVM
    Invoke-Step 'data disks online on the new controller' {
        $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SYSTEM\CurrentControlSet\Services\partmgr\Parameters')
        try {
            $was = $k.GetValue('SanPolicy')
            $k.SetValue('SanPolicy', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        } finally { $k.Close() }
        if ($null -eq $was) { 'SAN policy OnlineAll (was the default of the edition)' } else { 'SAN policy OnlineAll (was {0})' -f $was }
    } -BestEffort | Out-Null

    Invoke-Step 'save the static IPv4 configuration' {
        $adapters = Get-Adapters
        Write-JsonFile (Join-Path $WorkDir 'netconfig.json') @{ version = 1; source = 'guest'; run = $Cfg.run; adapters = $adapters }
        Set-AdminOwner (Join-Path $WorkDir 'netconfig.json')
        $static = @($adapters | Where-Object { -not $_.dhcp })
        '{0} adapter(s), {1} with static IPv4' -f @($adapters).Count, $static.Count
    } | Out-Null

    # what -Mode ToolsMedia accepts if the guest comes back to ESXi: an installer signed like these
    Invoke-Step 'signer of the ESXi guest tools' {
        $exe = Get-GuestToolsProgram
        if (-not $exe -or -not (Test-Path -LiteralPath $exe)) { return 'no guest tools service program, nothing saved' }
        $org = Get-SignerOrg $exe
        if (-not $org) { return 'their program carries no valid signature, a reinstall would be left to you' }
        [IO.File]::WriteAllText((Join-Path $WorkDir 'tools-signer.txt'), $org, $script:Utf8)
        $org
    } -BestEffort | Out-Null

    Invoke-Step 'first boot task' {
        if (-not (Test-Path -LiteralPath (Join-Path $WorkDir 'firstboot.cmd'))) {
            return 'no firstboot.cmd here (run by hand): PegaProx stages the first boot on Proxmox VE'
        }
        Register-FirstBootTask
        $TASK_FIRSTBOOT
    } | Out-Null
}

# ---------------------------------------------------------------------------- stage 2

function Find-AdapterConfig([string]$Mac) {
    foreach ($c in @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration)) {
        if ($c.MACAddress -and ([string]$c.MACAddress -ieq $Mac)) { return $c }
    }
    return $null
}

function Read-SavedAdapters {
    $j = Read-JsonFile (Join-Path $WorkDir 'netconfig.json')
    return ,@(Get-JsonProp $j 'adapters' | Where-Object { $null -ne $_ })
}

function Clear-StaticIPv4($Saved) {
    $n = 0
    foreach ($a in @($Saved)) {
        if ($a.dhcp) { continue }
        $c = Find-AdapterConfig $a.mac
        if (-not $c) { Write-Log ('    no adapter with MAC {0} any more' -f $a.mac); continue }
        $r = $c.EnableDHCP()
        Write-Log ('    {0}: DHCP on (result {1})' -f $a.mac, $r.ReturnValue)
        $r = $c.SetDNSServerSearchOrder()
        foreach ($g in @($a.gateway)) {
            if ($g -and [string]$g.ip -match $IPV4_RE) {
                Invoke-Native 'route.exe' @('delete', '0.0.0.0', 'mask', '0.0.0.0', [string]$g.ip) | Out-Null
            }
        }
        $n++
    }
    '{0} adapter(s) released' -f $n
}

function Uninstall-GuestTools {
    $code = Find-GuestToolsUninstall
    if (-not $code) { return 'no uninstall entry of the ESXi guest tools found, they stay installed' }
    $log = Join-Path $WorkDir 'guest-tools-uninstall.log'
    $rc = Invoke-Installer 'msiexec.exe' ('/x {0} /qn /norestart REBOOT=ReallySuppress /l*v "{1}"' -f $code, $log)
    if (@(0, 1605, 1641, 3010) -notcontains $rc) { throw ('msiexec /x exit code {0}, see {1}' -f $rc, $log) }
    'msiexec /x exit code {0}' -f $rc
}

# What keeps "the IP address is already assigned to another adapter" away once the old adapter
# is a hidden device: its interface has no address left in the registry
function Clear-InterfaceRegistry($Saved) {
    $n = 0
    foreach ($a in @($Saved)) {
        if ($a.dhcp -or -not ([string]$a.setting_id -match '^\{[0-9A-Fa-f-]{36}\}$')) { continue }
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $a.setting_id, $true)
        if (-not $k) { continue }
        try {
            $k.SetValue('EnableDHCP', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
            foreach ($name in 'IPAddress', 'SubnetMask', 'DefaultGateway', 'DefaultGatewayMetric') {
                $k.SetValue($name, [string[]]@(), [Microsoft.Win32.RegistryValueKind]::MultiString)
            }
            $k.SetValue('NameServer', '', [Microsoft.Win32.RegistryValueKind]::String)
        } finally { $k.Close() }
        $n++
    }
    '{0} interface(s) cleared' -f $n
}

function Invoke-Stage2([bool]$Shutdown) {
    $saved = Read-SavedAdapters
    # the address goes first, while the adapter still has its driver: the uninstall of the
    # ESXi guest tools takes the vmxnet3 driver and with it the adapter
    Invoke-Step 'release the static IPv4' { Clear-StaticIPv4 $saved } -BestEffort | Out-Null
    Invoke-Step 'uninstall the ESXi guest tools' { Uninstall-GuestTools } -BestEffort | Out-Null
    Invoke-Step 'registry pass of the saved interfaces' { Clear-InterfaceRegistry $saved } -BestEffort | Out-Null
    # the first boot task on ESXi (a migration given up) puts the guest back only after this
    try {
        [IO.File]::WriteAllText((Join-Path $WorkDir 'released.flag'), 'released', $script:Utf8)
        Set-AdminOwner (Join-Path $WorkDir 'released.flag')
    } catch { Write-Log ('released.flag: {0}' -f $_.Exception.Message) }
    if (-not $Shutdown) {
        Write-Log 'not shut down (-NoShutdown): shut the guest down, migrate it, and do not power it on again on ESXi'
        return
    }
    Write-Log 'shutting down; migrate the guest now, do not power it on again on ESXi'
    # a full shutdown, not the hybrid one: the offline steps after it want a clean NTFS
    Invoke-Native 'shutdown.exe' @('/s', '/t', '5', '/f', '/d', 'p:4:1') | Out-Null
    Remove-PegaTask $TASK_PREPARE
}

# ---------------------------------------------------------------------------- the modes

function Invoke-Probe {
    $here = Split-Path -Parent $PSCommandPath
    if (-not (Test-Elevated)) {
        # without the work folder: a filtered token (UAC) is all the account got here
        Write-JsonFile (Join-Path $here 'probe.json') @{ ok = $false; elevated = $false }
        exit 10
    }
    Initialize-WorkDir
    $script:LogReady = $true
    Write-Log 'probe: the work folder is locked to SYSTEM and Administrators'
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $WorkDir $SCRIPT_NAME) -Force
    Remove-StaleFiles
    Write-JsonFile (Join-Path $WorkDir 'probe.json') (Get-ProbeData)
    exit 0
}

function Invoke-Start {
    $script:LogReady = $true
    foreach ($n in 'go.flag', 'abort.flag', 'status.json') {
        $p = Join-Path $WorkDir $n
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
    }
    # an older run still waiting for its go would take this start
    try { Stop-ScheduledTask -TaskName $TASK_PREPARE -ErrorAction SilentlyContinue } catch { }
    Register-PegaTask -Name $TASK_PREPARE -TaskMode 'Run'
    Start-ScheduledTask -TaskName $TASK_PREPARE
    Write-Log ('start: task {0} started' -f $TASK_PREPARE)
    exit 0
}

function Invoke-Run {
    $script:LogReady = $true
    try {
        $cfg = Read-Config
    } catch {
        Write-Log ('pegaprox.json: {0}' -f $_.Exception.Message)
        Write-Status 'failed' $_.Exception.Message
        exit 1
    }
    $script:RunId = $cfg.run
    Write-Log ('=== run {0} ===' -f $cfg.run)
    Write-Status 'stage1' $null
    $build = [int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
    try {
        Invoke-Stage1 $cfg $build
    } catch {
        Write-Log ('stage 1 failed: {0}. Nothing destructive ran, the guest stays as it is on ESXi' -f $_.Exception.Message)
        Write-Status 'failed' $_.Exception.Message
        Remove-PegaTask $TASK_FIRSTBOOT
        Remove-PegaTask $TASK_PREPARE
        exit 1
    }
    Write-Status 'ready' $null
    Write-Log 'stage 1 done, waiting for PegaProx to start the switchover'
    $deadline = (Get-Date).AddSeconds($cfg.go_wait_seconds)
    $go = Join-Path $WorkDir 'go.flag'
    $abort = Join-Path $WorkDir 'abort.flag'
    $why = ''
    while ($true) {
        if (Test-Path -LiteralPath $abort) { $why = 'PegaProx called the switchover off'; break }
        if (Test-Path -LiteralPath $go) { break }
        if ((Get-Date) -ge $deadline) { $why = ('no switchover within {0}s' -f $cfg.go_wait_seconds); break }
        Start-Sleep -Seconds 5
    }
    if ($why) {
        Write-Log ('aborted: {0}. The VirtIO drivers and guest tools stay installed, harmless on ESXi' -f $why)
        Write-Status 'aborted' $why
        Remove-PegaTask $TASK_FIRSTBOOT
        Remove-PegaTask $TASK_PREPARE
        exit 0
    }
    Write-Status 'stage2' $null
    Write-Log 'go: releasing the network, uninstalling the ESXi guest tools, shutting down'
    Invoke-Stage2 $true
    exit 0
}

# back on ESXi after a migration that was given up, run by firstboot.cmd as SYSTEM: the guest
# tools installer PegaProx mounted, from a CD drive only, signed by the publisher saved in stage 1,
# copied into the work folder (no user can write there) and checked again; exit 0 once
# tools-setup.exe is that copy. Nothing found elsewhere is ever started.
function Invoke-ToolsMedia {
    $script:LogReady = $true
    $dest = Join-Path $WorkDir 'tools-setup.exe'
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
    $saved = Join-Path $WorkDir 'tools-signer.txt'
    $want = ''
    if (Test-Path -LiteralPath $saved) { $want = ([IO.File]::ReadAllText($saved)).Trim() }
    if (-not $want) {
        Write-Log 'tools media: no signer of the old guest tools was saved, no installer is started'
        exit 3
    }
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    $name = 'setup.exe'
    if ($arch -ne 'x86') { $name = 'setup64.exe' }
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ([string]$d.DriveType -ne 'CDRom' -or -not $d.IsReady) { continue }
        $src = Join-Path $d.RootDirectory.FullName $name
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { continue }
        if ((Get-SignerOrg $src) -ne $want) {
            Write-Log ('tools media: {0} is not signed by {1}, not used' -f $src, $want)
            continue
        }
        Copy-Item -LiteralPath $src -Destination $dest -Force
        if ((Get-SignerOrg $dest) -eq $want) {
            Write-Log ('tools media: {0} (signed by {1}) copied to {2}' -f $src, $want, $dest)
            exit 0
        }
        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
    }
    exit 2
}

function Find-VirtioMedia {
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ([string]$d.DriveType -ne 'CDRom' -or -not $d.IsReady) { continue }
        $root = $d.RootDirectory.FullName
        if ((Test-Path (Join-Path $root 'vioscsi')) -and
            ((Test-Path (Join-Path $root 'virtio-win-guest-tools.exe')) -or (Test-Path (Join-Path $root 'virtio-win-gt-x64.msi')))) {
            return $root
        }
    }
    return $null
}

function Invoke-Manual {
    if (-not (Test-Elevated)) {
        Write-Host 'Run this in a PowerShell started as administrator.'
        exit 10
    }
    Initialize-WorkDir
    $script:LogReady = $true
    $script:RunId = 'manual'
    Write-Log '=== run manual ==='
    if ($PSCommandPath -and ((Split-Path -Parent $PSCommandPath) -ne $WorkDir)) {
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $WorkDir $SCRIPT_NAME) -Force
    }
    $media = Find-VirtioMedia
    if (-not $media) { throw 'mount virtio-win.iso in this guest first (no CD drive with vioscsi and the guest tools found)' }
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    if ($build -lt 9200) { throw ('Windows build {0}: Windows 8 / Server 2012 or newer is needed' -f $build) }
    $folders = @(Get-DriverFolders $build ([int]$os.ProductType -ne 1))
    $dest = Join-Path $WorkDir 'drivers'
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $copied = @()
    foreach ($drv in 'viostor', 'vioscsi', 'NetKVM', 'Balloon', 'pvpanic', 'qemupciserial', 'vioserial', 'viorng') {
        foreach ($f in $folders) {
            $src = Join-Path $media ('{0}\{1}\amd64' -f $drv, $f)
            if ((Test-Path $src) -and @(Get-ChildItem -LiteralPath $src -Filter '*.sys' -File).Count) {
                Copy-Item -LiteralPath $src -Destination (Join-Path $dest $drv) -Recurse -Force
                $copied += ('{0} ({1})' -f $drv, $f)
                break
            }
        }
    }
    Write-Log ('drivers from {0}: {1}' -f $media, ($copied -join ', '))
    $cfg = Read-Config
    $cfg.drivers = @()
    foreach ($n in 'virtio-win-guest-tools.exe', 'virtio-win-gt-x64.msi') {
        if (Test-Path (Join-Path $media $n)) {
            Copy-Item -LiteralPath (Join-Path $media $n) -Destination (Join-Path $WorkDir $n) -Force
            $cfg.installer = $n
            break
        }
    }
    $agent = Join-Path $media 'guest-agent\qemu-ga-x86_64.msi'
    if (Test-Path $agent) {
        Copy-Item -LiteralPath $agent -Destination (Join-Path $WorkDir 'qemu-ga-x86_64.msi') -Force
        $cfg.agent_msi = 'qemu-ga-x86_64.msi'
    }
    Invoke-Stage1 $cfg $build
    Invoke-Stage2 (-not $NoShutdown)
}

try {
    switch ($Mode) {
        'Probe' { Invoke-Probe }
        'Start' { Invoke-Start }
        'Run' { Invoke-Run }
        'Manual' { Invoke-Manual }
        'ToolsMedia' { Invoke-ToolsMedia }
    }
    exit 0
} catch {
    Write-Log ('FAILED: {0}' -f $_.Exception.Message)
    if ($Mode -eq 'Manual') { Write-Host ('FAILED: {0}' -f $_.Exception.Message) }
    exit 1
}
