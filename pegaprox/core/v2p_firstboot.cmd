@echo off
rem PegaProx: the first boot of a Windows guest moved from ESXi to Proxmox VE (KVM)
rem
rem MK Nov 2026 - PegaProx puts this script, firstboot-data.cmd and the VirtIO packages into
rem %SystemDrive%\ProgramData\KVMMigration of the copied boot disk and registers the one-shot
rem SYSTEM service PegaProxFirstBoot, which starts it with "kvm". A guest prepared on ESXi with
rem a Windows login also has the scheduled task PegaProxKvmFirstBoot ("auto"): on ESXi, after a
rem migration that was given up, it puts the guest back as it was.
rem
rem On Proxmox VE: the VirtIO drivers and the guest agent installed, vioscsi and viostor start
rem at boot, the old adapter's interface holds no address any more (no "address already
rem assigned"), the saved static IPv4 goes onto the new adapter (by MAC, else by order), the old
rem adapters are removed where pnputil can, the ESXi guest tools are uninstalled. Each step runs
rem once (a .done file), every step goes to migrate.log, the script removes its service and task.
rem
rem Console tools only (reg, sc, netsh, pnputil, msiexec, route): no execution policy stops it.
rem PowerShell only back on ESXi, where nothing else checks the signature of the guest tools
rem installer. ASCII only. The values come from firstboot-data.cmd, which PegaProx checks.

setlocal EnableExtensions EnableDelayedExpansion
set "W=%~dp0"
if "%W:~-1%"=="\" set "W=%W:~0,-1%"
set "LOG=%W%\migrate.log"
set "MODE=%~1"
if /i not "%MODE%"=="auto" set "MODE=kvm"

rem a folder that is a junction or a link points somewhere else: nothing is run, nothing written
set "WATTR=-"
for %%I in ("%W%") do set "WATTR=%%~aI"
if not "!WATTR:l=!"=="!WATTR!" exit /b 1

rem the folder belongs to SYSTEM and the Administrators before anything in it runs (by SID),
rem without the grants a file written on Linux gets (Everyone) or a user of the guest left
icacls "%W%" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /T /C /Q >nul 2>&1
icacls "%W%" /remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545 *S-1-5-4 /T /C /Q >nul 2>&1
icacls "%W%" /setowner *S-1-5-32-544 /T /C /Q >nul 2>&1

if not exist "%W%\firstboot-data.cmd" goto :nodata
call "%W%\firstboot-data.cmd"
if not defined KM_RUN goto :nodata
if not defined KM_NICS set "KM_NICS=0"

call :platform
if /i "%MODE%"=="auto" if not "%PLATFORM%"=="kvm" goto :source
if /i "%MODE%"=="auto" (
    rem on Proxmox VE the service does the work when it is there
    sc query PegaProxFirstBoot >nul 2>&1
    if not errorlevel 1 exit /b 0
)
goto :kvm

:nodata
set "MSG=first boot task: firstboot-data.cmd is missing or empty, nothing to do"
call :log
exit /b 1

rem ============================================================================ Proxmox VE

:kvm
call :boots
set "MSG==== first boot on Proxmox VE, run %KM_RUN%, boot !BOOTS! ==="
call :log
set "TARGET=MAC"
set "TOOLS=kept"
set "DEVS=kept"
set "NET_OK=1"
if exist "%W%\firstboot.nics" del /q "%W%\firstboot.nics" >nul 2>&1

rem --- the VirtIO drivers and the balloon service of virtio-win
if exist "%W%\drivers.done" goto :agent
if not defined KM_DRIVER_MSI goto :agent
if not exist "%W%\%KM_DRIVER_MSI%" (
    set "MSG=step drivers: %KM_DRIVER_MSI% is not there, skipped"
    call :log
    goto :agent
)
set "MSIARGS=/i "%W%\%KM_DRIVER_MSI%" ADDLOCAL=ALL /qn /norestart /l*v "%W%\virtio-win-install.log""
call :msiexec
call :okcode 0 1641 3010
set "MSG=step drivers: msiexec %KM_DRIVER_MSI% exit code !RC!"
call :log
if "!OK!"=="1" (echo done>"%W%\drivers.done")

:agent
rem --- the guest agent, a package of its own on the ISO
sc query QEMU-GA >nul 2>&1
if not errorlevel 1 if not exist "%W%\agent.done" (echo done>"%W%\agent.done")
if exist "%W%\agent.done" goto :agent_start
if not defined KM_AGENT_MSI (
    set "MSG=step guest agent: no package for it on the ISO, PegaProx cannot talk to the guest"
    call :log
    goto :bootdrivers
)
if not exist "%W%\%KM_AGENT_MSI%" (
    set "MSG=step guest agent: %KM_AGENT_MSI% is not there, skipped"
    call :log
    goto :bootdrivers
)
set "MSIARGS=/i "%W%\%KM_AGENT_MSI%" /qn /norestart /l*v "%W%\qemu-ga-install.log""
call :msiexec
call :okcode 0 1641 3010
set "MSG=step guest agent: msiexec %KM_AGENT_MSI% exit code !RC!"
call :log
if "!OK!"=="1" (echo done>"%W%\agent.done")
:agent_start
sc start QEMU-GA >nul 2>&1

:bootdrivers
rem --- the storage drivers start at boot: the boot disk can move to VirtIO SCSI or VirtIO Block
for %%s in (vioscsi viostor) do (
    sc qc %%s >nul 2>&1
    if not errorlevel 1 (
        sc config %%s start= boot >nul 2>&1
        set "MSG=step %%s starts at boot: sc exit code !errorlevel!"
        call :log
    )
)

rem --- the network
if exist "%W%\net.done" goto :devices
if "%KM_NICS%"=="0" (
    set "MSG=step network: no adapter had a static IPv4 address, nothing to put back"
    call :log
    echo done>"%W%\net.done"
    goto :devices
)
call :network
if "!NET_OK!"=="1" (echo done>"%W%\net.done")

:devices
rem --- the old adapters, hidden devices now
if exist "%W%\devices.done" (
    set "DEVS=removed"
    goto :tools
)
if not "%KM_REMOVE_DEVICES%"=="1" (
    set "MSG=step old adapters: pnputil of build %KM_BUILD% cannot remove devices, they stay hidden and hold no address"
    call :log
    echo done>"%W%\devices.done"
    goto :tools
)
if not defined KM_OLDDEVS set "KM_OLDDEVS=0"
for /l %%n in (1,1,%KM_OLDDEVS%) do (
    if defined KM_OLDDEV%%n (
        pnputil /remove-device "!KM_OLDDEV%%n!" >>"%LOG%" 2>&1
        set "MSG=step old adapter !KM_OLDDEV%%n!: pnputil /remove-device exit code !errorlevel!"
        call :log
    )
)
set "DEVS=removed"
echo done>"%W%\devices.done"

:tools
rem --- the ESXi guest tools, never while a disk or a NIC still runs on one of their drivers
if exist "%W%\tools.done" (
    set /p TOOLS=<"%W%\tools.done"
    goto :finish
)
if not "%KM_TOOLS_UNINSTALL%"=="1" (
    set "MSG=step ESXi guest tools: left installed (no uninstall entry found, or the VM keeps a device of theirs)"
    call :log
    goto :tools_done
)
call :bound pvscsi
if "!BOUND!"=="1" (
    set "MSG=step ESXi guest tools: a disk controller still runs on pvscsi, they stay installed"
    call :log
    goto :tools_done
)
call :bound vmxnet3ndis6
if "!BOUND!"=="1" (
    set "MSG=step ESXi guest tools: a NIC still runs on vmxnet3, they stay installed"
    call :log
    goto :tools_done
)
set "MSIARGS=/x %KM_TOOLS_CODE% /qn /norestart REBOOT=ReallySuppress /l*v "%W%\guest-tools-uninstall.log""
call :msiexec
call :okcode 0 1605 1641 3010
if "!OK!"=="1" (
    set "TOOLS=removed"
    set "MSG=step ESXi guest tools: uninstalled, msiexec exit code !RC!"
) else (
    sc config VMTools start= disabled >nul 2>&1
    sc stop VMTools >nul 2>&1
    set "TOOLS=disabled"
    set "MSG=step ESXi guest tools: msiexec /x exit code !RC!, see guest-tools-uninstall.log; their service is disabled"
)
call :log
:tools_done
(echo !TOOLS!)>"%W%\tools.done"

:finish
set "STATE=applied"
if "!NET_OK!"=="0" (
    set "STATE=partial"
    if !BOOTS! geq 3 set "STATE=failed"
)
call :report kvm
if "!STATE!"=="partial" (
    set "MSG=not every address is back, the next boot tries again"
    call :log
    exit /b 0
)
if defined KM_DRIVER_MSI if exist "%W%\%KM_DRIVER_MSI%" del /q "%W%\%KM_DRIVER_MSI%" >nul 2>&1
if defined KM_AGENT_MSI if exist "%W%\%KM_AGENT_MSI%" del /q "%W%\%KM_AGENT_MSI%" >nul 2>&1
schtasks /delete /tn PegaProxKvmFirstBoot /f >nul 2>&1
sc delete PegaProxFirstBoot >nul 2>&1
set "MSG=done (!STATE!), the first boot service and task are removed"
call :log
exit /b 0

rem ============================================================================ back on ESXi

:source
rem nothing was released in the guest: it was never handed over, nothing to put back
if not exist "%W%\released.flag" exit /b 0
call :boots
set "MSG==== back on ESXi, run %KM_RUN%: the migration was given up, boot !BOOTS! ==="
call :log
set "TARGET=SRCMAC"
set "TOOLS=kept"
set "DEVS=kept"
set "NET_OK=1"
if exist "%W%\firstboot.nics" del /q "%W%\firstboot.nics" >nul 2>&1
sc query VMTools >nul 2>&1
if errorlevel 1 call :tools_back
if not "%KM_NICS%"=="0" call :network
set "STATE=restored"
if "!NET_OK!"=="0" (
    set "STATE=partial"
    if !BOOTS! geq 5 set "STATE=failed"
)
call :report esxi
if "!STATE!"=="partial" (
    set "MSG=not every address is back, the next boot tries again"
    call :log
    exit /b 0
)
del /q "%W%\released.flag" >nul 2>&1
schtasks /delete /tn PegaProxKvmFirstBoot /f >nul 2>&1
set "MSG=done (!STATE!), the first boot task is removed"
call :log
exit /b 0

:tools_back
rem the ESXi guest tools again, from the installer CD PegaProx mounted. Nothing found on a drive
rem is started: Prepare-KvmMigration.ps1 -Mode ToolsMedia takes the installer from a CD drive
rem only, checks that it is signed by the publisher of the guest tools this guest had (saved
rem before they were uninstalled), copies it into this folder and checks the copy; only that
rem copy runs. A user of the guest can write to a data volume or mount an ISO, not here.
set "TCD=%W%\tools-setup.exe"
set "PSX=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "!TCD!" del /q "!TCD!" >nul 2>&1
if not exist "%W%\Prepare-KvmMigration.ps1" (
    set "MSG=step ESXi guest tools: Prepare-KvmMigration.ps1 is not here, install them by hand"
    call :log
    goto :eof
)
set /a WAITED=0
:tools_cd
set "FOUND=0"
"!PSX!" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%W%\Prepare-KvmMigration.ps1" -Mode ToolsMedia -WorkDir "%W%" >nul 2>&1
if not errorlevel 1 if exist "!TCD!" set "FOUND=1"
if "!FOUND!"=="0" if !WAITED! lss 900 (
    ping -n 11 127.0.0.1 >nul
    set /a WAITED+=10
    goto :tools_cd
)
if "!FOUND!"=="0" (
    set "MSG=step ESXi guest tools: no installer signed like the old guest tools on a CD drive within 15 min, install them by hand"
    call :log
    goto :eof
)
start "" /wait "!TCD!" /s /v"/qn REBOOT=R"
set "RC=!errorlevel!"
call :okcode 0 1641 3010
set "TOOLS=reinstalled"
if not "!OK!"=="1" set "TOOLS=failed"
set "MSG=step ESXi guest tools: the checked installer from the CD, exit code !RC!"
call :log
del /q "!TCD!" >nul 2>&1
goto :eof

rem ============================================================================ helpers

:network
rem every saved adapter gets the adapter with its MAC (TARGET: MAC on Proxmox VE, SRCMAC on
rem ESXi), the others the adapters left over in order; waits up to 10 min for the adapters
set /a WAITED=0
:network_wait
call :scan
call :assign
if !UNMATCHED! gtr 0 if !WAITED! lss 600 (
    ping -n 11 127.0.0.1 >nul
    set /a WAITED+=10
    goto :network_wait
)
for /l %%n in (1,1,%KM_NICS%) do call :apply %%n
goto :eof

:scan
rem the interface list of route print: " 12...bc 24 11 aa bb cc ......Red Hat VirtIO Ethernet Adapter";
rem exactly six octets and then the dots (tunnel adapters show eight, the loopback none)
set /a A_COUNT=0
for /f "tokens=1,2 delims=." %%a in ('route print ^| findstr /r /i /c:"^ *[0-9][0-9]*\.\.\.[0-9a-f][0-9a-f] .. .. .. .. .. \."') do (
    set "AI=%%a"
    set "AM=%%b"
    set "AM=!AM: =!"
    if not "!AM:~11,1!"=="" if "!AM:~12!"=="" (
        set /a A_COUNT+=1
        set "A!A_COUNT!_IDX=!AI: =!"
        set "A!A_COUNT!_MAC=!AM!"
    )
)
goto :eof

:assign
set /a UNMATCHED=0
for /l %%k in (1,1,!A_COUNT!) do set "A%%k_TAKEN="
for /l %%n in (1,1,%KM_NICS%) do (
    set "NIDX%%n="
    set "NBY%%n="
    if defined KM_NIC%%n_%TARGET% (
        for /l %%k in (1,1,!A_COUNT!) do (
            if /i "!A%%k_MAC!"=="!KM_NIC%%n_%TARGET%!" (
                set "NIDX%%n=!A%%k_IDX!"
                set "NBY%%n=mac"
                set "A%%k_TAKEN=1"
            )
        )
        if not defined NIDX%%n set /a UNMATCHED+=1
    )
)
for /l %%n in (1,1,%KM_NICS%) do (
    if not defined NIDX%%n (
        set "PICK="
        for /l %%k in (1,1,!A_COUNT!) do if not defined PICK if not defined A%%k_TAKEN set "PICK=%%k"
        if defined PICK (
            for %%p in (!PICK!) do (
                set "NIDX%%n=!A%%p_IDX!"
                set "NBY%%n=order"
                set "A%%p_TAKEN=1"
            )
        ) else (
            if not defined KM_NIC%%n_%TARGET% set /a UNMATCHED+=1
        )
    )
)
goto :eof

:apply
set "N=%~1"
set "IDX=!NIDX%N%!"
set "IP=!KM_NIC%N%_IP1!"
if not defined IDX (
    set "NET_OK=0"
    set "MSG=step network: no adapter found for !IP! (MAC !KM_NIC%N%_%TARGET%!)"
    call :log
    >>"%W%\firstboot.nics" echo {"n":%N%,"ip":"!IP!","applied":false,"why":"no adapter"}
    goto :eof
)
if "%TARGET%"=="MAC" (
    rem the old interface holds no address any more: Windows would call it in use
    set "K=HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\!KM_NIC%N%_GUID!"
    reg add "!K!" /v EnableDHCP /t REG_DWORD /d 1 /f >nul 2>&1
    for %%v in (IPAddress SubnetMask DefaultGateway DefaultGatewayMetric) do reg add "!K!" /v %%v /t REG_MULTI_SZ /d "" /f >nul 2>&1
    reg add "!K!" /v NameServer /t REG_SZ /d "" /f >nul 2>&1
    set "MSG=step network: the old interface !KM_NIC%N%_GUID! holds no address any more"
    call :log
)
set "GWARG=gateway=none"
if !KM_NIC%N%_GWS! geq 1 (
    set "GWARG=gateway=!KM_NIC%N%_GW1!"
    if not "!KM_NIC%N%_GWM1!"=="0" set "GWARG=!GWARG! gwmetric=!KM_NIC%N%_GWM1!"
)
set /a TRY=0
:apply_again
set /a TRY+=1
netsh interface ipv4 set address name=!IDX! source=static address=!IP! mask=!KM_NIC%N%_MASK1! !GWARG! >>"%LOG%" 2>&1
set "RC=!errorlevel!"
if not "!RC!"=="0" if !TRY! lss 6 (
    ping -n 6 127.0.0.1 >nul
    goto :apply_again
)
if not "!RC!"=="0" (
    set "NET_OK=0"
    set "MSG=step network: netsh could not put !IP! on interface !IDX! (exit code !RC!)"
    call :log
    >>"%W%\firstboot.nics" echo {"n":%N%,"ip":"!IP!","index":"!IDX!","by":"!NBY%N%!","applied":false,"why":"netsh exit code !RC!"}
    goto :eof
)
for /l %%k in (2,1,!KM_NIC%N%_IPS!) do (
    netsh interface ipv4 add address name=!IDX! address=!KM_NIC%N%_IP%%k! mask=!KM_NIC%N%_MASK%%k! >>"%LOG%" 2>&1
)
for /l %%k in (2,1,!KM_NIC%N%_GWS!) do (
    set "GM="
    if not "!KM_NIC%N%_GWM%%k!"=="0" set "GM=gwmetric=!KM_NIC%N%_GWM%%k!"
    netsh interface ipv4 add address name=!IDX! gateway=!KM_NIC%N%_GW%%k! !GM! >>"%LOG%" 2>&1
)
set /a D=0
for %%d in (!KM_NIC%N%_DNS!) do (
    set /a D+=1
    if !D! equ 1 (
        netsh interface ipv4 set dnsservers name=!IDX! source=static address=%%d register=primary validate=no >>"%LOG%" 2>&1
        if errorlevel 1 netsh interface ipv4 set dnsservers name=!IDX! source=static address=%%d register=primary >>"%LOG%" 2>&1
    ) else (
        netsh interface ipv4 add dnsservers name=!IDX! address=%%d index=!D! validate=no >>"%LOG%" 2>&1
        if errorlevel 1 netsh interface ipv4 add dnsservers name=!IDX! address=%%d index=!D! >>"%LOG%" 2>&1
    )
)
set "MSG=step network: !IP!/!KM_NIC%N%_MASK1! put on interface !IDX! (by !NBY%N%!), !KM_NIC%N%_IPS! address(es), !KM_NIC%N%_GWS! gateway(s), DNS !KM_NIC%N%_DNS!"
call :log
>>"%W%\firstboot.nics" echo {"n":%N%,"ip":"!IP!","index":"!IDX!","by":"!NBY%N%!","applied":true}
goto :eof

:report
rem firstboot.json, which PegaProx reads through the guest agent
set "SEP="
> "%W%\firstboot.json" (
    echo {"version":1,"run":"%KM_RUN%","platform":"%~1","state":"!STATE!","boots":!BOOTS!,"tools":"!TOOLS!","devices":"!DEVS!","adapters":[
    if exist "%W%\firstboot.nics" for /f "usebackq delims=" %%l in ("%W%\firstboot.nics") do (
        echo !SEP!%%l
        set "SEP=,"
    )
    echo ]}
)
goto :eof

:msiexec
rem msiexec, again while another installation holds the installer (1618), up to 5 min
set /a TRY=0
:msiexec_again
set /a TRY+=1
start "" /wait msiexec.exe %MSIARGS%
set "RC=!errorlevel!"
if "!RC!"=="1618" if !TRY! lss 20 (
    ping -n 16 127.0.0.1 >nul
    goto :msiexec_again
)
goto :eof

:okcode
set "OK=0"
for %%c in (%*) do if "!RC!"=="%%c" set "OK=1"
goto :eof

:bound
rem BOUND=1 when a present device runs on the driver %1 (its Enum\Count, this boot)
set "BOUND=0"
set "BC=0"
for /f "tokens=3" %%c in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\%~1\Enum" /v Count 2^>nul ^| findstr /i /c:"REG_DWORD"') do set /a "BC=%%c" >nul 2>&1
if !BC! gtr 0 set "BOUND=1"
goto :eof

:platform
set "PLATFORM=source"
reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemManufacturer 2>nul | findstr /i /c:"QEMU" >nul && set "PLATFORM=kvm"
if "%PLATFORM%"=="source" reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v SystemProductName 2>nul | findstr /i /c:"Standard PC" >nul && set "PLATFORM=kvm"
goto :eof

:boots
set "BOOTS=0"
if exist "%W%\boots.txt" set /p BOOTS=<"%W%\boots.txt"
set /a BOOTS+=1 >nul 2>&1
> "%W%\boots.txt" echo !BOOTS!
goto :eof

:log
>> "%LOG%" echo(%date% %time% !MSG!
goto :eof
