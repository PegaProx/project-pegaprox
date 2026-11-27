"""The work folder in the guest is locked without emptying the ACL of the files in it.

Seen on a lab run of Windows Server 2025 with the in-guest preparation: after stage 2 every
file in C:\\ProgramData\\KVMMigration had an ACL without a single entry. The first boot task
(SYSTEM) could not open firstboot.cmd, so the static IPv4 never reached the new adapters, and
the guest agent got "Access is denied" for firstboot.json. The cause, reproduced on that
guest: `icacls <folder> /inheritance:r /grant:r SYSTEM:(OI)(CI)F ... /T` takes from each file
what it inherited and grants it nothing, since (OI)(CI) means nothing on a file. icacls says
"Successfully processed" all the same. Both scripts locked the folder that way.

Now the grants go on the folder only and the files take them over with /reset. Run on the
same Windows guest, the old lines left every file empty and the new ones left SYSTEM and the
Administrators on each, a file with an explicit Everyone entry (as ntfs-3g writes) included.
These tests hold the scripts to that; PowerShell and cmd do not run here.
"""
import pathlib
import re

CORE = pathlib.Path(__file__).resolve().parent.parent / 'pegaprox' / 'core'
PS1 = (CORE / 'v2p_guestprep.ps1').read_text(encoding='utf-8')
CMD = (CORE / 'v2p_firstboot.cmd').read_text(encoding='ascii')


def _function(name):
    i = PS1.index(f'function {name}')
    return PS1[i:PS1.index('\n}\n', i)]


def _code(lines):
    return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith(('#', 'rem '))]


def test_the_powershell_lock_grants_on_the_folder_only_and_resets_the_files():
    body = _function('Initialize-WorkDir')
    calls = re.findall(r"Invoke-Native 'icacls\.exe' @\((.*?)\)\n", body, re.S)
    grant = [c for c in calls if "'/inheritance:r'" in c]
    assert len(grant) == 1 and "'/T'" not in grant[0], grant
    reset = [c for c in calls if "'/reset'" in c]
    assert len(reset) == 1 and "'/T'" in reset[0] and "Join-Path $WorkDir '*'" in reset[0], reset
    # an empty folder has nothing to reset, and icacls fails on a pattern without a match
    assert 'Get-ChildItem -LiteralPath $WorkDir -Force | Select-Object -First 1' in body


def test_the_powershell_lock_checks_that_system_can_read_every_file():
    body = _function('Initialize-WorkDir')
    assert 'Get-ChildItem -LiteralPath $WorkDir -Force -Recurse' in body
    assert '-notcontains $SID_SYSTEM' in body and 'throw' in body.split('-notcontains $SID_SYSTEM', 1)[1][:200]


def test_firstboot_cmd_grants_on_the_folder_only_and_resets_the_files():
    acl = [ln for ln in _code(CMD.splitlines()) if ln.startswith('icacls ')]
    folder = [ln for ln in acl if ln.startswith('icacls "%W%" ')]
    assert any('/inheritance:r' in ln for ln in folder)
    for ln in folder:
        if '/inheritance:r' in ln or '/remove:g' in ln:
            assert ' /T ' not in ln, ln
    assert any(ln.startswith('icacls "%W%\\*" /reset /T') for ln in acl), acl
    # the reset comes after the folder has the grants the files take over
    order = [i for i, ln in enumerate(acl) if '/inheritance:r' in ln] + \
            [i for i, ln in enumerate(acl) if '/reset' in ln]
    assert order == sorted(order), acl
