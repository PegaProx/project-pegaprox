"""A firmware picked by hand that the source does not boot with (#1253).

SeaBIOS for a guest that boots with UEFI on ESXi (or OVMF for one on legacy BIOS) was applied
without a word, and the guest stopped at "Booting from Hard Disk" after the whole copy. The
choice is still applied as asked, but the plan says it: the wizard's review step and each guest
of a bulk check list the plan's warnings. A run started without a dry run logs it and keeps it
on its result.

A firmware nobody read gives no warning at all.

MK Nov 2026
"""
import pytest

import pegaprox.core.v2p as v2p

from test_esxi_mapping_verify import Run, route  # noqa: F401 (route is a fixture)
from test_esxi_bulk import env  # noqa: F401 (env is a fixture)


def _soap(firmware):
    return {'name': 'app01', 'hardware': {'firmware': firmware, 'secure_boot': False, 'has_tpm': False}}


def _rest(boot_type):
    # the vSphere REST model: hardware holds the version, the firmware is in boot.type
    return {'name': 'app01', 'hardware': {'version': 'VMX_19', 'upgrade_policy': 'NEVER'},
            'boot': {'type': boot_type, 'delay': 0}}


def _fw(warnings):
    return [w for w in warnings if w.startswith('Firmware:')]


# --------------------------------------------------------------------------- the source

@pytest.mark.parametrize('detail,want', [
    (_soap('efi'), 'efi'), (_soap('bios'), 'bios'),
    (_rest('EFI'), 'efi'), (_rest('BIOS'), 'bios'),
    ({'name': 'app01'}, None), ({'hardware': {}}, None), ({'hardware': {'firmware': ''}}, None),
    (_soap('something-new'), None), (_rest(None), None), ({'boot': 'EFI'}, None),
    (None, None), ('EFI', None), ({'hardware': 'efi'}, None),
])
def test_what_the_source_boots_with(detail, want):
    assert v2p.source_firmware(detail) == want


def test_the_hardware_reading_wins_over_boot_type():
    assert v2p.source_firmware({'hardware': {'firmware': 'bios'}, 'boot': {'type': 'EFI'}}) == 'bios'


# --------------------------------------------------------------------------- the warning

def test_seabios_for_an_efi_source_says_it_will_not_boot_and_what_matches():
    msg = v2p.firmware_mismatch(_soap('efi'), 'seabios')
    assert msg and msg.startswith('Firmware:')
    assert 'boots with UEFI on ESXi' in msg and 'Legacy BIOS (SeaBIOS) is chosen' in msg
    assert 'most likely not boot' in msg
    assert 'UEFI (OVMF) (what Auto picks) matches the source' in msg


def test_ovmf_for_a_bios_source_says_it_will_not_boot_and_what_matches():
    msg = v2p.firmware_mismatch(_soap('bios'), 'ovmf')
    assert msg and 'boots with legacy BIOS on ESXi' in msg and 'UEFI (OVMF) is chosen' in msg
    assert 'most likely not boot' in msg
    assert 'Legacy BIOS (SeaBIOS) (what Auto picks) matches the source' in msg


@pytest.mark.parametrize('detail,bios', [
    (_soap('efi'), 'ovmf'), (_soap('efi'), 'auto'), (_soap('efi'), None), (_soap('efi'), ''),
    (_soap('bios'), 'seabios'), (_soap('bios'), 'auto'), (_soap('bios'), None),
    (_rest('EFI'), 'ovmf'), (_rest('BIOS'), 'seabios'), (_rest('BIOS'), 'auto'),
])
def test_a_firmware_that_matches_the_source_is_no_warning(detail, bios):
    assert v2p.firmware_mismatch(detail, bios) is None


@pytest.mark.parametrize('detail', [{'name': 'app01'}, {'hardware': {}}, _soap('something-new'), _rest(None),
                                    None, {}])
@pytest.mark.parametrize('bios', ['seabios', 'ovmf', 'auto'])
def test_an_unknown_source_firmware_is_no_warning(detail, bios):
    assert v2p.firmware_mismatch(detail, bios) is None


@pytest.mark.parametrize('bios', ['SeaBIOS', 'uefi', 'foo', 7])
def test_a_value_the_run_does_not_know_as_a_firmware_is_not_judged_here(bios):
    assert v2p.firmware_mismatch(_soap('efi'), bios) is None


def test_on_rest_auto_resolves_to_seabios_and_an_efi_source_is_warned_about():
    """The run resolves Auto from hardware.firmware only. A REST answer has none, so an EFI
    guest gets SeaBIOS on Auto, and the warning names the firmware to pick instead."""
    msg = v2p.firmware_mismatch(_rest('EFI'), 'auto')
    assert msg and 'boots with UEFI on ESXi' in msg and 'Auto gives it Legacy BIOS (SeaBIOS)' in msg
    assert 'most likely not boot' in msg and 'choose UEFI (OVMF)' in msg
    # picked by hand there, Auto is no way out either
    msg = v2p.firmware_mismatch(_rest('EFI'), 'seabios')
    assert msg and 'UEFI (OVMF) matches the source' in msg and 'what Auto picks' not in msg


# --------------------------------------------------------------------------- single dry run

def test_the_dry_run_of_the_wizard_lists_the_warning_for_seabios_on_an_efi_source(route):
    route.esxi.firmware = 'efi'
    p = route.post(dry_run=True, esxi_password=None, bios='seabios').get_json()
    assert p['dry_run'] is True and p['ok'] is True, p
    fw = _fw(p['warnings'])
    assert len(fw) == 1 and 'UEFI (OVMF)' in fw[0] and 'most likely not boot' in fw[0], p['warnings']
    assert route.started == []


def test_the_dry_run_lists_the_warning_for_ovmf_on_a_bios_source(route):
    route.esxi.firmware = 'bios'
    p = route.post(dry_run=True, esxi_password=None, bios='ovmf').get_json()
    assert p['ok'] is True
    fw = _fw(p['warnings'])
    assert len(fw) == 1 and 'Legacy BIOS (SeaBIOS)' in fw[0] and 'UEFI (OVMF) is chosen' in fw[0]


@pytest.mark.parametrize('firmware,bios', [('efi', 'ovmf'), ('efi', 'auto'), ('bios', 'seabios'),
                                           ('bios', 'auto'), ('efi', None)])
def test_the_dry_run_has_no_firmware_warning_when_it_matches(route, firmware, bios):
    route.esxi.firmware = firmware
    p = route.post(dry_run=True, esxi_password=None, bios=bios).get_json()
    assert p['ok'] is True and _fw(p['warnings']) == [], p['warnings']


@pytest.mark.parametrize('bios', ['seabios', 'ovmf', 'auto'])
def test_the_dry_run_has_no_firmware_warning_when_the_source_firmware_is_unknown(route, monkeypatch, bios):
    real = route.esxi.get_vm

    def without_firmware(vm_id):
        d = real(vm_id)
        d['data']['hardware'].pop('firmware')
        return d
    monkeypatch.setattr(route.esxi, 'get_vm', without_firmware)
    p = route.post(dry_run=True, esxi_password=None, bios=bios).get_json()
    assert p['ok'] is True and _fw(p['warnings']) == [], p['warnings']


def test_the_warning_is_no_error_and_the_start_goes_ahead(route):
    route.esxi.firmware = 'efi'
    r = route.post(bios='seabios', disk_map=[{'index': 2, 'skip': True}])
    assert r.status_code == 202, r.get_data(as_text=True)
    assert route.wait_started()[0].bios_override == 'seabios'


# --------------------------------------------------------------------------- bulk check

def test_each_guest_of_a_bulk_check_gets_its_own_firmware_warning(env, monkeypatch):
    real = env.esxi.get_vm

    def efi_for_vm2(vm_id):
        d = real(vm_id)
        if vm_id == 'vm-2' and 'data' in d:
            d['data']['hardware']['firmware'] = 'efi'
        return d
    monkeypatch.setattr(env.esxi, 'get_vm', efi_for_vm2)

    d = env.post(dry_run=True, esxi_password=None, vms=['vm-1', 'vm-2'], bios='seabios').get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert d['ok'] is True, d
    assert _fw(items['vm-1']['warnings']) == []
    assert len(_fw(items['vm-2']['warnings'])) == 1 and 'boots with UEFI' in _fw(items['vm-2']['warnings'])[0]
    # a warning of one guest is no warning of the whole request
    assert _fw(d['warnings']) == []

    d = env.post(dry_run=True, esxi_password=None, vms=['vm-1', 'vm-2'], bios='ovmf').get_json()
    items = {it['vm_id']: it for it in d['items']}
    assert len(_fw(items['vm-1']['warnings'])) == 1 and _fw(items['vm-2']['warnings']) == []

    d = env.post(dry_run=True, esxi_password=None, vms=['vm-1', 'vm-2']).get_json()
    assert all(_fw(it['warnings']) == [] for it in d['items'])


# --------------------------------------------------------------------------- the run

def test_a_run_started_without_a_dry_run_logs_the_mismatch_and_keeps_it_on_its_result(monkeypatch):
    r = Run(monkeypatch, mode='offline', firmware='efi', tpm=False, config={'bios': 'seabios'}).go()
    said = _fw(r.task.warnings)
    assert len(said) == 1 and 'UEFI (OVMF)' in said[0], r.task.warnings
    assert sum('WARNING: Firmware:' in ln for ln in r.task.log_lines) == 1
    # still applied as asked
    assert any('Proxmox config: bios=seabios, machine=pc' in ln for ln in r.task.log_lines)


@pytest.mark.parametrize('firmware,bios', [('efi', 'ovmf'), ('efi', 'auto'), ('bios', 'seabios'), ('bios', 'auto')])
def test_a_run_that_matches_the_source_says_nothing_about_firmware(monkeypatch, firmware, bios):
    r = Run(monkeypatch, mode='offline', firmware=firmware, tpm=False, config={'bios': bios}).go()
    assert _fw(r.task.warnings) == []
    assert not any('Firmware:' in ln for ln in r.task.log_lines)


def test_a_run_with_ovmf_on_a_bios_source_logs_it(monkeypatch):
    r = Run(monkeypatch, mode='offline', firmware='bios', tpm=False, config={'bios': 'ovmf'}).go()
    said = _fw(r.task.warnings)
    assert len(said) == 1 and 'Legacy BIOS (SeaBIOS)' in said[0]
