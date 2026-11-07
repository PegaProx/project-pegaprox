"""Warn before migrating a detected EFI source with an explicit SeaBIOS override."""
import re
from types import SimpleNamespace

import pytest

from pegaprox.core.vmware import VMwareManager
from test_ha_ui import _App, _FakeServer, browser, ESXI_READS, SSE_TOKEN, CLUSTER, VM, _blocks, LANGS  # noqa: F401


def _source(firmware):
    """Use the real export adapter on the detail response used for execution too."""
    detail = {'name': 'legacy01', 'power_state': 'POWERED_ON', 'guest_OS': 'UBUNTU_64',
              'hardware': {'firmware': firmware}, 'cpu': {'count': 2},
              'disks': {'2000': {'capacity': 1 << 30, 'backing': {'vmdk_file': '[ds] vm/disk.vmdk'}}}}
    mgr = SimpleNamespace(get_vm=lambda _vm: {'data': detail})
    return VMwareManager.get_vm_disks_for_export(mgr, 'vm-1')['data']


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
@pytest.mark.parametrize('firmware', ['efi', 'bios', ''])
def test_runtime_firmware_choices_keep_the_warning_in_sync(browser, layout, firmware):
    """Drive both selects in the actual built wizard after the plan has loaded."""
    from playwright.sync_api import expect

    source = _source(firmware)
    plan = {'source': source, 'targets': [{'cluster_id': 'c1', 'cluster_name': 'Testi',
            'nodes': ['pve1'], 'storages': {'pve1': ['local-lvm']}}], 'esxi_host': 'esx01.lab'}
    extra = {**ESXI_READS, **SSE_TOKEN,
             ('GET', '/api/vmware/v1/vms/vm-1/migration-plan'): (200, plan),
             ('GET', '/api/vmware/migrations'): (200, [])}
    app = _App(browser, _FakeServer(role='standalone', layout=layout,
                                   clusters=[CLUSTER], resources=[VM], extra=extra))
    try:
        page = app.page
        page.set_default_timeout(5000)
        page.get_by_text('esx01', exact=True).first.click()
        page.get_by_text('legacy01', exact=True).first.click()
        page.get_by_role('button', name='Hardware', exact=True).first.click()
        page.locator('button:visible').filter(has_text='Migrate to Proxmox').last.click()
        label = page.locator('label', has_text='Firmware').first
        selector = label.locator('xpath=..').locator('select')
        expect(selector).to_be_visible()
        expect(selector.locator('option[value="auto"]')).to_have_text(f'Auto-detect ({firmware or "bios"})')
        warning = page.locator('[data-v2p-firmware-warning]')
        expect(warning).to_have_count(0)
        selector.select_option('seabios')
        expect(warning).to_have_count(1 if firmware == 'efi' else 0)
        if firmware == 'efi':
            expect(warning).to_contain_text('UEFI')
        page.get_by_role('button', name=re.compile('Hardware$')).last.click()
        selector = page.locator('label', has_text='BIOS / Firmware').locator('xpath=..').locator('select')
        expect(selector).to_have_value('seabios')
        expect(selector.locator('option[value="auto"]')).to_have_text(f'Auto ({firmware or "bios"})')
        expect(warning).to_have_count(1 if firmware == 'efi' else 0)
        selector.select_option('ovmf')
        expect(warning).to_have_count(0)
        selector.select_option('seabios')
        expect(warning).to_have_count(1 if firmware == 'efi' else 0)
        selector.select_option('auto')
        expect(warning).to_have_count(0)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


@pytest.mark.parametrize('lang', LANGS)
def test_firmware_warning_is_localized(lang):
    """Each supported locale supplies the warning without relying on a key-name fallback."""
    assert _blocks()[lang].count('v2pFirmwareMismatch:') == 1
