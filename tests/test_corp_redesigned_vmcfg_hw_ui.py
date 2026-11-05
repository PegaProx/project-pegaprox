"""The Hardware tab of a QEMU VM's configuration dialog in Corporate Redesigned (Preview), in the browser.

Round 5, stage B2: the tab comes in four sections (CPU, Memory, Firmware & Machine, Additional
Hardware) over the same changes and the same save as the classic tab. CPU groups sockets and cores
with the vCPUs they make, describes the CPU type and what it means for a live migration, and shows
the CPU flags qemu-server allows in a VM's own settings by group with default, on and off. Memory
draws what is guaranteed and what the host may take back by ballooning. The checks rest on the
Proxmox VE source (cr33/qemu_src: QemuServer.pm, Memory.pm, CPUConfig.pm, CPUFlags.pm, Machine.pm,
Drive.pm, OVMF.pm, API2/Qemu.pm) and feed the pending changes panel of stage B1. Devices keep their
own routes and dialogs. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against
the build before this stage). Skips without Playwright. LW Nov 2026
"""
import pytest

from test_corp_redesigned_guard_ui import CFG_RAW, _GuardApp, _corp_cluster, _exact
from test_corp_redesigned_vmcfg_ui import (BUNDLE, CFG_URL, LAYOUT, PENDING_URL, _CfgServer, _cfg, _hw_input, _no_errors,  # noqa: F401
                                           _open_config, _panel, _review, _rows, _save, _vc_input, browser, firefox, open_app,
                                           playwright)

PT_URL = '/api/clusters/c1/vms/pve1/qemu/100/passthrough'


def _hw(page, **_):
    _open_config(page, 'Hardware')
    page.locator('[data-cr-vc-hw]').wait_for(timeout=8000)


def _open_folds(page):
    shut = page.locator('[data-cr-vc-fold][data-open="0"] > button')
    for _ in range(shut.count()):
        shut.first.click()


def _errors(page):
    return page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-error]")).map(e => [e.dataset.crVcError, e.innerText])')


def _hw_select(page, label):
    """The select of a classic ConfigInputField on the Hardware tab, by its label."""
    return page.locator(f'xpath=//div[contains(@class, "corp-vm-modal-body")]//label[starts-with(normalize-space(.), "{label}")]'
                        '/following-sibling::select[1]').first


# --- the checks and the body edits, as functions --------------------------------------------------------

@pytest.fixture(scope='module')
def fn_page(browser):
    app = _GuardApp(browser, _CfgServer(layout=LAYOUT, bundle=BUNDLE))
    app.page.wait_for_function('() => !!window.PegaProxVmCfgRules', timeout=15000)
    yield app.page
    app.close()


def _check(page, changes, raw):
    if not page.evaluate('() => !!window.PegaProxVmCfgChecks'):
        pytest.fail('the bundle has no checks of the Hardware tab')
    return page.evaluate('([c, r]) => window.PegaProxVmCfgChecks.check(c, r).map(i => [i.key, i.msg, !!i.note])', [changes, raw])


RAW = {'sockets': 2, 'cores': 4, 'memory': '8192', 'balloon': '2048', 'numa': 1, 'machine': 'pc-q35-8.1', 'bios': 'ovmf',
       'efidisk0': 'local-lvm:vm-100-disk-1,efitype=4m,pre-enrolled-keys=1,size=4M', 'hotplug': 'network,disk,usb'}
HOTMEM = dict(RAW, hotplug='network,disk,usb,memory')

# (case, changes, stored over RAW, expected [key, message, note]); the source of each rule is in cr_vmcfg.js
CHECKS = [
    ('sockets-0', {'sockets': 0}, {}, [['sockets', 'crVcErrMin', False]]),            # QS 417-423
    ('cores-empty', {'cores': ''}, {}, [['cores', 'crVcErrMin', False]]),             # QS 424-430
    ('vcpus-over', {'vcpus': 9}, {}, [['vcpus', 'crVcErrVcpus', False]]),             # QS 4259-4260
    ('vcpus-fits', {'vcpus': 8}, {}, []),
    ('cores-under-vcpus', {'cores': 2}, {'vcpus': 6}, [['vcpus', 'crVcErrVcpus', False]]),
    ('cpulimit', {'cpulimit': 129}, {}, [['cpulimit', 'crVcErrNumRange', False]]),   # QS 279-288
    ('cpulimit-ok', {'cpulimit': 1.5}, {}, []),
    ('cpuunits', {'cpuunits': 0}, {}, [['cpuunits', 'crVcErrRange', False]]),        # QS 289-300
    ('affinity-ok', {'affinity': '0,5,8-11'}, {}, []),                                 # QS 730-735
    ('affinity-bad', {'affinity': '0-'}, {}, [['affinity', 'crVcErrAffinity', False]]),
    ('reported-model', {'cpu': 'host,reported-model=Skylake-Client'}, {}, [['cpu', 'crVcErrReportedModel', False]]),  # CPU 498-499
    ('level', {'cpu': 'host,level=-1'}, {}, [['cpu', 'crVcErrLevel', False]]),       # CPU 352-362
    ('memory-min', {'memory': 8, 'balloon': 0}, {}, [['memory', 'crVcErrMin', False]]),            # MEM 78-87
    ('balloon-over', {'balloon': 9000}, {}, [['balloon', 'crVcErrBalloon', False]]),  # API 2283-2292
    ('memory-under-balloon', {'memory': 1024}, {}, [['balloon', 'crVcErrBalloon', False]]),
    ('balloon-off', {'balloon': 0}, {}, []),
    ('shares', {'shares': 50001}, {}, [['shares', 'crVcErrRange', False]]),          # QS 327-335
    ('hotmem-numa', {'numa': 0}, HOTMEM, [['numa', 'crVcErrHotMemNuma', False]]),   # MEM 374
    ('hotmem-align', {'memory': 1500, 'balloon': 0}, HOTMEM, [['memory', 'crVcErrHotMemAlign', False]]),   # MEM 188-209, 500
    ('hotmem-step', {'memory': 1536, 'balloon': 0}, HOTMEM, []),
    ('hotmem-min', {'memory': 512, 'balloon': 0}, HOTMEM, [['memory', 'crVcErrHotMemMin', False]]),   # MEM 384-389
    ('hotmem-virtiofs', {'hotplug': 'network,disk,usb,memory'}, {'virtiofs0': 'dirid=share'}, [['memory', 'crVcErrHotMemVfs', False]]),  # MEM 400
    ('hugepages-numa', {'hugepages': '2', 'numa': 0}, {}, [['hugepages', 'crVcErrHugeNuma', False]]),   # MEM 398
    ('hugepages-ok', {'hugepages': '2'}, {}, []),
    ('numa-sum', {'numa0': 'cpus=0-3,memory=4096', 'numa1': 'cpus=4-7,memory=2048'}, {}, [['numa0', 'crVcErrNumaSum', False]]),  # MEM 459
    ('numa-policy', {'numa0': 'cpus=0-7,memory=8192,hostnodes=0'}, {}, [['numa0', 'crVcErrNumaPolicy', False]]),  # MEM 440
    ('numa-ok', {'numa0': 'cpus=0-7,memory=8192,hostnodes=0,policy=bind'}, {}, []),
    ('numa-off', {'numa': 0, 'numa0': 'cpus=0-7,memory=8192'}, {}, [['numa0', 'crVcNoteNumaOff', True]]),   # MEM 403
    ('viommu', {'machine': 'pc-i440fx-8.1,viommu=intel'}, {}, [['machine', 'crVcErrViommu', False]]),   # MACH 136-140
    ('viommu-q35', {'machine': 'pc-q35-8.1,viommu=intel'}, {}, []),
    ('vga-mem', {'vga': 'std,memory=1024'}, {}, [['vga', 'crVcErrVgaMem', False]]),   # QS 176-181
    ('no-efi', {'bios': 'ovmf'}, {'bios': 'seabios', 'efidisk0': None}, [['bios', 'crVcNoteNoEfi', True]]),   # OVMF 145-150
    # a problem of the stored config does not block an unrelated change
    ('unrelated', {'name': 'web02'}, {'hugepages': '2', 'numa': 0}, []),
]


@pytest.mark.parametrize('case,changes,over,expected', CHECKS, ids=[c[0] for c in CHECKS])
def test_checks_rest_on_proxmox_ve_constraints(fn_page, case, changes, over, expected):
    raw = {k: v for k, v in dict(RAW, **over).items() if v is not None}
    assert _check(fn_page, changes, raw) == expected


def test_a_body_edit_sets_removes_and_reverts(fn_page):
    if not fn_page.evaluate('() => !!window.PegaProxVmCfgChecks'):
        pytest.fail('the bundle has no body edits of the Hardware tab')
    patch = lambda prev, p, raw: fn_page.evaluate('([a, b, c]) => window.PegaProxVmCfgChecks.patch(a, b, c)', [prev, p, raw])
    raw = {'cpuunits': 200, 'cores': 2}
    assert patch({}, {'cpuunits': None}, raw) == {'delete': 'cpuunits'}            # stored key emptied: PVE's delete list
    assert patch({'delete': 'cpuunits'}, {'cpuunits': 300}, raw) == {'cpuunits': 300}
    assert patch({'cores': 4}, {'cores': '2'}, raw) == {}                           # back at the stored value: no change
    assert patch({}, {'vcpus': None}, raw) == {}                                    # not stored, nothing to remove
    assert patch({'delete': 'a'}, {'cpulimit': None, 'cpuunits': None}, dict(raw, cpulimit=2)) == {'delete': 'a,cpulimit,cpuunits'}


def test_a_flag_is_written_like_the_classic_cycle(fn_page):
    if not fn_page.evaluate('() => !!window.PegaProxVmCfgChecks'):
        pytest.fail('the bundle has no flag edit of the Hardware tab')
    flag = lambda cpu, f, st: fn_page.evaluate('([c, f, s]) => window.PegaProxVmCfgChecks.setFlag(c, f, s, "kvm64")', [cpu, f, st])
    cur = 'x86-64-v2-AES,flags=+aes;-pcid'
    assert flag(cur, 'pcid', 0) == 'x86-64-v2-AES,flags=+aes'
    assert flag(cur, 'spec-ctrl', 1) == 'x86-64-v2-AES,flags=+aes;-pcid;+spec-ctrl'
    assert flag('host,level=30', 'aes', -1) == 'host,level=30,flags=-aes'
    # CPU 469: the string needs a type; an unset cpu keeps its default type kvm64 (CPU 1152-1154)
    assert flag('', 'aes', 1) == 'kvm64,flags=+aes'


# --- the tab in the browser --------------------------------------------------------------------------------

def test_runtime_the_hardware_tab_in_four_sections(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    secs = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-hw] > [data-cr-vc-sec]")).map(s => s.dataset.crVcSec)')
    assert secs == ['cpu', 'memory', 'firmware', 'devices']
    # CPU: sockets x cores = vCPUs, the type described with what it means for a live migration
    assert _vc_input(page, 'sockets').input_value() == '2' and _vc_input(page, 'cores').input_value() == '2'
    assert page.locator('[data-cr-vc-total]').get_attribute('data-cr-vc-total') == '4'
    assert page.locator('[data-cr-vc-sum="cpu"]').inner_text() == '4 vCPUs · x86-64-v2-AES'
    assert _vc_input(page, 'cputype').input_value() == 'x86-64-v2-AES'
    assert page.locator('[data-cr-vc-cpu-kind]').get_attribute('data-cr-vc-cpu-kind') == 'level'
    mig = page.locator('[data-cr-vc-migration]').inner_text()
    assert 'support this level of the x86-64 instruction set' in mig and 'enforce' in mig and '(+aes)' in mig
    # every flag qemu-server allows in a VM's own settings (CPUFlags.pm), by group, with its state
    flags = dict(page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-flag]")).map(f => [f.dataset.crVcFlag, f.dataset.state])'))
    assert set(flags) == {'pcid', 'spec-ctrl', 'ssbd', 'ibpb', 'virt-ssbd', 'amd-ssbd', 'amd-no-ssb', 'pdpe1gb', 'hv-tlbflush',
                          'hv-evmcs', 'aes', 'md-clear', 'nested-virt'}
    assert flags['aes'] == 'on' and flags['pcid'] == 'off' and flags['ssbd'] == 'default'
    groups = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-flag-grp]")).map(g => g.dataset.crVcFlagGrp)')
    assert groups == ['crVcFlagGrpSec', 'crVcFlagGrpPerf', 'crVcFlagGrpWin', 'crVcFlagGrpVirt']
    assert page.locator('[data-cr-vc-flag="pcid"] [role="radio"][aria-checked="true"]').inner_text() == 'Off'
    # Memory: 8 GiB, 2 GiB guaranteed, 6 GiB the host may take back, 3 GiB in use
    assert _vc_input(page, 'memory').input_value() == '8' and page.locator('[data-cr-vc-unit="memory"]').input_value() == 'GiB'
    assert _vc_input(page, 'balloon').input_value() == '2'
    alloc = page.locator('[data-cr-vc-alloc]')
    assert alloc.get_attribute('data-cr-vc-alloc') == 'balloon'
    assert 'Guaranteed 2 GiB' in alloc.inner_text() and 'Host may take back 6 GiB' in alloc.inner_text() and 'In use 3 GiB' in alloc.inner_text()
    assert 'down to the minimum' in page.locator('[data-cr-vc-mem-explain]').inner_text()
    # Firmware & Machine
    assert page.locator('[data-cr-vc-bios="ovmf"]').get_attribute('aria-checked') == 'true'
    assert page.locator('[data-cr-vc-secureboot]').get_attribute('data-cr-vc-secureboot') == 'on'
    assert _vc_input(page, 'machine').input_value() == 'pc-q35-8.1'
    assert 'Pinned to version 8.1' in page.locator('[data-cr-vc-machine-note]').inner_text()
    assert _vc_input(page, 'scsihw').input_value() == 'virtio-scsi-single' and _vc_input(page, 'vga').input_value() == 'std'
    assert page.locator('[data-cr-vc-dev="efidisk0"]').count() == 1
    # no red restart tag, no classic hardware grid
    assert page.locator('.corp-vm-modal', has_text='NEEDS RESTART').count() == 0
    assert page.locator('.corp-vm-modal-body', has_text='Extra CPU Flags').count() == 0
    _no_errors(app)


def test_runtime_every_field_of_the_classic_tab_is_reachable(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    _open_folds(page)
    # classic: cores, sockets, memory, balloon, cpu type, VGA, reported-model, level, the 12 flags, BIOS,
    # SCSI controller, machine, vIOMMU, NUMA; EFI disk, TPM, cloud-init drive, RNG, virtiofs, PCI, USB, serial
    for key in ('cores', 'sockets', 'memory', 'balloon', 'cputype', 'vga', 'reported-model', 'level', 'bios', 'scsihw',
                'machine', 'viommu', 'numa'):
        assert page.locator(f'[data-cr-vc-input="{key}"]').count() == 1, key
    for flag in ('pcid', 'spec-ctrl', 'ssbd', 'ibpb', 'virt-ssbd', 'amd-ssbd', 'amd-no-ssb', 'pdpe1gb', 'hv-tlbflush', 'hv-evmcs',
                 'aes', 'md-clear'):
        assert page.locator(f'[data-cr-vc-flag="{flag}"] [role="radio"]').count() == 3, flag
    for lst in ('efi', 'tpm', 'cloudinit', 'pci', 'usb', 'serial'):
        assert page.locator(f'[data-cr-vc-devlist="{lst}"]').count() == 1, lst
    assert page.locator('[data-cr-vc-slot="rng"] [data-rng-card]').count() == 1
    assert page.locator('[data-cr-vc-slot="virtiofs"] [data-vfs-card]').count() == 1
    # and the keys the save path passes that the classic tab did not offer
    for key in ('vcpus', 'cpulimit', 'cpuunits', 'affinity', 'shares', 'hugepages', 'audio0.device', 'vga.memory', 'vga.clipboard'):
        assert page.locator(f'[data-cr-vc-input="{key}"]').count() == 1, key
    assert page.locator('[data-cr-vc-numa-add]').count() == 1
    _no_errors(app)


def _edit_hardware(page, variant):
    """The same edit in both forms: 4 cores, type host, spec-ctrl on, display qxl, 16 GiB memory with
    4 GiB minimum, NUMA off, the Intel vIOMMU, VirtIO SCSI."""
    if variant:
        _vc_input(page, 'cores').fill('4')
        _vc_input(page, 'cputype').select_option('host')
        page.locator('[data-cr-vc-flag="spec-ctrl"] [role="radio"]', has_text=_exact('On')).click()
        _vc_input(page, 'vga').select_option('qxl')
        _vc_input(page, 'memory').fill('16')
        _vc_input(page, 'balloon').fill('4')
        page.locator('label[for="cr-vc-numa"]').click()
        _open_folds(page)
        _vc_input(page, 'viommu').select_option('intel')
        _vc_input(page, 'scsihw').select_option('virtio-scsi-pci')
    else:
        _hw_input(page, 'CPU Cores').fill('4')
        _hw_select(page, 'CPU Type').select_option('host')
        page.locator('.corp-vm-modal-body button', has_text=_exact('spec-ctrl')).click()
        _hw_select(page, 'VGA').select_option('qxl')
        _hw_input(page, 'Memory (RAM)').fill('16')
        _hw_input(page, 'Ballooning Minimum').fill('4')
        page.locator('.corp-vm-modal-body label', has_text='Enable NUMA').locator('input[type=checkbox]').click()
        _hw_select(page, 'vIOMMU').select_option('intel')
        _hw_select(page, 'SCSI Controller').select_option('virtio-scsi-pci')


def test_runtime_the_hardware_save_sends_what_the_classic_form_sends(browser):
    bodies = {}
    for layout in ('corporate', LAYOUT):
        server = _CfgServer(layout=layout, bundle=BUNDLE)
        app = _GuardApp(browser, server)
        try:
            page = app.page
            if layout == 'corporate':
                _corp_cluster(page)
                page.locator('.corp-tree-child', has_text='web01').first.click()
                page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
                page.locator('input[value="web01"]').first.wait_for(timeout=8000)
                page.locator('.corp-vm-modal-tab', has_text=_exact('Hardware')).click()
                page.get_by_text('Sockets').first.wait_for(timeout=8000)
                _edit_hardware(page, False)
                page.locator('.corp-vm-modal button', has_text=_exact('Save')).last.click()
            else:
                _hw(page)
                _edit_hardware(page, True)
                _review(page)
                page.locator('[data-cr-vc-save]').click()
            for _ in range(50):
                if server.puts():
                    break
                page.wait_for_timeout(100)
            bodies[layout] = server.puts()
            assert not app.errors, (layout, app.errors)
        finally:
            app.close()
    expected = {'cores': 4, 'cpu': 'host,flags=+aes;-pcid;+spec-ctrl', 'vga': 'qxl', 'memory': 16384, 'balloon': 4096, 'numa': 0,
                'machine': 'pc-q35-8.1,viommu=intel', 'scsihw': 'virtio-scsi-pci'}
    assert [b[:2] for b in bodies['corporate']] == [('PUT', CFG_URL)] and bodies['corporate'][0][2] == expected, bodies
    assert [b[:2] for b in bodies[LAYOUT]] == [('PUT', CFG_URL)] and bodies[LAYOUT][0][2] == expected, bodies


def test_runtime_a_flag_has_three_clear_states(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    flag = page.locator('[data-cr-vc-flag="ssbd"]')
    flag.locator('[role="radio"]', has_text=_exact('On')).click()
    assert flag.get_attribute('data-state') == 'on'
    assert page.locator('[data-cr-vc-flags-sum]').inner_text() == '3 set'
    flag.locator('[role="radio"]', has_text=_exact('Off')).click()
    assert flag.get_attribute('data-state') == 'off'
    _review(page)
    row = {r['key']: r for r in _rows(page)}['cpu']
    assert row['cls'] == 'restart' and 'x86-64-v2-AES,flags=+aes;-pcid;-ssbd' in row['text']
    assert 'CPU type and flags' in row['text']
    flag.locator('[role="radio"]', has_text=_exact('Default')).click()
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '0'
    _no_errors(app)


def test_runtime_vcpus_and_the_checks_feed_the_panel(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    _vc_input(page, 'sockets').fill('0')
    _panel(page)
    errs = _errors(page)
    assert errs == [['sockets', 'Sockets: enter a whole number of 1 or more.']], errs
    assert page.locator('[data-cr-vc-field-error="sockets"]').count() == 1
    assert page.locator('[data-cr-vc-total]').get_attribute('data-cr-vc-total') == '-'
    _vc_input(page, 'sockets').fill('3')
    assert page.locator('[data-cr-vc-total]').get_attribute('data-cr-vc-total') == '6'
    _open_folds(page)
    _vc_input(page, 'vcpus').fill('7')
    errs = _errors(page)
    assert errs == [['vcpus', 'Active vCPUs (7) is above sockets × cores (6). Lower it, or add sockets or cores.']], errs
    _review(page)
    assert page.locator('[data-cr-vc-save]').is_disabled()
    _vc_input(page, 'vcpus').fill('6')
    assert _errors(page) == []
    assert not page.locator('[data-cr-vc-save]').is_disabled()
    rows = {r['key']: r['cls'] for r in _rows(page)}
    assert rows == {'sockets': 'restart', 'vcpus': 'restart'}   # CPU hotplug is off for web01
    assert not app.server.puts()
    _no_errors(app)


def test_runtime_memory_ballooning_and_its_minimum(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    # a minimum above the memory is refused by PVE (API2/Qemu.pm): said before the save
    _vc_input(page, 'balloon').fill('10')
    assert _errors(page) == [['balloon', 'The minimum memory (10240 MiB) is above the memory (8192 MiB). Lower the minimum or raise the memory.']]
    _vc_input(page, 'memory').fill('12')
    assert _errors(page) == []
    assert 'Host may take back 2 GiB' in page.locator('[data-cr-vc-alloc]').inner_text()
    # ballooning off is balloon 0 (QS 319-326); the minimum then has no meaning
    page.locator('label[for="cr-vc-ballooning"]').click()
    assert page.locator('[data-cr-vc-alloc]').get_attribute('data-cr-vc-alloc') == 'fixed'
    assert _vc_input(page, 'balloon').is_disabled()
    result = _save(page)
    assert app.server.puts() == [('PUT', CFG_URL, {'memory': 12288, 'balloon': 0})]
    assert result.get_attribute('data-cr-vc-saved') == '1'
    _no_errors(app)


def test_runtime_an_emptied_optional_key_is_removed_from_the_config(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    _open_folds(page)
    assert _vc_input(page, 'cpuunits').input_value() == '200'
    _vc_input(page, 'cpuunits').fill('')
    _review(page)
    row = _rows(page)[0]
    assert (row['key'], row['cls'], row['rule']) == ('cpuunits', 'now', 'cgroup') and 'removed' in row['text']
    page.locator('[data-cr-vc-save]').click()
    page.wait_for_function('() => { const r = document.querySelector("[data-cr-vc-result]"); return r && r.dataset.crVcResult !== "reading"; }', timeout=8000)
    assert app.server.puts() == [('PUT', CFG_URL, {'delete': 'cpuunits'})]
    _no_errors(app)


def test_runtime_hugepages_and_memory_hotplug_need_numa(open_app):
    app = open_app(cfg=_cfg(hotplug='network,disk,usb,memory'))
    page = app.page
    _hw(page)
    page.locator('label[for="cr-vc-numa"]').click()   # NUMA off with memory hotplug on (Memory.pm 374)
    assert ['numa', 'Memory hotplug is on and needs NUMA. Turn NUMA on, or switch memory hotplug off on the Options tab.'] in _errors(page)
    _open_folds(page)
    _vc_input(page, 'hugepages').select_option('2')
    assert ['hugepages', 'Hugepages need NUMA. Turn NUMA on in the CPU section or switch hugepages off.'] in _errors(page)
    page.locator('label[for="cr-vc-numa"]').click()
    assert _errors(page) == []
    _vc_input(page, 'memory').fill('8.3')   # 8499 MiB is no step of the memory modules (Memory.pm 500)
    assert _errors(page) == [['memory', 'With memory hotplug the memory grows in modules, and 8499 MiB is not a step. Use 8192 or 8704 MiB.']]
    _no_errors(app)


def test_runtime_numa_nodes_of_its_own(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    _open_folds(page)
    page.locator('[data-cr-vc-numa-add]').click()
    page.locator('[data-cr-vc-input="numa0.cpus"]').fill('0-3')
    page.locator('[data-cr-vc-input="numa0.memory"]').fill('4096')
    assert _errors(page) == [['numa0', 'The NUMA nodes add up to 4096 MiB, the memory is 8192 MiB. Make them equal.']]
    page.locator('[data-cr-vc-input="numa0.memory"]').fill('8192')
    page.locator('[data-cr-vc-input="numa0.hostnodes"]').fill('0')
    assert _errors(page) == [['numa0', 'numa0: host nodes need a policy. Choose preferred, bind or interleave.']]
    page.locator('[data-cr-vc-input="numa0.policy"]').select_option('bind')
    assert _errors(page) == []
    result = _save(page)
    assert app.server.puts() == [('PUT', CFG_URL, {'numa0': 'cpus=0-3,memory=8192,hostnodes=0,policy=bind'})]
    assert result.get_attribute('data-cr-vc-saved') == '1'
    _no_errors(app)


@pytest.mark.parametrize('case,over,state', [
    ('enrolled', {}, 'on'),
    ('seabios', {'bios': 'seabios'}, 'nouefi'),
    ('no-efi-disk', {'efidisk0': None}, 'noefi'),
    ('old-format', {'efidisk0': 'local-lvm:vm-100-disk-1,size=128K'}, 'efi2m'),
    ('no-keys', {'efidisk0': 'local-lvm:vm-100-disk-1,efitype=4m,size=4M'}, 'nokeys'),
])
def test_runtime_secure_boot_as_drive_pm_defines_it(open_app, case, over, state):
    app = open_app(cfg=_cfg(**over))
    page = app.page
    _hw(page)
    assert page.locator('[data-cr-vc-secureboot]').get_attribute('data-cr-vc-secureboot') == state
    _no_errors(app)


def test_runtime_the_intel_viommu_needs_q35(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    _open_folds(page)
    _vc_input(page, 'viommu').select_option('intel')
    assert _errors(page) == []
    _vc_input(page, 'machine').select_option('i440fx')
    assert _errors(page) == [['machine', 'The Intel vIOMMU needs a q35 machine type. Choose a q35 machine or the VirtIO vIOMMU.']]
    # the type changes, the vIOMMU stays in the string (the classic select would drop it)
    _review(page)
    assert 'i440fx,viommu=intel' in {r['key']: r for r in _rows(page)}['machine']['text']
    _no_errors(app)


def test_runtime_devices_keep_their_routes_and_show_what_waits(open_app):
    app = open_app(pending=(200, {'pending': [{'key': 'hostpci0', 'pending': '0000:01:00.0,pcie=1'}]}))
    app.server.routes[('GET', PT_URL)] = (200, {'pci': [{'key': 'hostpci0', 'value': '0000:01:00.0,pcie=1', 'parsed': {}}],
                                                'usb': [], 'serial': [{'key': 'serial0', 'value': 'socket', 'parsed': {}}]})
    app.server.routes[('DELETE', PT_URL + '/serial/serial0')] = (200, {'success': True})
    app.server.routes[('PUT', CFG_URL)] = (200, {'success': True})
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _hw(page)
    page.locator('[data-cr-vc-dev="hostpci0"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-vc-dev-pending="hostpci0"]').inner_text() == 'Waits for the next start'
    assert page.locator('[data-cr-vc-dev-pending="serial0"]').count() == 0
    reads = lambda: len([c for c in app.server.calls if c == ('GET', PENDING_URL)])
    before = reads()
    page.locator('[data-cr-vc-dev="serial0"] button').click()
    for _ in range(50):
        if reads() > before:
            break
        page.wait_for_timeout(100)
    assert ('DELETE', PT_URL + '/serial/serial0', None) in app.server.writes
    assert reads() == before + 1   # what waits is read again after the device went
    # the EFI disk goes with the classic request; the reloaded config without it reads the pending list again
    app.server.routes[('GET', CFG_URL)] = (200, _cfg(efidisk0=None))
    page.locator('[data-cr-vc-dev="efidisk0"] button').click()
    page.locator('[data-cr-vc-secureboot="noefi"]').wait_for(timeout=8000)
    assert ('PUT', CFG_URL, {'delete': 'efidisk0'}) in app.server.writes
    for _ in range(50):
        if reads() > before + 1:
            break
        page.wait_for_timeout(100)
    assert reads() == before + 2
    assert page.locator('[data-cr-vc-count]').get_attribute('data-cr-vc-count') == '0'
    _no_errors(app)


def test_runtime_the_audio_device_goes_through_the_review(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    _vc_input(page, 'audio0.device').select_option('ich9-intel-hda')
    _review(page)
    row = _rows(page)[0]
    assert (row['key'], row['cls']) == ('audio0', 'restart') and 'Audio device' in row['text']
    page.locator('[data-cr-vc-save]').click()
    page.wait_for_function('() => { const r = document.querySelector("[data-cr-vc-result]"); return r && r.dataset.crVcResult !== "reading"; }', timeout=8000)
    assert app.server.puts() == [('PUT', CFG_URL, {'audio0': 'device=ich9-intel-hda,driver=spice'})]
    _no_errors(app)


def test_runtime_a_technical_parameter_has_its_tooltip(open_app):
    app = open_app()
    page = app.page
    _hw(page)
    tip = page.locator('[data-cr-vc-flag="hv-tlbflush"] .cr-vc-tip-btn')
    tid = tip.get_attribute('aria-describedby')
    text = page.locator(f'#{tid}')
    assert not text.is_visible()
    tip.focus()
    assert text.is_visible() and 'overcommitted Windows guests' in text.inner_text()
    assert page.locator('[data-cr-vc-hw] .cr-vc-tip-btn').count() >= 25
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_hardware_tab(browser):
    server = _CfgServer(layout='corporate', bundle=BUNDLE)
    app = _GuardApp(browser, server)
    try:
        page = app.page
        _corp_cluster(page)
        page.locator('.corp-tree-child', has_text='web01').first.click()
        page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
        page.locator('input[value="web01"]').first.wait_for(timeout=8000)
        page.locator('.corp-vm-modal-tab', has_text=_exact('Hardware')).click()
        page.get_by_text('Extra CPU Flags').first.wait_for(timeout=8000)
        assert page.locator('[data-cr-vc-hw], [data-cr-vc-sec]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.close()


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280])
def test_runtime_the_hardware_tab_fits_without_sideways_scroll(browser, firefox, engine, width):
    br = browser if engine == 'chromium' else firefox
    app = _GuardApp(br, _CfgServer(layout=LAYOUT, bundle=BUNDLE), viewport=(width, 900))
    try:
        page = app.page
        _hw(page)
        _open_folds(page)
        page.locator('[data-cr-vc-numa-add]').click()
        over = page.evaluate('''() => [document.documentElement, document.querySelector('.corp-vm-modal-body'),
            ...document.querySelectorAll('[data-cr-vc-hw] > [data-cr-vc-sec]')].map(e => e.scrollWidth - e.clientWidth)''')
        assert all(o <= 0 for o in over), over
        cols = page.evaluate('() => Array.from(document.querySelectorAll(".cr-vc-hw-cols")).map(c => getComputedStyle(c).gridTemplateColumns.split(" ").length)')
        assert cols == [2, 2, 2, 2], cols
        assert not app.errors, app.errors
    finally:
        app.close()
