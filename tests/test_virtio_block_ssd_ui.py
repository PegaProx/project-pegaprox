"""SSD emulation is offered only on a bus that has it, in every dialog that sets up a disk.

PVE's drive schema has `ssd` on IDE, SATA and SCSI and not on VirtIO Block, and it refuses
the whole drive when virtioN carries it. The Create VM wizard offered the box on every bus,
for the main disk and each additional one, and so did the migration dialog. In the VM
settings Add Disk and Reattach counted VirtIO Block among the buses with SSD emulation, and
a bus change to VirtIO Block kept ssd=1 in the drive. Now the box is left out for VirtIO
Block and a ticked one is cleared when the bus changes to it, so nothing stale is sent. Add
Disk, Reattach and the bus change keep IDE without it, as before. Corporate Redesigned's own
disk card goes by CR_VC_BUS_OPTS and has its own tests.

The runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py and skip where Playwright is not installed.
LW Nov 2026
"""
import json
import re

import pytest

from test_ha_ui import CLUSTER, VM_CONFIG, _App, _FakeServer, _read, browser  # noqa: F401
from test_lxc_features_passthrough_ui import _open_config, _tab

VM = {'vmid': 100, 'name': 'web01', 'type': 'qemu', 'status': 'stopped', 'node': 'pve1',
      'cpu': 0, 'cpu_percent': 0, 'maxcpu': 2, 'mem': 0, 'maxmem': 4294967296,
      'mem_percent': 0, 'disk': 0, 'maxdisk': 34359738368, 'uptime': 0}
NODE = '/api/clusters/c1/nodes/pve1'
VM_URL = '/api/clusters/c1/vms/pve1/qemu/100'
CFG = f'{VM_URL}/config'
BUSES = [{'value': 'scsi', 'label': 'SCSI', 'max': 30}, {'value': 'virtio', 'label': 'VirtIO Block', 'max': 15},
         {'value': 'sata', 'label': 'SATA', 'max': 5}, {'value': 'ide', 'label': 'IDE', 'max': 3}]
OPTIONS = {'cpu_types': ['host'], 'scsi_controllers': [], 'network_models': [], 'disk_bus_types': BUSES,
           'cache_modes': [{'value': '', 'label': 'Default (No cache)'}], 'machine_types': [{'value': '', 'label': 'Default'}]}
STORAGE = [{'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'avail': 10 ** 11,
            'total': 2 * 10 ** 11, 'active': 1, 'enabled': 1}]
SSD = 'SSD Emulation'


# -- source ------------------------------------------------------------------------------------

def _between(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def test_add_disk_and_reattach_offer_ssd_on_scsi_and_sata_only():
    src = _read('web', 'src', 'vm_config.js')
    add = _between(src, 'function AddDiskModal(', 'function ResizeDiskModal(')
    assert "const supportsSsd = ['scsi', 'sata'].includes(currentBus);" in add
    assert "const busSupportsSsd = ['scsi', 'sata'].includes(newBus);" in add
    assert '{supportsSsd && (' in add and 'if (supportsSsd && diskConfig.ssd) {' in add
    re_att = _between(src, 'function ReattachDiskModal(', 'function MoveDiskModal(')
    assert "const supportsSsd = ['scsi', 'sata'].includes(busType);" in re_att
    assert re.search(r"if \(!\['scsi', 'sata'\]\.includes\(newBus\)\) \{\s*setSsd\(false\);", re_att)
    assert "if (supportsSsd && ssd) options.push('ssd=1');" in re_att


def test_a_bus_change_to_virtio_block_drops_ssd_and_says_so():
    src = _read('web', 'src', 'vm_config.js')
    # the save in ConfigModal and the warning of the dialog go by the same buses
    assert re.search(r"if \(!\['scsi', 'sata'\]\.includes\(newBusType\)\) \{\s*"
                     r"currentValue = currentValue\.replace\(/,ssd=\\d\+/g, ''\);", src)
    bus = _between(src, 'function EditDiskBusModal(', 'const handleSave')
    assert "const willStripSsd = hasSsd && !['scsi', 'sata'].includes(newBus);" in bus
    # nothing in the classic dialogs still counts VirtIO Block among the SSD buses
    assert not re.findall(r"\['scsi', 'virtio', 'sata'\]", src)


def _create_disk_step():
    src = _read('web', 'src', 'create_modals.js')
    return src, _between(src, 'case 3: // Disk', 'case 4: // Network')


def test_the_create_wizard_leaves_the_box_out_for_virtio_block():
    src, step = _create_disk_step()
    assert re.search(r"\{config\.disk_type !== 'virtio' && \(\s*<label[^>]*>\s*"
                     r"<input type=\"checkbox\" checked=\{config\.disk_ssd\}", step), 'main disk'
    assert re.search(r"\{disk\.type !== 'virtio' && \(\s*<label[^>]*>\s*"
                     r"<input type=\"checkbox\" checked=\{disk\.ssd \|\| false\}", step), 'additional disk'
    # a bus change to VirtIO Block clears a ticked box
    assert ("setConfig({...config, disk_type: e.target.value, disk_ssd: e.target.value === 'virtio' ? "
            "false : config.disk_ssd})") in step
    assert "newDisks[idx] = {...disk, type: e.target.value, ssd: e.target.value === 'virtio' ? false : disk.ssd};" in step
    # and so does a quick template that picks it
    presets = _between(src, 'const VM_PRESETS = [', '];')
    virtio = [ln for ln in presets.splitlines() if "disk_type: 'virtio'" in ln]
    assert virtio and all('disk_ssd: false' in ln for ln in virtio), virtio


def test_the_migration_dialog_leaves_the_box_out_for_virtio_block():
    src = _read('web', 'src', 'dashboard.js')
    assert re.search(r"\{vmwareMigrateForm\.disk_bus !== 'virtio' && \(\s*<label[^>]*>\s*"
                     r"<input type=\"checkbox\" checked=\{vmwareMigrateForm\.disk_ssd\}", src)
    assert ("<select value={vmwareMigrateForm.disk_bus} onChange={e => setVmwareMigrateForm(f => "
            "({...f, disk_bus: e.target.value, disk_ssd: e.target.value === 'virtio' ? false : f.disk_ssd}))}") in src
    assert len(re.findall(r'checked=\{vmwareMigrateForm\.disk_ssd\}', src)) == 1


# -- runtime -----------------------------------------------------------------------------------

class _DiskServer(_FakeServer):
    """The fake server with a stopped VM whose config a PUT changes, the node reads of the
    Create VM wizard and the disk routes of the VM settings."""

    def __init__(self, raw=None, disks=None, unused=None, **kw):
        super().__init__(**kw)
        self.vm_raw = {'name': 'web01', 'digest': 'x', **(raw or {})}
        self.disks = disks if disks is not None else VM_CONFIG['disks']
        self.unused = unused or []
        self.extra.update({
            ('GET', '/api/hardware-options'): (200, OPTIONS),
            ('GET', f'{VM_URL}/passthrough'): (200, {'pci': [], 'usb': [], 'serial': []}),
            ('GET', '/api/clusters/c1/nodes'): (200, [{'node': 'pve1', 'status': 'online'}]),
            ('GET', f'{NODE}/storage'): (200, STORAGE),
            ('GET', f'{NODE}/networks'): (200, [{'iface': 'vmbr0', 'type': 'bridge'}]),
            ('GET', f'{NODE}/nextid'): (200, {'vmid': 105}),
            ('POST', f'{NODE}/qemu'): (200, {'success': True, 'vmid': 105}),
            ('POST', f'{VM_URL}/disks'): (200, {'success': True, 'message': 'Disk added'}),
        })
        self._config()

    def _config(self):
        self.extra[('GET', CFG)] = (200, dict(VM_CONFIG, raw=dict(self.vm_raw), disks=self.disks,
                                              unused_disks=self.unused, status={'status': 'stopped'}))

    def handle(self, route):
        req = route.request
        if req.method == 'PUT' and req.url.split('?')[0].endswith(CFG):
            body = json.loads(req.post_data or '{}')
            for key in str(body.pop('delete', '') or '').split(','):
                self.vm_raw.pop(key.strip(), None)
            self.vm_raw.update(body)
            self._config()
            self.extra[('PUT', CFG)] = (200, {'message': 'Configuration updated'})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout='modern', **kw):
        app = _App(browser, _DiskServer(role='standalone', layout=layout, clusters=[CLUSTER],
                                        resources=[VM], metrics={}, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _sent(app, path):
    return [b for b in app.server.bodies.get(path, []) if b]


def _open_create(app, layout):
    page = app.page
    if layout == 'modern':
        page.get_by_text('Testi').first.click()
    else:
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('button', has_text='Resources').first.click()
    page.locator('button', has_text='Create new VM').first.click()
    page.locator('input[placeholder="my-virtual-machine"]').wait_for(timeout=8000)
    page.locator('input[placeholder="my-virtual-machine"]').fill('vm-new')
    _next(page, 3)
    page.get_by_text('Disk 0 (scsi0)').first.wait_for(timeout=5000)
    return page


def _next(page, times):
    # the Corporate wizard opens a step only after the ones before it
    for _ in range(times):
        page.locator('button', has_text=re.compile(r'^\s*Next\s*$')).last.click()
        page.wait_for_timeout(150)


def _bus_select(card):
    return card.locator('select').filter(has=card.page.locator('option[value="virtio"]')).first


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
def test_runtime_the_create_wizard_offers_ssd_off_virtio_block_only(open_app, layout):
    app = open_app(layout)
    page = _open_create(app, layout)
    main = page.locator('div.p-4', has=page.locator('h4', has_text=re.compile(r'Disk 0 \(\w+0\)'))).last
    ssd = main.get_by_text(SSD)
    assert ssd.count() == 1
    main.locator('label', has_text=SSD).locator('input').check()
    _bus_select(main).select_option('virtio')
    page.get_by_text('Disk 0 (virtio0)').first.wait_for(timeout=3000)
    assert ssd.count() == 0
    _bus_select(main).select_option('sata')
    assert ssd.count() == 1
    assert not main.locator('label', has_text=SSD).locator('input').is_checked()   # cleared on the way
    main.locator('label', has_text=SSD).locator('input').check()
    _bus_select(main).select_option('virtio')

    page.locator('button', has_text='Add Disk').last.click()
    extra = page.locator('div.p-4', has=page.locator('h4', has_text=re.compile(r'Disk 1 \(\w+1\)'))).last
    extra.wait_for(timeout=3000)
    extra.locator('label', has_text=SSD).locator('input').check()
    _bus_select(extra).select_option('virtio')
    page.get_by_text('Disk 1 (virtio1)').first.wait_for(timeout=3000)
    assert extra.get_by_text(SSD).count() == 0

    _next(page, 2)
    create = page.locator('button', has_text=re.compile(r'^\s*Create new VM\s*$')).last
    create.click()
    page.wait_for_timeout(500)
    [sent] = _sent(app, f'{NODE}/qemu')
    assert sent['disk_type'] == 'virtio' and sent['disk_ssd'] is False, sent
    assert [(d['type'], d['ssd']) for d in sent['additional_disks']] == [('virtio', False)], sent
    assert not app.errors, app.errors


def _disks_tab(app):
    _open_config(app, 'web01')
    _tab(app, 'Disks').click()
    app.page.get_by_text('scsi0').first.wait_for(timeout=5000)


def _modal(page, title):
    return page.locator('div.fixed.inset-0', has=page.locator('h3', has_text=title)).last


def test_runtime_add_disk_sends_no_ssd_for_virtio_block(open_app):
    app = open_app()
    page = app.page
    _disks_tab(app)
    page.locator('button', has_text='Add Disk').last.click()
    modal = _modal(page, 'Add Disk')
    modal.wait_for(timeout=3000)
    bus = modal.locator('select').first
    page.wait_for_function('''() => Array.from(document.querySelectorAll('select option'))
        .some(o => o.value === 'virtio')''', timeout=5000)
    assert modal.get_by_text(SSD).count() == 1
    modal.locator('label', has_text=SSD).locator('input').check()
    bus.select_option('virtio')
    assert modal.get_by_text(SSD).count() == 0
    bus.select_option('sata')
    assert not modal.locator('label', has_text=SSD).locator('input').is_checked()
    modal.locator('label', has_text=SSD).locator('input').check()
    bus.select_option('virtio')
    modal.locator('button', has_text=re.compile(r'^\s*Add\s*$')).click()
    page.wait_for_timeout(500)
    [sent] = _sent(app, f'{VM_URL}/disks')
    assert sent['disk_id'].startswith('virtio') and 'ssd' not in sent, sent
    assert not app.errors, app.errors


def test_runtime_reattach_offers_no_ssd_on_virtio_block(open_app):
    app = open_app(unused=[{'id': 'unused0', 'value': 'local-lvm:vm-100-disk-1'}])
    page = app.page
    _disks_tab(app)
    page.locator('button', has_text=re.compile(r'^\s*Reattach\s*$')).first.click()
    modal = _modal(page, 'Reattach disk')
    modal.wait_for(timeout=3000)
    assert modal.get_by_text(SSD).count() == 1
    modal.locator('label', has_text=SSD).locator('input').check()
    modal.locator('button', has_text='VirtIO Block').click()
    assert modal.get_by_text(SSD).count() == 0
    modal.locator('button', has_text=re.compile(r'^\s*Reattach\s*$')).last.click()
    page.wait_for_timeout(500)
    [sent] = _sent(app, CFG)
    [(key, drive)] = sent.items()
    assert key.startswith('virtio') and 'ssd' not in drive, sent
    assert not app.errors, app.errors


def test_runtime_a_bus_change_to_virtio_block_drops_ssd(open_app):
    drive = 'local-lvm:vm-100-disk-0,discard=on,ssd=1,size=32G'
    app = open_app(raw={'scsi0': drive}, disks=[dict(VM_CONFIG['disks'][0], value=drive, ssd=1)])
    page = app.page
    _disks_tab(app)
    page.locator('button[title="Change Bus Type"]').first.click()
    modal = _modal(page, 'Change Disk Bus Type')
    modal.wait_for(timeout=3000)
    modal.locator('label', has_text='VirtIO Block').click()
    page.wait_for_timeout(200)
    warning = modal.locator('div', has_text='will be removed')
    assert warning.count() > 0, modal.inner_text()
    assert warning.last.locator('span', has_text=re.compile(r'^SSD$')).count() == 1, warning.last.inner_text()
    modal.locator('button', has_text='Change Bus Type').click()
    page.wait_for_timeout(1500)
    puts = _sent(app, CFG)
    assert puts[0] == {'delete': 'scsi0'} and puts[1] == {'virtio0': 'local-lvm:vm-100-disk-0,discard=on'}, puts
    assert not app.errors, app.errors
