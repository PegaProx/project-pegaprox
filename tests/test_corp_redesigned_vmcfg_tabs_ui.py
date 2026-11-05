"""The Disks, Network and Options tabs of a QEMU VM's configuration dialog in Corporate Redesigned (Preview).

Round 5, stage B3: the three tabs come in sections with folds and help marks like the Hardware tab
(stage B2), over the same changes and the pending changes panel of stage B1. Disks lists every
device with its storage and size and lets the options of an existing volume (cache, discard, SSD
emulation, IO thread, backup, AIO, replication, read only) change in the drive's own string through
the review; adding, importing, detaching, removing, resizing, moving, the bus and the ISO keep their
classic dialogs and requests. Network edits each interface in place and saves it from the review with
the request of the classic edit dialog (PUT .../networks/<id>). Options has start and shutdown (with
the startup order the classic tab lacked), the boot order, the guest agent, hotplug (with PVE's
meaning of '1'), KVM and ACPI, and the classic SMBIOS card. The checks rest on the Proxmox VE source in
cr33/qemu_src (Drive.pm, QemuServer/Network.pm, QemuServer/Agent.pm, JSONSchema.pm, QemuServer.pm).
PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the build before this
stage). Skips without Playwright. LW Nov 2026
"""
import pytest

from test_corp_redesigned_guard_ui import CFG_RICH, _GuardApp, _corp_cluster, _exact
from test_corp_redesigned_vmcfg_ui import (BUNDLE, CFG_URL, LAYOUT, PENDING_URL, _CfgServer, _cfg, _no_errors,  # noqa: F401
                                           _open_config, _panel, _review, _rows, _save, _vc_input, browser, firefox, open_app,
                                           playwright)

VM = '/api/clusters/c1/vms/pve1/qemu/100'
NET0 = f'{VM}/networks/net0'
OK = (200, {'success': True})
# what the classic edit dialog sends for net0 of the rich config before any edit (vcNetEditInitial)
NET0_BODY = {'bridge': 'vmbr0', 'model': 'virtio', 'macaddr': 'BC:24:11:AA:BB:CC', 'firewall': 1, 'tag': '', 'rate': '',
             'mtu': '', 'queues': '', 'link_down': False, 'name': 'eth0', 'ip': 'dhcp', 'gw': '', 'hwaddr': ''}
HW_OPTS = {'network_models': [{'value': 'virtio', 'label': 'VirtIO'}, {'value': 'e1000', 'label': 'e1000'}],
           'cpu_types': ['host', 'kvm64'], 'scsi_controllers': [], 'machine_types': []}
BRIDGES = [{'iface': 'vmbr0', 'source': 'local'}, {'iface': 'vmbr1', 'source': 'local'},
           {'iface': 'vnet1', 'source': 'sdn', 'zone': 'zone1'}]
WRITES = {('PUT', NET0): OK, ('PUT', f'{NET0}/link'): OK, ('DELETE', NET0): OK, ('DELETE', f'{VM}/disks/scsi0'): OK,
          ('PUT', f'{VM}/cdrom'): OK, ('GET', '/api/hardware-options'): (200, HW_OPTS),
          ('GET', '/api/clusters/c1/nodes/pve1/networks'): (200, BRIDGES)}


def _app(open_app, **kw):
    app = open_app(**kw)
    app.server.routes.update(WRITES)
    return app


def _tab(page, name, mark):
    _open_config(page, name)
    page.locator(mark).wait_for(timeout=8000)


def _flip(page, key):
    """An on/off switch of the preview by the key (or key.part) it writes."""
    _vc_input(page, key).dispatch_event('click')


def _writes(app, method=None, path=None):
    return [w for w in app.server.writes if (method is None or w[0] == method) and (path is None or w[1] == path)]


def _wait_writes(page, app, n=1, **kw):
    for _ in range(60):
        if len(_writes(app, **kw)) >= n:
            break
        page.wait_for_timeout(100)
    return _writes(app, **kw)


def _pending_reads(app):
    return len([c for c in app.server.calls if c == ('GET', PENDING_URL)])


# --- the edits and checks as functions --------------------------------------------------------------

@pytest.fixture(scope='module')
def fn_page(browser):
    app = _GuardApp(browser, _CfgServer(layout=LAYOUT, bundle=BUNDLE))
    app.page.wait_for_function('() => !!window.PegaProxVmCfgRules', timeout=15000)
    yield app.page
    app.close()


def _tabs(page, fn, *args):
    if not page.evaluate('() => !!window.PegaProxVmCfgTabs'):
        pytest.fail('the bundle has no edits of the Disks, Network and Options tabs')
    return page.evaluate('([f, a]) => window.PegaProxVmCfgTabs[f](...a)', [fn, list(args)])


def test_the_interface_is_predicted_as_the_backend_builds_it(fn_page):
    # manager.py update_network: model[=mac], bridge, tag, firewall, rate, queues, mtu, link_down; a value
    # Python counts as false is left out, a string '0' is not
    assert _tabs(fn_page, 'netBuilt', NET0_BODY) == 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1'
    full = dict(NET0_BODY, tag='40', rate='12.5', queues='4', mtu='1', link_down=True, firewall=False)
    assert _tabs(fn_page, 'netBuilt', full) == 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=40,rate=12.5,queues=4,mtu=1,link_down=1'
    assert _tabs(fn_page, 'netBuilt', dict(NET0_BODY, macaddr='', model='e1000')) == 'e1000,bridge=vmbr0,firewall=1'
    assert _tabs(fn_page, 'netBuilt', dict(NET0_BODY, tag='0')) == 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=0,firewall=1'


def test_the_parts_the_edit_request_does_not_carry_are_kept(fn_page):
    # NET 94-121: trunks is a part of the format the edit request does not carry; manager.py
    # update_network keeps such parts as stored (_net_kept_parts) and appends them after its own
    cur = 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,trunks=10;20,host-tunnel=1,firewall=1'
    assert _tabs(fn_page, 'netKept', cur) == ['trunks=10;20', 'host-tunnel=1']
    assert _tabs(fn_page, 'netKept', 'e1000=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=5,firewall=0') == []
    assert _tabs(fn_page, 'netBuilt', NET0_BODY, cur) == 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,trunks=10;20,host-tunnel=1'


NET_CHECKS = [
    ('mac-ok', {'macaddr': 'bc:24:11:aa:bb:cc'}, []),
    ('mac-multicast', {'macaddr': 'BD:24:11:AA:BB:CC'}, [['net0', 'crVcErrNetMac', False]]),    # JS pve_verify_mac_addr
    ('mac-format', {'macaddr': 'BC:24:11'}, [['net0', 'crVcErrNetMac', False]]),
    ('mac-empty', {'macaddr': ''}, [['net0', 'crVcNoteNetNewMac', True]]),
    ('tag-0', {'tag': '0'}, [['net0', 'crVcErrNetTag', False]]),                                 # NET 87-92
    ('tag-4095', {'tag': '4095'}, [['net0', 'crVcErrNetTag', False]]),
    ('tag-ok', {'tag': '4094'}, []),
    ('rate-neg', {'rate': '-1'}, [['net0', 'crVcErrNetRate', False]]),                           # NET 81-86
    ('rate-ok', {'rate': '12.5'}, []),
    ('queues-65', {'queues': '65'}, [['net0', 'crVcErrNetQueues', False]]),                      # NET 74-80
    ('queues-e1000', {'queues': '4', 'model': 'e1000'}, [['net0', 'crVcNoteNetVirtioOnly', True]]),
    ('mtu-range', {'mtu': '70000'}, [['net0', 'crVcErrNetMtu', False]]),                         # NET 111-118
    ('mtu-under-576', {'mtu': '500'}, [['net0', 'crVcErrNetMtuMin', False]]),                    # QS 1338-1341
    ('mtu-bridge', {'mtu': '1'}, []),
    ('mtu-e1000', {'mtu': '9000', 'model': 'e1000'}, [['net0', 'crVcNoteNetVirtioOnly', True]]),
]


@pytest.mark.parametrize('case,edit,expected', NET_CHECKS, ids=[c[0] for c in NET_CHECKS])
def test_an_interface_is_checked_against_the_pve_schema(fn_page, case, edit, expected):
    got = _tabs(fn_page, 'checkNets', {'net0': dict(NET0_BODY, **edit)}, {'net0': CFG_RICH['raw']['net0']})
    assert [[i['key'], i['msg'], bool(i.get('note'))] for i in got] == expected


def test_a_kept_part_is_no_note(fn_page):
    # the backend keeps trunks as stored, so a save drops nothing and the panel has nothing to say
    raw = {'net0': 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,trunks=10;20,firewall=1'}
    assert _tabs(fn_page, 'checkNets', {'net0': dict(NET0_BODY, tag='40')}, raw) == []


def test_hotplug_is_written_with_the_meaning_pve_gives_it(fn_page):
    # QS 255-264, 1112-1129: unset and '1' are network,disk,usb, '0' is none; the classic boxes read '1'
    # as all five features
    assert _tabs(fn_page, 'hotplug', None, 'memory', True) == 'disk,network,usb,memory'
    assert _tabs(fn_page, 'hotplug', '1', 'usb', False) == 'disk,network'
    assert _tabs(fn_page, 'hotplug', '0', 'disk', True) == 'disk'
    assert _tabs(fn_page, 'hotplug', 'network,disk,usb', 'network', False) == 'disk,usb'
    assert _tabs(fn_page, 'hotplug', 'disk', 'disk', False) == '0'
    assert _tabs(fn_page, 'hotplug', 'disk,cloudinit', 'cloudinit', False) == 'disk'


def test_the_agent_keeps_its_other_parts(fn_page):
    # AGENT 16-58: enabled is the default key; the classic box writes a bare '1' or '0'
    assert _tabs(fn_page, 'agent', '', 'enabled', 1) == '1'
    assert _tabs(fn_page, 'agent', '1', 'fstrim_cloned_disks', 1) == '1,fstrim_cloned_disks=1'
    assert _tabs(fn_page, 'agent', '1,fstrim_cloned_disks=1', 'fstrim_cloned_disks', '') == '1'
    assert _tabs(fn_page, 'agent', '1,fstrim_cloned_disks=1', 'enabled', 0) == '0,fstrim_cloned_disks=1'
    assert _tabs(fn_page, 'agent', 'enabled=1,type=isa', 'freeze-fs-on-backup', 0) == '1,type=isa,freeze-fs-on-backup=0'


def test_the_startup_order_follows_pve_parse_startup_order(fn_page):
    for v, bad in (('order=2,up=30', False), ('2', False), ('order=1,down=60', False), ('order=-1', True),
                   ('up=x', True), ('order=2,sleep=5', True)):
        assert _tabs(fn_page, 'startupBad', v) is bad, v


DISK_CHECKS = [
    # DRIVE 455-520: ide and sata take no IO thread, VirtIO block no SSD emulation, ide and sata no read only
    ('ide-iothread', {'ide0': 'local-lvm:vm-100-disk-3,iothread=1,size=8G'}, {}, [['ide0', 'crVcErrDiskBusOpt', False]]),
    ('virtio-ssd', {'virtio0': 'local-lvm:vm-100-disk-3,ssd=1,size=8G'}, {}, [['virtio0', 'crVcErrDiskBusOpt', False]]),
    ('sata-ro', {'sata1': 'local-lvm:vm-100-disk-3,ro=1,size=8G'}, {}, [['sata1', 'crVcErrDiskBusOpt', False]]),
    ('scsi-ok', {'scsi0': 'local-lvm:vm-100-disk-0,iothread=1,ssd=1,ro=1,size=32G'}, {}, []),
    ('off-is-fine', {'ide0': 'local-lvm:vm-100-disk-3,iothread=0,size=8G'}, {}, []),
    # QS 3589-3600: the IO thread of a SCSI disk needs virtio-scsi-single, else PVE ignores it
    ('iothread-lsi', {'scsi0': 'local-lvm:vm-100-disk-0,iothread=1,size=32G,ssd=1'}, {'scsihw': 'lsi'},
     [['scsi0', 'crVcNoteIothreadScsihw', True]]),
    ('controller-change', {'scsihw': 'virtio-scsi-pci'}, {}, [['scsi0', 'crVcNoteIothreadScsihw', True]]),
    # JSONSchema pve_parse_startup_order
    ('startup', {'startup': 'order=x'}, {}, [['startup', 'crVcErrStartup', False]]),
]


@pytest.mark.parametrize('case,changes,over,expected', DISK_CHECKS, ids=[c[0] for c in DISK_CHECKS])
def test_a_disk_option_is_checked_against_its_bus(fn_page, case, changes, over, expected):
    if not fn_page.evaluate('() => !!window.PegaProxVmCfgTabs'):
        pytest.fail('the bundle has no checks of the Disks and Options tabs')
    raw = dict(CFG_RICH['raw'], **over)
    got = fn_page.evaluate('([c, r]) => window.PegaProxVmCfgChecks.check(c, r).map(i => [i.key, i.msg, !!i.note])', [changes, raw])
    assert got == expected


# --- Disks ---------------------------------------------------------------------------------------------

def test_runtime_the_disks_tab_in_sections_with_every_classic_action(open_app):
    cfg = _cfg(unused0='local-lvm:vm-100-disk-9')
    cfg['unused_disks'] = [{'id': 'unused0', 'value': 'local-lvm:vm-100-disk-9'}]
    cfg['disks'][2] = dict(cfg['disks'][2], value='local:iso/debian.iso,media=cdrom', volume='iso/debian.iso')
    app = _app(open_app, cfg=cfg)
    page = app.page
    _tab(page, 'Disks', '[data-cr-vc-disks]')
    secs = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-disks] > [data-cr-vc-sec]")).map(s => s.dataset.crVcSec)')
    assert secs == ['disks', 'media', 'fwvol', 'unused']
    acts = lambda sel: page.evaluate('(s) => Array.from(document.querySelectorAll(s + " [data-cr-vc-act]")).map(b => b.dataset.crVcAct)', sel)
    # the classic row of a data disk: bus, resize, move, reassign, detach, remove; a CD: ISO, eject, detach, remove
    assert acts('[data-cr-vc-disk="scsi0"]') == ['bus', 'resize', 'move', 'reassign', 'detach', 'remove']
    assert acts('[data-cr-vc-dev="ide2"]') == ['iso', 'eject', 'detach', 'remove']
    assert acts('[data-cr-vc-dev="efidisk0"]') == ['resize', 'move']
    assert acts('[data-cr-vc-dev="unused0"]') == ['reattach', 'purge']
    assert page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-add]")).map(b => b.dataset.crVcAdd)') == ['iso', 'import', 'disk']
    card = page.locator('[data-cr-vc-disk="scsi0"]')
    assert 'local-lvm' in card.inner_text() and '32G' in card.inner_text()
    assert _vc_input(page, 'scsi0.iothread').is_checked() and not _vc_input(page, 'scsi0.ssd').is_checked()
    assert _vc_input(page, 'scsi0.backup').is_checked() and _vc_input(page, 'scsi0.cache').input_value() == ''
    # each action sends the classic request
    page.on('dialog', lambda d: d.accept())
    card.locator('[data-cr-vc-act="detach"]').click()
    assert _wait_writes(page, app, method='DELETE', path=f'{VM}/disks/scsi0') == [('DELETE', f'{VM}/disks/scsi0', None)]
    page.locator('[data-cr-vc-dev="ide2"] [data-cr-vc-act="eject"]').click()
    assert _wait_writes(page, app, path=f'{VM}/cdrom') == [('PUT', f'{VM}/cdrom', {'iso': None, 'drive': 'ide2'})]
    app.server.routes[('PUT', CFG_URL)] = OK
    page.locator('[data-cr-vc-dev="unused0"] [data-cr-vc-act="purge"]').click()
    assert _wait_writes(page, app, path=CFG_URL) == [('PUT', CFG_URL, {'delete': 'unused0'})]
    card.locator('[data-cr-vc-act="resize"]').click()
    page.get_by_text('Resize', exact=False).last.wait_for(timeout=5000)
    _no_errors(app)


def test_runtime_a_disk_option_goes_through_the_review_with_its_class(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Disks', '[data-cr-vc-disks]')
    _flip(page, 'scsi0.ssd')
    _review(page)
    rows = _rows(page)
    # QS 5079-5091: SSD emulation of the same volume never changes live: it waits for the next start
    assert [(r['key'], r['cls'], r['rule']) for r in rows] == [('scsi0', 'restart', 'drive')]
    _flip(page, 'scsi0.ssd')
    assert page.locator('[data-cr-vc-row]').count() == 0
    _flip(page, 'scsi0.backup')
    page.locator('[data-cr-vc-review-open]').click()
    rows = _rows(page)
    # the backup flag is no option QEMU holds: written at once
    assert [(r['key'], r['cls']) for r in rows] == [('scsi0', 'now')]
    page.locator('[data-cr-vc-save]').click()
    puts = _wait_writes(page, app, path=CFG_URL)
    assert puts == [('PUT', CFG_URL, {'scsi0': 'local-lvm:vm-100-disk-0,iothread=1,size=32G,backup=0'})]
    assert not [w for w in app.server.writes if w[1] != CFG_URL]
    _no_errors(app)


def test_runtime_a_bus_without_an_option_says_so(open_app):
    cfg = _cfg(sata0='local-lvm:vm-100-disk-5,size=8G', virtio1='local-lvm:vm-100-disk-6,size=8G')
    cfg['disks'] += [{'id': 'sata0', 'value': cfg['raw']['sata0'], 'storage': 'local-lvm', 'size': '8G', 'volume': 'vm-100-disk-5'},
                     {'id': 'virtio1', 'value': cfg['raw']['virtio1'], 'storage': 'local-lvm', 'size': '8G', 'volume': 'vm-100-disk-6'}]
    app = _app(open_app, cfg=cfg)
    page = app.page
    _tab(page, 'Disks', '[data-cr-vc-disks]')
    assert page.locator('[data-cr-vc-na="sata0.iothread"]').count() == 1 and _vc_input(page, 'sata0.ssd').count() == 1
    assert page.locator('[data-cr-vc-na="virtio1.ssd"]').count() == 1 and _vc_input(page, 'virtio1.iothread').count() == 1
    disks = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-disk]")).map(d => d.dataset.crVcDisk)')
    assert disks == ['scsi0', 'virtio1', 'sata0']   # the classic order: by bus, then index
    _no_errors(app)


def test_runtime_a_disk_action_reads_the_pending_list_again(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Disks', '[data-cr-vc-disks]')
    page.wait_for_function('() => !!document.querySelector("[data-cr-vc-panel]")')
    page.wait_for_timeout(300)
    before = _pending_reads(app)
    # after the detach PVE answers with the disk as unused0
    cfg = _cfg(scsi0=None, unused0='local-lvm:vm-100-disk-0')
    cfg['disks'] = [d for d in cfg['disks'] if d['id'] != 'scsi0']
    cfg['unused_disks'] = [{'id': 'unused0', 'value': 'local-lvm:vm-100-disk-0'}]
    app.server.routes[('GET', CFG_URL)] = (200, cfg)
    app.server.routes[('GET', PENDING_URL)] = (200, {'pending': [{'key': 'unused0', 'value': 'local-lvm:vm-100-disk-0'}]})
    page.on('dialog', lambda d: d.accept())
    page.locator('[data-cr-vc-disk="scsi0"] [data-cr-vc-act="detach"]').click()
    page.locator('[data-cr-vc-dev="unused0"]').wait_for(timeout=8000)
    for _ in range(40):
        if _pending_reads(app) > before:
            break
        page.wait_for_timeout(100)
    assert _pending_reads(app) == before + 1
    page.locator('[data-cr-vc-dev-pending="unused0"]').wait_for(timeout=5000)
    _no_errors(app)


# --- Network ---------------------------------------------------------------------------------------------

def _edit_net(page, variant):
    if variant:
        _vc_input(page, 'net0.tag').fill('40')
        _vc_input(page, 'net0.rate').fill('10')
    else:
        page.locator('.corp-vm-modal-tab', has_text=_exact('Network')).click()
        page.locator('button[title="Edit"]').first.click()
        page.locator('xpath=//label[normalize-space(.)="VLAN Tag"]/following-sibling::input[1]').fill('40')
        page.locator('xpath=//label[normalize-space(.)="Rate Limit (MB/s)"]/following-sibling::input[1]').fill('10')
        page.locator('button', has_text=_exact('Save')).last.click()


def test_runtime_an_interface_is_saved_with_the_classic_request(browser):
    bodies = {}
    for layout in ('corporate', LAYOUT):
        server = _CfgServer(layout=layout, bundle=BUNDLE)
        server.routes.update(WRITES)
        app = _GuardApp(browser, server)
        try:
            page = app.page
            if layout == 'corporate':
                _corp_cluster(page)
                page.locator('.corp-tree-child', has_text='web01').first.click()
                page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
                page.locator('input[value="web01"]').first.wait_for(timeout=8000)
                _edit_net(page, False)
            else:
                _tab(page, 'Network', '[data-cr-vc-net]')
                _edit_net(page, True)
                _review(page)
                rows = _rows(page)
                # QS 4960-5014: a new VLAN tag and rate on the same bridge reach the running VM when the node takes
                # them (round 8, N1: PVE may keep it pending)
                assert [(r['key'], r['cls'], r['rule']) for r in rows] == [('net0', 'maybe', 'net')], rows
                new = page.locator('[data-cr-vc-row="net0"] .cr-vc-new').get_attribute('title')
                assert new == 'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=40,firewall=1,rate=10'
                page.locator('[data-cr-vc-save]').click()
            for _ in range(50):
                if [w for w in server.writes if w[1] == NET0]:
                    break
                page.wait_for_timeout(100)
            bodies[layout] = [w for w in server.writes if w[0] != 'GET']
            assert not app.errors, (layout, app.errors)
        finally:
            app.close()
    assert bodies['corporate'] == [('PUT', NET0, dict(NET0_BODY, tag='40', rate='10'))], bodies
    assert bodies[LAYOUT] == bodies['corporate']


def test_runtime_a_new_mac_replugs_and_a_bad_one_blocks_the_save(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Network', '[data-cr-vc-net]')
    assert page.locator('[data-cr-vc-nic-hint="hot"]').count() == 1
    _vc_input(page, 'net0.macaddr').fill('BD:24:11:AA:BB:CC')
    page.locator('[data-cr-vc-error="net0"]').wait_for(timeout=5000)
    assert 'unicast' in page.locator('[data-cr-vc-errors]').inner_text()
    _vc_input(page, 'net0.macaddr').fill('BC:24:11:AA:BB:CD')
    assert page.locator('[data-cr-vc-error]').count() == 0
    _review(page)
    # QS 4940-4955: a new MAC re-plugs the device; with network hotplug on the guest can refuse it
    assert [(r['key'], r['cls']) for r in _rows(page)] == [('net0', 'maybe')]
    assert page.locator('[data-cr-vc-save]').is_enabled()
    page.locator('[data-cr-vc-row="net0"] .cr-vc-link').click()
    assert page.locator('[data-cr-vc-row]').count() == 0 and _vc_input(page, 'net0.macaddr').input_value() == 'BC:24:11:AA:BB:CC'
    _no_errors(app)


def test_runtime_the_parts_an_edit_does_not_carry_are_kept(open_app):
    cfg = _cfg(net0='virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,trunks=10;20,firewall=1')
    app = _app(open_app, cfg=cfg)
    page = app.page
    _tab(page, 'Network', '[data-cr-vc-net]')
    page.locator('[data-cr-vc-fold="net0-adv"] > button').click()
    assert 'kept as stored on save: trunks=10;20' in page.locator('[data-cr-vc-net-kept="net0"]').inner_text()
    _vc_input(page, 'net0.tag').fill('40')
    _review(page)
    # the panel row shows the interface the backend writes, trunks included, and no drop warning
    assert [r['key'] for r in _rows(page)] == ['net0']
    assert 'trunks=10;20' in page.locator('[data-cr-vc-row="net0"]').inner_text()
    assert page.locator('[data-cr-vc-note="net0"]').count() == 0
    _no_errors(app)


def test_runtime_add_remove_and_link_keep_their_requests(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Network', '[data-cr-vc-net]')
    page.on('dialog', lambda d: d.accept())
    page.locator('[data-cr-vc-nic="net0"] [data-cr-vc-act="link"]').click()
    assert _wait_writes(page, app, path=f'{NET0}/link') == [('PUT', f'{NET0}/link', {'link_down': True})]
    page.locator('[data-cr-vc-nic="net0"] [data-cr-vc-act="remove"]').click()
    assert _wait_writes(page, app, method='DELETE', path=NET0) == [('DELETE', NET0, None)]
    # while an interface has unsaved changes its quick link switch waits
    _vc_input(page, 'net0.tag').fill('7')
    assert page.locator('[data-cr-vc-nic="net0"] [data-cr-vc-act="link"]').is_disabled()
    page.locator('[data-cr-vc-add="net"]').click()
    page.get_by_text('Add Network', exact=False).last.wait_for(timeout=5000)
    _no_errors(app)


def test_runtime_one_save_sends_the_interface_and_the_config_and_reads_once(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Network', '[data-cr-vc-net]')
    page.wait_for_timeout(300)
    _vc_input(page, 'net0.tag').fill('40')
    page.locator('.corp-vm-modal-tab', has_text=_exact('Options')).click()
    page.locator('[data-cr-vc-opts]').wait_for(timeout=5000)
    _flip(page, 'protection')
    before = _pending_reads(app)
    # the config PVE answers after the interface's request: net0 with its tag
    app.server.routes[('GET', CFG_URL)] = (200, _cfg(net0='virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=40,firewall=1'))
    res = _save(page)
    writes = [w for w in app.server.writes if w[0] != 'GET']
    assert writes == [('PUT', NET0, dict(NET0_BODY, tag='40')), ('PUT', CFG_URL, {'protection': 1})]
    assert _pending_reads(app) == before + 1
    assert res.get_attribute('data-cr-vc-result') == 'ok'
    _no_errors(app)


def test_runtime_pve_pending_devices_are_marked(open_app):
    app = _app(open_app, pending=(200, {'pending': [{'key': 'net0', 'value': CFG_RICH['raw']['net0'], 'pending': 'e1000=BC:24:11:AA:BB:CC,bridge=vmbr0'},
                                                    {'key': 'scsi0', 'value': CFG_RICH['raw']['scsi0'], 'pending': CFG_RICH['raw']['scsi0'] + ',ssd=1'}]}))
    page = app.page
    _tab(page, 'Disks', '[data-cr-vc-disks]')
    page.locator('[data-cr-vc-dev-pending="scsi0"]').wait_for(timeout=5000)
    page.locator('.corp-vm-modal-tab', has_text=_exact('Network')).click()
    page.locator('[data-cr-vc-dev-pending="net0"]').wait_for(timeout=5000)
    _no_errors(app)


# --- Options ----------------------------------------------------------------------------------------------

def test_runtime_the_options_tab_in_sections(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Options', '[data-cr-vc-opts]')
    secs = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-opts] [data-cr-vc-sec]")).map(s => s.dataset.crVcSec)')
    assert secs == ['start', 'agent', 'virt', 'boot', 'hotplug', 'smbios']
    assert _vc_input(page, 'onboot').is_checked() and not _vc_input(page, 'protection').is_checked()
    assert _vc_input(page, 'startup.order').input_value() == '2' and _vc_input(page, 'startup.up').input_value() == '30'
    assert _vc_input(page, 'agent').is_checked() and _vc_input(page, 'agent.fstrim').is_checked()
    hot = page.evaluate('() => Object.fromEntries(Array.from(document.querySelectorAll("[data-cr-vc-input^=\'hotplug.\']")).map(i => [i.dataset.crVcInput.slice(8), i.checked]))')
    assert hot == {'disk': True, 'network': True, 'usb': True, 'memory': False, 'cpu': False, 'cloudinit': False}
    assert _vc_input(page, 'kvm').is_checked() and _vc_input(page, 'acpi').is_checked()
    boot = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-vc-boot]")).map(b => [b.dataset.crVcBoot, b.dataset.crVcBootPos])')
    assert boot[:3] == [['scsi0', '1'], ['ide2', '2'], ['net0', '3']]
    smb = page.locator('[data-cr-vc-sec="smbios"]')
    assert 'SMBIOS' in smb.inner_text() and 'NEEDS RESTART' not in page.locator('.corp-vm-modal').inner_text()
    assert page.locator('[data-cr-vc-other]').count() == 1
    _no_errors(app)


def _edit_options(page, variant):
    """Start at boot off, protection on, ide2 out of the boot order, KVM off."""
    if variant:
        _flip(page, 'onboot')
        _flip(page, 'protection')
        page.locator('#cr-vc-boot-ide2').dispatch_event('click')
        _flip(page, 'kvm')
    else:
        page.locator('.corp-vm-modal-tab', has_text=_exact('Options')).click()
        page.get_by_text('Boot Order').first.wait_for(timeout=8000)
        page.locator('label', has_text=_exact('Start on Boot')).locator('input').click()
        page.locator('label', has_text='Protection').locator('input').first.click()
        page.locator('xpath=//span[normalize-space(.)="ide2"]/ancestor::div[contains(@class, "rounded-lg")][1]//input[@type="checkbox"]').first.click()
        page.locator('label', has_text='KVM').locator('input').first.click()


def test_runtime_the_options_save_sends_what_the_classic_form_sends(browser):
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
                _edit_options(page, False)
                page.locator('.corp-vm-modal button', has_text=_exact('Save')).last.click()
            else:
                _tab(page, 'Options', '[data-cr-vc-opts]')
                _edit_options(page, True)
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
    assert bodies['corporate'] == [('PUT', CFG_URL, {'onboot': 0, 'protection': 1, 'boot': 'order=scsi0;net0', 'kvm': 0})], bodies
    assert bodies[LAYOUT] == bodies['corporate']


def test_runtime_hotplug_one_is_network_disk_usb(open_app):
    app = _app(open_app, cfg=_cfg(hotplug='1'))
    page = app.page
    _tab(page, 'Options', '[data-cr-vc-opts]')
    assert page.locator('[data-cr-vc-hot-state="1"]').count() == 1
    assert not _vc_input(page, 'hotplug.memory').is_checked() and not _vc_input(page, 'hotplug.cpu').is_checked()
    _flip(page, 'hotplug.usb')
    _review(page)
    row = _rows(page)[0]
    # HL 229-233: neither the old nor the new value has cpu or memory, so it applies now
    assert (row['key'], row['cls'], row['rule']) == ('hotplug', 'now', 'hotplug-option')
    assert 'disk,network' in row['text']
    _flip(page, 'hotplug.memory')
    # MEM 374: memory hotplug needs NUMA; the rich config has it, so turning NUMA off would be the error
    rows = {r['key']: r for r in _rows(page)}
    assert rows['hotplug']['cls'] == 'restart'
    _no_errors(app)


def test_runtime_startup_order_and_agent_parts_through_the_review(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Options', '[data-cr-vc-opts]')
    _vc_input(page, 'startup.order').fill('3')
    _vc_input(page, 'startup.down').fill('60')
    page.locator('[data-cr-vc-fold="agent-adv"] > button').click()
    _flip(page, 'agent.freeze')
    _review(page)
    rows = {r['key']: r for r in _rows(page)}
    assert rows['startup']['cls'] == 'now' and rows['startup']['rule'] == 'fast-plug'
    assert rows['agent']['cls'] == 'restart'   # QS 5031-5052: only fstrim_cloned_disks changes live
    app.server.routes[('PUT', CFG_URL)] = OK
    page.locator('[data-cr-vc-save]').click()
    puts = _wait_writes(page, app, path=CFG_URL)
    assert puts == [('PUT', CFG_URL, {'startup': 'order=3,up=30,down=60', 'agent': '1,fstrim_cloned_disks=1,freeze-fs-on-backup=0'})]
    _no_errors(app)


def test_runtime_an_invalid_startup_delay_blocks_the_save(open_app):
    app = _app(open_app)
    page = app.page
    _tab(page, 'Options', '[data-cr-vc-opts]')
    _vc_input(page, 'startup.up').fill('-5')
    page.locator('[data-cr-vc-error="startup"]').wait_for(timeout=5000)
    _review(page)
    assert page.locator('[data-cr-vc-save]').is_disabled()
    _no_errors(app)


# --- classic layouts, layout ---------------------------------------------------------------------------------

def test_runtime_classic_corporate_keeps_its_tabs(browser):
    server = _CfgServer(layout='corporate', bundle=BUNDLE)
    app = _GuardApp(browser, server)
    try:
        page = app.page
        _corp_cluster(page)
        page.locator('.corp-tree-child', has_text='web01').first.click()
        page.locator('.corp-toolbar button', has_text=_exact('Configure')).first.click()
        page.locator('input[value="web01"]').first.wait_for(timeout=8000)
        for tab, mark in (('Disks', 'vm-100-disk-0'), ('Network', 'BC:24:11:AA:BB:CC'), ('Options', 'Boot Order')):
            page.locator('.corp-vm-modal-tab', has_text=_exact(tab)).click()
            page.locator('.corp-vm-modal').get_by_text(mark).first.wait_for(timeout=8000)
            assert page.locator('[data-cr-vc-disks], [data-cr-vc-net], [data-cr-vc-opts]').count() == 0, tab
        assert not app.errors, app.errors
    finally:
        app.close()


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280])
def test_runtime_the_tabs_fit_without_sideways_scroll(browser, firefox, engine, width):
    br = browser if engine == 'chromium' else firefox
    server = _CfgServer(layout=LAYOUT, bundle=BUNDLE)
    server.routes.update(WRITES)
    app = _GuardApp(br, server, viewport=(width, 900))
    try:
        page = app.page
        _open_config(page)
        _panel(page)
        for tab, mark, grid, n in (('Disks', '[data-cr-vc-disks]', '.cr-vc-hw-cols', 2), ('Network', '[data-cr-vc-net]', '.cr-vc-grid', 3),
                                   ('Options', '[data-cr-vc-opts]', '.cr-vc-hw-cols', 2)):
            page.locator('.corp-vm-modal-tab', has_text=_exact(tab)).click()
            page.locator(mark).wait_for(timeout=8000)
            folds = page.locator('[data-cr-vc-fold][data-open="0"] > button')
            for _ in range(folds.count()):
                folds.first.click()
            over = page.evaluate('''(m) => [document.documentElement, document.querySelector('.corp-vm-modal-body'), document.querySelector(m)]
                .map(e => e.scrollWidth - e.clientWidth)''', mark)
            assert all(o <= 0 for o in over), (tab, over)
            cols = page.evaluate('([m, g]) => getComputedStyle(document.querySelector(m + " " + g)).gridTemplateColumns.split(" ").length', [mark, grid])
            assert cols == n, tab
        assert not app.errors, app.errors
    finally:
        app.close()
