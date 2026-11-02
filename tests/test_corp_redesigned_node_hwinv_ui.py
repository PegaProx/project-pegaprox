"""The hardware inventory of a node and the storage tables in Corporate Redesigned, in the browser.

Round 9, B2. The Hardware tab of a Proxmox VE node gets the processor and memory from the summary
read the view already holds, the health and wear of each disk from the disks read Configure > Disks
makes (one read per visit, shared with that sub tab), and the PCI devices from GET .../hardware/pci
(the route the guest passthrough dialog reads), one read per visit with its own Refresh. A value
the node does not report says so; an empty PCI answer says it can also be a read that failed. The
in-band panel keeps every read and write and draws in Corporate Redesigned's tokens and buttons. Configure >
LVM, LVM-Thin, ZFS and Repositories list their rows as tables. Classic Corporate keeps its markup.

Pure parts through window.PegaProxNodeInv. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the
counterproof against the build before this stage). Skips without Playwright. LW Nov 2026
"""
import copy
import re

import pytest

from test_corp_redesigned_guard_ui import GUESTS_PVE1, RESOURCES, _GuardApp, _corp_cluster
from test_corp_redesigned_node_hw_ui import (BUNDLE, DISKS, NODE, _HwServer, _no_errors, _open_disks, _open_hardware,
                                             _settled_hw, browser, firefox, playwright)  # noqa: F401 (fixtures)

LAYOUT = 'corporate-redesigned'
PCI = NODE + '/hardware/pci'
REPOS = NODE + '/repos'

# hardware/pci as get_node_pci_devices passes PVE's list on (display_name and passthrough_capable are its own)
PCI_LIST = [
    {'id': '0000:01:00.0', 'class': '0x020000', 'vendor': '0x8086', 'device': '0x1521', 'vendor_name': 'Intel Corporation',
     'device_name': 'I350 Gigabit Network Connection', 'subsystem_vendor_name': 'Intel Corporation',
     'subsystem_device_name': 'Ethernet Server Adapter I350-T2', 'iommugroup': 12, 'display_name': 'x', 'passthrough_capable': True},
    {'id': '0000:00:02.0', 'class': '0x030000', 'vendor': '0x8086', 'device': '0x3e92', 'vendor_name': 'Intel Corporation',
     'device_name': 'UHD Graphics 630', 'iommugroup': 1, 'mdev': 1, 'display_name': 'x', 'passthrough_capable': True},
    {'id': '0000:00:14.0', 'class': '0x0c0330', 'vendor': '0x8086', 'device': '0xa36d', 'vendor_name': 'Intel Corporation',
     'device_name': 'USB 3.1 xHCI Host Controller', 'iommugroup': -1, 'display_name': 'x', 'passthrough_capable': False},
    {'id': '0000:02:00.0', 'class': '0x120000', 'vendor': '0x10de', 'device': '0x20b5', 'iommugroup': 14,
     'display_name': 'x', 'passthrough_capable': True},
]


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, routes=None, **kw):
        r = {('GET', PCI): (200, PCI_LIST)}
        r.update(routes or {})
        app = _GuardApp(br or browser, _HwServer(layout=layout, routes=r, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _hw(app):
    _open_hardware(app.page)
    _settled_hw(app.page)
    return app.page


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def inv_page(browser):
    app = _GuardApp(browser, _HwServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeInv'):
        app.close()
        pytest.fail('the bundle has no hardware inventory helpers (window.PegaProxNodeInv)')
    yield app.page
    app.close()


def test_rules_pci_class_from_the_code(inv_page):
    got = inv_page.evaluate("""() => ['0x030000', '0x0c0330', '020000', '0x120000', '0xff0000', '', null, 'vga']
        .map(c => window.PegaProxNodeInv.pciClass(c))""")
    assert [g['base'] for g in got] == ['03', '0c', '02', '12', 'ff', '', '', '']
    assert [g['key'] for g in got] == ['crNhPciDisplay', 'crNhPciSerial', 'crNhPciNetwork', 'crNhPciAccel', '', '', '', '']


def test_rules_pci_read_states_groups_and_order(inv_page):
    ev = lambda read: inv_page.evaluate('(r) => window.PegaProxNodeInv.pci(r)', read)
    assert inv_page.evaluate('() => window.PegaProxNodeInv.pci(undefined).state') == 'loading'
    assert ev({'__crFail': {'status': 500, 'error': 'Failed to get PCI devices', 'code': ''}})['state'] == 'error'
    bad = ev({'error': 'boom'})
    assert bad['state'] == 'error' and bad['fail']['error'] == 'boom'
    assert ev([])['state'] == 'empty'
    m = ev(PCI_LIST + [{'id': '0000:03:00.0', 'class': '0x010802', 'iommugroup': '7'}, None, 'x'])
    assert m['state'] == 'ok' and [r['id'] for r in m['rows']] == sorted(r['id'] for r in m['rows'])
    by = {r['id']: r for r in m['rows']}
    # -1 is outside every group, never group -1; a group sent as text counts
    assert by['0000:00:14.0']['group'] is None and by['0000:03:00.0']['group'] == 7 and by['0000:01:00.0']['group'] == 12
    assert by['0000:00:02.0']['mdev'] is True and by['0000:01:00.0']['mdev'] is False
    assert by['0000:02:00.0']['vendor'] == '' and by['0000:02:00.0']['vendorId'] == '0x10de'
    assert m['grouped'] == 4


def test_rules_pci_filter(inv_page):
    rows = inv_page.evaluate('(r) => window.PegaProxNodeInv.pci(r).rows', PCI_LIST)
    match = lambda f: [r['id'] for r in rows if inv_page.evaluate('([r, f]) => window.PegaProxNodeInv.pciMatch(r, f)', [r, f])]
    assert len(match({'cls': 'all', 'q': ''})) == 4
    assert match({'cls': '02', 'q': ''}) == ['0000:01:00.0']
    assert match({'cls': 'all', 'q': 'i350-t2'}) == ['0000:01:00.0']
    assert match({'cls': 'all', 'q': '10DE'}) == ['0000:02:00.0']
    assert match({'cls': '03', 'q': 'usb'}) == []


def test_rules_memory_totals_of_the_summary(inv_page):
    ev = lambda s: inv_page.evaluate('(s) => window.PegaProxNodeInv.mem(s)', s)
    ok = ev({'pveversion': '9', 'memory': {'total': 1024, 'used': 10}, 'swap': {'total': 0, 'used': 0}})
    assert ok['mem'] == 1024 and ok['swap'] is None and ok['swapNone'] is True
    # get_node_summary answers {} when it cannot read the node: nothing there is a size
    blank = ev({})
    assert blank['sum'] == 'empty' and blank['mem'] is None and blank['swapNone'] is False
    assert ev(None)['sum'] == 'error' and inv_page.evaluate('() => window.PegaProxNodeInv.mem(undefined).sum') == 'loading'


# --- the hardware tab ---------------------------------------------------------------------------

def _kv(scope, k):
    return scope.locator(f'[data-cr-nc-k="{k}"] > dd').first.inner_text().strip()


def test_runtime_processor_and_memory_from_the_summary(open_app):
    app = open_app()
    page = _hw(app)
    sec = page.locator('[data-cr-nc-sec="hw-cpu"]')
    sec.wait_for(timeout=8000)
    assert sec.get_attribute('data-cr-nh-cpu') == 'ok'
    assert _kv(sec, 'model') == 'Intel(R) Xeon(R) CPU E5-2680 v4'
    assert (_kv(sec, 'sockets'), _kv(sec, 'cores'), _kv(sec, 'cpus')) == ('1', '4', '8')
    # the summary of the guard fake sends no clock and no hvm flag: said, never a number
    assert _kv(sec, 'mhz') == 'not reported' and _kv(sec, 'hvm') == 'not reported'
    assert _kv(sec, 'mem') == '32.0 GB' and _kv(sec, 'swap') == '8.0 GB'
    assert _kv(sec, 'dimm') == 'not reported, no source reads them'
    _no_errors(app)


def test_runtime_disk_health_shares_the_disks_read(open_app):
    app = open_app()
    page = _hw(app)
    sec = page.locator('[data-cr-nc-sec="hw-disks"][data-cr-nh-disks="ok"]')
    sec.wait_for(timeout=8000)
    assert sec.locator('[data-cr-nh-disk]').count() == 5
    assert sec.locator('[data-cr-nh-disk="sdb"] [data-cr-nd-health="failed"]').count() == 1
    assert sec.locator('[data-cr-nh-disk="sdc"] [data-cr-nd-health="none"]').inner_text().strip() == 'not reported'
    assert sec.locator('[data-cr-nh-disk="nvme0n1"] [data-cr-nh-disk-cell="wear"]').inner_text().strip() == '3 % used'
    assert sec.locator('[data-cr-nh-disks-failed]').count() == 1
    assert app.server.reads(DISKS) == 1 and app.server.reads_like(r'/smart$') == 0
    # Open Disks goes to the sub tab, which shows the same read without asking again
    sec.locator('[data-cr-nh-open-disks]').click()
    page.locator('[data-cr-nd-row="sda"]').wait_for(timeout=8000)
    assert app.server.reads(DISKS) == 1
    _no_errors(app)


def test_runtime_disk_health_when_the_list_fails(open_app):
    app = open_app(routes={('GET', DISKS): (500, {'error': 'disks/list timed out'})})
    page = _hw(app)
    st = page.locator('[data-cr-nc-sec="hw-disks"] [data-cr-nc-state="error"]')
    st.wait_for(timeout=8000)
    assert 'disks/list timed out' in st.inner_text()
    app.server.routes[('GET', DISKS)] = (200, [])
    st.locator('[data-cr-nc-retry="hw-disks"]').click()
    page.locator('[data-cr-nc-sec="hw-disks"][data-cr-nh-disks="empty"]').wait_for(timeout=8000)
    assert app.server.reads(DISKS) == 2


def test_runtime_pci_devices_with_class_group_and_mdev(open_app):
    app = open_app()
    page = _hw(app)
    sec = page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="ok"]')
    sec.wait_for(timeout=8000)
    assert '4 devices' in sec.locator('.cr-nc-titleline').inner_text()
    ids = [x.get_attribute('data-cr-nh-pci-row') for x in sec.locator('[data-cr-nh-pci-row]').all()]
    assert ids == ['0000:00:02.0', '0000:00:14.0', '0000:01:00.0', '0000:02:00.0']
    row = lambda i: sec.locator('tbody tr', has=page.locator(f'[data-cr-nh-pci-row="{i}"]'))
    assert 'Display controller' in row('0000:00:02.0').inner_text()
    assert row('0000:00:02.0').locator('[data-cr-nh-pci-mdev="yes"]').count() == 1
    assert row('0000:00:14.0').locator('[data-cr-nh-pci-group="none"]').inner_text().strip() == 'none'
    assert row('0000:01:00.0').locator('[data-cr-nh-pci-group="12"]').count() == 1
    assert 'I350-T2' in row('0000:01:00.0').inner_text() and '[8086:1521]' in row('0000:01:00.0').inner_text()
    # no vendor name sent: said, the IDs still there
    nv = row('0000:02:00.0')
    assert 'not reported' in nv.inner_text() and '[10de:20b5]' in nv.inner_text() and 'Processing accelerator' in nv.inner_text()
    assert sec.locator('[data-cr-nc-state]').count() == 0, 'devices in IOMMU groups: no IOMMU note'
    assert app.server.reads(PCI) == 1
    _no_errors(app)


def test_runtime_pci_filters_ask_nothing(open_app):
    app = open_app()
    page = _hw(app)
    sec = page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="ok"]')
    sec.wait_for(timeout=8000)
    sec.locator('[data-cr-nh-pci-class]').select_option('02')
    page.wait_for_function("() => document.querySelectorAll('[data-cr-nh-pci-row]').length === 1", timeout=4000)
    sec.locator('[data-cr-nh-pci-class]').select_option('all')
    sec.locator('[data-cr-nh-pci-q]').fill('usb')
    page.wait_for_function("() => document.querySelectorAll('[data-cr-nh-pci-row]').length === 1", timeout=4000)
    assert sec.locator('[data-cr-nh-pci-row="0000:00:14.0"]').count() == 1
    sec.locator('[data-cr-nh-pci-clear]').click()
    page.wait_for_function("() => document.querySelectorAll('[data-cr-nh-pci-row]').length === 4", timeout=4000)
    assert app.server.reads(PCI) == 1


def test_runtime_pci_once_per_visit_and_refresh(open_app):
    app = open_app()
    page = _hw(app)
    page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="ok"]').wait_for(timeout=8000)
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='VMs').click()
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Hardware').click()
    page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="ok"]').wait_for(timeout=8000)
    assert app.server.reads(PCI) == 1 and app.server.reads(DISKS) == 1
    page.locator('[data-cr-nh-pci-reload]').click()
    page.wait_for_function("() => true")
    page.wait_for_timeout(600)
    assert app.server.reads(PCI) == 2


def test_runtime_pci_states(open_app):
    app = open_app(routes={('GET', PCI): 'hold'})
    page = _hw(app)
    page.locator('[data-cr-nc-sec="pci"] [data-cr-nc-state="loading"]').wait_for(timeout=8000)
    for r in app.server.held:
        r.fulfill(status=500, body='{"error": "Failed to get PCI devices"}', headers={'Content-Type': 'application/json'})
    app.server.held.clear()
    err = page.locator('[data-cr-nc-sec="pci"] [data-cr-nc-state="error"]')
    err.wait_for(timeout=8000)
    assert 'Failed to get PCI devices' in err.inner_text()
    app.server.routes[('GET', PCI)] = (200, [])
    err.locator('[data-cr-nc-retry="pci"]').click()
    empty = page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="empty"] [data-cr-nc-state="warning"]')
    empty.wait_for(timeout=8000)
    assert 'can also be a read that failed' in empty.inner_text()
    # every device outside a group: IOMMU is off, said once above the table
    app.server.routes[('GET', PCI)] = (200, [dict(d, iommugroup=-1) for d in PCI_LIST])
    page.locator('[data-cr-nh-pci-reload]').click()
    page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="ok"] [data-cr-nc-for="pci-iommu"]').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_temperature_history_average(open_app):
    app = open_app()
    page = _hw(app)
    page.locator('[data-cr-nh-hist="ok"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-nh-hist-avg]').inner_text().strip() == 'Average: 52.0 \u00b0C'


def test_runtime_temperature_chart_axis_stays_inside_its_box(open_app):
    app = open_app()
    page = _hw(app)
    page.locator('[data-cr-nh-hist="ok"] [data-cr-chart="nh-temp"]').wait_for(timeout=8000)
    page.wait_for_timeout(300)
    # the chart sizes itself like the Monitor charts: its axis labels stay inside its box
    out = page.evaluate("""() => {
        const cell = document.querySelector('[data-cr-chart="nh-temp"]');
        const box = cell.getBoundingClientRect();
        return [...cell.querySelectorAll('*')].map(e => e.getBoundingClientRect())
            .filter(r => r.height > 0 && r.bottom > box.bottom + 1).length;
    }""")
    assert out == 0


def test_runtime_in_band_panel_in_corporate_redesigned(open_app):
    app = open_app()
    page = _hw(app)
    ib = page.locator('.cr-nh-inband')
    ib.locator('[data-cr-nc-kv="hw-fru"]').wait_for(timeout=8000)
    assert _kv(ib, 'manufacturer') == 'Example Systems' and _kv(ib, 'part') == 'not reported'
    assert ib.locator('[data-cr-nh-ib-health="warning"]').count() == 1
    text = ib.inner_text()
    assert 'Contributing: PS2 Status' in text and 'hwHealthCause' not in text
    assert ib.locator('[data-cr-nh-ib-refresh]').count() == 1
    assert ib.locator('button.cr-btn', has_text='Enable out-of-band monitoring').count() == 1
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_hardware_tab(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _open_hardware(page, redesigned=False)
    page.locator('text=Hardware Monitoring').first.wait_for(timeout=8000)
    page.wait_for_timeout(800)
    assert page.locator('[data-cr-nh-basics], [data-cr-nc-sec="pci"], .cr-nh-inband').count() == 0
    assert app.server.reads(PCI) == 0 and app.server.reads(DISKS) == 0
    _no_errors(app)


# --- the storage tables and the guest states ------------------------------------------------------

def _open_cfg(page, label):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    page.locator('.corp-subnav-item', has_text=re.compile(r'^\s*' + re.escape(label) + r'\s*$')).first.click()


@pytest.mark.parametrize('label,row', [('LVM', '[data-cr-nv-vg="pve"]'), ('LVM-Thin', '[data-cr-nv-thin="pve/data"]'),
                                       ('ZFS', '[data-cr-nv-pool="tank"]')])
def test_runtime_storage_lists_are_tables(open_app, label, row):
    app = open_app()
    page = app.page
    _open_cfg(page, label)
    r = page.locator(row)
    r.wait_for(timeout=8000)
    assert r.evaluate('e => e.tagName') == 'TR' and r.evaluate("e => !!e.closest('table.cr-nv-table')")
    assert page.locator('.cr-nc-item[data-cr-nv-vg], .cr-nc-item[data-cr-nv-thin], .cr-nc-item[data-cr-nv-pool]').count() == 0
    _no_errors(app)


def test_runtime_repositories_are_a_grouped_table(open_app):
    from test_corp_redesigned_guard_ui import NODE_STORE_READS
    reads = {k: v for k, v in NODE_STORE_READS.items() if k[1].endswith('/repos')}
    app = open_app(routes=reads)
    page = app.page
    _open_cfg(page, 'Repositories')
    page.locator('[data-cr-nr-repo]').first.wait_for(timeout=8000)
    groups = page.locator('table.cr-nr-table > tbody[data-cr-nc-group]')
    assert [g.get_attribute('data-cr-nc-group') for g in groups.all()] == ['on', 'off', 'absent']
    first = page.locator('[data-cr-nr-repo]').first
    assert first.evaluate('e => e.tagName') == 'TR'
    # the source line and the file share one cell, the switch has its own
    assert first.locator('td').count() == 4 and first.locator('[data-cr-nc-k="file"]').count() == 1
    _no_errors(app)


def test_runtime_a_stopped_guest_says_stopped_like_running(open_app):
    app = open_app(resources=GUESTS_PVE1 + [r for r in RESOURCES if r.get('node') != 'pve1'])
    page = app.page
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='VMs').click()
    st = page.locator('[data-cr-ng-row="105"]')
    st.wait_for(timeout=8000)
    labels = {x.get_attribute('data-cr-state'): x.inner_text().strip() for x in page.locator('[data-cr-ng] [data-cr-state]').all()}
    assert labels.get('stopped') == 'Stopped' and labels.get('running') == 'Running'


# --- layout -------------------------------------------------------------------------------------

_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_hardware_tab_without_sideways_scroll(open_app, firefox, browser, engine, width):
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser)
    page = _hw(app)
    page.locator('[data-cr-nc-sec="pci"][data-cr-nh-pci="ok"]').wait_for(timeout=8000)
    page.locator('[data-cr-nc-sec="hw-disks"][data-cr-nh-disks="ok"]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS)
    # every PCI column and the sensor state column are in view without scrolling the tables
    clipped = page.evaluate("""() => {
        const out = [];
        for (const sel of ['[data-cr-nc-sec="pci"] thead th[data-cr-col]', '.cr-nh-table thead th']) {
            for (const th of document.querySelectorAll(sel)) {
                let p = th.parentElement;
                while (p && getComputedStyle(p).overflowX === 'visible') p = p.parentElement;
                if (p && th.getBoundingClientRect().right > p.getBoundingClientRect().right + 1) out.push(th.textContent);
            }
        }
        return out;
    }""")
    assert clipped == []
    _no_errors(app)
