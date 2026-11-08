"""Gaps in the charts, the optional columns of the guest table and the snapshot warning of
the migrate dialog, at runtime.

Drives the built bundle (web/index.html) in headless Chromium against the fake server of
tests/test_ha_ui.py. The charts are read back from Chart.js itself: a slot without a sample
has to be a skipped point with spanGaps off, not a 0. The disk rates of the table come from
two samples of the counters a later poll brings; Playwright's clock lets the 15 s poll pass at
once. The server side is tested in test_chart_gaps.py, test_guest_list_columns.py and
test_migrate_snapshot_check.py. Skips where Playwright is not installed.
LW Oct 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import (CLUSTER, LANGS, VM_CONFIG, _App, _FakeServer, _blocks, _classes, _read,  # noqa: F401
                        browser)

SHOTS = os.environ.get('PP_FEATURE_SHOTS', '')
G = '/api/clusters/c1/vms/pve1'
MiB = 1048576

_NODE = {'status': 'online', 'cpu_percent': 5.0, 'mem_percent': 20.0, 'disk_percent': 10.0, 'score': 42.0,
         'uptime': 86400, 'loadavg': [0.1, 0.2, 0.3], 'netin': 0, 'netout': 0, 'mem_used': 6871947673,
         'mem_total': 34359738368, 'disk_used': 0, 'disk_total': 0, 'cpu_count': 8, 'maxcpu': 8}
METRICS = {'pve1': dict(_NODE), 'pve2': dict(_NODE), 'pve3': dict(_NODE)}


def _guest(vmid, name, **kw):
    g = {'vmid': vmid, 'name': name, 'type': 'qemu', 'status': 'running', 'node': 'pve1', 'cpu': 0.05,
         'cpu_percent': 5, 'maxcpu': 2, 'mem': 1073741824, 'maxmem': 4294967296, 'mem_percent': 25,
         'disk': 0, 'maxdisk': 34359738368, 'uptime': 3600, 'diskread': 0, 'diskwrite': 0}
    g.update(kw)
    return g


GUESTS = [
    _guest(100, 'web01', uptime=3600, diskread=500 * MiB, diskwrite=20 * MiB, agent_running=True),
    _guest(101, 'db01', uptime=7200, diskread=900 * MiB, diskwrite=300 * MiB, agent_running=False),
    _guest(102, 'app01', uptime=100, diskread=5 * MiB, diskwrite=MiB),
    _guest(200, 'ct01', type='lxc', uptime=50, diskread=MiB, diskwrite=MiB),
    _guest(300, 'old01', status='stopped', uptime=0, cpu_percent=0, mem_percent=0, mem=0),
]

# six slots: two of them without a sample, a real 0 at the end, a lone sample in net_in
TS = [1759800000 + 60 * i for i in range(6)]
SERIES = {'timestamps': TS, 'metrics': {
    'cpu': [10, 20, None, None, 30, 0],
    'memory': [50, 50, None, None, 60, 60],
    'disk_read': [100, 200, None, None, 300, 0],
    'disk_write': [1, 2, None, None, 3, 0],
    'net_in': [None, 5, None, None, 7, 8],
    'net_out': [1, 1, None, None, 1, 1],
    'pressurecpusome': [None, 1.5, None, None, 2.5, 0],
    'pressurecpufull': [None, 0, None, None, 0.5, 0],
}}
GAPS = {2, 3}


class _ListServer(_FakeServer):
    def __init__(self, check=None, check_status=200, raw=None, vm_storages=None, **kw):
        kw.setdefault('metrics', METRICS)
        super().__init__(**kw)
        for tf in ('hour', 'day'):
            for vmid in (100, 101):
                self.extra[('GET', f'{G}/qemu/{vmid}/rrd/{tf}')] = (200, dict(SERIES))
        self.extra[('GET', f'{G}/qemu/100/config')] = (
            200, dict(VM_CONFIG, raw=dict({'name': 'web01', 'digest': 'x'}, **(raw or {})), status={'status': 'running'}))
        self.extra[('GET', f'{G}/qemu/100/migrate-check')] = (check_status, check if check is not None else {
            'supported': True, 'snapshot_count': 0, 'snapshots': [], 'volumes': [], 'replicated_to': []})
        stores = vm_storages if vm_storages is not None else [
            {'storage': 'local-lvm', 'type': 'lvmthin', 'content': 'images,rootdir', 'avail': 100 * 2 ** 30},
            {'storage': 'tank', 'type': 'zfspool', 'content': 'images,rootdir', 'avail': 100 * 2 ** 30},
            {'storage': 'nfs', 'type': 'nfs', 'content': 'images', 'avail': 100 * 2 ** 30},
        ]
        for n in ('pve1', 'pve2', 'pve3'):
            self.extra[('GET', f'/api/clusters/c1/nodes/{n}/storage')] = (200, [dict(s) for s in stores])


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(clock=False, **kw):
        kw.setdefault('role', 'standalone')
        kw.setdefault('layout', 'modern')
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [dict(g) for g in GUESTS])
        app = _App(browser, _ListServer(**kw), clock=clock)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.wait_for_timeout(300)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _resources(app, layout='modern', table=True):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=8000)
    if table and layout != 'corporate':
        page.locator('button[title="List View"]').first.click()
    if table:
        page.locator('table th[data-col="vmid"]').first.wait_for(timeout=5000)
    page.wait_for_timeout(200)


def _row(app, name):
    return app.page.locator('table tbody tr', has=app.page.get_by_text(name, exact=True)).first


def _columns(app, *keys):
    page = app.page
    page.locator('[data-col-picker]').first.click()
    menu = page.locator('[data-col-menu]')
    menu.wait_for(timeout=3000)
    for k in keys:
        menu.locator(f'[data-col-toggle="{k}"] input').click()
    # a click beside the menu closes it
    page.mouse.click(5, 990)
    menu.wait_for(state='detached', timeout=3000)


def _headers(app):
    return app.page.locator('table thead th[data-col]').evaluate_all('els => els.map(e => e.dataset.col)')


# --- charts ---------------------------------------------------------------------------------------

_CHARTS = """() => [...document.querySelectorAll('canvas')].map(c => window.Chart && window.Chart.getChart(c)).filter(Boolean)
    .map(ch => ({
        labels: ch.data.datasets.map(d => d.label),
        data: ch.data.datasets.map(d => d.data),
        span: ch.data.datasets.map(d => d.spanGaps),
        skip: ch.data.datasets.map((d, i) => ch.getDatasetMeta(i).data.map(p => !!p.skip)),
        radius: ch.data.datasets.map((d, i) => ch.getDatasetMeta(i).data.map(p => p.options ? p.options.radius : null)),
    }))"""


def _charts(app, want):
    app.page.wait_for_function(f'() => [...document.querySelectorAll("canvas")].filter(c => window.Chart && window.Chart.getChart(c)).length >= {want}',
                               timeout=8000)
    return app.page.evaluate(_CHARTS)


def _by_label(charts, label):
    return next(c for c in charts if c['labels'][0] == label)


def _check_gaps(charts, mem_values):
    cpu = _by_label(charts, 'CPU')
    assert cpu['data'][0] == [10, 20, None, None, 30, 0]
    assert cpu['span'] == [False]
    # Chart.js skips the null points: the line breaks there, the 0 at the end is drawn
    assert cpu['skip'][0] == [False, False, True, True, False, False]
    mem = _by_label(charts, 'Memory')
    assert [v is None for v in mem['data'][0]] == [i in GAPS for i in range(6)]
    assert [round(v, 2) for v in mem['data'][0] if v is not None] == mem_values
    net = _by_label(charts, 'Network In')
    # a sample between two gaps gets a dot, a line would not show it
    assert net['radius'][0][1] == 2 and net['radius'][0][4] == 0 and net['radius'][0][5] == 0


def test_runtime_the_metrics_dialog_draws_gaps(open_app):
    app = open_app()
    page = app.page
    _resources(app)
    _row(app, 'web01').locator('button[title="Metrics"]').click()
    charts = _charts(app, 7)
    _check_gaps(charts, [2.0, 2.0, 2.4, 2.4])
    psi = next(c for c in charts if c['labels'] == ['Some', 'Full'])
    assert psi['data'] == [[None, 1.5, None, None, 2.5, 0], [None, 0, None, None, 0.5, 0]]
    assert psi['skip'][0] == [True, False, True, True, False, False]

    # the tooltip over a gap shows a real sample next to it, never a 0 for the gap
    canvas = page.locator('canvas').first
    box = canvas.bounding_box()
    x = page.evaluate("""() => { const ch = window.Chart.getChart(document.querySelector('canvas'));
        return ch.getDatasetMeta(0).data[2].x; }""")
    page.mouse.move(box['x'] + x, box['y'] + box['height'] / 2)
    page.wait_for_timeout(200)
    active = page.evaluate("""() => window.Chart.getChart(document.querySelector('canvas'))
        .tooltip.getActiveElements().map(a => a.index)""")
    assert not set(active) & GAPS, active
    _shot(app, 'chart_gaps_modern')
    assert not app.errors, app.errors


def test_runtime_the_corporate_guest_view_draws_gaps(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('.corp-tree-child', has_text='web01').first.click()
    charts = _charts(app, 6)
    _check_gaps(charts, [2.0, 2.0, 2.4, 2.4])
    _shot(app, 'chart_gaps_corporate')
    assert not [e for e in app.errors if 'guest-info' not in e], app.errors


# --- the optional columns -------------------------------------------------------------------------

def test_runtime_the_columns_start_off_and_are_picked_per_user(open_app):
    app = open_app()
    page = app.page
    _resources(app)
    base = ['vmid', 'name', 'type', 'node', 'ip', 'cpu_percent', 'mem', 'disk', 'status', 'actions']
    assert _headers(app) == base
    _columns(app, 'agent')
    assert _headers(app) == base[:8] + ['agent'] + base[8:]
    _columns(app, 'diskio')
    assert _headers(app) == base[:8] + ['agent', 'diskio'] + base[8:]
    assert json.loads(page.evaluate("localStorage.getItem('pegaprox-vmcols-admin')")) == ['agent', 'diskio']
    # the picker belongs to the table view
    page.locator('button[title="Grid View"]').first.click()
    assert page.locator('[data-col-picker]').count() == 0
    page.reload(wait_until='load')
    app.wait_for_app()
    _resources(app)
    assert _headers(app) == base[:8] + ['agent', 'diskio'] + base[8:]
    _columns(app, 'agent')
    assert _headers(app) == base[:8] + ['diskio'] + base[8:]
    assert not app.errors, app.errors


def test_runtime_the_agent_column(open_app):
    app = open_app(clock=True)
    _resources(app)
    _columns(app, 'agent')
    cell = lambda name: _row(app, name).locator('td[data-col="agent"] [data-agent]')
    assert cell('web01').get_attribute('data-agent') == 'up' and cell('web01').inner_text().strip() == 'Yes'
    assert cell('db01').get_attribute('data-agent') == 'down' and cell('db01').inner_text().strip() == 'No'
    assert cell('app01').get_attribute('data-agent') == 'none'
    assert cell('app01').get_attribute('title') == 'Not checked yet'
    assert cell('ct01').get_attribute('data-agent') == 'none' and cell('ct01').get_attribute('title') is None
    assert cell('old01').get_attribute('data-agent') == 'none'
    # the agent comes up: the next poll redraws the row although nothing else moved
    app.server.resources = [dict(g, agent_running=True) if g['vmid'] == 102 else dict(g) for g in GUESTS]
    app.page.clock.run_for(15500)
    app.page.wait_for_function(
        """() => { const r = [...document.querySelectorAll('table tbody tr')].find(t => t.innerText.includes('app01'));
                   return r && r.querySelector('[data-agent="up"]'); }""", timeout=5000)
    # sorted by it: the ones with an agent last going up, first going down
    app.page.locator('table thead th[data-col="agent"]').click()
    app.page.locator('table thead th[data-col="agent"]').click()
    names = app.page.locator('table tbody tr td:nth-child(3)').all_inner_texts()
    assert [n.split('\n')[0] for n in names][:3] in (['web01', 'app01', 'db01'], ['app01', 'web01', 'db01'])
    _shot(app, 'list_agent_modern')
    assert not app.errors, app.errors


def _io(app, name):
    el = _row(app, name).locator('td[data-col="diskio"] [data-io]')
    return el.get_attribute('data-io'), el.get_attribute('data-io-read'), el.get_attribute('data-io-write'), el.inner_text()


def test_runtime_disk_rates_from_two_samples(open_app):
    app = open_app(clock=True, layout='corporate')
    _resources(app, 'corporate')
    _columns(app, 'diskio')
    # one sample is no rate yet
    for name in ('web01', 'db01', 'app01', 'ct01'):
        assert _io(app, name)[0] == 'none', name
    assert _row(app, 'web01').locator('[data-io]').get_attribute('title') == 'Shown from the next update on'
    assert _io(app, 'old01')[0] == 'none'

    # ten seconds later by the guests' uptime: web01 read 100 MiB and wrote 10 KiB, db01's
    # node has not sampled again, app01 restarted, the container did nothing
    nxt = {100: dict(uptime=3610, diskread=600 * MiB, diskwrite=20 * MiB + 10240),
           102: dict(uptime=5, diskread=1000, diskwrite=1000),
           200: dict(uptime=70)}
    app.server.resources = [dict(g, **nxt.get(g['vmid'], {})) for g in GUESTS]
    app.page.clock.run_for(15500)
    app.page.wait_for_function(
        """() => [...document.querySelectorAll('[data-io="rate"]')].length >= 2""", timeout=5000)
    state, read, write, text = _io(app, 'web01')
    assert (state, read, write) == ('rate', str(10 * MiB), '1024')
    assert 'Read 10 MB/s' in text and 'Write 1.0 KB/s' in text
    assert _io(app, 'ct01')[:3] == ('rate', '0', '0') and '0 B/s' in _io(app, 'ct01')[3]
    assert _io(app, 'db01')[0] == 'none'
    assert _io(app, 'app01')[0] == 'none'

    # the next sample of web01: idle now
    app.server.resources = [dict(g, **nxt.get(g['vmid'], {})) for g in GUESTS]
    app.server.resources[0].update(uptime=3620)
    app.page.clock.run_for(15500)
    app.page.wait_for_function(
        """() => { const r = [...document.querySelectorAll('table tbody tr')].find(t => t.innerText.includes('web01'));
                   const c = r && r.querySelector('[data-io]'); return c && c.dataset.ioRead === '0'; }""", timeout=5000)

    # sorted by throughput
    app.server.resources[0].update(uptime=3630, diskread=700 * MiB)
    app.page.clock.run_for(15500)
    app.page.wait_for_function(
        """() => { const r = [...document.querySelectorAll('table tbody tr')].find(t => t.innerText.includes('web01'));
                   const c = r && r.querySelector('[data-io]'); return c && c.dataset.ioRead === String(10 * 1048576); }""", timeout=5000)
    th = app.page.locator('table thead th[data-col="diskio"]')
    th.click()
    th.click()
    first = app.page.locator('table tbody tr').first
    assert 'web01' in first.inner_text()
    _shot(app, 'list_diskio_corporate')
    assert not app.errors, app.errors


def test_runtime_the_columns_in_corporate_and_german(open_app):
    app = open_app(layout='corporate', language='de')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.locator('table th[data-col="vmid"]').first.wait_for(timeout=8000)
    picker = page.locator('[data-col-picker]')
    assert picker.inner_text().strip() == 'Spalten'
    picker.click()
    menu = page.locator('[data-col-menu]')
    text = menu.inner_text()
    for needle in ('Gast-Agent', 'Ob der QEMU Guest Agent einer laufenden VM antwortet', 'Disk-I/O'):
        assert needle in text, needle
    menu.locator('[data-col-toggle="agent"] input').click()
    page.mouse.click(5, 990)
    assert 'GAST-AGENT' in page.locator('table thead th[data-col="agent"]').inner_text().upper()
    assert _row(app, 'web01').locator('[data-agent="up"]').inner_text().strip() == 'Ja'
    _shot(app, 'list_columns_corporate_de')
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_the_columns(open_app):
    app = open_app(role='standby')
    _resources(app)
    _columns(app, 'agent', 'diskio')
    assert 'agent' in _headers(app) and 'diskio' in _headers(app)
    assert not [c for c in app.server.calls if c[0] != 'GET' and '/api/clusters/' in c[1]]
    assert not app.errors, app.errors


# --- the snapshot warning of the migrate dialog -------------------------------------------------

LVM = {'key': 'scsi0', 'storage': 'local-lvm', 'type': 'lvmthin', 'format': 'raw', 'family': None}
ZFS = {'key': 'scsi1', 'storage': 'local-zfs', 'type': 'zfspool', 'format': 'raw', 'family': 'zfs'}
QCOW = {'key': 'virtio0', 'storage': 'local', 'type': 'dir', 'format': 'qcow2', 'family': 'qcow2'}


def _check(*volumes, count=3, replicated=()):
    snaps = [{'name': f'snap{i}', 'vmstate': False} for i in range(min(count, 50))]
    return {'supported': True, 'snapshot_count': count, 'snapshots': snaps, 'volumes': list(volumes),
            'replicated_to': list(replicated)}


def _migrate(app, layout='modern'):
    page = app.page
    _resources(app, layout, table=False)
    page.locator('button[title="Migrate"]').first.click()
    modal = page.locator('div.fixed', has=page.get_by_text('Target Node', exact=False)).last
    modal.wait_for(timeout=5000)
    return modal


def _box(modal):
    box = modal.locator('[data-mig-snap]')
    box.wait_for(timeout=5000)
    return box


def test_runtime_a_running_vm_with_snapshots_on_local_disks(open_app):
    app = open_app(check=_check(LVM, ZFS, count=8, replicated=['pve2']))
    modal = _migrate(app)
    box = _box(modal)
    assert box.get_attribute('data-mig-snap') == 'blocked'
    text = box.inner_text()
    assert 'Snapshots on local disks' in text and 'This guest has 8 snapshots' in text
    # the newest six by name, and how many more there are
    assert box.locator('[data-mig-snap-names] code').all_inner_texts() == ['snap7', 'snap6', 'snap5', 'snap4', 'snap3', 'snap2']
    assert '+2 more' in box.locator('[data-mig-snap-names]').inner_text()
    live = box.locator('[data-mig-snap-live]')
    assert 'scsi0 (local-lvm, lvmthin), scsi1 (local-zfs, zfspool)' in live.inner_text()
    assert 'while the VM runs' in live.inner_text()
    # replication keeps the ZFS disk on pve2 already
    target = modal.locator('select').first
    target.select_option('pve2')
    assert live.inner_text().count('(') == 1 and 'scsi0 (local-lvm, lvmthin)' in live.inner_text()
    target.select_option('pve3')
    assert 'scsi1 (local-zfs, zfspool)' in live.inner_text()
    _shot(app, 'mig_snap_live')

    # offline: LVM-thin cannot carry them, ZFS copies them along
    modal.get_by_text('Live Migration', exact=False).first.click()
    assert box.locator('[data-mig-snap-live]').count() == 0
    assert 'scsi0 (local-lvm, lvmthin)' in box.locator('[data-mig-snap-stuck]').inner_text()
    assert 'scsi1 (local-zfs, zfspool)' in box.locator('[data-mig-snap-copied]').inner_text()
    # a warning, the decision stays with the admin
    assert modal.get_by_role('button', name='Migrate', exact=True).is_enabled()
    assert app.server.calls.count(('GET', f'{G}/qemu/100/migrate-check')) == 1
    _shot(app, 'mig_snap_offline')
    assert not app.errors, app.errors


def test_runtime_the_target_storage_decides_whether_snapshots_travel(open_app):
    app = open_app(resources=[_guest(100, 'web01', status='stopped', uptime=0)], check=_check(QCOW))
    modal = _migrate(app)
    box = _box(modal)
    assert box.get_attribute('data-mig-snap') == 'copied'
    assert 'virtio0 (local, dir)' in box.locator('[data-mig-snap-copied]').inner_text()
    modal.locator('select').first.select_option('pve2')
    store = modal.locator('select').nth(1)
    modal.locator('select').nth(1).locator('option[value="tank"]').wait_for(state='attached', timeout=5000)
    for name, state in (('local-lvm', 'blocked'), ('tank', 'blocked'), ('nfs', 'copied'), ('', 'copied')):
        store.select_option(name)
        assert box.get_attribute('data-mig-snap') == state, name
    store.select_option('tank')
    assert 'cannot take the snapshots' in box.locator('[data-mig-snap-stuck]').inner_text()
    assert not app.errors, app.errors


def test_runtime_no_snapshots_no_warning(open_app):
    app = open_app()
    modal = _migrate(app)
    modal.locator('select').first.select_option('pve2')
    app.page.wait_for_timeout(500)
    assert modal.locator('[data-mig-snap]').count() == 0
    assert app.server.calls.count(('GET', f'{G}/qemu/100/migrate-check')) == 1
    assert not app.errors, app.errors


def test_runtime_only_shared_disks_no_warning(open_app):
    app = open_app(check=_check())
    modal = _migrate(app)
    app.page.wait_for_timeout(500)
    assert modal.locator('[data-mig-snap]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_failed_check_leaves_the_dialog_as_it_was(open_app):
    app = open_app(check={'error': 'Could not read the snapshots of the guest'}, check_status=502)
    modal = _migrate(app)
    modal.locator('select').first.select_option('pve2')
    app.page.wait_for_timeout(500)
    assert modal.locator('[data-mig-snap]').count() == 0
    assert modal.get_by_role('button', name='Migrate', exact=True).is_enabled()
    assert not [e for e in app.errors if '502' not in e], app.errors


def test_runtime_the_warning_in_corporate_and_german(open_app):
    app = open_app(layout='corporate', language='de', check=_check(LVM, count=2))
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text='Ressourcen').first.click()
    page.get_by_text('web01').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    page.locator('button[title="Migrieren"]').first.click()
    box = page.locator('[data-mig-snap]')
    box.wait_for(timeout=5000)
    text = box.inner_text()
    assert 'Snapshots auf lokalen Disks' in text and 'Dieser Gast hat 2 Snapshots' in text
    assert 'nicht im laufenden Betrieb' in box.locator('[data-mig-snap-live]').inner_text()
    _shot(app, 'mig_snap_corporate_de')
    assert not app.errors, app.errors


def test_runtime_a_standby_opens_no_migrate_dialog(open_app):
    app = open_app(role='standby', check=_check(LVM))
    _resources(app, table=False)
    assert app.page.locator('button[title="Migrate"]').count() == 0
    assert not [c for c in app.server.calls if c[1].endswith('/migrate-check')]
    assert not app.errors, app.errors


# --- the source ----------------------------------------------------------------------------------

def _src(name):
    return _read('web', 'src', name)


def _new_code():
    tables, modals, ui, dash = _src('tables.js'), _src('vm_modals.js'), _src('ui.js'), _src('dashboard.js')
    parts = [tables[tables.index('// LW Oct 2026 - optional columns of the guest table'):tables.index('// Resource Table Component')]]
    i = tables.index('// the optional columns, kept per user next to the sort')
    parts.append(tables[i:tables.index('const [actionLoading, setActionLoading]', i)])
    i = tables.index('const extraColText = {')
    parts.append(tables[i:tables.index('return(', i)])
    i = modals.index('// LW Oct 2026 - snapshots on local disks, read once')
    parts.append(modals[i:modals.index('// Fetch storages when target node changes', i)])
    i = modals.index('{snapVols.length > 0 &&')
    parts.append(modals[i:modals.index('{(hasCdDvd ||', i)])
    i = ui.index('// LW Oct 2026 - a slot without a sample')
    parts.append(ui[i:ui.index('// Set canvas dimensions explicitly', i)])
    i = dash.index('// LW Oct 2026 - the agent column of the list redraws')
    parts.append(dash[i:dash.index('function areResourcesEqual', i)])
    return parts


def _keys():
    keys = set()
    for name in ('tables.js', 'vm_modals.js'):
        keys |= set(re.findall(r"'((?:listCol|migSnap)[A-Za-z]*)'", _src(name)))
    return keys


def test_every_new_string_is_in_all_nine_languages_once():
    keys = _keys()
    assert keys == {'listColumns', 'listColAgent', 'listColAgentHint', 'listColAgentUnknown', 'listColDiskIo',
                    'listColDiskIoHint', 'listColDiskIoWait', 'listColRead', 'listColWrite',
                    'migSnapTitle', 'migSnapIntro', 'migSnapMore', 'migSnapLive', 'migSnapStuck',
                    'migSnapCopied'}, sorted(keys)
    blocks = _blocks()
    for lang in LANGS:
        for key in keys:
            lines = re.findall(r'^ +' + key + r': (.+)$', blocks[lang], re.M)
            assert len(lines) == 1, (lang, key, len(lines))
            assert '\u2014' not in lines[0] and '\u2013' not in lines[0], (lang, key)
    for key, holder in (('migSnapIntro', '{count}'), ('migSnapMore', '{n}'), ('migSnapLive', '{disks}'),
                        ('migSnapStuck', '{disks}'), ('migSnapCopied', '{disks}')):
        for lang in LANGS:
            line = re.findall(r'^ +' + key + r': (.+)$', blocks[lang], re.M)[0]
            assert line.count(holder) == 1 and not set(re.findall(r'\{[a-z]+\}', line)) - {holder}, (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _src('contexts.js')


def test_no_em_dash_in_the_new_code():
    for part in _new_code():
        assert '\u2014' not in part and '\u2013' not in part


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code():
        names |= _classes(part)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_every_icon_exists():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _src('icons.js'), re.M))
    used = set()
    for part in _new_code():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used and used <= icons, sorted(used - icons)


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('data-col-picker', 'pegaprox-resources-frame', 'migrate-check', 'data-mig-snap',
                   'spanGaps', 'listColDiskIoHint', 'migSnapStuck'):
        assert needle in bundle, needle
