"""The object views of Corporate Redesigned (Preview) in the browser: cluster, node, VM and
container.

Each object gets the same head (icon, name, id, state, where it sits, facts) and a tab list
that walks with the arrow keys; the tab contents are the classic ones. The buttons of a head
are the classic view's own, so a standby still shows none of the power actions and every
dangerous one still asks first. The performance charts read the existing metrics endpoints
with the existing presets and say when a read failed, when a range holds no samples and why a
stopped guest has none. Runs against the fake server of tests/test_ha_ui.py and skips without
Playwright. LW Oct 2026
"""
import json
import re
import time

import pytest

from test_corp_redesigned_dashboard_ui import STATUS, _bytes, _crumbs, _DashServer
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, METRICS, VM, _GuardApp
from test_ha_ui import BASE, NODE_METRICS

LAYOUT = 'corporate-redesigned'

STAMPS = [FIXED - 60 * (59 - i) for i in range(60)]


def _series(base, step):
    return [round(base + step * ((i * 7) % 11), 2) for i in range(60)]


NODE_RRD = {'timestamps': STAMPS, 'metrics': {
    'cpu': _series(5, 1), 'memory': _series(20, 0.5), 'iowait': _series(0.5, 0.1), 'loadavg': _series(0.2, 0.05),
    'net_in': _series(40, 3), 'net_out': _series(25, 2), 'swap': _series(1, 0), 'rootfs': _series(10, 0)}}
GUEST_RRD = {'timestamps': STAMPS, 'metrics': {
    'cpu': _series(4, 1), 'memory': _series(25, 1), 'disk_read': _series(2048, 300), 'disk_write': _series(4096, 200),
    'net_in': _series(1500, 90), 'net_out': _series(900, 40)}}
EMPTY_RRD = {'timestamps': [], 'metrics': {'cpu': [], 'memory': []}}
SUMMARY = {'pveversion': 'pve-manager/9.0.3', 'kversion': 'Linux 6.14.8-2-pve', 'uptime': 3 * 86400 + 5 * 3600,
           'cpuinfo': {'model': 'AMD EPYC 7302P', 'cores': 16, 'cpus': 32, 'sockets': 1},
           'swap': {'used': 0, 'total': 8 * 1024 ** 3}}
GUEST_INFO = {'agent_running': True, 'os_pretty_name': 'Debian GNU/Linux 12 (bookworm)',
              'ip_addresses': ['10.0.0.50', 'fe80::1'], 'hostname': 'web01'}


class _ObjServer(_DashServer):
    """The dashboard fake plus what the object views read: node summary and address, guest
    agent, and the metrics of node and guests (rrd_status / rrd_body to make them fail or empty)."""

    def __init__(self, rrd_status=200, rrd_body=None, **kw):
        extra = {
            ('GET', '/api/clusters/c1/nodes/pve1/summary'): (200, SUMMARY),
            ('GET', '/api/clusters/c1/nodes/pve1/ip'): (200, {'ip': '10.0.0.11'}),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/100/guest-info'): (200, GUEST_INFO),
            ('GET', '/api/clusters/c1/vms/pve1/qemu/100/lock'): (200, {'locked': False}),
            ('GET', '/api/clusters/c1/proxmox-ha/resources'): (200, [{'sid': 'vm:100', 'state': 'started'}]),
            ('GET', '/api/clusters/c1/metrics'): (200, METRICS),
        }
        extra.update(kw.pop('extra', {}))
        super().__init__(extra=extra, **kw)
        self.rrd_status = rrd_status
        self.rrd_body = rrd_body

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        node = path == '/api/clusters/c1/nodes/pve1/rrddata'
        guest = re.fullmatch(r'/api/clusters/c1/vms/[^/]+/(qemu|lxc)/\d+/rrd/(hour|day|week|month|year)', path)
        if req.url.startswith(BASE) and (node or guest):
            self.calls.append((req.method, path))
            self.urls.append(req.url)
            if self.rrd_status != 200:
                return route.fulfill(status=self.rrd_status, body='{"error": "rrd went away"}',
                                     headers={'Content-Type': 'application/json'})
            body = self.rrd_body if self.rrd_body is not None else (NODE_RRD if node else GUEST_RRD)
            return route.fulfill(status=200, body=json.dumps(body), headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(storage=None, viewport=(1600, 1000), **kw):
        app = _GuardApp(browser, _ObjServer(layout=LAYOUT, **kw), storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _cluster(page):
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=10000)


def _open_node(page):
    _cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    page.locator('[data-cr-objhead="node"]').wait_for(timeout=8000)


def _open_guest(page, name, kind='vm'):
    _cluster(page)
    page.locator('.corp-tree-child', has_text=name).first.click()
    page.locator(f'[data-cr-objhead="{kind}"]').wait_for(timeout=8000)


def _meta(page, kind):
    return page.evaluate('''(k) => Object.fromEntries(Array.from(document.querySelectorAll(`[data-cr-objhead="${k}"] [data-cr-meta]`))
        .map(m => [m.dataset.crMeta, m.querySelector('dd').innerText.trim()]))''', kind)


def _tabs(page, which):
    return page.evaluate('''(w) => Array.from(document.querySelectorAll(`[data-cr-tabs="${w}"] [role="tab"]`))
        .map(b => [b.dataset.crTab, b.innerText.trim(), b.getAttribute('aria-selected'), b.tabIndex])''', which)


def _actions(page, kind):
    return [x.strip() for x in page.locator(f'[data-cr-objhead="{kind}"] .cr-objhead-actions > button, '
                                            f'[data-cr-objhead="{kind}"] .cr-objhead-actions > .relative > button').all_inner_texts()]


def _rrd_urls(app, part):
    return [u for u in app.server.urls if part in u]


def _wait(page, fn, seconds=4):
    deadline = time.time() + seconds
    while time.time() < deadline and not fn():
        page.wait_for_timeout(100)
    return fn()


def _no_errors(app):
    assert not app.errors, app.errors


# --- node ----------------------------------------------------------------------------------------

def test_runtime_the_node_head_says_what_the_node_reports(open_app):
    app = open_app()
    page = app.page
    _open_node(page)
    head = page.locator('[data-cr-objhead="node"]')
    assert head.locator('.cr-objhead-name').inner_text() == 'pve1'
    assert head.locator('[data-cr-state]').get_attribute('data-cr-state') == 'online'
    page.wait_for_function('() => document.querySelector(\'[data-cr-objhead="node"] [data-cr-meta="ip"]\')', timeout=5000)
    m = NODE_METRICS['pve1']
    meta = _meta(page, 'node')
    assert meta == {
        'cluster': 'Testi', 'ip': '10.0.0.11', 'pve': SUMMARY['pveversion'], 'cpu': f"{m['cpu_percent']:.1f}%",
        'mem': f"{m['mem_used'] / m['mem_total'] * 100:.1f}% ({_bytes(m['mem_used'])} / {_bytes(m['mem_total'])})",
        'guests': '2/2 running', 'uptime': '3d 5h 0m'}, meta
    # the node's own web UI, and the classic actions in the classic menu
    assert _actions(page, 'node') == ['Open in Proxmox', 'Actions']
    assert _crumbs(page) == ['All', 'Testi', 'Overview', 'pve1']
    _no_errors(app)


def test_runtime_the_node_tabs_walk_with_the_arrow_keys(open_app):
    app = open_app()
    page = app.page
    _open_node(page)
    tabs = _tabs(page, 'node')
    assert [x[0] for x in tabs] == ['summary', 'monitor', 'configure', 'hardware', 'vms', 'shell', 'subscription']
    assert [x[1] for x in tabs] == ['Summary', 'Monitor', 'Configure', 'Hardware', 'VMs', 'Shell', 'Subscription']
    assert [(x[2], x[3]) for x in tabs][:2] == [('true', 0), ('false', -1)]
    page.locator('[data-cr-tabs="node"] [data-cr-tab="summary"]').focus()
    page.keyboard.press('ArrowRight')
    assert _tabs(page, 'node')[1][2] == 'true'
    assert page.evaluate('() => document.activeElement.dataset.crTab') == 'monitor'
    # the monitor tab is the classic one with its sub navigation, the charts are the preview's
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    assert page.locator('.corp-subnav [data-corp-node-timeline]').count() == 1
    page.keyboard.press('End')
    assert _tabs(page, 'node')[-1][2] == 'true'
    page.keyboard.press('ArrowRight')
    assert _tabs(page, 'node')[0][2] == 'true'
    page.keyboard.press('ArrowLeft')
    assert _tabs(page, 'node')[-1][2] == 'true'
    page.keyboard.press('Home')
    assert _tabs(page, 'node')[0][2] == 'true'
    # back on the summary: the system information card (round 7 moved the CPU model there)
    assert page.locator('[data-cr-nsi]', has_text='AMD EPYC 7302P').count() >= 1
    _no_errors(app)


def test_runtime_the_node_charts_follow_the_time_range(open_app):
    app = open_app()
    page = app.page
    _open_node(page)
    page.locator('[data-cr-tabs="node"] [data-cr-tab="monitor"]').click()
    panel = page.locator('[data-cr-perf="ready"]')
    panel.wait_for(timeout=8000)
    assert _rrd_urls(app, '/nodes/pve1/rrddata') == [f'{BASE}/api/clusters/c1/nodes/pve1/rrddata?timeframe=hour']
    charts = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-chart]'))
        .map(c => [c.dataset.crChart, !!c.querySelector('canvas')])''')
    assert charts == [[k, True] for k in ('cpu', 'memory', 'iowait', 'loadavg', 'net', 'swap', 'rootfs')], charts
    ranges = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-perf] [data-cr-range]'))
        .map(b => [b.dataset.crRange, b.innerText, b.getAttribute('aria-pressed')])''')
    assert ranges == [['hour', '1h', 'true'], ['day', '24h', 'false'], ['week', '7d', 'false'],
                      ['month', '30d', 'false'], ['year', '1y', 'false']]
    page.locator('[data-cr-perf] [data-cr-range="day"]').click()
    assert _wait(page, lambda: len(_rrd_urls(app, '/nodes/pve1/rrddata')) == 2)
    assert _rrd_urls(app, '/nodes/pve1/rrddata')[-1].endswith('rrddata?timeframe=day')
    assert page.locator('[data-cr-perf] [data-cr-range="day"]').get_attribute('aria-pressed') == 'true'
    # picking the range that is on does not ask again
    page.locator('[data-cr-perf] [data-cr-range="day"]').click()
    page.wait_for_timeout(300)
    assert len(_rrd_urls(app, '/nodes/pve1/rrddata')) == 2
    _no_errors(app)


@pytest.mark.parametrize('case', ['failed', 'empty'])
def test_runtime_the_node_charts_say_when_there_is_nothing_to_draw(open_app, case):
    app = open_app(rrd_status=500) if case == 'failed' else open_app(rrd_body=EMPTY_RRD)
    page = app.page
    _open_node(page)
    page.locator('[data-cr-tabs="node"] [data-cr-tab="monitor"]').click()
    if case == 'failed':
        box = page.locator('[data-cr-perf="error"]')
        box.wait_for(timeout=8000)
        assert box.locator('[role="alert"]').inner_text().startswith('The metrics could not be loaded')
        box.locator('[data-cr-perf-retry]').click()
        assert _wait(page, lambda: len(_rrd_urls(app, '/nodes/pve1/rrddata')) == 2)
        page.locator('[data-cr-perf="error"]').wait_for(timeout=8000)
    else:
        box = page.locator('[data-cr-perf="empty"]')
        box.wait_for(timeout=8000)
        assert 'No samples in this time range' in box.inner_text()
    assert page.locator('[data-cr-chart]').count() == 0
    # a failed read is not an error of the page
    _no_errors(app)


def test_runtime_the_node_actions_still_ask_first(open_app):
    app = open_app()
    page = app.page
    _open_node(page)
    asked = []

    def answer(dialog):
        asked.append(dialog.message)
        dialog.dismiss()
    page.on('dialog', answer)
    head = page.locator('[data-cr-objhead="node"]')
    head.locator('.cr-objhead-actions button', has_text='Actions').click()
    items = [x.strip() for x in head.locator('.corp-dropdown button').all_inner_texts()]
    assert items == ['Maintenance', 'Reboot Node', 'Shutdown Node', 'Update', 'Node Settings', 'Open Web UI'], items
    head.locator('.corp-dropdown button', has_text='Reboot Node').click()
    page.wait_for_timeout(300)
    assert asked == ['Reboot node "pve1"?']
    assert not [c for c in app.server.calls if c[0] == 'POST' and '/nodes/pve1' in c[1]]
    _no_errors(app)


def test_runtime_a_standby_shows_no_power_actions(open_app):
    app = open_app(role='standby')
    page = app.page
    _open_node(page)
    head = page.locator('[data-cr-objhead="node"]')
    head.locator('.cr-objhead-actions button', has_text='Actions').click()
    items = [x.strip() for x in head.locator('.corp-dropdown button').all_inner_texts()]
    assert items == ['Node Settings', 'Open Web UI'], items
    page.locator('.corp-tree-child', has_text='web01').first.click()
    page.locator('[data-cr-objhead="vm"]').wait_for(timeout=8000)
    acts = _actions(page, 'vm')
    assert not {'Start', 'Shutdown', 'Reboot', 'Console'} & set(acts), acts
    assert 'Configure' in acts
    # nor rename, re-configure or delete on the cluster
    page.locator('[data-cr-crumb="cluster"] button').click()
    page.locator('[data-cr-objhead="cluster"]').wait_for(timeout=8000)
    assert page.locator('[data-cr-objhead="cluster"] .cr-objhead-actions .cr-icon-btn').count() == 0


# --- VM and container ----------------------------------------------------------------------------

def test_runtime_the_vm_head_and_tabs(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    head = page.locator('[data-cr-objhead="vm"]')
    assert head.locator('.cr-objhead-name').inner_text() == 'web01'
    assert head.locator('[data-cr-objid]').inner_text() == '100'
    assert head.locator('[data-cr-state]').get_attribute('data-cr-state') == 'running'
    page.wait_for_function('() => document.querySelector(\'[data-cr-objhead="vm"] [data-cr-meta="os"]\')', timeout=5000)
    assert head.locator('.cr-objhead-title').inner_text().split('\n')[-1].strip() == 'HA'
    assert _meta(page, 'vm') == {
        'type': 'QEMU/KVM', 'node': 'pve1', 'cluster': 'Testi', 'os': GUEST_INFO['os_pretty_name'],
        'ip': '10.0.0.50, fe80::1', 'cpus': str(VM['maxcpu']), 'mem': _bytes(VM['maxmem']), 'uptime': '1h 0m'}
    assert _actions(page, 'vm') == ['Shutdown', 'Reboot', 'Console', 'SPICE Console', 'Configure', 'Actions']
    tabs = _tabs(page, 'guest')
    assert [x[:2] for x in tabs] == [['summary', 'Summary'], ['monitor', 'Monitor'], ['snapshots', 'Snapshots'],
                                     ['timeline', 'Timeline']]
    assert page.locator('[data-cr-tabs="guest"] [data-corp-vm-timeline]').count() == 1
    # the charts left the summary for their own tab
    assert page.locator('[data-cr-perf]').count() == 0
    # round 3: the summary body is the preview's own (cr_vm.js); the guest agent is a line of its health
    assert page.locator('[data-cr-vm-summary="vm"] [data-cr-vm-h="agent"]').count() == 1
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="summary"]').focus()
    page.keyboard.press('ArrowRight')
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    charts = page.evaluate('() => Array.from(document.querySelectorAll("[data-cr-chart]")).map(c => [c.dataset.crChart, !!c.querySelector("canvas")])')
    assert charts == [['cpu', True], ['memory', True], ['disk', True], ['net', True]], charts
    page.keyboard.press('ArrowRight')
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="snapshots"][aria-selected="true"]').wait_for(timeout=3000)
    assert _wait(page, lambda: any('/qemu/100/snapshots' in c[1] for c in app.server.calls))
    _no_errors(app)


def test_runtime_the_vm_charts_follow_the_time_range_and_say_when_they_failed(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="monitor"]').click()
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    assert _rrd_urls(app, '/qemu/100/rrd/') == [f'{BASE}/api/clusters/c1/vms/pve1/qemu/100/rrd/hour']
    page.locator('[data-cr-perf] [data-cr-range="week"]').click()
    assert _wait(page, lambda: _rrd_urls(app, '/qemu/100/rrd/')[-1:] == [f'{BASE}/api/clusters/c1/vms/pve1/qemu/100/rrd/week'])
    page.locator('[data-cr-perf="ready"] [data-cr-range="week"][aria-pressed="true"]').wait_for(timeout=5000)
    # the endpoint goes away: the panel says so and offers another try
    app.server.rrd_status = 500
    page.locator('[data-cr-perf] [data-cr-range="month"]').click()
    page.locator('[data-cr-perf="error"]').wait_for(timeout=8000)
    app.server.rrd_status = 200
    page.locator('[data-cr-perf-retry]').click()
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    assert _rrd_urls(app, '/qemu/100/rrd/')[-1].endswith('/rrd/month')
    _no_errors(app)


def test_runtime_back_in_classic_corporate_the_monitor_tab_falls_back_to_the_summary(open_app):
    """Monitor is a tab of the preview only. Picking classic Corporate in My Profile while it is
    open keeps the VM view mounted; it must show the summary, not an empty page."""
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="monitor"]').click()
    page.locator('[data-cr-perf="ready"]').wait_for(timeout=8000)
    app.server.extra[('PUT', '/api/user/preferences')] = (200, {
        'success': True, 'theme': 'corporateDark', 'language': 'en', 'ui_layout': 'corporate',
        'layout_chosen': True, 'taskbar_auto_expand': True, 'sidebar_show_vmid': False})
    page.locator('[data-user-menu]').click()
    page.get_by_text('My Profile').first.click()
    # the classic card sits right before the preview's
    page.locator('[data-layout-pick="corporate-redesigned"]').locator('xpath=preceding-sibling::button[1]').click()
    page.wait_for_function('() => !document.body.dataset.corpVariant', timeout=5000)
    page.keyboard.press('Escape')
    strip = page.locator('.corp-tab-strip', has=page.locator('[data-corp-vm-timeline]'))
    strip.locator('button.active').wait_for(timeout=5000)
    assert strip.locator('button.active').inner_text().strip() == 'Summary'
    assert page.locator('.corp-property-grid', has_text='QEMU Agent').count() == 1
    assert page.locator('[data-cr-perf]').count() == 0
    _no_errors(app)


def test_runtime_a_stopped_guest_says_why_it_has_no_charts(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'db01')
    head = page.locator('[data-cr-objhead="vm"]')
    assert head.locator('[data-cr-state]').get_attribute('data-cr-state') == 'stopped'
    assert 'uptime' not in _meta(page, 'vm')
    assert _actions(page, 'vm')[0] == 'Start'
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="monitor"]').click()
    box = page.locator('[data-cr-perf="empty"]')
    box.wait_for(timeout=5000)
    assert 'Metrics are shown while the guest is running' in box.inner_text()
    assert not _rrd_urls(app, '/qemu/102/rrd/')
    _no_errors(app)


def test_runtime_a_container_has_its_own_head_and_keeps_its_console(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'ct01', kind='ct')
    head = page.locator('[data-cr-objhead="ct"]')
    assert head.locator('.cr-objhead-name').inner_text() == 'ct01'
    assert head.locator('[data-cr-objid]').inner_text() == '101'
    assert _meta(page, 'ct')['type'] == 'LXC'
    # a container's console was a button of the classic tab strip; it is an action of the head now
    acts = _actions(page, 'ct')
    assert acts[0] == 'Console' and 'Configure' in acts, acts
    assert _crumbs(page) == ['All', 'Testi', 'Resources', 'ct01']
    _no_errors(app)


def test_runtime_the_vm_force_stop_still_asks_first(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    asked = []

    def answer(dialog):
        asked.append(dialog.message)
        dialog.dismiss()
    page.on('dialog', answer)
    head = page.locator('[data-cr-objhead="vm"]')
    head.locator('.cr-objhead-actions button', has_text='Actions').click()
    head.locator('.corp-dropdown button', has_text='Force Stop').click()
    page.wait_for_timeout(300)
    head.locator('.cr-objhead-actions > button', has_text='Shutdown').click()
    page.wait_for_timeout(300)
    assert len(asked) == 2 and 'web01' in asked[0] and asked[1] == 'Shutdown "web01"?', asked
    assert not [c for c in app.server.calls if c[0] == 'POST' and '/qemu/100/' in c[1]]
    _no_errors(app)


# --- cluster -------------------------------------------------------------------------------------

def test_runtime_the_cluster_head_and_summary(open_app):
    app = open_app()
    page = app.page
    _cluster(page)
    head = page.locator('[data-cr-objhead="cluster"]')
    assert head.locator('.cr-objhead-name').inner_text() == 'Testi'
    assert head.locator('[data-cr-objid]').inner_text() == '10.0.0.1'
    assert head.locator('[data-cr-state]').get_attribute('data-cr-state') == 'online'
    page.wait_for_function('() => document.querySelector(\'[data-cr-objhead="cluster"] [data-cr-meta="guests"]\')', timeout=8000)
    st = STATUS['c1']
    g = st['guests']
    assert _meta(page, 'cluster') == {
        'guests': f"{g['vms']['running'] + g['containers']['running']}/{g['vms']['total'] + g['containers']['total']} running",
        'pve': 'testi'}
    # nodes and quorum are the classic services bar's, right under the head, and only there
    assert 'Quorum' not in head.inner_text()
    assert 'Quorum OK' in page.locator('.corp-services-bar').inner_text()
    labels = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-objhead="cluster"] .cr-objhead-actions > button'))
        .map(b => b.getAttribute('aria-label') || b.innerText.trim())''')
    assert labels == ['Refresh', 'Rename Cluster', 'Re-configure Cluster', 'Delete Cluster'], labels
    # the summary: CPU from the datacenter status, memory and disk from the node figures
    summary = page.locator('[data-cr-cluster-summary]')
    summary.locator('[data-cr-stat="cpu"]').wait_for(timeout=8000)
    val = lambda sid: re.sub(r'\s+', '', summary.locator(f'[data-cr-stat="{sid}"] .cr-stat-value').inner_text())  # noqa: E731
    nodes = METRICS.values()
    mem_used, mem_total = sum(n['mem_used'] for n in nodes), sum(n['mem_total'] for n in nodes)
    disk_used, disk_total = sum(n['disk_used'] for n in nodes), sum(n['disk_total'] for n in nodes)
    assert val('cpu') == f"{st['resources']['cpu']['percent']:.1f}%"
    assert val('mem') == f'{mem_used / mem_total * 100:.1f}%'
    assert summary.locator('[data-cr-stat="mem"] .cr-stat-sub').inner_text() == f'{_bytes(mem_used)} of {_bytes(mem_total)}'
    assert val('storage') == f'{disk_used / disk_total * 100:.1f}%'
    assert val('guests') == '2/3'
    assert summary.locator('.corp-overview-card').count() == 1
    # removing still asks, and nothing is sent when the answer is no
    asked = []
    page.on('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    head.locator('[aria-label="Delete Cluster"]').click()
    page.wait_for_timeout(300)
    assert len(asked) == 1
    assert not [c for c in app.server.calls if c[0] == 'DELETE']
    _no_errors(app)


def test_runtime_refresh_in_the_cluster_head_reads_the_cluster_again(open_app):
    # the button called a function only the node view has, so the click threw and read nothing
    app = open_app()
    page = app.page
    _cluster(page)
    button = page.locator('[data-cr-objhead="cluster"] [data-cr-refresh]')
    button.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    before = len(app.server.calls)
    button.click()
    assert _wait(page, lambda: {'metrics', 'resources', 'datastores'} <= {
        p.rsplit('/', 1)[-1] for m, p in app.server.calls[before:] if m == 'GET' and p.startswith('/api/clusters/c1/')}), \
        app.server.calls[before:]
    _no_errors(app)


def test_runtime_a_user_who_is_no_admin_cannot_reconfigure_or_remove(open_app):
    app = open_app(admin=False, permissions=['cluster.view', 'vm.view'])
    page = app.page
    _cluster(page)
    labels = page.evaluate('''() => Array.from(document.querySelectorAll('[data-cr-objhead="cluster"] .cr-objhead-actions > button'))
        .map(b => b.getAttribute('aria-label') || b.innerText.trim())''')
    assert labels == ['Refresh', 'Rename Cluster'], labels
    _no_errors(app)


def test_runtime_the_cluster_tabs_are_a_tab_list(open_app):
    app = open_app(viewport=(1280, 900))
    page = app.page
    _cluster(page)
    tabs = _tabs(page, 'cluster')
    ids = [x[0] for x in tabs]
    assert ids[:3] == ['overview', 'resources', 'datacenter'] and ids[-1] == 'settings', ids
    assert tabs[0][2] == 'true'
    page.locator('[data-cr-tabs="cluster"] [data-cr-tab="overview"]').focus()
    page.keyboard.press('ArrowRight')
    page.wait_for_function('() => document.querySelectorAll(".cr-crumbs li").length === 3', timeout=5000)
    assert _crumbs(page) == ['All', 'Testi', 'Resources']
    # at 1280 the strip scrolls instead of cutting off its last tabs
    page.keyboard.press('End')
    last = page.locator('[data-cr-tabs="cluster"] [data-cr-tab="settings"]')
    assert last.get_attribute('aria-selected') == 'true'
    box, strip = last.bounding_box(), page.locator('[data-cr-tabs="cluster"]').bounding_box()
    assert box['x'] + box['width'] <= strip['x'] + strip['width'] + 1
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 1280
    _no_errors(app)
