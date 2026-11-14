"""Round 4 of Corporate Redesigned (Preview): the alert strip under the header and the task
center whose bar is its header.

The strip takes the place of the red node banner, the yellow Corporate banner and the fixed
"live updates disconnected" overlay in the variant, in the page flow under the header. Its
severities are the ones PegaProx gives already: a cluster that is not connected, a lost quorum
and an offline node are critical, an offline node in maintenance is information, hardware is the
server's rollup verdict, an active alert keeps its own. quorate null (XCP-ng, a single node) is
no verdict. A status that is old, not read or not readable is said as such, never as nothing
wrong. Dismiss hides a line in this browser for this user, comes back when something new shows,
and shrinks a critical line to a chip; it never calls the server. A line opens the view it is
about, and the Timeline where it keeps a history.

The task center: the bar is the header. Collapsed it sits on the status bar, open it sits on top
of the drawer; a click on it beside its own controls closes it, the resize grip never toggles,
and there is no other toggle. Running, Queued, Completed, Failed and Cancelled are always on it,
with what they are counted over; a count nothing was read for is no 0. The open state is kept
per user in this browser.

Runs against the fake servers of the other redesign tests with the real backend shapes, and skips
without Playwright. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof).
LW Nov 2026
"""
import json
import re
import time

import pytest

from test_corp_redesigned_dashboard_ui import EDGE, PROD
from test_corp_redesigned_guard_ui import DETERMINISTIC, FIXED, METRICS, _GuardApp
from test_corp_redesigned_tasks_ui import (C1, LAYOUT, RUN, SSE, TOGGLE, _Browser, _TaskServer,
                                           _need, _open, _pick_testi, _task, _tasks_reads, shaped)
from test_ha_ui import CLUSTER

GIB = 1024 ** 3

XEN = {'id': 'c4', 'name': 'Xen', 'display_name': 'Xen', 'host': '10.0.4.1', 'connected': True,
       'status': 'running', 'cluster_type': 'xcpng', 'enabled': True}
SOLO = {'id': 'c5', 'name': 'Solo', 'display_name': 'Solo', 'host': '10.0.5.1', 'connected': True,
        'status': 'running', 'cluster_type': 'proxmox', 'enabled': True}
CLUSTERS = [CLUSTER, PROD, EDGE, XEN, SOLO]


def _status(quorate, online, offline, hardware=None, standalone=False, kind=None):
    """/datacenter/status as pegaprox/api/vms.py answers it."""
    cluster = {'name': 'x', 'quorate': quorate, 'standalone': standalone, 'version': 3}
    if kind:
        cluster['cluster_type'] = kind
    return {'cluster': cluster, 'nodes': {'online': online, 'offline': offline, 'total': online + offline},
            'guests': {'vms': {'running': 1, 'stopped': 0, 'total': 1}, 'containers': {'running': 0, 'stopped': 0, 'total': 0}},
            'resources': {'cpu': {'total': 8, 'used': 1.0, 'percent': 12.5},
                          'memory': {'total': 32 * GIB, 'used': 8 * GIB, 'percent': 25.0},
                          'storage': {'total': 100 * GIB, 'used': 10 * GIB, 'percent': 10.0}},
            'hardware': hardware}


SCENE = {
    # the selected one: its node list names pve2 (offline) and pve3 (offline, in maintenance)
    'c1': _status(True, 1, 2),
    # quorum lost, one node offline by count, degraded hardware (a warning by the rollup)
    'c2': _status(False, 2, 1, hardware={'health': 'warning', 'degraded': 1, 'checked': 3}),
    # XCP-ng: no quorum verdict, the rollup says critical
    'c4': _status(None, 2, 0, hardware={'health': 'critical', 'degraded': 2, 'checked': 2}, kind='xcpng'),
    # a single node: no quorum verdict either
    'c5': _status(None, 1, 0, standalone=True),
}
NODES = {'pve1': dict(METRICS['pve1']),
         'pve2': dict(METRICS['pve2'], status='offline', offline=True, cpu_percent=0, mem_percent=0),
         'pve3': dict(METRICS['pve2'], status='offline', offline=True, maintenance_mode=True, cpu_percent=0, mem_percent=0)}


def _incident(fid, severity, message, target_type='cluster', target_name='Testi', **kw):
    """One row of GET /api/clusters/<id>/active-alerts (pegaprox/api/alerts.py get_active_alerts)."""
    row = {'id': fid, 'alert_id': 'r-' + fid, 'severity': severity, 'message': message, 'target_type': target_type,
           'target_name': target_name, 'metric': 'ceph_health', 'current_value': 2, 'threshold': 1, 'operator': 'event',
           'triggered_at': '2026-10-30T08:40:00.123456', 'last_fired_at': '2026-10-30T08:59:00.123456', 'acked_at': None,
           'acked_by': None, 'escalation_step': 0, 'object_key': '', 'muted_until': None}
    row.update(kw)
    return row


INCIDENTS = [_incident('a1', 'critical', 'Ceph health is HEALTH_ERR'),
             _incident('a2', 'warning', 'web01 CPU above 80%', target_type='vm', target_name='web01', metric='cpu',
                       current_value=85, threshold=80, operator='>', acked_at='2026-10-30T08:55:00', acked_by='ops')]
ALERTS_ROUTE = ('GET', '/api/clusters/c1/active-alerts')


class _AlertServer(_TaskServer):
    """The task fake (dashboard, tasks, registries) with the alert scene."""

    def __init__(self, scene=None, incidents=None, extra=None, **kw):
        reads = {ALERTS_ROUTE: (200, {'active_alerts': list(INCIDENTS if incidents is None else incidents)}),
                 ('GET', '/api/timeline'): (200, {'events': [], 'next_before': None, 'sources': {},
                                                  'correlation': {'window_minutes': 10, 'note': ''}})}
        reads.update(extra or {})
        kw.setdefault('clusters', CLUSTERS)
        kw.setdefault('metrics', NODES)
        super().__init__(status=SCENE if scene is None else scene, extra=reads, **kw)

    def reads_of(self, path):
        return sum(1 for m, p in self.calls if m == 'GET' and p == path)

    def writes(self):
        return [(m, p) for m, p in self.calls if m not in ('GET', 'HEAD') and p not in ('/api/sse/token', '/api/sse/subscribe')]


@pytest.fixture(scope='module')
def browsers():
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
    try:
        ff = pw.firefox.launch(headless=True)
    except Exception:
        ff = None
    yield {'chromium': br, 'firefox': ff}
    br.close()
    if ff:
        ff.close()
    pw.stop()


@pytest.fixture
def open_app(browsers):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), storage=None, live=True, server=None, **kw):
        br = browsers[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        kw.setdefault('layout', LAYOUT)
        srv = server or _AlertServer(sse=live, **kw)
        app = _GuardApp(_Browser(br, [SSE] if live else []), srv, storage=storage, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


# --- helpers ------------------------------------------------------------------------------------

STRIP = '''() => {
    const s = document.querySelector('[data-cr-alerts]');
    if (!s) return null;
    return Array.from(s.querySelectorAll('[data-cr-al-row]')).map(r => ({
        sev: r.dataset.crAlRow,
        n: r.querySelector('[data-cr-al-n]') ? Number(r.querySelector('[data-cr-al-n]').innerText) : null,
        segs: Array.from(r.querySelectorAll('[data-cr-al-seg]')).map(b => [b.dataset.crAlSeg, b.innerText.trim()]),
        asof: r.querySelector('[data-cr-al-asof]') ? r.querySelector('[data-cr-al-asof]').innerText.trim() : null,
        cls: r.className,
    }));
}'''


def _strip(page):
    return page.evaluate(STRIP)


CRUMBS = "() => Array.from(document.querySelectorAll('.cr-crumbs .cr-crumb-text')).map(x => x.innerText.trim()).join('/')"


def _at(page, trail, what):
    try:
        page.wait_for_function(f'() => ({CRUMBS})() === {json.dumps(trail)}', timeout=5000)
    except Exception:
        raise AssertionError(f'{what}: the page is at {page.evaluate(CRUMBS)!r}, not {trail!r}') from None


def _segs(page, sev):
    return dict((k, v) for row in (_strip(page) or []) if row['sev'] == sev for k, v in row['segs'])


def _wait_seg(page, sev, kind, text=None, timeout=10000):
    try:
        page.wait_for_function('''([sev, kind, text]) => {
            const b = document.querySelector(`[data-cr-al-row="${sev}"] [data-cr-al-seg="${kind}"]`);
            return !!b && (text === null || b.innerText.trim() === text);
        }''', arg=[sev, kind, text], timeout=timeout)
    except Exception:
        raise AssertionError(f'the strip has no {sev} {kind} line saying {text!r}: {_strip(page)}') from None


def _no_errors(app):
    assert not app.errors, app.errors


def _eventually(check, what, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if check():
            return
        time.sleep(0.1)
    raise AssertionError(what)


def _settled(page):
    """Every source of the scene drawn: the status of the four clusters, Testi's nodes, its alerts."""
    _pick_testi(page)
    _wait_seg(page, 'critical', 'disconnected', 'Edge not connected')
    _wait_seg(page, 'critical', 'quorum', 'Prod has lost quorum')
    _wait_seg(page, 'critical', 'incident', '1 active alert (Testi)')
    _wait_seg(page, 'info', 'maint')


# --- the strip: what it says ------------------------------------------------------------------

def test_runtime_the_strip_takes_the_severity_the_existing_logic_gives(open_app):
    app = open_app()
    page = app.page
    _settled(page)
    _wait_seg(page, 'critical', 'nodes', '2 nodes offline in Prod, Testi')
    rows = _strip(page)
    assert [r['sev'] for r in rows] == ['critical', 'warning', 'info'], rows
    crit = _segs(page, 'critical')
    assert crit == {'disconnected': 'Edge not connected', 'quorum': 'Prod has lost quorum',
                    'nodes': '2 nodes offline in Prod, Testi', 'incident': '1 active alert (Testi)',
                    'hardware': 'Hardware degraded on 2 of 2 checked nodes (Xen)'}, crit
    # six things are critical: Edge, Prod's quorum, Prod's node, Testi's node, Testi's Ceph alert, Xen's hardware
    assert rows[0]['n'] == 6, rows[0]
    assert _segs(page, 'warning') == {'incident': '1 active alert (Testi)',
                                      'hardware': 'Hardware degraded on 1 of 3 checked nodes (Prod)'}
    # pve3 is offline but in maintenance: information, not critical
    assert _segs(page, 'info') == {'maint': 'pve3 offline in maintenance (Testi)'}
    # quorate null (XCP-ng, a single node) is no verdict either way: nothing about the quorum of Xen or Solo
    text = page.locator('[data-cr-alerts]').inner_text()
    assert 'Xen has lost quorum' not in text and 'Solo' not in text, text
    # the tones are the skin's own, every line says how old it is
    assert 'cr-al-critical' in rows[0]['cls'] and 'cr-al-warning' in rows[1]['cls'] and 'cr-al-info' in rows[2]['cls']
    assert all(re.fullmatch(r'as of \d{1,2}:\d{2}(:\d{2})?( [AP]M)?', r['asof'] or '') for r in rows), rows
    # the details name each node once: pve2 critical, pve3 in maintenance, never both or twice
    page.locator('[data-cr-al-details]').click()
    _need(page, '[data-cr-al-detail]', 'Details lists every line')
    detail = page.locator('[data-cr-al-detail]').inner_text()
    assert detail.count('pve2 offline (Testi)') == 1 and detail.count('pve3 offline in maintenance (Testi)') == 1, detail
    assert '1 node offline (Prod)' in detail and 'counts only, names and maintenance are not known for this cluster' in detail
    assert 'Ceph health is HEALTH_ERR' in detail and 'web01 CPU above 80% (acknowledged by ops)' in detail
    _no_errors(app)


def test_runtime_the_classic_banners_are_gone_and_the_strip_is_in_the_flow(open_app):
    app = open_app(live=False, extra={('GET', '/api/clusters/c1/ha/status'): (200, {'nodes': {
        'pve2': {'status': 'offline', 'last_seen': '2026-10-30T08:55:00', 'consecutive_failures': 3}}})})
    page = app.page
    _settled(page)
    # the stream of this fake never connects: the live line comes after 4 s, in the strip
    _wait_seg(page, 'state', 'live', timeout=8000)
    assert page.locator('.corp-warning-banner').count() == 0, 'no yellow Corporate banner in the variant'
    assert page.get_by_text('CRITICAL ALERT').count() == 0, 'no red node banner in the variant'
    assert page.get_by_text('Live updates disconnected').count() == 1, 'the live line once, in the strip'
    assert page.locator('[data-cr-alerts]').get_by_text('Live updates disconnected', exact=False).count() == 1
    geo = page.evaluate('''() => {
        const h = document.querySelector('.cr-header').getBoundingClientRect();
        const s = document.querySelector('[data-cr-alerts]');
        const r = s.getBoundingClientRect();
        const main = document.querySelector('.pp-main-wrap').getBoundingClientRect();
        // nothing lies over the header: its middle and its right end (the user menu) are its own
        const own = [[h.left + h.width / 2, h.top + h.height / 2], [h.right - 20, h.top + h.height / 2]]
            .every(([x, y]) => { const e = document.elementFromPoint(x, y); return !!(e && e.closest('.cr-header')); });
        return { hb: h.bottom, st: r.top, sb: r.bottom, mt: main.top, pos: getComputedStyle(s).position, own,
                 rows: Array.from(s.querySelectorAll('[data-cr-al-row]')).map(x => x.getBoundingClientRect().height) };
    }''')
    # the strip publishes the room it takes (the sticky sidebar takes it off its height)
    page.wait_for_function('''() => getComputedStyle(document.body).getPropertyValue('--cr-alerts-h').trim()
        === Math.round(document.querySelector('[data-cr-alerts]').getBoundingClientRect().height) + 'px' ''', timeout=3000)
    assert geo['pos'] != 'fixed' and abs(geo['st'] - geo['hb']) <= 1, ('the strip starts where the header ends', geo)
    assert abs(geo['mt'] - geo['sb']) <= 1, ('the page starts under the strip, nothing hidden behind it', geo)
    assert geo['own'], ('nothing covers the header', geo)
    assert all(h <= 32 for h in geo['rows']), ('one compact line per severity', geo)
    # the sticky sidebar ends above the bottom bars with the strip at the top
    side = page.locator('.cr-sidebar > .sticky').bounding_box()
    bar = page.locator('.cr-taskcenter').bounding_box()
    assert side['y'] + side['height'] <= bar['y'] + 0.5, (side, bar)
    _no_errors(app)


def test_runtime_the_ha_monitor_adds_its_offline_nodes_once_and_only_known_ones(open_app):
    # the PegaProx HA monitor of Testi has pve1 and pve2 offline, and a name the node list does not know
    ha = {'nodes': {'pve1': {'status': 'offline', 'last_seen': '2026-10-30T08:58:00', 'consecutive_failures': 3},
                    'pve2': {'status': 'offline', 'last_seen': '2026-10-30T08:55:00', 'consecutive_failures': 3},
                    'ghost': {'status': 'offline', 'last_seen': '2026-10-30T08:50:00', 'consecutive_failures': 9}}}
    app = open_app(extra={('GET', '/api/clusters/c1/ha/status'): (200, ha)})
    page = app.page
    _settled(page)
    _wait_seg(page, 'critical', 'nodes', '3 nodes offline in Prod, Testi')
    page.locator('[data-cr-al-details]').click()
    line = page.locator('[data-cr-al-item="nodes|c1"]').inner_text()
    assert 'pve1, pve2 offline (Testi)' in line and 'and the PegaProx HA monitor' in line, line
    assert 'ghost' not in page.locator('[data-cr-alerts]').inner_text(), 'a name the node list does not show is not named'
    _no_errors(app)


def test_runtime_forty_offline_nodes_and_forty_lost_clusters_stay_two_short_lines(open_app):
    lost = [dict(EDGE, id=f'x{i:02d}', name=f'lost{i:02d}', display_name=f'lost{i:02d}') for i in range(40)]
    nodes = {'pve1': dict(METRICS['pve1'])}
    nodes.update({f'n{i:02d}': dict(METRICS['pve2'], status='offline', offline=True) for i in range(40)})
    app = open_app(clusters=[CLUSTER] + lost, scene={'c1': _status(True, 1, 40)}, metrics=nodes, incidents=[],
                   viewport=(1280, 800))
    page = app.page
    _pick_testi(page)
    _wait_seg(page, 'critical', 'nodes', 'n00, n01, n02 and 37 more offline (Testi)')
    _wait_seg(page, 'critical', 'disconnected', 'Not connected: lost00, lost01, lost02 and 37 more')
    rows = _strip(page)
    assert len(rows) == 1 and rows[0]['n'] == 41, rows
    h = page.locator('[data-cr-al-row="critical"]').bounding_box()['height']
    assert h <= 32, ('still one line', h)
    assert page.evaluate('() => document.documentElement.scrollWidth') <= 1280
    # forty clusters are no one place to go: the list opens, and it names them all
    page.locator('[data-cr-al-seg="disconnected"]').click()
    _need(page, '[data-cr-al-detail]', 'a line about many clusters opens the list')
    detail = page.locator('[data-cr-al-detail]').inner_text()
    assert all(f'n{i:02d}' in detail for i in range(40)) and all(f'lost{i:02d} not connected' in detail for i in range(40))
    # the nodes of one cluster lead to that cluster
    page.locator('[data-cr-al-seg="nodes"]').click()
    _at(page, 'All/Testi/Overview', 'the offline nodes of Testi open Testi')
    _no_errors(app)


# --- what is not known is said ------------------------------------------------------------------

def test_runtime_an_old_status_is_not_current_and_drops_its_verdicts(open_app):
    app = open_app()
    page = app.page
    _settled(page)
    # Prod stops answering; two minutes on, the next poll of the cluster list (30 s) reads the others
    # again and Prod's last status is no verdict any more
    app.server.extra[('GET', '/api/clusters/c2/datacenter/status')] = (500, {'error': 'boom'})
    app.ctx.clock.set_fixed_time(FIXED + 120)
    try:
        page.wait_for_function('''() => { const b = document.querySelector('[data-cr-al-row="state"] [data-cr-al-seg="stale"]');
            return !!b && /^Status of Prod not current \\(last read [^)]+\\)$/.test(b.innerText.trim()); }''', timeout=40000)
    except Exception:
        raise AssertionError(f'Prod alone is not current: {_strip(page)}') from None
    crit = _segs(page, 'critical')
    assert 'quorum' not in crit, ('the quorum verdict of an old status is not shown as current', crit)
    assert 'Prod' not in crit.get('nodes', '') and 'Prod' not in json.dumps(_segs(page, 'warning')), _strip(page)
    _no_errors(app)


def test_runtime_a_cluster_whose_status_never_came_is_not_read(open_app):
    scene = {k: v for k, v in SCENE.items() if k != 'c2'}
    app = open_app(scene=scene)
    page = app.page
    _pick_testi(page)
    _wait_seg(page, 'critical', 'incident', '1 active alert (Testi)')
    _wait_seg(page, 'critical', 'hardware', 'Hardware degraded on 2 of 2 checked nodes (Xen)')
    assert 'unread' not in _segs(page, 'state'), 'a moment after the page opened nothing is called unread yet'
    assert 'quorum' not in _segs(page, 'critical'), 'no answer is no verdict'
    app.ctx.clock.set_fixed_time(FIXED + 60)
    page.locator('.cr-sidebar').get_by_text('All Clusters').first.click()
    _wait_seg(page, 'state', 'unread', 'Status of Prod not read yet')
    _no_errors(app)


def test_runtime_without_cluster_view_the_strip_says_so_and_names_no_node(open_app):
    perms = ['vm.view', 'node.view', 'storage.view', 'backup.view']
    # what the server answers a role without cluster.view: the status and the node list are refused
    refused = {('GET', f'/api/clusters/{c["id"]}/{what}'): (403, {'error': 'Permission denied'})
               for c in CLUSTERS for what in ('datacenter/status', 'metrics')}
    app = open_app(admin=False, permissions=perms, extra=refused)
    page = app.page
    _pick_testi(page)
    _wait_seg(page, 'state', 'noaccess')
    assert 'not readable with your permissions' in _segs(page, 'state')['noaccess']
    # the stream still brings the node list of the selected cluster (it is not trimmed per user): it is
    # counted, and names nobody the REST view would not name either
    page.wait_for_function('() => window.__sse && window.__sse.made.some(s => s.readyState === 1)', timeout=8000)
    page.evaluate('(d) => window.__sse.say({type: "metrics", cluster_id: "c1", data: d})', NODES)
    _wait_seg(page, 'critical', 'nodes', '1 node offline (Testi)')
    _wait_seg(page, 'info', 'maint', '1 node offline in maintenance (Testi)')
    text = page.locator('[data-cr-alerts]').inner_text()
    assert 'pve2' not in text and 'pve3' not in text and 'lost quorum' not in text, text
    _no_errors(app)


@pytest.mark.parametrize('answer,said', [
    ((503, {'code': 'HA_ACTIVE_UNREACHABLE', 'error': 'The active instance cannot be reached'}),
     'The leader instance does not answer; only it keeps the alerts.'),
    ((500, {'error': 'boom'}), 'The read failed (HTTP 500).'),
    # alerts.py answers a failed read with 200, an empty list and the error
    ((200, {'active_alerts': [], 'error': 'Alert operation failed'}), 'The read failed (HTTP 200).'),
])
def test_runtime_active_alerts_that_could_not_be_read_are_not_none(open_app, answer, said):
    app = open_app(extra={ALERTS_ROUTE: answer})
    page = app.page
    _pick_testi(page)
    _wait_seg(page, 'state', 'alertsunread', 'Active alerts of Testi not read')
    assert 'incident' not in _segs(page, 'critical') and 'incident' not in _segs(page, 'warning')
    page.locator('[data-cr-al-details]').click()
    assert said in page.locator('[data-cr-al-item="alertsunread|c1"]').inner_text()
    _no_errors(app)


def test_runtime_active_alerts_are_read_for_the_selected_cluster_only_and_not_on_a_timer(open_app):
    app = open_app()
    page = app.page
    page.wait_for_timeout(1500)
    assert not any(p.endswith('/active-alerts') for _, p in app.server.calls), 'nothing in All Clusters'
    _settled(page)
    assert app.server.reads_of('/api/clusters/c1/active-alerts') == 1
    page.wait_for_timeout(2000)
    assert app.server.reads_of('/api/clusters/c1/active-alerts') == 1, 'no read of its own between the beats of the cluster list'
    assert [p for _, p in app.server.calls if p.endswith('/active-alerts')] == ['/api/clusters/c1/active-alerts']
    _no_errors(app)


# --- dismiss: local only, back when something new shows ---------------------------------------

def test_runtime_dismiss_hides_a_line_here_only_and_brings_it_back_when_the_set_changes(open_app):
    app = open_app()
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-dismiss="warning"]').click()
    page.locator('[data-cr-al-row="warning"]').wait_for(state='detached', timeout=3000)
    page.locator('[data-cr-al-dismiss="info"]').click()
    page.locator('[data-cr-al-row="info"]').wait_for(state='detached', timeout=3000)
    assert app.server.writes() == [], ('Dismiss asks the server nothing', app.server.writes())
    stored = page.evaluate('() => localStorage.getItem("cr-alerts-dismissed:admin")')
    assert stored and len(json.loads(stored)) == 3, stored
    # a reload keeps them hidden: the same things are shown
    page.reload()
    app.wait_for_app()
    _pick_testi(page)
    _wait_seg(page, 'critical', 'incident', '1 active alert (Testi)')
    page.wait_for_timeout(800)
    assert page.locator('[data-cr-al-row="warning"], [data-cr-al-row="info"]').count() == 0, 'still dismissed after a reload'
    # pve1 goes down for maintenance as well: something new in the line, so it comes back with all it says
    frame = {**NODES, 'pve1': dict(NODES['pve3'])}
    page.evaluate('(d) => window.__sse.say({type: "metrics", cluster_id: "c1", data: d})', frame)
    _wait_seg(page, 'info', 'maint', 'pve1, pve3 offline in maintenance (Testi)', timeout=5000)
    assert page.locator('[data-cr-al-row="warning"]').count() == 0, 'the warning line has nothing new'
    assert app.server.writes() == []
    _no_errors(app)


def test_runtime_a_dismissed_critical_shrinks_to_a_chip_and_stays_until_it_is_gone(open_app):
    app = open_app()
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-dismiss="critical"]').click()
    page.locator('[data-cr-al-row="critical"]').wait_for(state='detached', timeout=3000)
    chip = page.locator('[data-cr-al-chip]')
    assert chip.inner_text().strip() == '6 critical hidden', chip.inner_text()
    assert page.evaluate('() => !!document.activeElement.closest("[data-cr-alerts]")'), 'the focus stays in the strip'
    # still listed in the details: hidden is not resolved
    page.locator('[data-cr-al-details]').click()
    assert 'Prod has lost quorum' in page.locator('[data-cr-al-detail]').inner_text()
    page.locator('[data-cr-al-details]').click()
    # the chip brings the line back
    chip.click()
    page.locator('[data-cr-al-row="critical"]').wait_for(timeout=3000)
    assert app.server.writes() == []
    _no_errors(app)


def test_runtime_the_dismissal_is_per_user(open_app):
    sigs = {'warning|hardware|c2|1|3': FIXED * 1000, 'warning|incident|c1|a2|': FIXED * 1000}
    # another user's dismissal hides nothing here
    other = open_app(storage={'cr-alerts-dismissed:someoneelse': json.dumps(sigs)})
    _settled(other.page)
    _wait_seg(other.page, 'warning', 'hardware')
    # the same dismissal under this user's name does
    mine = open_app(storage={'cr-alerts-dismissed:admin': json.dumps(sigs)})
    _settled(mine.page)
    mine.page.wait_for_timeout(500)
    assert mine.page.locator('[data-cr-al-row="warning"]').count() == 0, _strip(mine.page)
    _no_errors(other)
    _no_errors(mine)


# --- a line leads somewhere ----------------------------------------------------------------------

def test_runtime_a_line_opens_its_view_and_the_history_the_timeline_keeps(open_app):
    app = open_app()
    page = app.page
    _settled(page)
    # Testi's alerts: Automation > Alerts of Testi
    page.locator('[data-cr-al-row="critical"] [data-cr-al-seg="incident"]').click()
    _at(page, 'All/Testi/Automation', 'an active alert opens Automation of its cluster')
    page.get_by_text('Active Alerts').first.wait_for(timeout=5000)
    # the node: from the list, pve2 opens its node view
    page.locator('[data-cr-al-details]').click()
    page.locator('[data-cr-al-item="nodes|c1"] [data-cr-al-open]').click()
    _at(page, 'All/Testi/Overview/pve2', 'an offline node opens its node view')
    # its history: the Timeline of Testi with the node kind picked, read with that filter
    if page.locator('[data-cr-al-detail]').count() == 0:
        page.locator('[data-cr-al-details]').click()
    page.locator('[data-cr-al-item="nodes|c1"] [data-cr-al-history]').click()
    page.locator('[data-tl-filter-kind]').wait_for(timeout=5000)
    assert page.locator('[data-tl-filter-kind]').input_value() == 'node'
    _eventually(lambda: any('/api/timeline?' in u and 'kinds=node' in u and 'cluster=c1' in u for u in app.server.urls),
                f'the Timeline reads with the node kind: {app.server.urls[-5:]}')
    # an alert's history: alert kind with its severity
    page.locator('[data-cr-al-item="incident|c1"]').first.locator('[data-cr-al-history]').click()
    page.wait_for_function('() => document.querySelector("[data-tl-filter-kind]").value === "alert"', timeout=5000)
    assert page.locator('[data-tl-filter-severity]').input_value() == 'critical'
    # the quorum of Prod: its datacenter page
    page.locator('[data-cr-al-seg="quorum"]').click()
    _at(page, 'All/Prod/Datacenter', 'a lost quorum opens the datacenter page of its cluster')
    assert app.server.writes() == []
    _no_errors(app)


def test_runtime_no_history_link_without_the_permission_to_read_it(open_app):
    perms = ['cluster.view', 'vm.view', 'storage.view']
    app = open_app(admin=False, permissions=perms)
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-details]').click()
    assert page.locator('[data-cr-al-item="nodes|c1"] [data-cr-al-history]').count() == 0, 'node rows need node.view'
    assert page.locator('[data-cr-al-item="incident|c1"] [data-cr-al-history]').count() >= 1
    _no_errors(app)


def test_runtime_the_strip_by_the_keyboard(open_app):
    app = open_app()
    page = app.page
    _settled(page)
    page.locator('[data-cr-palette]').focus()
    seen = []
    for _ in range(40):
        page.keyboard.press('Tab')
        hit = page.evaluate('''() => { const a = document.activeElement;
            return a && a.closest('[data-cr-alerts]') ? (a.dataset.crAlSeg || (a.hasAttribute('data-cr-al-details') ? 'details' : '')
                || (a.dataset.crAlDismiss ? 'dismiss:' + a.dataset.crAlDismiss : '')) : null; }''')
        if hit:
            seen.append(hit)
        if hit == 'dismiss:info':
            break
    assert seen[:6] == ['disconnected', 'quorum', 'nodes', 'incident', 'hardware', 'details'], seen
    assert 'dismiss:critical' in seen and seen[-1] == 'dismiss:info', seen
    details = page.locator('[data-cr-al-details]')
    details.focus()
    page.keyboard.press('Enter')
    assert details.get_attribute('aria-expanded') == 'true'
    assert page.locator('#' + details.get_attribute('aria-controls')).count() == 1
    page.keyboard.press(' ')
    page.locator('[data-cr-al-detail]').wait_for(state='detached', timeout=3000)
    _no_errors(app)


@pytest.mark.parametrize('engine,viewport', [('chromium', (1600, 1000)), ('chromium', (1280, 800)),
                                             ('firefox', (1600, 1000)), ('firefox', (1280, 800))],
                         ids=['chromium-1600', 'chromium-1280', 'firefox-1600', 'firefox-1280'])
def test_runtime_the_strip_fits_the_window(open_app, engine, viewport):
    app = open_app(engine=engine, viewport=viewport)
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-details]').click()
    _need(page, '[data-cr-al-detail]', 'the list opens')
    got = page.evaluate('''() => {
        const s = document.querySelector('[data-cr-alerts]');
        const rows = Array.from(s.querySelectorAll('[data-cr-al-row]')).map(r => {
            const b = r.getBoundingClientRect();
            const kids = Array.from(r.children).map(c => c.getBoundingClientRect());
            return { h: b.height, right: b.right, out: kids.some(k => k.right > b.right + 0.5 || k.left < b.left - 0.5) };
        });
        return { sw: document.documentElement.scrollWidth, rows,
                 detail: s.querySelector('[data-cr-al-detail]').scrollWidth <= s.querySelector('[data-cr-al-detail]').clientWidth };
    }''')
    assert got['sw'] <= viewport[0], ('no sideways scroll', got)
    assert all(r['h'] <= 32 and not r['out'] and r['right'] <= viewport[0] + 0.5 for r in got['rows']), got
    assert got['detail'], ('the list wraps instead of scrolling sideways', got)
    _no_errors(app)


def test_runtime_classic_corporate_keeps_its_banners(open_app):
    app = open_app(layout='corporate', extra={('GET', '/api/clusters/c1/ha/status'): (200, {'nodes': {
        'pve2': {'status': 'offline', 'last_seen': '2026-10-30T08:55:00', 'consecutive_failures': 3}}})})
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.get_by_text('Node pve2 is offline').first.wait_for(timeout=8000)
    page.locator('.corp-warning-banner').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-alerts]').count() == 0
    _no_errors(app)


# --- the task center: the bar is the header ----------------------------------------------------

def _drawer_open(page):
    return page.locator('#cr-tc-drawer').count() == 1


def test_runtime_the_grip_resizes_and_never_toggles(open_app):
    app = open_app()
    page = app.page
    _open(page)
    _need(page, '[data-cr-tc-bar]', 'the bar is the header of the open panel')
    grip = page.locator('[data-cr-tc-grip]')
    # a sibling of the bar, not inside it, and at the top edge of the open panel
    assert page.evaluate('() => !document.querySelector("[data-cr-tc-bar]").contains(document.querySelector("[data-cr-tc-grip]"))')
    g, bar = grip.bounding_box(), page.locator('[data-cr-tc-bar]').bounding_box()
    assert g['y'] < bar['y'] + 6, ('the grip sits on the top edge', g, bar)
    h0 = page.locator('#cr-tc-drawer').bounding_box()['height']
    x, y = g['x'] + g['width'] / 2, g['y'] + g['height'] / 2
    # a drag
    page.mouse.move(x, y)
    page.mouse.down()
    page.mouse.move(x, y - 60, steps=5)
    page.mouse.up()
    assert _drawer_open(page), 'a drag on the grip leaves the drawer open'
    assert abs(page.locator('#cr-tc-drawer').bounding_box()['height'] - (h0 + 60)) <= 3
    # a plain click and a double click
    g = grip.bounding_box()
    page.mouse.click(g['x'] + g['width'] / 3, g['y'] + g['height'] / 2)
    page.mouse.dblclick(g['x'] + g['width'] / 3, g['y'] + g['height'] / 2)
    page.wait_for_timeout(300)
    assert _drawer_open(page), 'a click on the grip leaves the drawer open'
    # its keys resize; Enter and Space on it do nothing to the drawer
    grip.focus()
    for key in ('ArrowUp', 'Enter', ' ', 'PageDown'):
        page.keyboard.press(key)
    page.wait_for_timeout(200)
    assert _drawer_open(page) and page.locator(TOGGLE).get_attribute('aria-expanded') == 'true'
    _no_errors(app)


def test_runtime_the_bar_toggles_beside_its_controls_but_not_on_them(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    _open(page)
    # its controls do their own job and leave the drawer open
    for sel in ('[data-cr-tc-refresh]', '[data-cr-tc-scope-pick="all"]', '[data-cr-tc-coverage]'):
        page.locator(sel).click()
        page.wait_for_timeout(200)
        assert _drawer_open(page), f'{sel} leaves the drawer open'
    page.keyboard.press('Escape')        # the coverage list
    page.wait_for_timeout(200)
    assert _drawer_open(page)
    # a drag across the bar is no click
    box = page.locator('.cr-tc-hit').bounding_box()
    page.mouse.move(box['x'] + 200, box['y'] + 16)
    page.mouse.down()
    page.mouse.move(box['x'] + 420, box['y'] + 16, steps=6)
    page.mouse.up()
    page.wait_for_timeout(200)
    assert _drawer_open(page), 'a drag (or a text selection) across the bar does not close it'
    # beside them, at the end of the bar: it closes
    bar = page.locator('[data-cr-tc-bar]').bounding_box()
    page.mouse.click(bar['x'] + bar['width'] - 3, bar['y'] + bar['height'] / 2)
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    assert page.evaluate('() => getComputedStyle(document.querySelector("[data-cr-tc-bar]")).cursor') == 'pointer'
    _no_errors(app)


def test_runtime_the_open_state_is_kept_per_user_and_auto_expand_does_not_change_it(open_app):
    app = open_app()
    page = app.page
    _open(page)
    assert page.evaluate('() => localStorage.getItem("cr-tc-open:admin")') == '1'
    page.reload()
    app.wait_for_app()
    _need(page, '#cr-tc-drawer', 'the drawer is open again after a reload')
    page.locator(TOGGLE).click()
    page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    assert page.evaluate('() => localStorage.getItem("cr-tc-open:admin")') is None
    page.reload()
    app.wait_for_app()
    page.wait_for_timeout(800)
    assert not _drawer_open(page), 'closed stays closed'
    # a task the user just started opens the drawer (#738) for now; the kept choice stays closed
    fresh = _task('pve1', 30, 'qmstart', 100, 'running', 5)
    _pick_testi(page)
    page.wait_for_timeout(800)
    app.server.lists['c1'] = shaped([fresh] + C1, 'real')
    page.evaluate('(d) => window.__sse.say({type: "tasks", cluster_id: "c1", data: d})', app.server.lists['c1'])
    _need(page, '#cr-tc-drawer', 'a task just started opens the drawer', timeout=5000)
    assert page.evaluate('() => localStorage.getItem("cr-tc-open:admin")') is None, 'auto-expand writes no choice'
    _no_errors(app)


def test_runtime_the_collapsed_bar_counts_everything_and_says_over_what(open_app):
    app = open_app()
    page = app.page
    # All clusters before any list was read: no numbers, and it says why
    _need(page, '[data-cr-tc-window]', 'the bar says what it counts over')
    page.wait_for_timeout(600)
    counts = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-tc-hit [data-cr-tc-count]'))
        .map(x => [x.dataset.crTcCount, x.dataset.n === undefined ? null : Number(x.dataset.n), x.querySelector('b').innerText])''')
    assert [c[0] for c in counts] == ['running', 'queued', 'completed', 'failed', 'cancelled'], counts
    assert all(c[1] is None and c[2] == '-' for c in counts), ('nothing read is no 0', counts)
    assert page.locator('[data-cr-tc-window]').inner_text().startswith('not read yet'), page.locator('[data-cr-tc-window]').inner_text()
    # the cluster's list: the numbers, the window they are counted over, the task that runs and its cluster
    _pick_testi(page)
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n === "1"', timeout=8000)
    got = page.evaluate('''() => Object.fromEntries(Array.from(document.querySelectorAll('.cr-tc-hit [data-cr-tc-count]'))
        .map(x => [x.dataset.crTcCount, x.dataset.n === undefined ? null : Number(x.dataset.n)]))''')
    assert got == {'running': 1, 'queued': None, 'completed': 4, 'failed': 2, 'cancelled': 1}, got
    assert page.locator('[data-cr-tc-window]').inner_text() == 'last 50 tasks per cluster'
    assert 'interrupted by signal' in page.locator('[data-cr-tc-count="cancelled"]').get_attribute('title')
    latest = page.locator('[data-cr-tc-latest]')
    assert latest.get_attribute('data-cr-tc-latest-state') == 'running'
    assert 'VM Migration (100)' in latest.inner_text() and latest.locator('[data-cr-tc-latest-cluster]').inner_text() == 'Testi'
    assert re.fullmatch(r'since \S.*', latest.locator('[data-cr-tc-since]').inner_text()), latest.inner_text()
    # nothing runs any more: the newest task, said as the last one
    done = shaped([dict(t, _result='OK', endtime=t['starttime'] + 30) if t is RUN else t for t in C1], 'real')
    page.evaluate('(d) => window.__sse.say({type: "tasks", cluster_id: "c1", data: d})', done)
    page.wait_for_function('() => document.querySelector("[data-cr-tc-latest]").dataset.crTcLatestState === "last"', timeout=5000)
    assert latest.inner_text().startswith('Last task'), latest.inner_text()
    _no_errors(app)


def test_runtime_live_frames_count_while_collapsed_and_collapsing_touches_no_task(open_app):
    app = open_app()
    page = app.page
    _pick_testi(page)
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n === "1"', timeout=8000)
    reads = len(_tasks_reads(app.server, 'c1'))
    for _ in range(3):
        _open(page)
        page.locator(TOGGLE).click()
        page.locator('#cr-tc-drawer').wait_for(state='detached', timeout=3000)
    # (started long ago: a task the user just started would open the drawer, #738)
    second = _task('pve2', 31, 'vzdump', 102, 'running', 900)
    page.evaluate('(d) => window.__sse.say({type: "tasks", cluster_id: "c1", data: d})', shaped([second] + C1, 'real'))
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n === "2"', timeout=5000)
    assert '+1 more running' in page.locator('[data-cr-tc-latest]').inner_text()
    # open and close read nothing new of the cluster's list and change nothing on the server
    assert len(_tasks_reads(app.server, 'c1')) == reads
    assert app.server.deletes == [] and app.server.writes() == []
    _no_errors(app)


# --- stage X: what the review of round 4 found -----------------------------------------------------

class _RefusingTasks(_AlertServer):
    """The alert fake whose task list of Testi answers with a refusal or a failure."""

    def __init__(self, code, **kw):
        super().__init__(**kw)
        self.code = code

    def handle(self, route):
        req = route.request
        if req.method == 'GET' and re.search(r'/api/clusters/c1/tasks$', req.url.split('?')[0]):
            self.calls.append(('GET', '/api/clusters/c1/tasks'))
            return route.fulfill(status=self.code, body=json.dumps({'error': 'Permission denied' if self.code == 403 else 'boom'}),
                                 headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.mark.parametrize('code,said', [(403, 'not readable with your permissions (HTTP 403)'), (500, 'could not be read (HTTP 500)')])
def test_runtime_a_refused_task_list_is_no_count_of_zero(open_app, code, said):
    # R-01: the collapsed bar of a cluster whose task read was refused or failed shows no numbers
    app = open_app(server=_RefusingTasks(code, sse=True, layout=LAYOUT))
    page = app.page
    _pick_testi(page)
    _eventually(lambda: any(p == '/api/clusters/c1/tasks' for _, p in app.server.calls), 'the task list of Testi was asked for')
    page.wait_for_timeout(1500)
    counts = page.evaluate('''() => Array.from(document.querySelectorAll('.cr-tc-hit [data-cr-tc-count]'))
        .map(x => [x.dataset.crTcCount, x.dataset.n === undefined ? null : x.dataset.n, x.querySelector('b').innerText])''')
    assert all(c[1] is None and c[2] == '-' for c in counts), ('a refused read is no 0', counts)
    window = page.locator('[data-cr-tc-window]').inner_text()
    assert said in window and 'last 50' not in window, window
    # All clusters: Testi is not counted as read
    _open(page)
    page.locator('[data-cr-tc-scope-pick="all"]').click()
    page.locator('[data-cr-tc-coverage]').click()
    _eventually(lambda: page.locator('[data-cr-tc-cover="c1"]').count() == 1, 'the coverage list names Testi')
    st = page.locator('[data-cr-tc-cover="c1"]').get_attribute('data-st')
    assert st == ('denied' if code == 403 else 'error'), st
    _no_errors(app)


def test_runtime_the_bar_button_is_described_by_its_counts(open_app):
    # R-13: the short name stays; the counts, their window and the running task describe the button
    app = open_app()
    page = app.page
    _pick_testi(page)
    page.wait_for_function('() => document.querySelector(\'[data-cr-tc-count="running"]\').dataset.n === "1"', timeout=8000)
    ids = page.locator(TOGGLE).get_attribute('aria-describedby') or ''
    assert set(ids.split()) == {'cr-tc-counts', 'cr-tc-window', 'cr-tc-latest'}, ids
    for i in ids.split():
        assert page.evaluate('(i) => !!document.getElementById(i) && document.querySelector(".cr-tc-hit").contains(document.getElementById(i))', i), i
    said = page.evaluate('() => document.getElementById("cr-tc-counts").innerText')
    assert 'Running' in said and 'Failed' in said, said
    _no_errors(app)


def test_runtime_with_every_line_dismissed_the_details_close_from_the_chip(open_app):
    # R-12: the Details switch sits beside the chip once no line is left
    app = open_app()
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-details]').click()
    _need(page, '[data-cr-al-detail]', 'Details lists every line')
    for sev in ('critical', 'warning', 'info'):
        page.locator(f'[data-cr-al-dismiss="{sev}"]').click()
        page.locator(f'[data-cr-al-row="{sev}"]').wait_for(state='detached', timeout=3000)
    assert page.locator('[data-cr-al-row]').count() == 0 and page.locator('[data-cr-al-chip]').count() == 1
    switch = page.locator('[data-cr-al-details]')
    assert switch.count() == 1 and switch.get_attribute('aria-expanded') == 'true'
    switch.click()
    page.locator('[data-cr-al-detail]').wait_for(state='detached', timeout=3000)
    assert app.server.writes() == []
    _no_errors(app)


def test_runtime_the_timeline_filter_of_a_history_link_holds_for_that_visit_only(open_app):
    # R-03: History filters the Timeline once; a plain visit later starts without the filter
    app = open_app()
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-details]').click()
    page.locator('[data-cr-al-item="incident|c1"]').first.locator('[data-cr-al-history]').click()
    page.wait_for_function('() => (document.querySelector("[data-tl-filter-kind]") || {}).value === "alert"', timeout=5000)
    assert page.locator('[data-tl-filter-severity]').input_value() == 'critical'
    page.locator('[data-cr-tab="overview"]').click()
    page.wait_for_timeout(300)
    page.locator('[data-cr-tab="timeline"]').click()
    page.locator('[data-tl-filter-kind]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert page.locator('[data-tl-filter-kind]').input_value() == '' and page.locator('[data-tl-filter-severity]').input_value() == ''
    # and again from the strip: filtered again
    if page.locator('[data-cr-al-detail]').count() == 0:
        page.locator('[data-cr-al-details]').click()
    page.locator('[data-cr-al-item="incident|c1"]').first.locator('[data-cr-al-history]').click()
    page.wait_for_function('() => (document.querySelector("[data-tl-filter-kind]") || {}).value === "alert"', timeout=5000)
    _no_errors(app)


def test_runtime_a_status_without_any_node_is_said_not_silent(open_app):
    # R-09: vms.py answers zeros when Proxmox VE did not deliver its cluster status
    scene = dict(SCENE, c2=_status(None, 0, 0, standalone=True))
    app = open_app(scene=scene)
    page = app.page
    _pick_testi(page)
    _wait_seg(page, 'state', 'empty', 'Status of Prod came back without any node')
    page.locator('[data-cr-al-details]').click()
    assert 'This is not an empty cluster' in page.locator('[data-cr-al-item="empty|c2"]').inner_text()
    assert 'Prod' not in json.dumps(_segs(page, 'critical')), _strip(page)
    _no_errors(app)


def test_runtime_an_old_status_says_what_it_said_last(open_app):
    # R-10: the verdicts of an old status are not shown as current, and what it said last is named
    app = open_app()
    page = app.page
    _settled(page)
    app.server.extra[('GET', '/api/clusters/c2/datacenter/status')] = (500, {'error': 'boom'})
    app.ctx.clock.set_fixed_time(FIXED + 120)
    page.wait_for_function('() => !!document.querySelector(\'[data-cr-al-row="state"] [data-cr-al-seg="stale"]\')', timeout=40000)
    assert 'quorum' not in _segs(page, 'critical')
    assert 'quorum lost' in page.locator('[data-cr-al-row="state"] [data-cr-al-seg="stale"]').get_attribute('title')
    page.locator('[data-cr-al-details]').click()
    line = page.locator('[data-cr-al-item="stale|c2"]').inner_text()
    assert 'Last known at' in line and 'quorum lost' in line and '1 node offline' in line and 'hardware degraded' in line, line
    assert 'Not shown as current' in line
    _no_errors(app)


def test_runtime_an_alert_of_an_unknown_severity_is_not_made_information(open_app):
    # R-11: the rule API takes any word as severity; such a row is said apart, never counted as info
    rows = INCIDENTS + [_incident('a3', 'high', 'Backup lag above 6 h')]
    app = open_app(incidents=rows)
    page = app.page
    _pick_testi(page)
    _wait_seg(page, 'state', 'oddsev', '1 active alert with a severity PegaProx does not know (Testi)')
    assert 'incident' not in _segs(page, 'info'), _strip(page)
    page.locator('[data-cr-al-details]').click()
    line = page.locator('[data-cr-al-item="oddsev|c1"]').inner_text()
    assert 'Backup lag above 6 h' in line and 'severity high' in line, line
    _no_errors(app)


def test_runtime_the_details_say_how_old_hardware_is_and_what_is_acknowledged(open_app):
    # R-18: the rollup is a cache of up to 30 minutes; acknowledged alerts are counted and said
    app = open_app()
    page = app.page
    _settled(page)
    page.locator('[data-cr-al-details]').click()
    assert 'up to 30 minutes old' in page.locator('[data-cr-al-item="hardware|c2"]').inner_text()
    lines = page.locator('[data-cr-al-item="incident|c1"]')
    texts = [lines.nth(i).inner_text() for i in range(lines.count())]
    assert any('Counted with them: 1 acknowledged' in x for x in texts), texts
    assert not any('Counted with them' in x for x in texts if 'Ceph health' in x), texts
    _no_errors(app)
