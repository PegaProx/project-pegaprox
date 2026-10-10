"""The timeline in the UI: a tab of the cluster, a tab of the node, a tab or section of the guest.

One list from GET /api/timeline, newest first, filtered by kind, severity and time range on
the server, a page at a time, worded in the reader's language from what the server stored.
What happened shortly before an alert, a failed task, a node going offline or a failed
backup opens under it and says it is correlation, not cause. A guest or node in a row opens
its own view. Modern, Corporate and the cloud layout; a standby shows it as well (it only
reads), and says so when the leader that keeps the rows does not answer.
Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Oct 2026
"""
import calendar
import os
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import (CLUSTER, LANGS, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer, _blocks,  # noqa: F401
                        _classes, browser)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTE = '/api/timeline'

KEYS = ['tlTab', 'tlTitle', 'tlDesc', 'tlDescNode', 'tlDescGuest', 'tlFilterRange', 'tlFilterKind',
        'tlFilterSeverity', 'tlAllKinds', 'tlAllSeverities', 'tlRange1h', 'tlRange24h', 'tlRange7d', 'tlRange30d',
        'tlKindAudit', 'tlKindAlert', 'tlKindMigration', 'tlKindBalancer', 'tlKindDrift', 'tlKindTask',
        'tlKindBackup', 'tlKindBackupVerify', 'tlKindNode', 'tlKindSiteRecovery', 'tlKindRollingUpdate',
        'tlKindSyslog', 'tlKindIncident', 'tlSevCritical', 'tlSevWarning', 'tlSevInfo', 'tlNone', 'tlNoMatch',
        'tlLoadMore', 'tlLoadError', 'tlHidden', 'tlOpenView', 'tlShortlyBefore', 'tlShortlyBeforeNote',
        'tlMinBefore', 'tlSecBefore', 'tlNodeOffline', 'tlNodeOnline', 'tlNodeUnknown', 'tlNodeMaintenance',
        'tlNodeMaintenanceEnd', 'tlNodeNoQuorum', 'tlNodeQuorate', 'tlInMaintenance', 'tlAlertFired',
        'tlAlertResolved', 'tlMigrated', 'tlBalancerMoved', 'tlBalancerDryRun', 'tlMigrationFailed',
        'tlVerifyPassed', 'tlVerifyFailed', 'tlVerifyRunning', 'tlRollingStarted', 'tlRollingEnded',
        'tlSiteRecovery']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('// LW Oct 2026 - the flight recorder: what happened on a cluster')
    return src[start:src.index('// MK May 2026', start)]


def _between(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def _mounts():
    dash = _read('web', 'src', 'dashboard.js')
    nodes = _read('web', 'src', 'node_modals.js')
    vms = _read('web', 'src', 'vm_modals.js')
    cloud = _read('web', 'src', 'cloud.js')
    return [
        _between(dash, "{ id: 'timeline', labelKey: 'tlTab'", '\n'),
        _between(dash, '{/* LW Oct 2026 - the flight recorder of the cluster */}', "{activeTab === 'compliance' && ("),
        _between(nodes, "{ id: 'timeline', label: t('tlTab')", '\n'),
        _between(nodes, "{activeTab === 'timeline' && (", "{activeTab === 'subscription' && ("),
        _between(nodes, "<button className={`corp-subnav-item ${monitorSubTab === 'timeline'", '\n'),
        _between(nodes, '{/* LW Oct 2026 - what happened on this node', "{monitorSubTab === 'tasks' && ("),
        _between(vms, "<button className={activeDetailTab === 'timeline'", '</button>'),
        _between(vms, '{/* LW Oct 2026 - what happened to this guest and its host */}', '{/* NS: Mar 2026 - inline snapshots tab */}'),
        _between(vms, '{/* Timeline of this guest and its host */}', '{/* Tags */}'),
        _between(cloud, "// LW Oct 2026 - the flight recorder of the selected cluster", '] },'),
        _between(cloud, "case 'timeline':", 'break;'),
    ]


def _all():
    return _component() + ''.join(_mounts())


# -- source -------------------------------------------------------------------------------------

def test_every_new_key_exists_once_per_language():
    for lang, block in _blocks().items():
        for key in KEYS:
            assert len(re.findall(r'^ +%s:' % key, block, re.M)) == 1, (lang, key)


def test_the_keys_sit_together_after_the_balancer_history():
    for lang, block in _blocks().items():
        lines = block.splitlines()
        at = next(i for i, line in enumerate(lines) if re.match(r'^ +balHistFailedWith:', line))
        assert [re.match(r'^ +(\w+):', line).group(1) for line in lines[at + 1:at + 1 + len(KEYS)]] == KEYS, lang


def test_every_new_key_is_used_and_nothing_else_is_new():
    used = set(re.findall(r"'(tl[A-Z]\w*)'", _all()))
    assert used == set(KEYS)


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in KEYS:
        en = re.search(r"^ +%s: '(.*)',$" % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r"^ +%s: '(.*)',$" % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_no_dash_in_what_this_change_added():
    lines = [line for block in _blocks().values() for line in block.splitlines()
             if re.match(r'^ +(%s):' % '|'.join(KEYS), line)]
    assert len(lines) == len(KEYS) * len(LANGS)
    for text in [_all()] + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = _classes(_all())
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    used = set(re.findall(r'Icons\.(\w+)', _all())) | set(re.findall(r"icon: '(\w+)'", _mounts()[9]))
    assert {'Clock', 'Bell', 'Server', 'Monitor'} <= used
    for name in used:
        assert re.search(r'^ +%s: \(' % name, icons, re.M), name


def test_the_timeline_only_reads_and_is_never_locked():
    nodes = _read('web', 'src', 'node_modals.js')
    assert "!['summary', 'performance', 'tasks', 'timeline'].includes(activeTab)" in nodes
    # nothing in it writes
    assert 'method:' not in _component() and "method: 'POST'" not in _component()


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('function TimelineView(', '/timeline?', 'data-tl-row', 'tlShortlyBeforeNote', 'data-vm-timeline',
                   'data-corp-node-timeline', 'data-corp-vm-timeline'):
        assert needle in bundle, needle


# -- runtime ------------------------------------------------------------------------------------

NOW = time.time()


def _iso(sec_ago):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(NOW - sec_ago))


def _ev(eid, kind, sec_ago, severity='info', what=None, title='', node=None, guest=None, guest_name='',
        details='', params=None, links=(), anchor=False):
    return {'id': eid, 'kind': kind, 'time': _iso(sec_ago), 'severity': severity, 'cluster': 'c1', 'node': node,
            'guest': guest, 'guest_name': guest_name, 'title': title, 'details': details, 'what': what or kind,
            'params': params or {}, 'source': {'route': '', 'id': eid}, 'anchor': anchor,
            'shortly_before': list(links)}


DRIFT = _ev('drift:1', 'drift', 300, 'warning', title='memory changed', guest=100, guest_name='web01',
            params={'drift_kind': 'vm_config', 'scope': 'qemu/100'})
MOVE = _ev('migration:7', 'migration', 480, what='migration', node='pve1', guest=100, guest_name='web01',
           params={'status': 'success', 'source': 'pve2', 'target': 'pve1'})


def _link(ev, seconds):
    return {k: ev[k] for k in ('id', 'kind', 'time', 'severity', 'title', 'what', 'params', 'node', 'guest',
                               'guest_name')} | {'seconds_before': seconds}


EVENTS = [
    _ev('alert:a1', 'alert', 60, 'critical', 'alert.fired', 'web01 CPU above 90%', guest=100, guest_name='web01',
        links=[_link(DRIFT, 240), _link(MOVE, 420)], anchor=True),
    _ev('node:3', 'node', 120, 'critical', 'node.offline', node='pve1', params={'node': 'pve1', 'previous': 'online'},
        anchor=True),
    DRIFT, MOVE,
    _ev('task:u1', 'task', 600, 'warning', 'task', 'qmstart 100', node='pve1', guest=100, guest_name='web01',
        details='start failed: no space', params={'type': 'qmstart', 'status': 'start failed'}, anchor=True),
    _ev('audit:5', 'audit', 900, title='vm.config', details='Updated config of VM 100', guest=100,
        guest_name='web01', params={'action': 'vm.config', 'user': 'root'}),
    _ev('balancer:9', 'balancer', 1000, what='migration', node='pve2', guest=100, guest_name='web01',
        params={'status': 'dry_run', 'source': 'pve1', 'target': 'pve2', 'trigger': 'balance'}),
] + [_ev(f'audit:{100 + i}', 'audit', 2000 + i * 60, title=f'user.login {i}', params={'action': 'user.login'})
     for i in range(60)]


class _TimelineServer(_FakeServer):
    """The timeline route as the server pages it: filtered, newest first, PAGE rows at a time."""

    events = EVENTS
    hidden = ()

    def handle(self, route):
        req = route.request
        parsed = urlparse(req.url)
        if parsed.path == ROUTE and ('GET', ROUTE) not in self.fixed:
            q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            rows = [e for e in self.events
                    if (not q.get('kinds') or e['kind'] in q['kinds'].split(','))
                    and (not q.get('severity') or e['severity'] in q['severity'].split(','))
                    and (not q.get('vmid') or e['guest'] == int(q['vmid']))
                    and (not q.get('node') or e['node'] == q['node'])]
            if q.get('before'):
                at = next(i for i, e in enumerate(rows) if f"{e['time']}|{e['id']}" == q['before'])
                rows = rows[at + 1:]
            limit = int(q.get('limit', 50))
            page = rows[:limit]
            sources = {k: {'shown': k not in self.hidden, 'why': 'permission' if k in self.hidden else '',
                           'capped': False, 'count': 0}
                       for k in ('audit', 'alert', 'drift', 'node', 'syslog')}
            nxt = f"{page[-1]['time']}|{page[-1]['id']}" if len(rows) > limit else None
            self.extra[('GET', ROUTE)] = (200, {'events': page, 'next_before': nxt, 'sources': sources,
                                                'correlation': {'window_minutes': 10, 'note': ''}})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(events=None, hidden=(), **kw):
        extra = dict(SSE_TOKEN)
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        kw.setdefault('metrics', NODE_METRICS)
        server = _TimelineServer(clusters=[CLUSTER], resources=[VM], extra=extra, **kw)
        server.fixed = set(extra)
        if events is not None:
            server.events = events
        server.hidden = hidden
        app = _App(browser, server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _wait_for(page, fn, seconds=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        page.wait_for_timeout(100)
    return fn()


def _reads(app):
    return [parse_qs(urlparse(u).query) for u in app.server.urls if urlparse(u).path == ROUTE]


def _open_cluster_timeline(app, name='Timeline'):
    page = app.page
    if app.server.layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.get_by_role('button', name=name, exact=True).first.click()
    page.locator('[data-timeline="cluster"]').wait_for(timeout=5000)
    page.locator('[data-tl-row]').first.wait_for(timeout=5000)
    return page


def _row(page, eid):
    return page.locator(f'[data-tl-row="{eid}"]')


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_cluster_timeline_with_what_happened_shortly_before(open_app, layout):
    app = open_app(layout=layout, hidden=('drift', 'syslog'))
    page = _open_cluster_timeline(app)
    assert page.locator('[data-timeline] h3').inner_text().strip() == 'Timeline'
    assert page.locator('[data-tl-row]').count() == 50
    first = _reads(app)[0]
    assert first['cluster'] == ['c1'] and first['limit'] == ['50'] and 'node' not in first and 'vmid' not in first
    since = calendar.timegm(time.strptime(first['from'][0][:19], '%Y-%m-%dT%H:%M:%S'))
    assert abs((time.time() - since) - 24 * 3600) < 120
    alert = _row(page, 'alert:a1').inner_text()
    assert 'Fired: web01 CPU above 90%' in alert and 'Alert' in alert and 'web01 (100)' in alert
    assert _row(page, 'alert:a1').locator('[data-tl-sev="critical"]').count() == 1
    assert 'Node pve1 went offline' in _row(page, 'node:3').inner_text()
    assert 'web01 (100) migrated from pve2 to pve1' in _row(page, 'migration:7').inner_text()
    assert 'The balancer would have moved web01 (100) from pve1 to pve2 (dry run)' in \
        _row(page, 'balancer:9').inner_text()
    assert 'start failed: no space' in _row(page, 'task:u1').inner_text()
    # what the account may not read is named, not silently missing
    assert page.locator('[data-tl-hidden]').inner_text().strip() == 'Not shown for your account: Config drift, Syslog'
    # the links open on demand and say what they are
    assert page.locator('[data-tl-links]').count() == 0
    toggle = _row(page, 'alert:a1').locator('[data-tl-links-toggle]')
    assert toggle.inner_text().strip() == '2 happened shortly before'
    toggle.click()
    links = _row(page, 'alert:a1').locator('[data-tl-links]')
    links.wait_for(timeout=3000)
    assert 'This is correlation, not cause.' in links.locator('[data-tl-links-note]').inner_text()
    assert '4 min before' in links.locator('[data-tl-link="drift:1"]').inner_text()
    assert 'memory changed' in links.locator('[data-tl-link="drift:1"]').inner_text()
    assert '7 min before' in links.locator('[data-tl-link="migration:7"]').inner_text()
    # one read on opening, no polling
    page.wait_for_timeout(2000)
    assert len(_reads(app)) == 1
    assert not app.errors, app.errors


def test_runtime_filters_range_and_older_pages_ask_the_server(open_app):
    app = open_app(layout='modern')
    page = _open_cluster_timeline(app)
    page.locator('[data-tl-more]').click()
    assert _wait_for(page, lambda: 'before' in _reads(app)[-1])
    assert _reads(app)[-1]['before'] == [f"{EVENTS[49]['time']}|{EVENTS[49]['id']}"]
    assert _reads(app)[-1]['from'] == _reads(app)[0]['from']
    _wait_for(page, lambda: page.locator('[data-tl-row]').count() == len(EVENTS))
    assert page.locator('[data-tl-row]').count() == len(EVENTS)
    assert page.locator('[data-tl-more]').count() == 0

    page.locator('[data-tl-filter-kind]').select_option('alert')
    assert _wait_for(page, lambda: _reads(app)[-1].get('kinds') == ['alert'])
    page.locator('[data-tl-row="node:3"]').wait_for(state='detached', timeout=5000)
    assert page.locator('[data-tl-row]').count() == 1
    page.locator('[data-tl-filter-severity]').select_option('info')
    assert _wait_for(page, lambda: _reads(app)[-1].get('severity') == ['info'])
    page.locator('[data-tl-empty]').wait_for(timeout=5000)
    assert page.locator('[data-tl-empty]').inner_text().strip() == 'No event matches this filter.'
    page.locator('[data-tl-range]').select_option('168')
    assert _wait_for(page, lambda: len(_reads(app)) >= 5)
    since = calendar.timegm(time.strptime(_reads(app)[-1]['from'][0][:19], '%Y-%m-%dT%H:%M:%S'))
    assert abs((time.time() - since) - 7 * 86400) < 120
    assert not app.errors, app.errors


def test_runtime_nothing_happened(open_app):
    app = open_app(layout='modern', events=[])
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Timeline', exact=True).first.click()
    page.locator('[data-tl-empty]').wait_for(timeout=5000)
    assert page.locator('[data-tl-empty]').inner_text().strip() == 'Nothing happened in this time range.'
    assert not app.errors, app.errors


def test_runtime_a_guest_and_a_node_open_their_views_in_modern(open_app):
    app = open_app(layout='modern')
    page = _open_cluster_timeline(app)
    _row(page, 'node:3').locator('[data-tl-open-node="pve1"]').click()
    page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
    # the node modal's own close button
    page.locator('h2', has_text='pve1').locator('xpath=ancestor::div[contains(@class, "justify-between")][1]') \
        .locator('button').last.click()
    page.get_by_text('Proxmox Node').first.wait_for(state='hidden', timeout=5000)
    _row(page, 'alert:a1').locator('[data-tl-open-guest="100"]').click()
    page.locator('[data-timeline]').wait_for(state='detached', timeout=5000)
    page.get_by_text('web01').first.wait_for(timeout=5000)
    assert 'bg-proxmox-orange' in page.get_by_role('button', name='Resources', exact=True).first.get_attribute('class')
    assert not app.errors, app.errors


def test_runtime_a_node_opens_its_detail_view_in_corporate(open_app):
    app = open_app(layout='corporate')
    page = _open_cluster_timeline(app)
    _row(page, 'node:3').locator('[data-tl-open-node="pve1"]').click()
    strip = page.locator('.corp-tab-strip').last
    strip.get_by_text('Configure').wait_for(timeout=5000)
    assert page.locator('[data-timeline]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_node_modal_has_the_nodes_timeline(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
        child = page.locator('.corp-tree-child', has_text='pve1').first
        child.wait_for(timeout=5000)
        child.click()
        page.locator('.corp-toolbar button', has_text='Actions').last.click()
        page.locator('.corp-dropdown').last.get_by_text('Node Settings').click()
        page.locator('.corp-vm-modal').wait_for(timeout=5000)
        page.locator('.corp-vm-modal-tab', has_text='Timeline').click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button[title="Node Configuration"]').first.click()
        page.get_by_text('Proxmox Node').first.wait_for(timeout=5000)
        page.locator('button', has_text='Timeline').last.click()
    page.locator('[data-timeline="node"]').wait_for(timeout=5000)
    page.locator('[data-tl-row="node:3"]').wait_for(timeout=5000)
    assert _reads(app)[-1]['node'] == ['pve1']
    assert 'Everything that happened on this node, newest first.' in page.locator('[data-timeline="node"]').inner_text()
    # the node is the page: its rows carry no chip to itself
    assert page.locator('[data-timeline="node"] [data-tl-open-node]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_corporate_node_view_has_it_under_monitor(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    child = page.locator('.corp-tree-child', has_text='pve1').first
    child.wait_for(timeout=5000)
    child.click()
    page.locator('.corp-tab-strip').last.get_by_text('Monitor').click()
    page.locator('[data-corp-node-timeline]').click()
    page.locator('[data-timeline="node"] [data-tl-row="task:u1"]').wait_for(timeout=5000)
    assert _reads(app)[-1]['node'] == ['pve1']
    # a guest in a row opens the guest's view
    page.locator('[data-timeline="node"] [data-tl-row="task:u1"] [data-tl-open-guest="100"]').click()
    page.get_by_text('Snapshots').first.wait_for(timeout=5000)
    assert not app.errors, app.errors


def test_runtime_the_corporate_guest_view_has_a_timeline_tab(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.locator('span', has_text='web01').first.click()
    page.locator('[data-corp-vm-timeline]').click()
    page.locator('[data-timeline="guest"] [data-tl-row="alert:a1"]').wait_for(timeout=5000)
    assert _reads(app)[-1]['vmid'] == ['100']
    text = page.locator('[data-timeline="guest"]').inner_text()
    assert 'Everything that happened to this guest and its host, newest first.' in text
    # the guest is the page: no chip back to itself, the node still shows
    assert page.locator('[data-timeline="guest"] [data-tl-open-guest]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_modern_guest_panel_opens_its_timeline_on_demand(open_app):
    app = open_app(layout='modern')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.locator('button', has_text='Resources').first.click()
    page.get_by_text('web01').first.wait_for(timeout=5000)
    page.locator('button[title="Compact View"]').first.click()
    page.locator('div.cursor-pointer', has_text='web01').first.click()
    page.get_by_text('Quick Actions').wait_for(timeout=3000)
    toggle = page.locator('[data-vm-timeline-toggle]')
    toggle.scroll_into_view_if_needed()
    assert toggle.inner_text().strip() == 'Timeline'
    assert not _reads(app)
    toggle.click()
    page.locator('[data-timeline="guest"] [data-tl-row="alert:a1"]').wait_for(timeout=5000)
    assert _reads(app)[-1]['vmid'] == ['100']
    assert not app.errors, app.errors


def test_runtime_the_cloud_layout_lists_it_under_activity(open_app):
    app = open_app(layout='cloud')
    page = app.page
    page.locator('.cloud-nav').get_by_text('Timeline', exact=True).click()
    page.locator('[data-timeline="cluster"] [data-tl-row="alert:a1"]').wait_for(timeout=5000)
    assert _reads(app)[-1]['cluster'] == ['c1']
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_it_and_names_a_leader_that_does_not_answer(open_app):
    away = {'error': 'The active instance does not answer', 'code': 'HA_ACTIVE_UNREACHABLE'}
    app = open_app(layout='modern', role='standby', extra={('GET', ROUTE): (503, away)})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Timeline', exact=True).first.click()
    page.locator('[data-tl-leader-away]').wait_for(timeout=5000)
    assert 'Only the leader' in page.locator('[data-tl-leader-away]').inner_text()
    assert page.locator('[data-tl-error]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_standby_reads_it_through_its_active(open_app):
    app = open_app(layout='corporate', role='standby')
    page = _open_cluster_timeline(app)
    assert page.locator('[data-tl-row]').count() == 50
    assert not app.errors, app.errors


def test_runtime_a_failed_read_says_so(open_app):
    app = open_app(layout='modern', extra={('GET', ROUTE): (500, {'error': 'boom'})})
    page = app.page
    page.get_by_text('Testi').first.click()
    page.get_by_role('button', name='Timeline', exact=True).first.click()
    page.locator('[data-tl-error]').wait_for(timeout=5000)
    assert page.locator('[data-tl-error]').inner_text().strip() == 'The timeline could not be loaded.'


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = _open_cluster_timeline(app, name='Zeitachse')
    assert 'Node pve1 ist offline gegangen' in _row(page, 'node:3').inner_text()
    _row(page, 'alert:a1').locator('[data-tl-links-toggle]').click()
    note = _row(page, 'alert:a1').locator('[data-tl-links-note]').inner_text()
    assert 'keine Ursache' in note
    assert not app.errors, app.errors
