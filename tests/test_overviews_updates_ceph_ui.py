"""Pending updates and Ceph across all clusters, on the All Clusters overview.

The source checks read web/src and the bundle; the runtime tests drive the built bundle in
headless Chromium against the fake server of tests/test_ha_ui.py, in Modern and Corporate,
as an active instance and as a standby, in English and German. They skip where Playwright
is not installed. The routes behind the panels are tested in tests/test_overviews_updates_ceph.py.
LW Oct 2026
"""
import os
import re
import time

import pytest

from test_ha_ui import CLUSTER, SSE_TOKEN, VM, _App, _FakeServer, _classes, _wait_for_call, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')

UPDATE_KEYS = ['allUpdatesTitle', 'allUpdatesDesc', 'allUpdatesHost', 'allUpdatesPending', 'allUpdatesSecurity',
               'allUpdatesRepo', 'allUpdatesSubscription', 'allUpdatesChecked', 'allUpdatesKernel',
               'allUpdatesKernelHint', 'allUpdatesCheckFailed', 'allUpdatesSecurityUnknown', 'allUpdatesStale',
               'allUpdatesOpen', 'allUpdatesPendingOnly', 'allUpdatesSummary', 'allUpdatesFailedHosts',
               'allUpdatesEmpty', 'allUpdatesUpToDate', 'allUpdatesNoMatch', 'allUpdatesReadFailed',
               'allUpdatesUnchecked', 'allUpdatesRolling', 'allUpdatesRollingPaused', 'allUpdatesEnterprise',
               'allUpdatesNoSubscription', 'allUpdatesTest', 'allUpdatesMixed', 'allUpdatesNoRepo',
               'allUpdatesRepoWarnings', 'allUpdatesEnterpriseNoSub', 'allUpdatesSubActive', 'allUpdatesSubNone',
               'allUpdatesSubNew', 'allUpdatesSubInvalid', 'allUpdatesSubExpired', 'allUpdatesSubSuspended',
               'allUpdatesSubUnknown']
CEPH_KEYS = ['allCephTitle', 'allCephDesc', 'allCephHealth', 'allCephCapacity', 'allCephOsds', 'allCephOsdsValue',
             'allCephPgs', 'allCephPgsClean', 'allCephIo', 'allCephRead', 'allCephWrite', 'allCephRecovery',
             'allCephMons', 'allCephMonsValue', 'allCephMoreChecks', 'allCephFailed', 'allCephOpen',
             'allCephUnhealthy', 'allCephHealthy']
KEYS = UPDATE_KEYS + CEPH_KEYS
PLACEHOLDERS = {
    'allUpdatesSummary': ('{n}', '{h}'), 'allUpdatesFailedHosts': ('{n}',), 'allUpdatesRepoWarnings': ('{n}',),
    'allCephOsdsValue': ('{up}', '{total}', '{in}'), 'allCephPgsClean': ('{clean}', '{total}'),
    'allCephRead': ('{v}', '{n}'), 'allCephWrite': ('{v}', '{n}'), 'allCephRecovery': ('{v}',),
    'allCephMonsValue': ('{quorum}', '{total}'), 'allCephMoreChecks': ('{n}',), 'allCephUnhealthy': ('{n}',),
}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _block(src, start, end):
    at = src.index(start)
    return src[at:src.index(end, at)]


def _panels():
    return _block(_read('web', 'src', 'vm_modals.js'), '// LW Oct 2026 - the pending updates of every node',
                  '// LW Oct 2026 - every storage of every cluster in one table')


def _updates_panel():
    return _block(_panels(), 'function PendingUpdatesOverview(', 'function CephOverview(')


def _ceph_panel():
    return _panels()[_panels().index('function CephOverview('):]


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one():
    used = set(re.findall(r"t\('((?:allUpdates|allCeph)[A-Za-z]*)'\)", _read('web', 'src', 'vm_modals.js')))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))
    # and what the panels borrow is in every language as well
    tr = _read('web', 'src', 'translations.js')
    for key in set(re.findall(r"t\('([A-Za-z]+)'\)", _panels())) - set(KEYS):
        assert len(re.findall(rf'^\s*{key}:', tr, re.M)) >= 9, key


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, phs in PLACEHOLDERS.items():
        values = re.findall(rf'^\s*{key}: "(.*)",$', tr, re.M)
        assert len(values) == 9 and all(ph in v for v in values for ph in phs), (key, values)


def test_no_em_dash_in_what_this_change_added():
    dash = _read('web', 'src', 'dashboard.js')
    wiring = _block(dash, 'onOpenClusterTab={(cluster, tab, section) => {', 'onAutoInstall=')
    for block in (_panels(), wiring, _block(_read('web', 'src', 'datacenter.js'), 'function DatacenterTab(', 'const [loading')):
        assert '\u2014' not in block and '\u2013' not in block, block[:120]
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (".*"),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icons_exist():
    icons = _read('web', 'src', 'icons.js')
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', icons, re.M))
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _panels()))
    assert used and used <= have, sorted(used - have)
    # sized by the panel: it has to take a class
    for name in ('HardDrive', 'Search'):
        assert re.search(rf'^\s{{12}}{name}: \(\{{[^}}]*className', icons, re.M), name


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    missing = sorted(n for n in _classes(_panels()) if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_both_only_read():
    """Refresh reads, the chevron folds, a row navigates: nothing here writes, so a standby
    shows both unchanged."""
    for block in (_updates_panel(), _ceph_panel()):
        assert 'method:' not in block and 'POST' not in block and 'DELETE' not in block
        assert 'authFetch(' not in block
    assert _updates_panel().count('fetch(`${API_URL}/updates-overview`') == 1
    assert _ceph_panel().count('fetch(`${API_URL}/ceph-overview`') == 1


def test_both_are_on_the_overview_in_both_layouts_and_open_their_place():
    vm = _read('web', 'src', 'vm_modals.js')
    body = _block(vm, 'function AllClustersOverview(', 'function GroupSettingsModal(')
    assert body.count("<PendingUpdatesOverview clusters={clusters} onOpen={openIn('settings', 'updates')} />") == 2
    assert body.count("<CephOverview clusters={clusters} onOpen={openIn('datacenter', 'ceph')} />") == 2
    dash = _read('web', 'src', 'dashboard.js')
    wiring = _block(dash, 'onOpenClusterTab={(cluster, tab, section) => {', 'onAutoInstall=')
    assert "setDatacenterSection(tab === 'datacenter' ? section : null);" in wiring and 'setActiveTab(tab);' in wiring
    assert '<div className="lg:col-span-2" data-update-manager>' in dash
    assert 'initialSection={datacenterSection} onSectionShown={() => setDatacenterSection(null)}' in dash
    dc = _read('web', 'src', 'datacenter.js')
    assert "useState(initialSection || 'summary')" in dc


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function PendingUpdatesOverview(', 'function CephOverview(', '/updates-overview', '/ceph-overview',
                   'data-updates-overview-row', 'data-ceph-overview-row', 'data-update-manager',
                   'allUpdatesEnterpriseNoSub', 'allCephPgsClean'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

NOW = int(time.time())


def _h(cid, name, kind, host, count=0, ok=True, security=None, kernel=False, channel=None, repo_warnings=0,
       subscription=None, stale=False, pbs_id=None):
    return {'cluster_id': cid, 'cluster_name': name, 'kind': kind, 'name': host, 'pbs_id': pbs_id,
            'ok': ok, 'count': count if ok else None, 'security': security, 'kernel': kernel, 'channel': channel,
            'repo_warnings': repo_warnings, 'subscription': subscription,
            'checked_at': NOW - (90000 if stale else 600), 'stale': stale}


def _c(cid, name, state='ok', rolling=None):
    return {'cluster_id': cid, 'cluster_name': name, 'state': state, 'count': 0,
            'checked_at': NOW - 600 if state == 'ok' else None, 'stale': False, 'rolling': rolling}


UPDATES = {
    'hosts': [
        _h('c1', 'Testi', 'node', 'pve1', 12, kernel=True, channel='enterprise', subscription='active'),
        _h('c1', 'Testi', 'node', 'pve2', ok=False, channel='enterprise', repo_warnings=1, subscription='notfound'),
        _h('c1', 'Testi', 'node', 'pve3', 0, channel='no-subscription', subscription='notfound'),
        _h('x1', 'Xen', 'node', 'xcp1', 3, security=2),
        _h('c1', 'Testi', 'pbs', 'backup-a', 1, channel='no-subscription', subscription='notfound', stale=True,
           pbs_id='p1'),
    ],
    'clusters': [_c('c2', 'Branch', 'unchecked'), _c('c4', 'Pooled', 'confined'), _c('c1', 'Testi', rolling='running'),
                 _c('x1', 'Xen')],
}
# failed first, then the most pending
BY_PENDING = ['c1:node:pve2', 'c1:node:pve1', 'x1:node:xcp1', 'c1:pbs:p1', 'c1:node:pve3']

GiB = 1024 ** 3


def _ceph_row(cid, name, health, checks=(), more=0, osds=(6, 6, 6), pgs=(129, 129, ()), used=300, total=3000,
              io=(1048576, 2097152, 50, 120, 0), mons=(3, 3)):
    return {'cluster_id': cid, 'cluster_name': name, 'health': health,
            'checks': [{'name': n, 'severity': s, 'message': m} for n, s, m in checks], 'checks_more': more,
            'osds': {'total': osds[0], 'up': osds[1], 'in': osds[2]},
            'pgs': {'total': pgs[0], 'clean': pgs[1],
                    'states': [{'state': 'active+clean', 'count': pgs[1]}] + [{'state': s, 'count': n} for s, n in pgs[2]]},
            'bytes': {'used': used * GiB, 'avail': (total - used) * GiB, 'total': total * GiB},
            'percent': round(used * 100.0 / total, 1),
            'io': {'read_bps': io[0], 'write_bps': io[1], 'read_iops': io[2], 'write_iops': io[3], 'recovery_bps': io[4]},
            'mons': {'total': mons[0], 'quorum': mons[1]}, 'read_at': NOW}


CEPH = {
    'ceph': [
        _ceph_row('c2', 'Branch', 'HEALTH_WARN',
                  checks=[('OSD_DOWN', 'HEALTH_WARN', '1 osds down'), ('PG_DEGRADED', 'HEALTH_WARN', '40 pgs degraded'),
                          ('MON_DOWN', 'HEALTH_WARN', '1/3 mons down')], more=1,
                  osds=(3, 2, 3), pgs=(128, 88, [('active+undersized+degraded', 40)]), used=900, total=1000,
                  io=(0, 0, 0, 0, 5242880), mons=(3, 2)),
        _ceph_row('c1', 'Testi', 'HEALTH_OK'),
    ],
    'clusters': [{'cluster_id': 'c2', 'cluster_name': 'Branch', 'state': 'ok'},
                 {'cluster_id': 'c3', 'cluster_name': 'Plain', 'state': 'none', 'had_ceph': False},
                 {'cluster_id': 'c4', 'cluster_name': 'Pooled', 'state': 'confined'},
                 {'cluster_id': 'c5', 'cluster_name': 'Lost', 'state': 'unreadable', 'had_ceph': True},
                 {'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'ok'}],
}
UP = ('GET', '/api/updates-overview')
CE = ('GET', '/api/ceph-overview')
SHOWN = dict(CLUSTER, display_name='Testi (Vienna)')
BRANCH = dict(CLUSTER, id='c2', name='Branch', display_name='Branch')
QUIET = {('GET', '/api/storage-overview'): (200, {'storages': [], 'clusters': []}),
         ('GET', '/api/backup-coverage'): (200, {'guests': [], 'clusters': []})}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(updates=(200, UPDATES), ceph=(200, CEPH), **kw):
        extra = dict(SSE_TOKEN)
        extra.update(QUIET)
        extra[UP] = updates
        extra[CE] = ceph
        extra.update(kw.pop('extra', {}))
        kw.setdefault('role', 'standalone')
        kw.setdefault('clusters', [SHOWN, BRANCH])
        app = _App(browser, _FakeServer(resources=[VM], extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _on(app, kind):
    panel = app.page.locator(f'[data-{kind}-overview]')
    panel.wait_for(timeout=10000)
    app.page.locator(f'[data-{kind}-overview-row]').first.wait_for(timeout=5000)
    panel.scroll_into_view_if_needed()
    app.page.wait_for_timeout(200)
    return panel


def _rows(page, kind='updates'):
    attr = 'updatesOverviewRow' if kind == 'updates' else 'cephOverviewRow'
    return page.locator(f'[data-{kind}-overview-row]').evaluate_all(f'rs => rs.map(r => r.dataset.{attr})')


def _cells(page, key, kind='updates'):
    return page.locator(f'[data-{kind}-overview-row="{key}"] td').evaluate_all(
        'ts => ts.map(t => t.innerText.replace(/\\s+/g, " ").trim())')


def _only_reads(app):
    return [c for c in app.server.calls if c[0] != 'GET' and c[1] not in ('/api/sse/token', '/api/sse/subscribe')]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_pending_updates_of_every_host(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    panel = _on(app, 'updates')
    assert 'Pending updates across all clusters' in panel.inner_text()
    assert _rows(page) == BY_PENDING
    assert page.locator('[data-updates-overview-count]').inner_text().strip('() ') == '5'
    assert page.locator('[data-updates-overview-summary]').inner_text().split() == \
        '16 update(s) on 3 host(s) 1 check(s) failed'.split()
    # cluster (with its rolling update), host, updates, security, repository, subscription, last check
    pve1 = _cells(page, 'c1:node:pve1')
    assert pve1[0] == 'Testi (Vienna) rolling update running' and pve1[1] == 'pve1'
    assert pve1[2] == '12 kernel' and pve1[3] == '-' and pve1[4] == 'Enterprise' and pve1[5] == 'Active'
    kernel = page.locator('[data-updates-overview-row="c1:node:pve1"] [data-updates-overview-kernel]')
    assert kernel.get_attribute('title') == 'Includes a new kernel, which takes effect after a reboot'
    security = page.locator('[data-updates-overview-row="c1:node:pve1"] td').nth(3)
    assert 'not whether it is a security update' in security.get_attribute('title')
    # a failed check is said, and the enterprise repo without a subscription is why
    pve2 = _cells(page, 'c1:node:pve2')
    assert pve2[2] == 'check failed' and pve2[5] == 'None'
    note = page.locator('[data-updates-overview-row="c1:node:pve2"] [data-updates-overview-repo-note]')
    assert note.get_attribute('title').split('\n') == [
        'Enterprise repository without an active subscription: apt cannot download from it',
        '1 repository warning(s), see the repositories of the host']
    assert page.locator('[data-updates-overview-row="c1:node:pve1"] [data-updates-overview-repo-note]').count() == 0
    # where the list says which are security updates, the count shows; a cluster the page does not list keeps its name
    xen = _cells(page, 'x1:node:xcp1')
    assert xen[:4] == ['Xen', 'xcp1', '3', '2'] and xen[4] == '-'
    pbs = _cells(page, 'c1:pbs:p1')
    assert pbs[1] == 'backup-a PBS' and pbs[4] == 'No-subscription'
    stale = page.locator('[data-updates-overview-row="c1:pbs:p1"] td').nth(6)
    assert stale.get_attribute('title') == 'Checked more than a day ago'
    assert page.locator('[data-updates-overview-unchecked]').inner_text() == 'No update check yet: Branch'
    assert page.locator('[data-updates-overview-unlisted]').inner_text() == \
        'Not listed: Pooled (your access covers single guests only)'
    _shot(page, f'{layout}_updates_overview.png')
    assert [c for c in app.server.calls if c == UP] == [UP]
    assert not _only_reads(app) and not app.errors, (_only_reads(app), app.errors)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_sort_and_filter_the_updates(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _on(app, 'updates')
    sort = lambda col: page.locator(f'[data-updates-overview-sort="{col}"]').click()  # noqa: E731
    sort('host')
    assert _rows(page) == ['c1:pbs:p1', 'c1:node:pve1', 'c1:node:pve2', 'c1:node:pve3', 'x1:node:xcp1']
    sort('security')
    assert _rows(page)[0] == 'x1:node:xcp1'
    sort('checked')
    assert _rows(page)[-1] == 'c1:pbs:p1'
    page.locator('[data-updates-overview-search]').fill('xcp')
    assert _rows(page) == ['x1:node:xcp1']
    page.locator('[data-updates-overview-search]').fill('nothing-like-it')
    assert page.locator('[data-updates-overview-empty]').inner_text() == 'No host matches the filter.'
    page.locator('[data-updates-overview-search]').fill('')
    page.locator('[data-updates-overview-pending]').check()
    assert 'c1:node:pve3' not in _rows(page) and len(_rows(page)) == 4
    # the choice is the user's: a reload keeps it
    page.reload(wait_until='load')
    app.wait_for_app()
    _on(app, 'updates')
    assert page.locator('[data-updates-overview-pending]').is_checked() and len(_rows(page)) == 4
    assert not app.errors, app.errors


def test_runtime_every_host_up_to_date(open_app):
    calm = {'hosts': [_h('c1', 'Testi', 'node', 'pve1', 0)], 'clusters': [_c('c1', 'Testi')]}
    app = open_app(layout='modern', updates=(200, calm))
    page = app.page
    _on(app, 'updates')
    page.locator('[data-updates-overview-pending]').check()
    assert page.locator('[data-updates-overview-empty]').inner_text().strip() == 'Every checked host is up to date.'
    assert page.locator('[data-updates-overview-summary]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_row_opens_the_update_manager_of_its_cluster(open_app, layout):
    app = open_app(layout=layout, extra={('GET', '/api/clusters/c1/updates/status'): (200, {'success': True})})
    page = app.page
    _on(app, 'updates')
    page.locator('[data-updates-overview-row="c1:node:pve1"] td').first.click()
    manager = page.locator('[data-update-manager]')
    manager.wait_for(timeout=8000)
    assert 'Update Manager' in manager.inner_text()
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/updates/status'))
    page.wait_for_timeout(600)
    # scrolled to it
    assert manager.evaluate('e => { const r = e.getBoundingClientRect(); return r.top < window.innerHeight && r.bottom > 0; }')
    _shot(page, f'{layout}_updates_overview_opened.png')
    assert not app.errors, app.errors


def test_runtime_an_unchecked_cluster_opens_its_update_manager(open_app):
    app = open_app(layout='modern')
    page = app.page
    _on(app, 'updates')
    page.locator('[data-updates-overview-open="c2"]').click()
    page.locator('[data-update-manager]').wait_for(timeout=8000)
    assert _wait_for_call(app, ('GET', '/api/clusters/c2/updates/status'))
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_ceph_of_every_cluster(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    panel = _on(app, 'ceph')
    text = panel.inner_text()
    assert 'Ceph across all clusters' in text
    assert _rows(page, 'ceph') == ['c2', 'c1']
    assert page.locator('[data-ceph-overview-summary]').inner_text() == '1 not healthy'
    assert page.locator('[data-ceph-overview-row="c2"]').get_attribute('data-health') == 'HEALTH_WARN'
    branch = _cells(page, 'c2', 'ceph')
    assert branch[0] == 'Branch'
    # the two worst checks shown, the others counted
    assert branch[1] == 'WARN 1 osds down 40 pgs degraded 2 more'
    assert branch[2].startswith('90.0%') and '900.0 GB / 1000.0 GB' in branch[2]
    assert branch[3] == '2 of 3 up, 3 in'
    assert branch[4] == '88 of 128 active+clean 40 active+undersized+degraded'
    assert branch[5] == 'Read 0 B/s, 0 IOPS Write 0 B/s, 0 IOPS Recovery 5.0 MB/s'
    assert branch[6] == '2 of 3 in quorum'
    testi = _cells(page, 'c1', 'ceph')
    assert testi[0] == 'Testi (Vienna)' and testi[1] == 'OK' and testi[3] == '6 of 6 up, 6 in'
    assert testi[4] == '129 of 129 active+clean' and testi[5] == 'Read 1.0 MB/s, 50 IOPS Write 2.0 MB/s, 120 IOPS'
    # a cluster without Ceph is not news; one that lost it is
    assert page.locator('[data-ceph-overview-unlisted]').inner_text() == \
        'Not listed: Lost (no answer), Pooled (your access covers single guests only)'
    _shot(page, f'{layout}_ceph_overview.png')
    assert [c for c in app.server.calls if c == CE] == [CE]
    assert not _only_reads(app) and not app.errors, (_only_reads(app), app.errors)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_ceph_row_opens_the_ceph_page_of_its_cluster(open_app, layout):
    none = {'available': False, 'status': None, 'osd': [], 'mon': [], 'mds': [], 'mgr': [], 'pools': [], 'fs': [], 'rules': []}
    app = open_app(layout=layout, extra={('GET', '/api/clusters/c1/datacenter/ceph'): (200, none)})
    page = app.page
    _on(app, 'ceph')
    page.locator('[data-ceph-overview-row="c1"] td').first.click()
    # the datacenter tab opened on its Ceph section, which reads the cluster's Ceph
    assert _wait_for_call(app, ('GET', '/api/clusters/c1/datacenter/ceph'), seconds=8)
    page.wait_for_timeout(400)
    _shot(page, f'{layout}_ceph_overview_opened.png')
    assert not app.errors, app.errors


def test_runtime_no_ceph_anywhere_no_panel(open_app):
    plain = {'ceph': [], 'clusters': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'none', 'had_ceph': False},
                                      {'cluster_id': 'c2', 'cluster_name': 'Branch', 'state': 'unreadable', 'had_ceph': False}]}
    app = open_app(layout='modern', ceph=(200, plain))
    assert _wait_for_call(app, CE)
    _on(app, 'updates')
    app.page.wait_for_timeout(300)
    assert app.page.locator('[data-ceph-overview]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_ceph_that_went_silent_keeps_the_panel(open_app):
    lost = {'ceph': [], 'clusters': [{'cluster_id': 'c1', 'cluster_name': 'Testi', 'state': 'unreadable', 'had_ceph': True}]}
    app = open_app(layout='corporate', ceph=(200, lost))
    page = app.page
    page.locator('[data-ceph-overview-unlisted]').wait_for(timeout=10000)
    assert page.locator('[data-ceph-overview-unlisted]').inner_text() == 'Not listed: Testi (Vienna) (no answer)'
    assert page.locator('[data-ceph-overview-row]').count() == 0
    assert not app.errors, app.errors


def test_runtime_without_the_permissions_there_is_no_panel_and_no_read(open_app):
    app = open_app(layout='modern', admin=False, permissions=['vm.view', 'storage.view'])
    app.page.wait_for_timeout(1500)
    assert app.page.locator('[data-updates-overview]').count() == 0
    assert app.page.locator('[data-ceph-overview]').count() == 0
    assert UP not in app.server.calls and CE not in app.server.calls
    app = open_app(layout='modern', admin=False, permissions=['node.view'])
    _on(app, 'updates')
    assert CE not in app.server.calls and app.page.locator('[data-ceph-overview]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_refusal_hides_the_panels_and_a_failure_says_so(open_app):
    app = open_app(layout='modern', admin=False, permissions=['node.view', 'cluster.view'],
                   updates=(403, {'error': 'Permission denied'}), ceph=(403, {'error': 'Permission denied'}))
    assert _wait_for_call(app, UP) and _wait_for_call(app, CE)
    app.page.wait_for_timeout(500)
    assert app.page.locator('[data-updates-overview]').count() == 0
    assert app.page.locator('[data-ceph-overview]').count() == 0
    app = open_app(layout='corporate', updates=(500, {'error': 'boom'}), ceph=(500, {'error': 'boom'}))
    app.page.locator('[data-updates-overview-failed]').wait_for(timeout=10000)
    assert app.page.locator('[data-updates-overview-failed]').inner_text() == 'The update overview could not be read.'
    assert app.page.locator('[data-ceph-overview-failed]').inner_text() == 'The Ceph overview could not be read.'


def test_runtime_a_folded_panel_reads_nothing(open_app):
    app = open_app(layout='modern')
    page = app.page
    for kind, call in (('updates', UP), ('ceph', CE)):
        panel = _on(app, kind)
        panel.locator('button[title="Collapse"]').click()
        assert page.locator(f'[data-{kind}-overview-row]').count() == 0
    page.reload(wait_until='load')
    app.wait_for_app()
    page.locator('[data-updates-overview]').wait_for(timeout=10000)
    page.locator('[data-ceph-overview]').wait_for(timeout=10000)
    page.wait_for_timeout(800)
    assert app.server.calls.count(UP) == 1 and app.server.calls.count(CE) == 1
    page.locator('[data-updates-overview] button[title="Expand"]').click()
    page.locator('[data-updates-overview-row]').first.wait_for(timeout=3000)
    assert app.server.calls.count(UP) == 2
    page.locator('[data-updates-overview] button[title="Refresh"]').click()
    page.wait_for_timeout(500)
    assert app.server.calls.count(UP) >= 3
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_standby_shows_both_and_sends_nothing(open_app, layout):
    app = open_app(layout=layout, role='standby')
    page = app.page
    for kind in ('updates', 'ceph'):
        panel = _on(app, kind)
        # refresh reads, the chevron and the title fold; the cluster names in the footer navigate
        buttons = panel.locator('button').evaluate_all(
            f"bs => bs.map(b => b.hasAttribute('data-{kind}-overview-fold') ? 'fold' : b.title)")
        assert set(buttons) <= {'Refresh', 'Collapse', 'fold', 'Open the update manager of this cluster'}, buttons
        panel.locator('button[title="Refresh"]').click()
    page.wait_for_timeout(300)
    _shot(page, f'{layout}_updates_ceph_standby.png')
    assert not _only_reads(app), _only_reads(app)
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    text = _on(app, 'updates').inner_text()
    assert 'Ausstehende Updates aller Cluster' in text and '16 Update(s) auf 3 Host(s)' in text
    assert 'Prüfung fehlgeschlagen' in text and 'Noch keine Update-Prüfung: Branch' in text
    ceph = _on(app, 'ceph').inner_text()
    assert 'Ceph aller Cluster' in ceph and '2 von 3 up, 3 in' in ceph and '2 von 3 im Quorum' in ceph
    _shot(page, 'modern_updates_ceph_de.png')
    assert not app.errors, app.errors
