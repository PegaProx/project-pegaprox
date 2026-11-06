"""Resources > Snapshot overview in Corporate Redesigned (round 9, B4).

The variant draws the list the dashboard already holds (POST /snapshots/overview when the sub tab
opens, the date filter, the selection of #696 and the two deletes with their confirm) as tiles and a
table. Every request is the classic one: a test drives classic Corporate and compares the bodies.
Ages count from snapshot_ts (the server's "age" string sorts "5 h" after "3 days"); a failed read is
an error with its reason, not "no snapshots"; the server's 200 cut is said. Classic Corporate, Modern
and Cloud keep their markup (tests/test_corp_redesigned_guard_ui.py, view "res_snapshots").
PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof). LW Nov 2026
"""
import copy
import json
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import DETERMINISTIC, RES_SNAPS, _GuardApp, _GuardServer, _corp_cluster

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None


class _SnapServer(_GuardServer):
    """The guard fake with the two snapshot routes in memory and every body kept."""

    def __init__(self, snaps=None, read=None, **kw):
        super().__init__(bundle=BUNDLE, **kw)
        self.snaps = copy.deepcopy(RES_SNAPS['snapshots'] if snaps is None else snaps)
        self.read = read                    # (status, body) instead of the list
        self.delete_answer = None
        self.reqs = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if path in ('/api/snapshots/overview', '/api/snapshots/delete') and req.method == 'POST':
            body = json.loads(req.post_data) if req.post_data else {}
            self.reqs.append((path, body))
            self.calls.append(('POST', path))
            if path.endswith('/overview'):
                status, data = self.read or (200, {'snapshots': [s for s in self.snaps
                                                                 if not body.get('date') or s['snapshot_date'][:10] < body['date']]})
            else:
                gone = {(s['vmid'], s['snapshot_name']) for s in body.get('snapshots', [])}
                self.snaps = [s for s in self.snaps if (s['vmid'], s['snapshot_name']) not in gone]
                status, data = self.delete_answer or (200, {'success': True, 'deleted': len(gone), 'errors': []})
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
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
def open_app(browser):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), layout='corporate-redesigned', **kw):
        br = browser[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = _GuardApp(br, _SnapServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _need(page, selector, what, timeout=8000):
    try:
        page.locator(selector).first.wait_for(timeout=timeout)
    except Exception:
        raise AssertionError(f'{what} (no {selector})') from None


def _poll(cond, page, seconds=6):
    deadline = time.time() + seconds
    while time.time() < deadline and not cond():
        page.wait_for_timeout(100)
    return cond()


def _read_again(reqs):
    # the list is read again after a delete: until then a copy of what was sent is one short
    return len(reqs) >= 2 and reqs[-2][0].endswith('/delete') and reqs[-1][0].endswith('/overview')


def _open_tab(app, wait='ok'):
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="resources"]').first.click()
    page.locator('.corp-tab-strip button', has_text='Snapshot').first.click()
    _need(page, f'[data-cr-snap="{wait}"]', f'the snapshot overview of the variant is {wait}')
    return page


def _rows(page):
    return page.locator('[data-cr-table="res-snapshots"] tbody tr [data-cr-snap-name]').evaluate_all('els => els.map(e => e.innerText)')


RULES = r'''() => {
    const M = window.PegaProxModules;
    const now = Date.UTC(2026, 9, 30, 9, 0, 0);
    const s = (vmid, type, node, name, ts) => ({ vmid, vm_type: type, node, snapshot_name: name, snapshot_ts: ts });
    const m = M.snapModel([s(100, 'qemu', 'pve1', 'a', 1793336400), s(100, 'qemu', 'pve1', 'b', 1785651000), s(100, 'lxc', 'pve2', 'c', null)], now);
    const cut = M.snapModel(Array.from({ length: 200 }, (_, i) => s(i, 'qemu', 'pve1', 'x', 1793336400)), now);
    return { guests: m.guests, nodes: m.nodes, oldest: m.oldest.snapshot_name, age: m.oldestAge, undated: m.undated, cut: m.cut,
             cut200: cut.cut, empty: M.snapModel(null, now).list.length };
}'''


def test_the_rules_of_the_overview(open_app):
    app = open_app()
    page = app.page
    page.wait_for_function('() => !!(window.PegaProxModules && window.PegaProxModules.snapModel)', timeout=8000)
    r = page.evaluate(RULES)
    # a VM and a CT with the same id are two guests; the oldest by its time stamp; an undated one counted apart
    assert r == {'guests': 2, 'nodes': 2, 'oldest': 'b', 'age': 7699800, 'undated': 1, 'cut': False, 'cut200': True, 'empty': 0}, r


def test_runtime_the_list_is_read_once_and_drawn_oldest_first(open_app):
    app = open_app()
    page = _open_tab(app)
    assert app.server.reqs == [('/api/snapshots/overview', {'cluster_id': 'c1'})]
    assert _rows(page) == ['pre-upgrade', 'before_php84', 'nightly']
    # the age from the time stamp, not the server's string ('1 days', '3 h')
    ages = page.locator('[data-cr-snap-age]').evaluate_all('els => els.map(e => e.innerText.trim())')
    assert ages == ['89 days', '35 h', '4 h'], ages
    stat = lambda sid: page.locator(f'[data-cr-stat="{sid}"] .cr-stat-value').inner_text().strip()
    assert (stat('snap-count'), stat('snap-guests'), stat('snap-oldest')) == ('3', '3', '89 days')
    assert 'db01' in page.locator('[data-cr-stat="snap-oldest"]').inner_text()
    # sorting by age puts hours before days
    page.locator('[data-cr-table="res-snapshots"] th', has_text='Age').first.click()
    assert _rows(page)[0] == 'nightly'
    # the guest and its node are a click away
    _need(page, '[data-cr-md-node="pve2"]', 'the node is a link')
    assert app.errors == []


def test_runtime_the_filter_and_refresh_send_the_classic_bodies(open_app):
    app = open_app()
    page = _open_tab(app)
    page.locator('[data-cr-snap-date]').fill('2026-10-29')
    page.locator('[data-cr-snap-filter]').click()
    _poll(lambda: len(app.server.reqs) == 2, page)
    assert app.server.reqs[1] == ('/api/snapshots/overview', {'cluster_id': 'c1', 'date': '2026-10-29'})
    page.wait_for_function('() => document.querySelectorAll("[data-cr-snap-name]").length === 2', timeout=5000)
    assert 'created before 2026-10-29' in page.locator('[data-cr-stat="snap-count"]').inner_text()
    # Refresh reads everything again, without a date, and says so in the field
    page.locator('[data-cr-snap-refresh]').click()
    _poll(lambda: len(app.server.reqs) == 3, page)
    assert app.server.reqs[2] == ('/api/snapshots/overview', {'cluster_id': 'c1'})
    page.wait_for_function('() => document.querySelectorAll("[data-cr-snap-name]").length === 3', timeout=5000)
    assert page.locator('[data-cr-snap-date]').input_value() == ''
    assert 'every guest' in page.locator('[data-cr-stat="snap-count"]').inner_text()
    assert app.errors == []


def test_runtime_one_delete_asks_and_sends_the_classic_body(open_app):
    app = open_app()
    page = _open_tab(app)
    msgs = []
    page.once('dialog', lambda d: (msgs.append(d.message), d.dismiss()))
    page.locator('[data-cr-snap-del]').first.click()
    page.wait_for_timeout(300)
    assert msgs == ['Delete snapshot "pre-upgrade" from VM 101?']
    assert [r for r in app.server.reqs if r[0].endswith('/delete')] == []
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-cr-snap-del]').first.click()
    _poll(lambda: any(r[0].endswith('/delete') for r in app.server.reqs), page)
    sent = [r[1] for r in app.server.reqs if r[0].endswith('/delete')]
    assert sent == [{'snapshots': [RES_SNAPS['snapshots'][0]]}], sent
    page.wait_for_function('() => document.querySelectorAll("[data-cr-snap-name]").length === 2', timeout=5000)
    assert app.errors == []


def test_runtime_several_are_selected_and_deleted_at_once(open_app):
    app = open_app()
    page = _open_tab(app)
    assert page.locator('[data-cr-snap-bar]').count() == 0
    page.locator('[data-cr-snap-sel]').nth(0).check()
    page.locator('[data-cr-table="res-snapshots"] tbody tr').nth(2).click()      # a row click selects too
    _need(page, '[data-cr-snap-bar]', 'a selection shows its bar')
    assert '2 selected' in page.locator('[data-cr-snap-bar]').inner_text()
    page.locator('[data-cr-snap-sel-clear]').click()
    assert page.locator('[data-cr-snap-bar]').count() == 0
    page.locator('[data-cr-snap-sel-all]').click()
    assert '3 selected' in page.locator('[data-cr-snap-bar]').inner_text()
    assert 'cr-btn-danger' in page.locator('[data-cr-snap-del-sel]').get_attribute('class')
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-cr-snap-del-sel]').click()
    _poll(lambda: any(r[0].endswith('/delete') for r in app.server.reqs), page)
    sent = [r[1] for r in app.server.reqs if r[0].endswith('/delete')][0]
    assert sorted(s['snapshot_name'] for s in sent['snapshots']) == ['before_php84', 'nightly', 'pre-upgrade']
    assert all(s['cluster_id'] == 'c1' for s in sent['snapshots'])
    _need(page, '[data-cr-snap="empty"]', 'everything deleted: the empty state')
    assert 'No guest of this cluster has a snapshot' in page.locator('[data-cr-snap]').inner_text()
    assert app.errors == []


def test_runtime_the_variant_sends_what_classic_sends(open_app):
    classic = open_app(layout='corporate')
    page = classic.page
    _corp_cluster(page)
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.locator('button', has_text='Snapshot').first.click()
    page.get_by_text('before_php84').first.wait_for(timeout=8000)
    page.once('dialog', lambda d: d.accept())
    page.locator('tr', has_text='pre-upgrade').locator('button').last.click()
    _poll(lambda: _read_again(classic.server.reqs), page)
    want = [r for r in classic.server.reqs]
    app = open_app()
    page = _open_tab(app)
    page.once('dialog', lambda d: d.accept())
    page.locator('[data-cr-snap-del]').first.click()
    _poll(lambda: _read_again(app.server.reqs), page)
    assert app.server.reqs == want, (app.server.reqs, want)
    assert app.errors == [] and classic.errors == []


def test_runtime_without_vm_snapshot_the_list_only_reads(open_app):
    app = open_app(admin=False, permissions=['vm.view', 'node.view', 'cluster.view'])
    page = _open_tab(app)
    assert page.locator('[data-cr-snap-sel], [data-cr-snap-del], [data-cr-snap-sel-all]').count() == 0
    assert 'vm.snapshot' in page.locator('[data-cr-snap-foot]').inner_text()
    page.locator('[data-cr-table="res-snapshots"] tbody tr').first.click()
    assert page.locator('[data-cr-snap-bar]').count() == 0
    assert app.errors == []


def test_runtime_a_failed_read_is_an_error_not_an_empty_list(open_app):
    app = open_app(read=(500, {'error': 'Failed to list snapshots'}))
    page = _open_tab(app, wait='error')
    assert 'Failed to list snapshots' in page.locator('[data-cr-snap-error]').inner_text()
    assert 'HTTP 500' in page.locator('[data-cr-snap-error]').inner_text()
    assert page.locator('[data-cr-table="res-snapshots"]').count() == 0
    assert page.locator('[data-cr-stat="snap-count"]').count() == 0
    app.server.read = None
    page.locator('[data-cr-snap-retry]').click()
    _need(page, '[data-cr-snap="ok"]', 'Read again reads the list')
    assert app.errors == []


def test_runtime_the_server_cut_is_said(open_app):
    many = [dict(RES_SNAPS['snapshots'][2], vmid=1000 + i, snapshot_name=f'auto-{i}') for i in range(200)]
    app = open_app(snaps=many)
    page = _open_tab(app)
    sub = page.locator('[data-cr-stat="snap-count"]')
    assert 'the oldest 200' in sub.inner_text()
    assert 'cr-stat-warning' in sub.get_attribute('class')
    assert app.errors == []


def test_runtime_classic_corporate_keeps_its_overview(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _corp_cluster(page)
    page.locator('button', has_text=re.compile(r'^\s*Resources\s*$')).first.click()
    page.locator('button', has_text='Snapshot').first.click()
    page.get_by_text('before_php84').first.wait_for(timeout=8000)
    assert page.locator('.corp-snap-overview').count() == 1
    assert page.locator('[data-cr-snap]').count() == 0
    assert app.errors == []


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('size', [(1600, 1000), (1280, 900), (1024, 800)])
def test_runtime_it_fits_without_sideways_scroll(open_app, engine, size):
    app = open_app(engine=engine, viewport=size)
    page = _open_tab(app)
    page.locator('[data-cr-snap-sel]').first.check()
    _need(page, '[data-cr-snap-bar]', 'the selection bar shows')
    over = page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')
    assert over <= 0, (engine, size, over)
    # the header actions stay inside the page
    for sel in ('[data-cr-snap-refresh]', '[data-cr-snap-date]'):
        b = page.locator(sel).bounding_box()
        assert b['x'] + b['width'] <= size[0], (sel, engine, size, b)
    assert app.errors == []


def test_every_new_key_is_in_english_and_german_before_the_pinned_block():
    src = open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8').read()
    code = open(os.path.join(ROOT, 'web', 'src', 'cr_modules.js'), encoding='utf-8').read()
    keys = sorted(set(re.findall(r"'(crSnap[A-Za-z]+)'", code)))
    assert len(keys) >= 20
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[a:b] for (a, lang), b in zip(starts, ends)}
    for lang in ('en', 'de'):
        marker = blocks[lang].index('// LW Oct 2026 (#625) - the banners of a group that fails over automatically')
        for k in keys:
            found = re.findall(rf'^                {k}: "((?:[^"\\]|\\.)*)",$', blocks[lang], re.M)
            assert len(found) == 1, (lang, k)
            assert '\u2014' not in found[0] and '\u2013' not in found[0], (lang, k)
            assert 'preview' not in found[0].lower(), (lang, k)
            assert blocks[lang].index(f'                {k}: ') < marker, (lang, k)
