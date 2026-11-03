"""Automation > Affinity rules in Corporate Redesigned (round 9, B4).

The variant draws the rules the dashboard reads when the sub tab opens (GET .../affinity-rules) as a
table: type, enforced, the guests by name (an id the cluster does not list is marked), state and
creation time. New Rule opens the classic dialog (POST .../affinity-rules), Delete is the classic
DELETE .../affinity-rules/<id>; since round 10 it asks first in the variant (the rule, its type and
its guests, Delete in danger style) and the DELETE goes only after that, classic Corporate deletes at
once as before. A refused delete is said. A failed read is an error, not "no rules". Classic Corporate, Modern and Cloud keep their markup
(tests/test_corp_redesigned_guard_ui.py, view "auto_affinity"). PEGAPROX_CR_BUNDLE=<file> serves
another bundle (the counterproof). LW Nov 2026
"""
import copy
import json
import re
import time

import pytest

from test_corp_redesigned_guard_ui import AUTO_AFFINITY, _GuardApp, _GuardServer, _corp_cluster
from test_corp_redesigned_res_snapshots_ui import BUNDLE, browser  # noqa: F401  (the module's Chromium and Firefox)


class _AffServer(_GuardServer):
    def __init__(self, read=None, delete_status=200, **kw):
        super().__init__(bundle=BUNDLE, **kw)
        self.rules = copy.deepcopy(AUTO_AFFINITY['rules'])
        self.read = read
        self.delete_status = delete_status
        self.reqs = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        m = re.fullmatch(r'/api/clusters/c1/affinity-rules(?:/([^/]+))?', path)
        if m:
            body = json.loads(req.post_data) if req.post_data else {}
            self.reqs.append((req.method, path, body))
            self.calls.append((req.method, path))
            if req.method == 'GET':
                status, data = self.read or (200, {'rules': self.rules})
            elif req.method == 'DELETE':
                status, data = (self.delete_status, {'success': True} if self.delete_status == 200 else {'error': 'Rule not found'})
                if status == 200:
                    self.rules = [r for r in self.rules if r['id'] != m.group(1)]
            else:
                rule = {'id': 'f00dbabe', 'name': body.get('name'), 'type': body.get('type'), 'vms': body.get('vm_ids'),
                        'vm_ids': body.get('vm_ids'), 'enforce': body.get('enforce'), 'enabled': True,
                        'created_at': '2026-10-30T09:00:00.000001'}
                self.rules.append(rule)
                status, data = 200, {'success': True, 'rule': rule}
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(engine='chromium', viewport=(1600, 1000), layout='corporate-redesigned', **kw):
        br = browser[engine]
        if br is None:
            pytest.skip(f'no {engine} for Playwright')
        app = _GuardApp(br, _AffServer(layout=layout, **kw), viewport=viewport)
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


def _open_tab(app, wait='ok'):
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="automation"]').first.click()
    page.locator('.corp-tab-strip button', has_text='Affinity').first.click()
    _need(page, f'[data-cr-aff="{wait}"]', f'the affinity rules of the variant are {wait}')
    return page


def test_runtime_the_rules_are_a_table_with_their_guests(open_app):
    app = open_app()
    page = _open_tab(app)
    assert [r[:2] for r in app.server.reqs] == [('GET', '/api/clusters/c1/affinity-rules')]
    rows = page.locator('[data-cr-aff-rule]').evaluate_all('els => els.map(e => e.innerText)')
    assert rows == ['db pair', 'web with cache']
    assert page.locator('[data-cr-aff-type="separate"]').count() == 1 and page.locator('[data-cr-aff-type="together"]').count() == 1
    assert page.locator('[data-cr-aff-enforced]').count() == 1
    # the guests by name, an id the cluster does not list marked as such
    row = page.locator('[data-cr-table="auto-affinity"] tbody tr', has_text='db pair').first
    assert 'web01' in row.inner_text() and 'ct01' in row.inner_text()
    _need(page, '[data-cr-aff-gone="999"]', 'a guest id the cluster does not list is marked')
    assert '2026-10-12 14:03:11' in row.inner_text()
    page.locator('[data-cr-md-guest="100"]').first.click()
    page.wait_for_function('() => !document.querySelector("[data-cr-aff]")', timeout=5000)
    assert app.errors == []


def test_runtime_new_rule_opens_the_classic_dialog_and_sends_its_body(open_app):
    app = open_app()
    page = _open_tab(app)
    page.locator('[data-cr-aff-new]').click()
    page.locator('input[name="rule_name"]').fill('pair')
    page.locator('input[name="vm_ids"]').fill('100, 101')
    page.locator('button[type="submit"]', has_text=re.compile('Create|Save|Add', re.I)).last.click()
    _poll(lambda: any(r[0] == 'POST' for r in app.server.reqs), page)
    post = [r for r in app.server.reqs if r[0] == 'POST'][0]
    assert post[1] == '/api/clusters/c1/affinity-rules' and post[2]['name'] == 'pair' and post[2]['vm_ids'] == [100, 101], post
    _need(page, '[data-cr-aff-rule="f00dbabe"]', 'the new rule is read back into the table')
    assert app.errors == []


def _confirm(page, rid):
    page.locator(f'[data-cr-aff-del="{rid}"]').click()
    _need(page, '[data-cr-upd-dialog="nc-aff-del"]', 'Delete asks first')
    page.locator('[data-cr-nc-confirm-go="aff-del"]').click()


def test_runtime_delete_sends_the_classic_request_and_a_refusal_is_said(open_app):
    app = open_app()
    page = _open_tab(app)
    assert 'cr-btn-danger' in page.locator('[data-cr-aff-del="a1b2c3d4"]').get_attribute('class')
    _confirm(page, 'a1b2c3d4')
    _poll(lambda: any(r[0] == 'DELETE' for r in app.server.reqs), page)
    assert [r[:2] for r in app.server.reqs if r[0] == 'DELETE'] == [('DELETE', '/api/clusters/c1/affinity-rules/a1b2c3d4')]
    page.wait_for_function('() => !document.querySelector("[data-cr-aff-rule=a1b2c3d4]")', timeout=5000)
    app.server.delete_status = 404
    _confirm(page, 'e5f6a7b8')
    _need(page, '[data-cr-aff-del-error]', 'a refused delete is said')
    assert 'web with cache' in page.locator('[data-cr-aff-del-error]').inner_text()
    assert page.locator('[data-cr-aff-rule="e5f6a7b8"]').count() == 1
    assert app.errors == []


def test_runtime_the_variant_deletes_what_classic_deletes(open_app):
    classic = open_app(layout='corporate')
    page = classic.page
    _corp_cluster(page)
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.locator('button', has_text='Affinity').first.click()
    page.get_by_text('web with cache').first.wait_for(timeout=8000)
    page.locator('div.flex.items-center.justify-between', has_text='db pair').locator('button').last.click()
    _poll(lambda: any(r[0] == 'DELETE' for r in classic.server.reqs), page)
    want = [r for r in classic.server.reqs if r[0] == 'DELETE']
    app = open_app()
    page = _open_tab(app)
    _confirm(page, 'a1b2c3d4')
    _poll(lambda: any(r[0] == 'DELETE' for r in app.server.reqs), page)
    assert [r for r in app.server.reqs if r[0] == 'DELETE'] == want
    assert app.errors == [] and classic.errors == []


@pytest.mark.parametrize('rid,name,kind,guests', [('a1b2c3d4', 'db pair', 'Separate (different hosts), Enforced', ['web01', 'ct01']),
                                                   ('e5f6a7b8', 'web with cache', 'Together (same host)', ['web01', '999'])])
def test_runtime_delete_asks_first_with_the_rule_its_type_and_guests(open_app, rid, name, kind, guests):
    app = open_app()
    page = _open_tab(app)
    page.locator(f'[data-cr-aff-del="{rid}"]').click()
    _need(page, '[data-cr-upd-dialog="nc-aff-del"]', 'Delete opens a confirmation')
    dlg = page.locator('[data-cr-upd-dialog="nc-aff-del"]')
    assert name in dlg.locator('h2').inner_text()
    assert dlg.locator('[data-cr-nc-k="type"] dd').inner_text().strip() == kind
    said = dlg.locator('[data-cr-nc-k="guests"] dd').inner_text()
    for g in guests:
        assert g in said, (g, said)
    assert 'Nothing moves now' in dlg.inner_text()
    go = dlg.locator('[data-cr-nc-confirm-go="aff-del"]')
    assert 'cr-btn-danger' in go.get_attribute('class') and go.inner_text().strip() == 'Delete'
    # nothing is sent while it asks, Cancel and Escape send nothing
    page.wait_for_timeout(300)
    assert not [r for r in app.server.reqs if r[0] == 'DELETE']
    dlg.locator('[data-cr-nc-confirm-cancel="aff-del"]').click()
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=5000)
    page.locator(f'[data-cr-aff-del="{rid}"]').click()
    _need(page, '[data-cr-upd-dialog="nc-aff-del"]', 'Delete asks again')
    page.keyboard.press('Escape')
    page.wait_for_function('() => !document.querySelector("[data-cr-upd-dialog]")', timeout=5000)
    assert not [r for r in app.server.reqs if r[0] == 'DELETE'] and page.locator(f'[data-cr-aff-rule="{rid}"]').count() == 1
    _confirm(page, rid)
    _poll(lambda: any(r[0] == 'DELETE' for r in app.server.reqs), page)
    page.wait_for_timeout(300)
    assert [r[:2] for r in app.server.reqs if r[0] == 'DELETE'] == [('DELETE', f'/api/clusters/c1/affinity-rules/{rid}')]
    page.wait_for_function(f'() => !document.querySelector("[data-cr-aff-rule={rid}]")', timeout=5000)
    assert page.locator('[data-cr-upd-dialog]').count() == 0
    assert 'asks first' in page.locator('[data-cr-aff-foot]').inner_text()
    assert app.errors == []


def test_runtime_a_standby_only_lists(open_app):
    app = open_app(role='standby')
    page = _open_tab(app)
    assert page.locator('[data-cr-aff-new], [data-cr-aff-del]').count() == 0
    assert 'standby' in page.locator('[data-cr-aff-foot]').inner_text()
    assert app.errors == []


def test_runtime_a_failed_read_is_an_error_and_an_empty_list_says_so(open_app):
    app = open_app(read=(500, {'error': 'rules store unreadable'}))
    page = _open_tab(app, wait='error')
    assert 'rules store unreadable' in page.locator('[data-cr-aff-error]').inner_text()
    assert page.locator('[data-cr-table="auto-affinity"]').count() == 0
    app.server.read = (200, {'rules': []})
    page.locator('[data-cr-aff-retry]').click()
    _need(page, '[data-cr-aff="empty"]', 'Read again reads the list')
    assert 'No affinity rules' in page.locator('[data-cr-aff]').inner_text()
    assert app.errors == []


def test_runtime_classic_corporate_keeps_its_list(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _corp_cluster(page)
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.locator('button', has_text='Affinity').first.click()
    page.get_by_text('web with cache').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-aff]').count() == 0
    assert app.errors == []


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('size', [(1600, 1000), (1280, 900), (1024, 800)])
def test_runtime_it_fits_without_sideways_scroll(open_app, engine, size):
    app = open_app(engine=engine, viewport=size)
    page = _open_tab(app)
    over = page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')
    assert over <= 0, (engine, size, over)
    b = page.locator('[data-cr-aff-new]').bounding_box()
    assert b['x'] + b['width'] <= size[0], (engine, size, b)
    page.locator('[data-cr-aff-del="a1b2c3d4"]').click()
    _need(page, '[data-cr-upd-dialog="nc-aff-del"]', 'Delete asks first')
    assert page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth') <= 0, (engine, size, 'confirm')
    assert app.errors == []
