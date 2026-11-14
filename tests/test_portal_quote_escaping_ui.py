"""The client portal in Chromium with names that carry quotes.

Drives the real plugins/client_portal/portal.html in headless Chromium. A fake same-origin
PegaProx behind page.route answers the portal's API and records what it is sent. Each case
puts a quote into a value the portal shows (a guest name, an ISO file name, a snapshot
name, the logo URL, the search box) and checks both halves: nothing in the value runs,
and the value reads and travels exactly as written - in the card, in the confirm dialog,
in the request the button sends. The helpers on their own are tested under node in
test_portal_quote_escaping.py. Skips where Playwright is not installed.
LW Nov 2026
"""
import json
import os

import pytest

from test_ha_ui import ROOT, browser  # noqa: F401  (browser is a fixture)

ORIGIN = 'https://portal.test'
API = '/api/plugins/client_portal/api'
PORTAL = os.path.join(ROOT, 'plugins', 'client_portal', 'portal.html')
TAILWIND = os.path.join(ROOT, 'static', 'css', 'tailwind.min.css')

# a double quote ends the attribute and needs no click, the page ships a keyframe named spin
DQ = 'web01" style="animation:spin 1s" onanimationstart="window.__ran=true//'
# a single quote ends the JS string of an onclick, so this one needs the click
SQ = "web01');window.__ran=true;//"
# what a real name can look like
REAL = "Müller's \"Büro\" & <Co>"

BASE_CFG = {'allowed_actions': ['vm.view', 'vm.start', 'vm.stop', 'vm.restart', 'vm.console'],
            'allow_iso_mount': True, 'allow_snapshots': True, 'show_resource_usage': False,
            'show_ip_addresses': False, 'portal_title': 'Portal', 'custom_logo_url': ''}


def _vm(name, status='stopped'):
    return {'vmid': 100, 'name': name, 'type': 'qemu', 'status': status, 'node': 'n1',
            'cluster_id': 'c1', 'cluster_name': 'c1', 'uptime': 0}


class _Portal:
    def __init__(self, browser, vms, isos=(), snapshots=(), cfg=None, destroy=False):
        self.posts = []
        self.answers = {
            '/api/auth/oidc/config': {'enabled': False},
            '/api/auth/check': {'authenticated': True, 'session_id': 'sid-1',
                                'user': {'username': 'cust', 'role': 'user', 'portal_only': True,
                                         'totp_enabled': True}},
            API + '/config': dict(BASE_CFG, **(cfg or {})),
            API + '/ct/create-options': {'enabled': False},
            API + '/vm/destroy-options': {'enabled': destroy},
            API + '/my-vms': {'vms': vms, 'user': 'cust'},
            API + '/vm/isos': {'isos': list(isos)},
            API + '/vm/snapshots': {'snapshots': list(snapshots), 'max': 5},
        }
        with open(PORTAL, encoding='utf-8') as fh:
            self.html = fh.read()
        self.ctx = browser.new_context(viewport={'width': 1400, 'height': 900})
        self.page = self.ctx.new_page()
        self.page.route('**/*', self._handle)
        self.page.goto(ORIGIN + '/portal')
        self.page.wait_for_selector('.vm-actions button', timeout=10000)

    def _handle(self, route):
        req = route.request
        if not req.url.startswith(ORIGIN + '/'):
            return route.fulfill(status=404, body='')
        path = req.url[len(ORIGIN):].split('?')[0]
        if path == '/portal':
            return route.fulfill(status=200, body=self.html, headers={'Content-Type': 'text/html'})
        if path == '/static/css/tailwind.min.css':
            return route.fulfill(status=200, path=TAILWIND, headers={'Content-Type': 'text/css'})
        if req.method == 'POST' and path.startswith(API + '/'):
            self.posts.append((path[len(API):], req.post_data_json))
            return route.fulfill(status=200, body=json.dumps({'success': True}),
                                 headers={'Content-Type': 'application/json'})
        if path in self.answers:
            return route.fulfill(status=200, body=json.dumps(self.answers[path]),
                                 headers={'Content-Type': 'application/json'})
        return route.fulfill(status=404, body='{}', headers={'Content-Type': 'application/json'})

    def ran(self):
        self.page.wait_for_timeout(600)
        return self.page.evaluate('window.__ran === true')

    def sent(self, path, timeout=5000):
        waited = 0
        while waited < timeout:
            hits = [body for p, body in self.posts if p == path]
            if hits:
                return hits[-1]
            self.page.wait_for_timeout(100)
            waited += 100
        raise AssertionError(f'{path} was never sent, saw {self.posts}')

    def confirm_text(self):
        return self.page.locator('.confirm-msg').inner_text(timeout=5000)


@pytest.fixture
def portal(browser):
    opened = []

    def open_(**kw):
        p = _Portal(browser, **kw)
        opened.append(p)
        return p
    yield open_
    for p in opened:
        p.ctx.close()


def test_runtime_a_guest_name_with_a_double_quote_runs_nothing_and_reads_as_written(portal):
    p = portal(vms=[_vm(DQ)])

    assert not p.ran()
    assert p.page.locator('.vm-meta .font-medium').inner_text() == DQ
    start = p.page.locator('.vm-actions button', has_text='Start')
    assert start.evaluate('b => b.getAttributeNames()') == ['class', 'onclick']


def test_runtime_start_with_a_single_quote_in_the_name_starts_that_guest(portal):
    p = portal(vms=[_vm(SQ)])

    p.page.locator('.vm-actions button', has_text='Start').click()

    assert p.confirm_text() == f'Start "{SQ}"?'
    assert not p.ran()
    p.page.click('#confirm-ok')
    assert p.sent('/vm/power') == {'cluster_id': 'c1', 'vmid': 100, 'action': 'start'}
    assert not p.ran()


@pytest.mark.parametrize('volid', ['local:iso/' + DQ + '.iso', 'local:iso/' + SQ + '.iso',
                                   'local:iso/' + REAL + '.iso'])
def test_runtime_the_iso_dialog_mounts_exactly_the_file_it_lists(portal, volid):
    p = portal(vms=[_vm('web01')],
               isos=[{'volid': volid, 'name': volid.split('/', 1)[1], 'size': 0, 'cluster_id': 'c1'}])

    p.page.locator('.vm-actions button', has_text='ISO').click()
    p.page.wait_for_selector('text=Mount ISO', timeout=5000)

    assert not p.ran()
    assert p.page.locator('.modal-card .text-sm.font-medium').inner_text() == volid.split('/', 1)[1]
    p.page.get_by_role('button', name='Mount', exact=True).click()
    assert p.sent('/vm/iso-mount') == {'cluster_id': 'c1', 'vmid': 100, 'iso': volid}
    assert not p.ran()


@pytest.mark.parametrize('button,path', [('Rollback to this snapshot', '/vm/snapshot-rollback'),
                                         ('Delete snapshot', '/vm/snapshot-delete')])
@pytest.mark.parametrize('snapname', [SQ, REAL])
def test_runtime_a_snapshot_button_acts_on_exactly_that_snapshot(portal, button, path, snapname):
    p = portal(vms=[_vm('web01')], snapshots=[{'name': snapname, 'description': '', 'snaptime': 0}])

    p.page.locator('.vm-actions button', has_text='Snapshots').click()
    p.page.locator(f'button[title="{button}"]').click()

    assert f'"{snapname}"' in p.confirm_text()
    assert not p.ran()
    p.page.click('#confirm-ok')
    assert p.sent(path) == {'cluster_id': 'c1', 'vmid': 100, 'snapname': snapname}
    assert not p.ran()


def test_runtime_a_name_with_quotes_can_be_typed_into_the_destroy_confirmation(portal):
    p = portal(vms=[_vm(REAL)], destroy=True)

    p.page.locator('.vm-actions button', has_text='Destroy').click()
    field = p.page.locator('#dcn')
    assert field.evaluate('el => el.dataset.name') == REAL
    assert field.get_attribute('placeholder') == REAL
    field.fill(REAL)

    assert p.page.locator('#dbtn').is_enabled()
    p.page.click('#dbtn')
    assert p.sent('/vm/destroy') == {'cluster_id': 'c1', 'vmid': 100, 'confirm_name': REAL}
    assert not p.ran()


def test_runtime_a_logo_url_with_a_quote_stays_one_src(portal):
    url = 'https://logo.test/a.png" onerror="window.__ran=true'
    p = portal(vms=[_vm('web01')], cfg={'custom_logo_url': url})

    logo = p.page.locator('img[alt=""]').first
    assert not p.ran()
    assert logo.get_attribute('src') == url
    assert logo.evaluate('i => i.getAttributeNames()') == ['src', 'alt', 'style']


def test_runtime_the_search_box_keeps_a_typed_quote(portal):
    p = portal(vms=[_vm('web01'), dict(_vm('a"b'), vmid=101)])

    p.page.locator('#vm-search').press_sequentially('a"b', delay=50)

    assert p.page.locator('#vm-search').input_value() == 'a"b'
    assert p.page.locator('.vm-meta .font-medium').all_inner_texts() == ['a"b']
