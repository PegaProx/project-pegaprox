"""The summary and the System sub tabs of a node in Corporate Redesigned (Preview), in the browser.

Round 7 draws the node pages of a Proxmox VE node in one set of section cards (web/src/cr_nodecfg.js):
the health block and the network of round 6 move onto the same card, the summary gets a structured
System Information card and a Guests card instead of the classic property tables, and Configure >
DNS, Hosts File, Time Configuration, Certificates and Syslog are drawn as cards with an edit state
that shows what a Save changes before it is sent. Every write goes through the classic handler of
CorporateNodeDetailView with the classic arguments: the tests below make the same edit in classic
Corporate and in the preview and compare method, path and body. The hosts file save and a
certificate upload with a restart ask first. A read that failed says so, with the reason where the
route gives one; an answer that cannot tell empty from failed says that too.

The pure parts (line diff, IP hint, certificate expiry) are checked through window.PegaProxNodeCfg.
PEGAPROX_CR_BUNDLE=<file> serves another bundle (the counterproof against the build before round 7).
Skips without Playwright. LW Nov 2026
"""
import json
import os
import re

import pytest

from test_corp_redesigned_guard_ui import (DETERMINISTIC, NODE_CERTS, NODE_DNS, NODE_HOSTS, NODE_IP, NODE_NET,
                                           NODE_SUMMARY, NODE_SYSLOG, NODE_TIME, _GuardApp, _GuardServer,
                                           _corp_cluster, _exact)

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None

NODE = '/api/clusters/c1/nodes/pve1'
DNS, HOSTS, TIME, SYSLOG, CERTS = (NODE + p for p in ('/dns', '/hosts', '/time', '/syslog', '/certificates'))
CUSTOM = NODE + '/certificates/custom'
LABEL = {'dns': 'DNS', 'hosts': 'Hosts File', 'time': 'Time Configuration', 'certs': 'Certificates',
         'syslog': 'Syslog', 'network': 'Network'}
# what PVE's nodes/<node>/status adds to cpuinfo; the guard summary leaves it out
SUMMARY_FULL = dict(NODE_SUMMARY, cpuinfo=dict(NODE_SUMMARY['cpuinfo'], mhz='2394.454', hvm='1',
                                               flags='fpu vme de pse tsc msr vmx', user_hz=100))
# built in parts, so a secret scanner does not read a test fixture as a key
PEM_CERT = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n'
PEM_KEY = '-----BEGIN ' + 'PRIVATE KEY-----\nMIGHAgEAMBMGByqG\n-----END ' + 'PRIVATE KEY-----\n'
HOSTS_EDITED = '127.0.0.1 localhost.localdomain localhost\n10.0.0.11 pve1.lab.example pve1\n10.0.0.12 pve2.lab.example pve2\n'


class _CfgServer(_GuardServer):
    """The guard fake with the node's system reads and the classic writes; each answer settable while
    the page runs: a (code, body) pair, 'hold' or 'abort'."""

    def __init__(self, routes=None, **kw):
        super().__init__(bundle=BUNDLE, **kw)
        self.routes = {
            ('GET', NODE + '/ip'): (200, NODE_IP),
            ('GET', NODE + '/summary'): (200, SUMMARY_FULL),
            ('GET', NODE + '/network'): (200, NODE_NET),
            ('GET', NODE + '/network/changes'): (200, {'changes': ''}),
            ('GET', DNS): (200, NODE_DNS), ('GET', HOSTS): (200, NODE_HOSTS), ('GET', TIME): (200, NODE_TIME),
            ('GET', SYSLOG): (200, NODE_SYSLOG), ('GET', CERTS): (200, NODE_CERTS),
            ('PUT', DNS): (200, {'message': 'DNS updated'}), ('POST', HOSTS): (200, {'message': 'Hosts updated'}),
            ('PUT', TIME): (200, {'message': 'Timezone updated'}),
            ('POST', CUSTOM): (200, {'message': 'Certificate uploaded'}),
        }
        self.routes.update(routes or {})
        self.sent = []
        self.held = []

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        how = self.routes.get((req.method, path))
        if how is None:
            return super().handle(route)
        self.calls.append((req.method, path))
        if req.method != 'GET':
            self.sent.append((req.method, path, req.post_data))
        if how == 'abort':
            return route.abort('connectionrefused')
        if how == 'hold':
            self.held.append(route)
            return None
        code, data = how
        return route.fulfill(status=code, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def reads(self, path):
        return len([c for c in self.calls if c == ('GET', path)])


@pytest.fixture(scope='module')
def playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    yield pw
    pw.stop()


@pytest.fixture(scope='module')
def browser(playwright):
    try:
        br = playwright.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture(scope='module')
def firefox(playwright):
    try:
        br = playwright.firefox.launch(headless=True)
    except Exception as e:
        pytest.skip(f'no Firefox for Playwright: {e}')
    yield br
    br.close()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, **kw):
        app = _GuardApp(br or browser, _CfgServer(layout=layout, **kw), viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _no_errors(app):
    assert not [e for e in app.errors if 'pageerror' in e], app.errors


def _open_node(page, tab=None, redesigned=True):
    _corp_cluster(page)
    page.locator('.corp-tree-child', has_text='pve1').first.click()
    if tab:
        if redesigned:
            page.locator('[data-cr-tabs="node"] [role="tab"]', has_text=tab).click()
        else:
            page.locator('.corp-tab-strip button', has_text=tab).first.click()


def _open_cfg(page, sub, redesigned=True):
    _open_node(page, 'Configure', redesigned)
    page.locator('.corp-subnav-item', has_text=_exact(LABEL[sub])).first.click()


def _sec(page, sid):
    sec = page.locator(f'[data-cr-nc-sec="{sid}"]')
    sec.wait_for(timeout=8000)
    return sec


def _wait_sent(app, n=1):
    for _ in range(50):
        if len(app.server.sent) >= n:
            return app.server.sent
        app.page.wait_for_timeout(100)
    raise AssertionError(f'expected {n} writes, got {app.server.sent}')


# the classic configure content beside its sub nav
CFG = '.corp-subnav + div'


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def cfg_page(browser):
    app = _GuardApp(browser, _CfgServer(layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxNodeCfg'):
        app.close()
        pytest.fail('the bundle has no node configuration helpers (window.PegaProxNodeCfg)')
    yield app.page
    app.close()


def _diff(page, a, b):
    return page.evaluate('([a, b]) => window.PegaProxNodeCfg.lineDiff(a, b)', [a, b])


def test_rules_line_diff(cfg_page):
    same = _diff(cfg_page, 'a\nb\n', 'a\nb\n')
    assert same['same'] and same['lines'] == []
    d = _diff(cfg_page, '1\n2\n3\n4\n5\n6\n7\n', '1\n2\n3\nX\n5\n6\n7\nY\n')
    assert [(x['kind'], x['text']) for x in d['lines']] == [
        ('hunk', '@@ -2 +2 @@'), ('ctx', ' 2'), ('ctx', ' 3'), ('del', '-4'), ('add', '+X'), ('ctx', ' 5'),
        ('ctx', ' 6'), ('ctx', ' 7'), ('add', '+Y')]
    assert (d['added'], d['removed']) == (2, 1)
    # only the newline at the end differs: no line changed, but the text is not the same
    eol = _diff(cfg_page, 'a\nb\n', 'a\nb')
    assert not eol['same'] and eol['eolOnly'] and eol['lines'] == []
    # a change too long to compare line by line is counted whole
    big = _diff(cfg_page, '\n'.join(f'0.0.0.0 ad{i}' for i in range(700)), '\n'.join(f'0.0.0.0 bd{i}' for i in range(700)))
    assert big['big'] and (big['added'], big['removed']) == (700, 700)


def test_rules_hints(cfg_page):
    ip = cfg_page.evaluate('(v) => v.map(x => window.PegaProxNodeCfg.isIp(x))',
                           ['10.0.0.1', '1.1.1.1', '2001:db8::1', '::1', '::ffff:10.0.0.1', '256.1.1.1', 'dns.lab', '10.0.0', ''])
    assert ip == [True, True, True, True, True, False, False, False, False]
    day = 86400
    now = 1_800_000_000
    ex = cfg_page.evaluate('([v, now]) => v.map(x => window.PegaProxNodeCfg.expiry(x, now))',
                           [[now + 40 * day, now + 10 * day + 5, now - 3 * day, None, 'x'], now * 1000])
    assert [e['state'] for e in ex] == ['ok', 'soon', 'expired', 'none', 'none']
    assert ex[0]['days'] == 40 and ex[1]['days'] == 10 and ex[2]['days'] == 3
    assert cfg_page.evaluate('(t) => window.PegaProxNodeCfg.pemCount(t)', PEM_CERT + PEM_CERT) == 2
    ch = cfg_page.evaluate('([d, f]) => window.PegaProxNodeCfg.dnsChanges(d, f)',
                           [NODE_DNS, {'search': 'lab.example', 'dns1': '10.0.0.1', 'dns2': '', 'dns3': '1.1.1.1'}])
    assert ch == [{'k': 'dns2', 'from': '9.9.9.9', 'to': ''}, {'k': 'dns3', 'from': '', 'to': '1.1.1.1'}]


# --- the summary --------------------------------------------------------------------------------

def test_runtime_summary_cards(open_app):
    app = open_app()
    page = app.page
    _open_node(page)
    info = _sec(page, 'sysinfo')
    info.locator('[data-cr-nc-k="kernel"]').wait_for(timeout=8000)
    page.wait_for_function('() => document.querySelector("[data-cr-nsi-sum]").dataset.crNsiSum === "ok"', timeout=8000)
    text = info.inner_text()
    for want in ('pve1', 'pve-manager/9.0.3/abcdef', 'Linux 6.14.8-2-pve', 'E5-2680 v4', '2394 MHz', 'Available', '10.0.0.11'):
        assert want in text, want
    kv = lambda k: info.locator(f'[data-cr-nc-k="{k}"] dd').inner_text().strip()
    assert (kv('sockets'), kv('cores'), kv('cpus')) == ('1', '4', '8')
    # the interfaces are not read by the summary: said so, with the way to read them
    assert 'not read yet' in kv('nics')
    assert info.locator('[data-cr-nsi-flags="7"]').count() == 1
    guests = _sec(page, 'guests')
    gv = lambda k: guests.locator(f'[data-cr-nc-k="{k}"] dd').inner_text().strip()
    assert (gv('qemu'), gv('lxc'), gv('running'), gv('stopped')) == ('1', '1', '2', '0')
    # one set of cards: the health block is a section card too, the classic tables are gone, and
    # status and uptime are not repeated (they are in the header and the health tiles)
    assert page.locator('[data-cr-ns][data-cr-nc-sec="health"]').count() == 1
    assert page.get_by_text('Host Details').count() == 0 and page.locator('.corp-property-grid').count() == 0
    assert '1d 0h 0m' not in text and 'Online' not in text
    assert '1d 0h 0m' in page.locator('[data-cr-stat="ns-uptime"]').inner_text()
    info.locator('[data-cr-nsi-open-net]').click()
    page.locator('.corp-subnav-item.active', has_text=_exact('Network')).wait_for(timeout=5000)
    page.locator('[data-cr-nn]').wait_for(timeout=8000)
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Summary').click()
    assert _sec(page, 'sysinfo').locator('[data-cr-nc-k="nics"] dd').inner_text().startswith('7')
    _sec(page, 'guests').locator('[data-cr-nsi-open-guests]').click()
    page.locator('[data-cr-tabs="node"] [role="tab"][aria-selected="true"]', has_text='VMs').wait_for(timeout=5000)
    _no_errors(app)


def test_runtime_summary_missing_values_are_said(open_app):
    bare = {k: v for k, v in NODE_SUMMARY.items() if k != 'kversion'}
    bare['cpuinfo'] = {'model': 'Intel(R) Xeon(R) CPU E5-2680 v4', 'cpus': 8}
    app = open_app(routes={('GET', NODE + '/summary'): (200, bare)})
    page = app.page
    _open_node(page)
    info = _sec(page, 'sysinfo')
    info.locator('[data-cr-nc-k="kernel"] [data-cr-nc-missing]').wait_for(timeout=8000)
    for k in ('kernel', 'sockets', 'cores', 'mhz', 'hvm'):
        dd = info.locator(f'[data-cr-nc-k="{k}"] dd')
        assert dd.inner_text().strip() == 'not reported', k
    assert not re.search(r'(^|\s)(-|0)(\s|$)', info.inner_text())


def test_runtime_summary_failed_read(open_app):
    app = open_app(routes={('GET', NODE + '/summary'): (500, {'error': 'boom'})})
    page = app.page
    _open_node(page)
    page.locator('[data-cr-nsi-sum="error"]').wait_for(timeout=8000)
    info = _sec(page, 'sysinfo')
    assert info.locator('[data-cr-nc-k="model"] dd').inner_text().strip() == 'summary not read'
    # the version still comes from the live metrics, as in the classic card
    assert info.locator('[data-cr-nc-k="pve"] dd').inner_text().strip() == 'pve-manager/9.0.3'


# --- DNS ----------------------------------------------------------------------------------------

def _dns_classic(app, values):
    page = app.page
    _open_cfg(page, 'dns', redesigned=False)
    page.get_by_text('9.9.9.9').first.wait_for(timeout=8000)
    page.locator(CFG).locator('button', has_text=_exact('Edit')).first.click()
    for label, v in values.items():
        page.locator(f'div:has(> label:text-is("{label}")) > input').fill(v)
    page.locator(CFG).locator('button', has_text=_exact('Save')).first.click()
    return _wait_sent(app)


def test_runtime_dns_edit_shows_the_change_and_sends_the_classic_request(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'dns')
    sec = _sec(page, 'dns')
    sec.locator('[data-cr-nc-k="dns2"]').wait_for(timeout=8000)
    assert 'not set' in sec.locator('[data-cr-nc-k="dns3"]').inner_text()
    sec.locator('[data-cr-nc-edit="dns"]').click()
    assert sec.get_attribute('data-cr-nc-editing') == ''
    assert sec.locator('[data-cr-nc-count="0"]').count() == 1
    sec.locator('#cr-nc-dns-dns2').fill('8.8.8.8')
    sec.locator('#cr-nc-dns-search').fill('lab2.example')
    sec.locator('[data-cr-nc-count="2"]').wait_for(timeout=3000)
    row = sec.locator('[data-cr-nc-change="dns2"]').inner_text()
    assert '9.9.9.9' in row and '8.8.8.8' in row
    assert sec.locator('[data-cr-nc-field="dns-dns2"][data-cr-nc-changed]').count() == 1
    # a name where the node takes an address: a hint, the save stays possible
    sec.locator('#cr-nc-dns-dns3').fill('resolver.lab')
    assert sec.locator('[data-cr-nc-field="dns-dns3"] [data-cr-nc-hint="warning"]').count() == 1
    sec.locator('#cr-nc-dns-dns3').fill('')
    assert app.server.sent == []
    reads = app.server.reads(DNS)
    sec.locator('[data-cr-nc-save="dns"]').click()
    sent = _wait_sent(app)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-sec=dns][data-cr-nc-editing]")', timeout=5000)
    assert app.server.reads(DNS) > reads
    classic = open_app(layout='corporate')
    want = _dns_classic(classic, {'DNS 2': '8.8.8.8', 'Search Domain': 'lab2.example'})
    assert sent == want and sent[0][:2] == ('PUT', DNS)
    assert json.loads(sent[0][2]) == {'search': 'lab2.example', 'dns1': '10.0.0.1', 'dns2': '8.8.8.8', 'dns3': ''}
    _no_errors(app)


def test_runtime_dns_cancel_and_a_refused_save(open_app):
    app = open_app(routes={('PUT', DNS): (500, {'error': 'dns1: invalid format'})})
    page = app.page
    _open_cfg(page, 'dns')
    sec = _sec(page, 'dns')
    sec.locator('[data-cr-nc-edit="dns"]').click()
    sec.locator('#cr-nc-dns-dns1').fill('10.0.0.2')
    sec.locator('[data-cr-nc-cancel="dns"]').click()
    assert sec.locator('[data-cr-nc-k="dns1"] dd').inner_text().strip() == '10.0.0.1'
    assert app.server.sent == []
    sec.locator('[data-cr-nc-edit="dns"]').click()
    sec.locator('#cr-nc-dns-dns1').fill('10.0.0.2')
    sec.locator('[data-cr-nc-save="dns"]').click()
    _wait_sent(app)
    page.get_by_text('dns1: invalid format').first.wait_for(timeout=5000)
    # the refusal keeps the edit and what was typed
    assert sec.get_attribute('data-cr-nc-editing') == ''
    assert sec.locator('#cr-nc-dns-dns1').input_value() == '10.0.0.2'


def test_runtime_dns_failed_read(open_app):
    app = open_app(routes={('GET', DNS): (502, {'error': 'Proxmox VE answered 500', 'upstream_status': 500})})
    page = app.page
    _open_cfg(page, 'dns')
    sec = _sec(page, 'dns')
    state = sec.locator('[data-cr-nc-state="error"]')
    state.wait_for(timeout=8000)
    assert 'Proxmox VE answered 500' in state.inner_text()
    assert sec.locator('[data-cr-nc-edit="dns"]').is_disabled()
    assert sec.locator('[data-cr-nc-kv]').count() == 0
    # the classic alert above the form is not drawn twice
    assert page.locator('[role="alert"].text-red-400').count() == 0
    reads = app.server.reads(DNS)
    app.server.routes[('GET', DNS)] = (200, NODE_DNS)
    sec.locator('[data-cr-nc-retry="dns"]').click()
    sec.locator('[data-cr-nc-k="dns2"]').wait_for(timeout=8000)
    assert app.server.reads(DNS) == reads + 1
    assert not sec.locator('[data-cr-nc-edit="dns"]').is_disabled()


def test_runtime_loading_states(open_app):
    app = open_app(routes={('GET', DNS): 'hold', ('GET', HOSTS): 'hold'})
    page = app.page
    _open_cfg(page, 'dns')
    _sec(page, 'dns').locator('[data-cr-nc-state="loading"]').wait_for(timeout=8000)
    assert _sec(page, 'dns').locator('[data-cr-nc-edit="dns"]').is_disabled()
    page.locator('.corp-subnav-item', has_text=_exact('Hosts File')).first.click()
    _sec(page, 'hosts').locator('[data-cr-nc-state="loading"]').wait_for(timeout=8000)


# --- hosts file ---------------------------------------------------------------------------------

def test_runtime_hosts_diff_confirm_and_the_classic_request(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'hosts')
    sec = _sec(page, 'hosts')
    lines = sec.locator('[data-cr-nc-lines="hosts"] li')
    lines.first.wait_for(timeout=8000)
    assert lines.count() == 5
    sec.locator('[data-cr-nc-edit="hosts"]').click()
    sec.locator('#cr-nc-hosts-text').fill(HOSTS_EDITED)
    bar = sec.locator('[data-cr-nc-editbar="hosts"]')
    assert 'cr-nc-editbar-danger' in bar.get_attribute('class')
    assert '1 lines added, 3 removed' in bar.locator('[data-cr-nc-diffsum]').inner_text()
    diff = bar.locator('[data-cr-nn-diff]').inner_text()
    assert '+10.0.0.12 pve2.lab.example pve2' in diff and '-::1     ip6-localhost ip6-loopback' in diff
    bar.locator('[data-cr-nc-save="hosts"]').click()
    dlg = page.locator('[data-cr-upd-dialog="nc-hosts"]')
    dlg.wait_for(timeout=3000)
    assert 'replaced' in dlg.inner_text()
    dlg.locator('[data-cr-nc-confirm-cancel="hosts"]').click()
    assert dlg.count() == 0 and app.server.sent == []
    bar.locator('[data-cr-nc-save="hosts"]').click()
    page.locator('[data-cr-nc-confirm-go="hosts"]').click()
    sent = _wait_sent(app)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-sec=hosts][data-cr-nc-editing]")', timeout=5000)
    classic = open_app(layout='corporate')
    cpage = classic.page
    _open_cfg(cpage, 'hosts', redesigned=False)
    cpage.get_by_text('ip6-loopback').first.wait_for(timeout=8000)
    cpage.locator(CFG).locator('button', has_text=_exact('Edit')).first.click()
    cpage.locator(CFG).locator('textarea').fill(HOSTS_EDITED)
    cpage.locator(CFG).locator('button', has_text=_exact('Save')).first.click()
    assert sent == _wait_sent(classic) and sent[0][:2] == ('POST', HOSTS)
    assert json.loads(sent[0][2]) == {'data': HOSTS_EDITED}
    _no_errors(app)


def test_runtime_hosts_warns_when_the_node_name_goes(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'hosts')
    sec = _sec(page, 'hosts')
    sec.locator('[data-cr-nc-edit="hosts"]').click()
    sec.locator('#cr-nc-hosts-text').fill('127.0.0.1 localhost\n')
    assert 'pve1 no longer appears' in sec.locator('[data-cr-nc-hint="warning"]').inner_text()
    sec.locator('[data-cr-nc-save="hosts"]').click()
    assert page.locator('[data-cr-nc-confirm-warn]').count() == 1


def test_runtime_hosts_failed_and_empty(open_app):
    app = open_app(routes={('GET', HOSTS): (502, {'error': 'Could not read hosts file from node'})})
    page = app.page
    _open_cfg(page, 'hosts')
    sec = _sec(page, 'hosts')
    state = sec.locator('[data-cr-nc-state="error"]')
    state.wait_for(timeout=8000)
    assert 'Could not read hosts file from node' in state.inner_text()
    assert sec.locator('[data-cr-nc-edit="hosts"]').is_disabled()
    app.server.routes[('GET', HOSTS)] = (200, {'data': ''})
    sec.locator('[data-cr-nc-retry="hosts"]').click()
    sec.locator('[data-cr-nc-state="empty"]').wait_for(timeout=8000)
    assert 'empty' in sec.locator('[data-cr-nc-state="empty"]').inner_text()
    assert not sec.locator('[data-cr-nc-edit="hosts"]').is_disabled()


# --- time ---------------------------------------------------------------------------------------

def test_runtime_time_waits_for_save_and_sends_the_classic_request(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'time')
    sec = _sec(page, 'time')
    sec.locator('[data-cr-nc-k="tz"]').wait_for(timeout=8000)
    assert sec.locator('[data-cr-nc-k="tz"] dd').inner_text().strip() == 'Europe/Vienna'
    assert '10:00:00' in sec.locator('[data-cr-nc-k="local"] dd').inner_text()
    sec.locator('[data-cr-nc-edit="time"]').click()
    sec.locator('#cr-nc-time-tz').select_option('UTC')
    page.wait_for_timeout(300)
    # classic writes on change; here the change waits for Save and is shown first
    assert app.server.sent == []
    row = sec.locator('[data-cr-nc-change="timezone"]').inner_text()
    assert 'Europe/Vienna' in row and 'UTC' in row
    sec.locator('[data-cr-nc-save="time"]').click()
    sent = _wait_sent(app)
    classic = open_app(layout='corporate')
    cpage = classic.page
    _open_cfg(cpage, 'time', redesigned=False)
    cpage.get_by_text('10:00:00').first.wait_for(timeout=8000)
    cpage.locator(CFG).locator('select').select_option('UTC')
    assert sent == _wait_sent(classic) and sent[0][:2] == ('PUT', TIME)
    assert json.loads(sent[0][2]) == {'timezone': 'UTC'}


def test_runtime_time_answer_without_a_zone(open_app):
    app = open_app(routes={('GET', TIME): (200, {})})
    page = app.page
    _open_cfg(page, 'time')
    sec = _sec(page, 'time')
    sec.locator('[data-cr-nc-state="warning"]').wait_for(timeout=8000)
    assert sec.locator('[data-cr-nc-k="tz"] dd').inner_text().strip() == 'not reported'
    # no made-up zone: classic shows UTC in the select for this answer
    assert 'UTC' not in sec.locator('[data-cr-nc-kv="time"]').inner_text().replace('UTC time', '')
    sec.locator('[data-cr-nc-edit="time"]').click()
    assert sec.locator('#cr-nc-time-tz').input_value() == ''
    assert sec.locator('[data-cr-nc-save="time"]').is_disabled()


# --- certificates -------------------------------------------------------------------------------

def _certs_classic(app, restart):
    page = app.page
    _open_cfg(page, 'certs', redesigned=False)
    page.get_by_text('pve-ssl.pem').first.wait_for(timeout=8000)
    page.locator(CFG).locator('button', has_text=_exact('Upload')).first.click()
    page.locator('textarea[placeholder="-----BEGIN CERTIFICATE-----"]').fill(PEM_CERT)
    page.locator('textarea[placeholder="-----BEGIN PRIVATE KEY-----"]').fill(PEM_KEY)
    if not restart:
        page.locator(CFG).locator('input[type="checkbox"]').uncheck()
    page.locator('button', has_text=_exact('Upload Certificate')).click()
    return _wait_sent(app)


@pytest.mark.parametrize('restart', [True, False])
def test_runtime_certificates_upload_sends_the_classic_request(open_app, restart):
    app = open_app()
    page = app.page
    _open_cfg(page, 'certs')
    sec = _sec(page, 'certs')
    sec.locator('[data-cr-nc-cert="pve-ssl.pem"]').wait_for(timeout=8000)
    assert sec.locator('[data-cr-nc-cert="pve-ssl.pem"]').get_attribute('data-cr-nc-expiry') == 'soon'
    assert sec.locator('[data-cr-nc-cert="pve-root-ca.pem"]').get_attribute('data-cr-nc-expiry') == 'ok'
    assert 'pve1.lab.example' in sec.locator('[data-cr-nc-cert="pve-ssl.pem"] [data-cr-nc-k="san"]').inner_text()
    open_btn = sec.locator('[data-cr-nc-cert-open]')
    assert 'cr-btn-danger' in open_btn.get_attribute('class')
    open_btn.click()
    assert sec.locator('[data-cr-nc-save="certs"]').is_disabled()
    sec.locator('#cr-nc-cert-pem').fill(PEM_CERT)
    sec.locator('#cr-nc-cert-key').fill(PEM_KEY)
    if not restart:
        sec.locator('[data-cr-nc-restart] input').uncheck()
    assert 'none' in sec.locator('[data-cr-nc-change="custom"]').inner_text()
    sec.locator('[data-cr-nc-save="certs"]').click()
    # round 8 (R7-1): every upload asks first, with and without the restart
    dlg = page.locator('[data-cr-upd-dialog="nc-certs"]')
    dlg.wait_for(timeout=3000)
    assert ('restart pveproxy' in dlg.inner_text()) == restart
    assert app.server.sent == []
    dlg.locator('[data-cr-nc-confirm-go="certs"]').click()
    sent = _wait_sent(app)
    page.locator('[data-cr-nc-certform]').wait_for(state='detached', timeout=5000)
    want = _certs_classic(open_app(layout='corporate'), restart)
    assert sent == want and sent[0][:2] == ('POST', CUSTOM)
    assert json.loads(sent[0][2]) == {'certificates': PEM_CERT, 'key': PEM_KEY, 'restart': restart, 'force': True}
    _no_errors(app)


def test_runtime_certificates_empty_and_refused(open_app):
    app = open_app(routes={('GET', CERTS): (200, [])})
    page = app.page
    _open_cfg(page, 'certs')
    sec = _sec(page, 'certs')
    empty = sec.locator('[data-cr-nc-state="empty"]')
    empty.wait_for(timeout=8000)
    assert 'same answer' in empty.inner_text()
    app.server.routes[('GET', CERTS)] = (403, {'error': 'Permission denied (node.view)'})
    empty.locator('[data-cr-nc-retry="certs"]').click()
    err = sec.locator('[data-cr-nc-state="error"]')
    err.wait_for(timeout=8000)
    assert 'Permission denied (node.view)' in err.inner_text()


# --- syslog -------------------------------------------------------------------------------------

def test_runtime_syslog_filter_refresh_and_refusal(open_app):
    app = open_app()
    page = app.page
    _open_cfg(page, 'syslog')
    sec = _sec(page, 'syslog')
    lines = sec.locator('[data-cr-nc-lines="syslog"] li')
    lines.first.wait_for(timeout=8000)
    assert lines.count() == 12 and 'pvedaemon[1000]' in lines.first.inner_text()
    sec.locator('[data-cr-nc-syslog-q]').fill('pvedaemon[1011]')
    assert lines.count() == 1 and sec.locator('[data-cr-nc-syslog-count="1"]').count() == 1
    sec.locator('[data-cr-nc-syslog-q]').fill('no such line')
    sec.locator('[data-cr-nc-for="syslog-filter"]').wait_for(timeout=3000)
    reads = app.server.reads(SYSLOG)
    app.server.routes[('GET', SYSLOG)] = (403, {'error': 'Not available to a user confined to a pool'})
    sec.locator('[data-cr-nc-refresh="syslog"]').click()
    err = sec.locator('[data-cr-nc-state="error"]')
    err.wait_for(timeout=8000)
    assert 'confined to a pool' in err.inner_text() and app.server.reads(SYSLOG) == reads + 1


# --- standby, classic, layout -------------------------------------------------------------------

def test_runtime_a_standby_reads_but_does_not_write(open_app):
    app = open_app(role='standby')
    page = app.page
    _open_cfg(page, 'dns')
    sec = _sec(page, 'dns')
    sec.locator('[data-cr-nc-k="dns2"]').wait_for(timeout=8000)
    assert sec.locator('[data-cr-nc-edit="dns"]').is_disabled()
    page.locator('.corp-subnav-item', has_text=_exact('Certificates')).first.click()
    assert _sec(page, 'certs').locator('[data-cr-nc-cert-open]').is_disabled()
    page.locator('.corp-subnav-item', has_text=_exact('Syslog')).first.click()
    reads = app.server.reads(SYSLOG)
    refresh = _sec(page, 'syslog').locator('[data-cr-nc-refresh="syslog"]')
    refresh.wait_for(timeout=8000)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-refresh=syslog]").disabled', timeout=8000)
    refresh.click()
    for _ in range(30):
        if app.server.reads(SYSLOG) > reads:
            break
        page.wait_for_timeout(100)
    assert app.server.reads(SYSLOG) == reads + 1


def test_runtime_network_and_health_sit_on_the_same_card(open_app):
    app = open_app()
    page = app.page
    _open_node(page)
    assert _sec(page, 'health').get_attribute('data-cr-ns') == ''
    _open_node(page, 'Configure')
    net = _sec(page, 'network')
    assert net.get_attribute('data-cr-nn') == ''
    assert 'cr-btn-danger' in net.locator('[data-cr-nn-revert]').get_attribute('class')
    assert 'cr-btn-primary' in net.locator('[data-cr-nn-apply]').get_attribute('class')


def test_runtime_classic_corporate_is_unchanged(open_app):
    app = open_app(layout='corporate')
    page = app.page
    _open_node(page, redesigned=False)
    page.get_by_text('Host Details').first.wait_for(timeout=8000)
    assert page.locator('[data-cr-nc-sec]').count() == 0
    page.locator('.corp-tab-strip button', has_text='Configure').first.click()
    page.locator('.corp-subnav-item', has_text=_exact('DNS')).first.click()
    page.locator('.corp-property-grid', has=page.get_by_text('Search Domain')).wait_for(timeout=8000)
    page.locator('.corp-subnav-item', has_text=_exact('Time Configuration')).first.click()
    page.locator(CFG).locator('select').wait_for(timeout=8000)
    assert page.locator('[data-cr-nc-sec]').count() == 0


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'
LONG_LINE = '10.0.0.99 ' + ' '.join(f'host{i}.a-very-long-domain-name.lab.example' for i in range(12)) + '\n'


@pytest.mark.parametrize('engine,width', [('chromium', 1600), ('chromium', 1280), ('chromium', 1024),
                                          ('firefox', 1600), ('firefox', 1280), ('firefox', 1024)])
def test_runtime_layout_without_sideways_scroll(open_app, firefox, browser, engine, width):
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser)
    page = app.page
    _open_node(page)
    _sec(page, 'sysinfo').locator('[data-cr-nc-k="kernel"]').wait_for(timeout=8000)
    assert page.evaluate(_NO_SIDEWAYS), 'summary'
    page.locator('[data-cr-tabs="node"] [role="tab"]', has_text='Configure').click()
    page.locator('.corp-subnav-item', has_text=_exact('DNS')).first.click()
    sec = _sec(page, 'dns')
    sec.locator('[data-cr-nc-edit="dns"]').click()
    sec.locator('#cr-nc-dns-dns2').fill('8.8.8.8')
    assert page.evaluate(_NO_SIDEWAYS), 'dns editing'
    sec.locator('[data-cr-nc-cancel="dns"]').click()
    page.locator('.corp-subnav-item', has_text=_exact('Hosts File')).first.click()
    sec = _sec(page, 'hosts')
    sec.locator('[data-cr-nc-edit="hosts"]').click()
    sec.locator('#cr-nc-hosts-text').fill(HOSTS_EDITED + LONG_LINE)
    assert page.evaluate(_NO_SIDEWAYS), 'hosts editing'
    sec.locator('[data-cr-nc-save="hosts"]').click()
    box = page.locator('[data-cr-upd-dialog="nc-hosts"]').bounding_box()
    assert box['x'] >= 0 and box['x'] + box['width'] <= width
    page.locator('[data-cr-nc-confirm-cancel="hosts"]').click()
    sec.locator('[data-cr-nc-cancel="hosts"]').click()
    for sub, probe in (('certs', '[data-cr-nc-cert="pve-ssl.pem"]'), ('syslog', '[data-cr-nc-lines="syslog"]'),
                       ('time', '[data-cr-nc-k="tz"]')):
        page.locator('.corp-subnav-item', has_text=_exact(LABEL[sub])).first.click()
        _sec(page, sub).locator(probe).wait_for(timeout=8000)
        assert page.evaluate(_NO_SIDEWAYS), sub
    _no_errors(app)


# --- after a Save, a read that failed under an open form (review of round 7) ---------------------

def _release(app, body):
    route = app.server.held.pop()
    route.fulfill(status=200, body=json.dumps(body), headers={'Content-Type': 'application/json'})


def _edit_and_save(page, sub, sec):
    if sub == 'dns':
        sec.locator('[data-cr-nc-edit="dns"]').click()
        sec.locator('#cr-nc-dns-dns2').fill('8.8.8.8')
        sec.locator('[data-cr-nc-save="dns"]').click()
    elif sub == 'hosts':
        sec.locator('[data-cr-nc-edit="hosts"]').click()
        sec.locator('#cr-nc-hosts-text').fill(HOSTS_EDITED)
        sec.locator('[data-cr-nc-save="hosts"]').click()
        page.locator('[data-cr-nc-confirm-go="hosts"]').click()
    else:
        sec.locator('[data-cr-nc-edit="time"]').click()
        sec.locator('#cr-nc-time-tz').select_option('UTC')
        sec.locator('[data-cr-nc-save="time"]').click()


@pytest.mark.parametrize('sub,path,fresh,probe,old,new', [
    ('dns', DNS, dict(NODE_DNS, dns2='8.8.8.8'), '[data-cr-nc-k="dns2"] dd', '9.9.9.9', '8.8.8.8'),
    ('hosts', HOSTS, {'data': HOSTS_EDITED}, '.cr-nc-head .cr-nn-count', '5 lines', '3 lines'),
    ('time', TIME, dict(NODE_TIME, timezone='UTC'), '[data-cr-nc-k="tz"] dd', 'Europe/Vienna', 'UTC'),
])
def test_runtime_after_a_save_the_card_says_it_is_read_again(open_app, sub, path, fresh, probe, old, new):
    """The Save leaves the edit state at once and the classic handler reads the node again; until
    that answer is in, the card shows the last read and says that a new one is under way."""
    app = open_app()
    page = app.page
    _open_cfg(page, sub)
    sec = _sec(page, sub)
    sec.locator(probe).wait_for(timeout=8000)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-updating]")', timeout=8000)
    assert old in sec.locator(probe).inner_text()
    app.server.routes[('GET', path)] = 'hold'
    _edit_and_save(page, sub, sec)
    _wait_sent(app)
    page.wait_for_function(f'() => !document.querySelector("[data-cr-nc-sec={sub}][data-cr-nc-editing]")', timeout=5000)
    badge = sec.locator('.cr-nc-head [data-cr-nc-updating]')
    badge.wait_for(timeout=5000)
    assert 'Reading again' in badge.inner_text()
    assert badge.locator('.cr-badge-neutral').count() == 1
    assert old in sec.locator(probe).inner_text()
    for _ in range(50):
        if app.server.held:
            break
        page.wait_for_timeout(100)
    app.server.routes[('GET', path)] = (200, fresh)
    _release(app, fresh)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-updating]")', timeout=8000)
    assert new in sec.locator(probe).inner_text()
    _no_errors(app)


def test_runtime_the_system_read_of_the_preview_asks_only_what_it_shows(open_app):
    """The classic system read also starts cluster-health and sensors (over SSH on the node) and drops
    both answers; the preview leaves them out, so the read after a Save does not wait for them."""
    extra = {('GET', NODE + '/sensors'): (200, {'sensors': []}),
             ('GET', NODE + '/cluster-health'): (200, {'quorate': True})}
    counts = {}
    for layout in ('corporate', LAYOUT):
        app = open_app(layout=layout, routes=dict(extra))
        _open_cfg(app.page, 'dns', redesigned=layout == LAYOUT)
        app.page.get_by_text('9.9.9.9').first.wait_for(timeout=8000)
        app.page.wait_for_timeout(300)
        counts[layout] = [app.server.reads(p) for p in (DNS, HOSTS, TIME, SYSLOG, CERTS, NODE + '/cluster-health', NODE + '/sensors')]
    assert counts['corporate'][5:] == [counts['corporate'][0]] * 2, counts
    assert counts[LAYOUT][:5] == counts['corporate'][:5], counts
    assert counts[LAYOUT][5:] == [0, 0], counts


def test_runtime_a_failed_read_under_an_open_certificate_form(open_app):
    """The upload form keeps its state in the view across sub tabs. When the certificates read then
    fails, the card says so and offers no Save without a form; once the read works, the form is back.
    Round 8 (R7-3): a form with typed text asks before another sub tab, so the form crosses it open
    and empty here."""
    app = open_app()
    page = app.page
    _open_cfg(page, 'certs')
    sec = _sec(page, 'certs')
    sec.locator('[data-cr-nc-cert="pve-ssl.pem"]').wait_for(timeout=8000)
    sec.locator('[data-cr-nc-cert-open]').click()
    sec.locator('[data-cr-nc-certform]').wait_for(timeout=5000)
    page.locator('.corp-subnav-item', has_text=_exact('Syslog')).first.click()
    _sec(page, 'syslog')
    assert page.locator('[data-cr-upd-dialog="nc-leave"]').count() == 0
    app.server.routes[('GET', CERTS)] = (500, {'error': 'pvedaemon did not answer'})
    reads = app.server.reads(CERTS)
    _sec(page, 'syslog').locator('[data-cr-nc-refresh="syslog"]').click()
    for _ in range(50):
        if app.server.reads(CERTS) > reads:
            break
        page.wait_for_timeout(100)
    page.locator('.corp-subnav-item', has_text=_exact('Certificates')).first.click()
    sec = _sec(page, 'certs')
    err = sec.locator('[data-cr-nc-state="error"]')
    err.wait_for(timeout=8000)
    assert 'pvedaemon did not answer' in err.inner_text()
    assert sec.locator('[data-cr-nc-editbar="certs"]').count() == 0
    assert sec.locator('[data-cr-nc-save="certs"]').count() == 0
    assert sec.get_attribute('data-cr-nc-editing') is None
    app.server.routes[('GET', CERTS)] = (200, NODE_CERTS)
    page.wait_for_function('() => !document.querySelector("[data-cr-nc-retry=certs]").disabled', timeout=8000)
    err.locator('[data-cr-nc-retry="certs"]').click()
    sec.locator('[data-cr-nc-certform]').wait_for(timeout=8000)
    assert sec.locator('#cr-nc-cert-pem').input_value() == ''
    sec.locator('#cr-nc-cert-pem').fill(PEM_CERT)
    sec.locator('#cr-nc-cert-key').fill(PEM_KEY)
    assert sec.locator('[data-cr-nc-save="certs"]').is_enabled()
    assert app.server.sent == []
    _no_errors(app)
