"""The Reports modules CVE Scanner, Cost Dashboard, Power & Carbon, Network Topology and API Health
in Corporate Redesigned, in the browser.

Round 9, B3. The CVE page draws the dashboard's scan state; the scan and the debsecan install stay
the two POSTs of the tab, sent only on a click. Costs, power and the topology are drawn from the
classic tab's own reads and handlers, so the rates PUT and the host profile PUT and DELETE are the
classic requests. API health reads the route the classic page polls and says "no samples" where
the route answers zeros. A read that failed says so; a figure the answer leaves out is never drawn
as zero. Classic Corporate keeps its markup.

Pure parts through window.PegaProxModules. PEGAPROX_CR_BUNDLE=<file> serves another bundle (the
counterproof against the build before this stage). Skips without Playwright. LW Nov 2026
"""
import copy
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import (FIXED, REP_API, REP_COST_RATES, REP_COST_ROWS, REP_COST_SUMMARY, REP_CVE,
                                           REP_POWER_HOSTS, REP_POWER_RATES, REP_POWER_ROWS, REP_POWER_SUMMARY, REP_READS,
                                           REP_TOPOLOGY, _corp_cluster, _GuardApp, _GuardServer)
from test_corp_redesigned_node_hw_ui import browser, firefox, playwright  # noqa: F401 (fixtures)

LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CVE = '/api/clusters/c1/reports/cve-scan'
INSTALL = '/api/clusters/c1/reports/install-debsecan'
COST_SUM = '/api/clusters/c1/costs/summary'
COST_RATES = '/api/cost/rates/c1'
POWER_SUM = '/api/clusters/c1/power/summary'
POWER_RATES = '/api/power/rates/c1'
HOSTS = '/api/clusters/c1/power/hosts'
TOPO = '/api/clusters/c1/topology'
API = '/api/clusters/c1/api-latency'
TAB = {'cve': 'CVE Scanner', 'costs': 'Cost Dashboard', 'power': 'Power & Carbon', 'topology': 'Network Topology',
       'api': 'API Health'}
ROOTS = {'cve': '[data-cr-cve]', 'costs': '[data-cr-cost]', 'power': '[data-cr-power]', 'topology': '[data-cr-net]',
         'api': '[data-cr-api]'}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout=LAYOUT, viewport=(1600, 1000), br=None, routes=None, theme=''):
        r = {}
        for v in REP_READS.values():
            r.update(v)
        r.update({('POST', INSTALL): (200, {'installed': 2, 'total': 2}),
                  ('PUT', COST_RATES): (200, {'ok': True}), ('PUT', POWER_RATES): (200, {'ok': True})})
        for node in ('pve1', 'pve2'):
            r[('PUT', f'{HOSTS}/{node}')] = (200, {'ok': True})
            r[('DELETE', f'{HOSTS}/{node}')] = (200, {'ok': True, 'removed': True})
        r.update(routes or {})
        app = _GuardApp(br or browser, _GuardServer(bundle=BUNDLE, layout=layout, extra=r), corp_theme=theme, viewport=viewport)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _wait(page, fn, seconds=6):
    deadline = time.time() + seconds
    while time.time() < deadline and not fn():
        page.wait_for_timeout(100)
    return fn()


def _open(app, mod):
    page = app.page
    _corp_cluster(page)
    page.locator('[data-cr-tab="reports"]').click()
    page.locator('.corp-tab-strip button', has_text=TAB[mod]).first.click()
    page.locator(ROOTS[mod]).first.wait_for(timeout=8000)
    return page


def _state(page, mod, want, seconds=8):
    attr = ROOTS[mod][1:-1]
    _wait(page, lambda: page.locator(ROOTS[mod]).first.get_attribute(attr) == want, seconds)
    return page.locator(ROOTS[mod]).first.get_attribute(attr)


def _stats(page, scope):
    return page.evaluate('''(scope) => Object.fromEntries(Array.from(document.querySelectorAll(`${scope} [data-cr-rp-stat]`)).map(s => [
        s.dataset.crRpStat, [Array.from(s.querySelector('.cr-stat-value').childNodes).map(n => n.textContent.trim()).filter(Boolean).join(' '),
                             (s.querySelector('[data-cr-rp-sub]') || {innerText: ''}).innerText.trim()]]))''', scope)


def _rows(page, table, cols):
    return page.evaluate('''([table, cols]) => Array.from(document.querySelectorAll(`[data-cr-table="${table}"] tbody tr.cr-row`))
        .map(tr => { const tds = Array.from(tr.children); const heads = Array.from(tr.closest('table').querySelectorAll('thead th'));
                     return Object.fromEntries(cols.map(c => { const i = heads.findIndex(h => h.dataset.crCol === c);
                         return [c, i < 0 ? null : tds[i].innerText.replace(/\\s+/g, ' ').trim()]; })); })''', [table, cols])


def _calls(app, method, path):
    return [c for c in app.server.calls if c == (method, path)]


def _no_errors(app):
    assert not app.errors, app.errors


# --- the pure parts -----------------------------------------------------------------------------

@pytest.fixture(scope='module')
def mods_page(browser):
    app = _GuardApp(browser, _GuardServer(bundle=BUNDLE, layout=LAYOUT))
    if not app.page.evaluate('() => !!window.PegaProxModules'):
        app.close()
        pytest.fail('the bundle has no Reports module helpers (window.PegaProxModules)')
    yield app.page
    app.close()


def test_rules_cve_counts_and_node_states(mods_page):
    m = mods_page.evaluate('(r) => window.PegaProxModules.cveModel(r)', REP_CVE)
    assert (m['total'], m['ok'], m['failed']) == (2, 1, 1)
    assert (m['cves'], m['high'], m['security'], m['updates'], m['clean'], m['reboot'], m['withDebsecan']) == (3, 1, 2, 3, 0, 1, 1)
    assert {r['node']: r['state'] for r in m['rows']} == {'pve1': 'vulnerable', 'pve2': 'failed'}
    plain = copy.deepcopy(REP_CVE)
    n = plain['nodes'][0]
    n.update(cves=[], cve_count=0, debsecan_available=False)
    assert mods_page.evaluate('(r) => window.PegaProxModules.cveModel(r).rows[0].state', plain) == 'security'
    n.update(packages=[n['packages'][2]], security_count=0, total_count=1)
    assert mods_page.evaluate('(r) => window.PegaProxModules.cveModel(r).rows[0].state', plain) == 'updates'
    n.update(packages=[], total_count=0)
    got = mods_page.evaluate('(r) => window.PegaProxModules.cveModel(r)', plain)
    assert got['rows'][0]['state'] == 'clean' and got['clean'] == 1 and got['withDebsecan'] == 0
    assert mods_page.evaluate('() => window.PegaProxModules.cveModel(null)') is None
    assert mods_page.evaluate("() => window.PegaProxModules.cveModel({error: 'x'})") is None


def test_rules_api_health_none_and_an_old_window(mods_page):
    ev = lambda body, now: mods_page.evaluate('([b, n]) => window.PegaProxModules.apiModel(b, n)', [body, now])
    zero = {'samples': 0, 'p50': 0, 'p95': 0, 'p99': 0, 'avg': 0, 'max': 0, 'error_rate': 0, 'recent': [], 'by_endpoint': []}
    assert ev(zero, FIXED * 1000)['none'] is True
    m = ev(REP_API, FIXED * 1000)
    assert m['none'] is False and m['n'] == 42 and m['old'] is False and m['errs'] == 2 and len(m['ms']) == 30
    # nothing in the window: the server falls back to the last 50 calls
    later = ev(REP_API, (FIXED + 900) * 1000)
    assert later['old'] is True and later['age'] == 900


def test_rules_topology_interfaces_guests_and_unlinked(mods_page):
    m = mods_page.evaluate('(g) => window.PegaProxModules.netModel(g)', REP_TOPOLOGY)
    by = {i['id']: i for i in m['all']}
    assert by['br:pve1:vmbr0']['node'] == 'pve1' and by['br:pve1:vmbr0']['vlan'] is True
    assert [g['label'] for g in by['br:pve1:vmbr0']['guests']] == ['web01'] and by['br:pve1:vmbr0']['running'] == 1
    assert by['sdn:vnet1']['node'] == '' and by['sdn:vnet1']['cts'] == 1 and by['sdn:vnet1']['tag'] == 100
    assert by['br:pve1:bond0']['ports'] == 'eno1 eno2' and by['br:pve1:bond0']['guests'] == []
    assert [g['label'] for g in m['orphans']] == ['db01']
    assert m['count'] == {'nodes': 2, 'online': 1, 'bridges': 2, 'bonds': 1, 'vnets': 1, 'vms': 2, 'cts': 1}
    assert mods_page.evaluate("() => window.PegaProxModules.netModel({error: 'x'})") is None


def test_rules_report_states_and_where_rates_come_from(mods_page):
    ev = lambda *a: mods_page.evaluate('(a) => window.PegaProxModules.report(...a)', list(a))
    assert ev(None, True, None, True) == 'loading'
    # before the tab started its first read an empty page is not a failed one
    assert ev(None, False, None, False) == 'loading'
    assert ev(None, False, {'why': ''}, True) == 'error'
    assert ev({'enough_data': False}, False, None, True) == 'notenough'
    assert ev({'enough_data': True}, False, None, True) == 'ok'
    assert ev({'enough_data': True}, False, {'why': 'boom'}, True) == 'stale'
    src = lambda f: mods_page.evaluate("(f) => window.PegaProxModules.rateSource(f, 'c1')", f)
    assert src({'cluster_id': 'c1'}) == 'own' and src({'cluster_id': '__default__'}) == 'default' and src({'currency': 'EUR'}) == 'builtin'
    assert mods_page.evaluate("() => window.PegaProxModules.money(null, 'EUR')") is None


def test_every_new_key_is_in_english_and_german_once():
    src = open(os.path.join(ROOT, 'web', 'src', 'cr_modules.js'), encoding='utf-8').read()
    keys = set(re.findall(r"t\('(cr(?:Md|Cve|Api|Net)\w+)'\)", src)) | set(re.findall(r"'(cr(?:Md|Cve|Api|Net)[A-Z]\w+)'", src))
    tr = open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8').read()
    de, en = tr.index('            de: {'), tr.index('            en: {')
    zh = tr.index('            zh: {')
    assert len(keys) > 100
    for k in sorted(keys):
        assert len(re.findall(r'^ +%s:' % k, tr[de:en], re.M)) == 1, ('de', k)
        assert len(re.findall(r'^ +%s:' % k, tr[en:zh], re.M)) == 1, ('en', k)
    for line in tr[de:zh].splitlines():
        if re.match(r'^ +cr(Md|Cve|Api|Net)\w+:', line):
            assert '\u2014' not in line and '\u2013' not in line and 'preview' not in line.lower(), line


# --- CVE Scanner --------------------------------------------------------------------------------

def test_runtime_cve_waits_for_the_button_then_draws_tiles_and_node_rows(open_app):
    app = open_app()
    page = _open(app, 'cve')
    assert _state(page, 'cve', 'none') == 'none'
    page.locator('[data-cr-nc-sec="cve-none"]').wait_for(timeout=5000)
    # the scan is one SSH session per node: never sent on open
    page.wait_for_timeout(500)
    assert _calls(app, 'POST', CVE) == []
    page.locator('[data-cr-cve-scan]').click()
    assert _state(page, 'cve', 'ok') == 'ok'
    assert len(_calls(app, 'POST', CVE)) == 1
    st = _stats(page, '[data-cr-cve]')
    assert st['nodes'] == ['1/2', '1 failed'] and st['cves'] == ['3', '1 of high urgency']
    assert st['security'][0] == '2' and st['updates'][0] == '3' and st['clean'][0] == '0/1' and st['reboot'][0] == '1'
    rows = {r['node']: r for r in _rows(page, 'cve-nodes', ['node', 'state', 'cves', 'sec', 'reboot'])}
    assert rows['pve2']['state'] == 'Scan failed' and rows['pve2']['cves'] == '-'
    assert rows['pve1']['state'] == 'High urgency CVEs' and rows['pve1']['cves'] == '3' and rows['pve1']['reboot'] == 'needed'
    # a row opens its CVEs, high urgency first, and the pending packages, critical first
    page.locator('tr:has([data-cr-cve-row="pve1"]) [data-cr-cve-state]').click()
    det = page.locator('[data-cr-cve-detail="pve1"]')
    det.wait_for(timeout=5000)
    assert [x.get_attribute('data-cr-cve-id') for x in det.locator('[data-cr-cve-id]').all()] == ['CVE-2026-1001', 'CVE-2026-1002', 'CVE-2025-0999']
    assert [x.get_attribute('data-cr-cve-fix') for x in det.locator('[data-cr-cve-fix]').all()] == ['apt', 'pve_upgrade', 'none']
    assert [x.get_attribute('data-cr-cve-pkg') for x in det.locator('[data-cr-cve-pkg]').all()] == ['openssl', 'curl', 'proxmox-widget-toolkit']
    assert 'trixie' in det.inner_text() and 'with a fix available' in det.inner_text()
    # the failed node opens its reason, not a clean list
    page.locator('tr:has([data-cr-cve-row="pve2"]) [data-cr-cve-state]').click()
    assert 'Node offline' in page.locator('[data-cr-cve-detail="pve2"]').inner_text()
    det.locator('[data-cr-cve-updates="pve1"]').click()
    page.locator('[data-cr-upd-tiles]').wait_for(timeout=8000)
    _no_errors(app)


def test_runtime_cve_without_debsecan_offers_the_install_and_counts_no_cves(open_app):
    res = copy.deepcopy(REP_CVE)
    res['summary']['debsecan_available'] = False
    res['summary']['total_cves'] = 0
    res['nodes'][0].update(debsecan_available=False, cves=[], cve_count=0, suite='', cve_mode='')
    app = open_app(routes={('POST', CVE): (200, res)})
    page = _open(app, 'cve')
    page.locator('[data-cr-cve-scan]').click()
    assert _state(page, 'cve', 'ok') == 'ok'
    page.locator('[data-cr-nc-sec="cve-debsecan"]').wait_for(timeout=5000)
    st = _stats(page, '[data-cr-cve]')
    # without debsecan there is no CVE figure: not reported, not a green 0
    assert st['cves'] == ['not reported', 'debsecan not installed']
    rows = {r['node']: r for r in _rows(page, 'cve-nodes', ['node', 'cves'])}
    assert rows['pve1']['cves'] == 'not reported'
    page.locator('[data-cr-cve-install]').click()
    # the classic handler: install, then scan again
    assert _wait(page, lambda: len(_calls(app, 'POST', CVE)) == 2)
    assert len(_calls(app, 'POST', INSTALL)) == 1
    _no_errors(app)


def test_runtime_cve_every_node_failed_shows_no_figures(open_app):
    res = {'cluster_id': 'c1', 'scanned_at': '2026-10-30T09:00:00+00:00',
           'nodes': [{'node': 'pve1', 'error': 'SSH connection failed'}, {'node': 'pve2', 'error': 'Node offline'}],
           'summary': {'nodes_scanned': 2, 'nodes_ok': 0, 'total_cves': 0, 'total_security': 0, 'total_updates': 0, 'debsecan_available': False}}
    app = open_app(routes={('POST', CVE): (200, res)})
    page = _open(app, 'cve')
    page.locator('[data-cr-cve-scan]').click()
    assert _state(page, 'cve', 'ok') == 'ok'
    page.locator('[data-cr-rp-note="cve-allfailed"]').wait_for(timeout=5000)
    st = _stats(page, '[data-cr-cve]')
    assert st['nodes'][0] == '0/2' and st['security'][0] == '-' and st['updates'][0] == '-' and st['clean'][0] == '-'
    assert page.locator('[data-cr-cve-state="clean"]').count() == 0


# --- API Health ---------------------------------------------------------------------------------

def test_runtime_api_health_tiles_chart_and_endpoints(open_app):
    app = open_app()
    page = _open(app, 'api')
    assert _state(page, 'api', 'ok') == 'ok'
    st = _stats(page, '[data-cr-api]')
    assert st['p50'] == ['38.2 ms', 'avg 61.7 ms'] and st['p95'][0] == '210.4 ms' and st['max'][0] == '1,180.0 ms'
    assert st['samples'] == ['42', 'last 5 min'] and st['errors'][0] == '4.8 %'
    tone = page.evaluate("() => ['max', 'p99', 'p50'].map(k => document.querySelector(`[data-cr-rp-stat=\"${k}\"]`).className)")
    assert 'cr-stat-error' in tone[0] and 'cr-stat-warning' in tone[1] and 'cr-stat-' not in tone[2].replace('cr-stat-click', '')
    page.locator('[data-cr-chart="api-recent"] canvas').wait_for(timeout=5000)
    assert 'The last 30 calls, 2 of them failed.' in page.locator('[data-cr-api-recent-basis]').inner_text()
    rows = _rows(page, 'api-endpoints', ['endpoint', 'count', 'errors'])
    assert rows[0]['endpoint'].startswith('GET /nodes/{node}/qemu') and rows[0]['errors'] == '2' and rows[1]['errors'] == '0'
    # auto off: a Refresh still reads
    page.locator('[data-cr-api-auto]').click()
    assert page.locator('[data-cr-api-auto]').get_attribute('data-cr-api-auto') == 'off'
    before = len(_calls(app, 'GET', API))
    page.locator('[data-cr-api-refresh]').click()
    assert _wait(page, lambda: len(_calls(app, 'GET', API)) == before + 1)
    _no_errors(app)


def test_runtime_api_health_without_samples_draws_no_zero(open_app):
    zero = {'samples': 0, 'p50': 0, 'p95': 0, 'p99': 0, 'avg': 0, 'max': 0, 'error_rate': 0, 'recent': [], 'by_endpoint': []}
    app = open_app(routes={('GET', API): (200, zero)})
    page = _open(app, 'api')
    assert _state(page, 'api', 'none') == 'none'
    page.locator('[data-cr-api-none]').wait_for(timeout=5000)
    assert page.locator('[data-cr-api-tiles]').count() == 0 and page.locator('[data-cr-table="api-endpoints"]').count() == 0
    assert '0 ms' not in page.locator('[data-cr-api]').inner_text()


def test_runtime_api_health_an_old_window_and_a_failed_read(open_app):
    old = copy.deepcopy(REP_API)
    for r in old['recent']:
        r['ts'] -= 3600
    app = open_app(routes={('GET', API): (200, old)})
    page = _open(app, 'api')
    assert _state(page, 'api', 'ok') == 'ok'
    page.locator('[data-cr-rp-note="api-old"]').wait_for(timeout=5000)
    assert _stats(page, '[data-cr-api]')['samples'][1] == 'last 50 calls'
    app2 = open_app(routes={('GET', API): (500, {'error': 'boom'})})
    page2 = _open(app2, 'api')
    assert _state(page2, 'api', 'error') == 'error'
    assert 'boom' in page2.locator('[data-cr-nc-state="error"][data-cr-nc-for="api"]').inner_text()
    assert page2.locator('[data-cr-api-tiles]').count() == 0


# --- Cost Dashboard -----------------------------------------------------------------------------

def test_runtime_costs_tiles_rates_nodes_and_guests(open_app):
    app = open_app()
    page = _open(app, 'costs')
    assert _state(page, 'costs', 'ok') == 'ok'
    st = _stats(page, '[data-cr-cost]')
    assert st['monthly'] == ['€ 25.17', 'the last 30 days'] and st['cpu'] == ['€ 4.46', '18 % of the total']
    assert st['guests'] == ['3', '1 with limited samples']
    assert page.locator('[data-cr-cost-basis="own"]').inner_text().startswith('Rates: 0.0120 EUR per core hour')
    nodes = _rows(page, 'cost-nodes', ['node', 'v', 'share'])
    assert nodes == [{'node': 'pve1', 'v': '€ 18.77', 'share': '74.6%'}, {'node': 'pve2', 'v': '€ 6.40', 'share': '25.4%'}]
    rows = _rows(page, 'cost-guests', ['name', 'csto', 'monthly'])
    assert [r['name'] for r in rows] == ['web01', 'db01 few samples', 'ct01'] and rows[1]['csto'] == '€ 6.40'
    _no_errors(app)


def test_runtime_costs_rates_dialog_marks_changes_and_sends_the_classic_put(open_app):
    app = open_app()
    page = _open(app, 'costs')
    _state(page, 'costs', 'ok')
    page.locator('[data-cr-cost-rates]').click()
    form = page.locator('[data-cr-md-form="cost"]')
    form.wait_for(timeout=5000)
    assert _calls(app, 'GET', COST_RATES)
    assert page.locator('[data-cr-md-changed="0"]').count() == 1
    form.locator('[data-cr-md-field="cpu_per_core_h"]').fill('0.02')
    form.locator('[data-cr-md-field="currency"]').select_option('USD')
    assert page.locator('[data-cr-md-changed="2"]').count() == 1
    assert form.locator('[data-cr-nc-field="md-cpu_per_core_h"][data-cr-nc-changed]').count() == 1
    page.locator('[data-cr-md-save="cost"]').click()
    form.wait_for(state='detached', timeout=5000)
    assert app.server.bodies[COST_RATES][-1] == {'cpu_per_core_h': 0.02, 'mem_per_gb_h': 0.0035, 'storage_per_gb_month': 0.1,
                                                 'currency': 'USD', 'notes': ''}
    # saveRates reads the report again
    assert _wait(page, lambda: len(_calls(app, 'GET', COST_SUM)) >= 2)
    _no_errors(app)


@pytest.mark.parametrize('answer,src', [((200, dict(REP_COST_RATES, cluster_id='__default__')), 'default'), ((500, {'error': 'x'}), 'builtin')])
def test_runtime_costs_rates_dialog_says_where_the_rates_come_from(open_app, answer, src):
    app = open_app(routes={('GET', COST_RATES): answer})
    page = _open(app, 'costs')
    _state(page, 'costs', 'ok')
    page.locator('[data-cr-cost-rates]').click()
    page.locator(f'[data-cr-md-form="cost"] [data-cr-md-rate-src="{src}"]').wait_for(timeout=5000)


def test_runtime_costs_not_enough_history_and_a_failed_read(open_app):
    app = open_app(routes={('GET', COST_SUM): (200, {'enough_data': False, 'cluster_id': 'c1', 'rates': REP_COST_RATES, 'days': 30})})
    page = _open(app, 'costs')
    assert _state(page, 'costs', 'notenough') == 'notenough'
    assert page.locator('[data-cr-cost-tiles]').count() == 0
    app2 = open_app(routes={('GET', COST_SUM): (500, {'error': 'internal error'})})
    page2 = _open(app2, 'costs')
    assert _state(page2, 'costs', 'error') == 'error'
    assert 'internal error' in page2.locator('[data-cr-nc-for="cost"]').inner_text()
    assert '€ 0.00' not in page2.locator('[data-cr-cost]').inner_text()


def test_runtime_costs_a_refresh_that_fails_keeps_the_figures_and_says_so(open_app):
    app = open_app()
    page = _open(app, 'costs')
    assert _state(page, 'costs', 'ok') == 'ok'
    app.server.extra[('GET', COST_SUM)] = (502, {'error': 'cluster not connected'})
    page.locator('[data-cr-cost-refresh]').click()
    assert _state(page, 'costs', 'stale') == 'stale'
    assert 'cluster not connected' in page.locator('[data-cr-rp-note="cost-stale"]').inner_text()
    assert page.locator('[data-cr-cost-tiles]').count() == 1


# --- Power & Carbon -----------------------------------------------------------------------------

def test_runtime_power_hosts_notes_and_guest_markers(open_app):
    app = open_app()
    page = _open(app, 'power')
    assert _state(page, 'power', 'ok') == 'ok'
    st = _stats(page, '[data-cr-power]')
    assert st['kwh'][0] == '150.0 kWh' and st['cost'][0] == '€ 45.00' and st['coverage'] == ['83 %', '600 of 720 h']
    notes = page.locator('[data-cr-power-notes]').inner_text()
    assert 'Unallocated (host power no guest accounts for): 115.5 kWh' in notes and 'Estimate from 600 of 720 h of history' in notes
    assert 'For 1 guests the host is taken from where they run today' in notes
    hosts = {r['node'].split()[0]: r for r in _rows(page, 'power-hosts', ['node', 'profile', 'unalloc'])}
    assert hosts['pve1']['profile'] == 'Own profile' and hosts['pve2']['profile'] == 'Cluster default' and 'offline' in hosts['pve2']['node']
    assert page.locator('[data-cr-power-nohost]').count() == 1 and page.locator('[data-cr-power-memover]').count() == 1
    assert page.locator('[data-cr-power-moved]').get_attribute('title').endswith('pve1 20 kWh, pve2 10 kWh')
    assert page.locator('[data-cr-power-guessed]').count() == 1
    _no_errors(app)


def test_runtime_power_host_profiles_send_the_classic_writes(open_app):
    app = open_app()
    page = _open(app, 'power')
    _state(page, 'power', 'ok')
    page.locator('[data-cr-power-hosts]').click()
    page.locator('[data-cr-power-hostform]').wait_for(timeout=5000)
    assert page.locator('[data-cr-power-idle="pve2"]').is_disabled()
    page.locator('[data-cr-power-own="pve2"]').check()
    page.locator('[data-cr-power-idle="pve2"]').fill('12')
    page.locator('[data-cr-power-max="pve2"]').fill('95')
    page.locator('[data-cr-power-notes="pve2"]').fill('Box two')
    page.locator('[data-cr-power-own="pve1"]').uncheck()
    assert page.locator('[data-cr-md-changed="2"]').count() == 1
    page.locator('[data-cr-md-save="hosts"]').click()
    page.locator('[data-cr-power-hostform]').wait_for(state='detached', timeout=5000)
    assert app.server.bodies[f'{HOSTS}/pve2'] == [{'idle_w': 12, 'max_w': 95, 'notes': 'Box two'}]
    assert ('DELETE', f'{HOSTS}/pve1') in app.server.calls and ('PUT', f'{HOSTS}/pve1') not in app.server.calls
    assert _wait(page, lambda: len(_calls(app, 'GET', POWER_SUM)) >= 2)
    _no_errors(app)


def test_runtime_power_refused_rates_keep_the_dialog_and_say_why(open_app):
    app = open_app(routes={('PUT', POWER_RATES): (400, {'error': 'pue must be at least 1'})})
    page = _open(app, 'power')
    _state(page, 'power', 'ok')
    page.locator('[data-cr-power-rates]').click()
    pue = page.locator('[data-cr-md-field="pue"]')
    pue.wait_for(timeout=5000)
    pue.fill('0.5')
    page.locator('[data-cr-md-save="power"]').click()
    page.get_by_text('pue must be at least 1').first.wait_for(timeout=5000)
    assert pue.is_visible() and app.server.bodies[POWER_RATES][-1]['pue'] == 0.5


# --- Network Topology ---------------------------------------------------------------------------

def test_runtime_topology_lanes_pick_and_unlinked_guests(open_app):
    app = open_app()
    page = _open(app, 'topology')
    assert _state(page, 'topology', 'ok') == 'ok'
    st = _stats(page, '[data-cr-net]')
    assert st['nodes'] == ['2', '1 online'] and st['bridges'][0] == '2' and st['bonds'][0] == '1' and st['orphans'][0] == '1'
    assert page.locator('[data-cr-net-lane="pve1"] [data-cr-net-chip]').count() == 2
    assert page.locator('[data-cr-net-lane="sdn"] [data-cr-net-chip="sdn:vnet1"]').count() == 1
    page.locator('[data-cr-net-chip="br:pve1:vmbr0"]').click()
    det = page.locator('[data-cr-net-detail="br:pve1:vmbr0"]')
    det.wait_for(timeout=5000)
    assert '10.0.0.11' in det.inner_text() and 'web01' in det.inner_text()
    assert page.locator('[data-cr-net-chip="br:pve1:vmbr0"]').get_attribute('aria-pressed') == 'true'
    # a table row picks the same way
    page.locator('[data-cr-net-row="sdn:vnet1"]').click()
    page.locator('[data-cr-net-detail="sdn:vnet1"]').wait_for(timeout=5000)
    assert 'zone1' in page.locator('[data-cr-net-detail="sdn:vnet1"]').inner_text()
    page.locator('[data-cr-net-orphans-toggle]').click()
    page.locator('[data-cr-net-orphan="102"]').wait_for(timeout=5000)
    _no_errors(app)


def test_runtime_topology_a_failed_read_is_not_an_empty_cluster(open_app):
    app = open_app(routes={('GET', TOPO): (500, {'error': 'cluster not connected'})})
    page = _open(app, 'topology')
    assert _state(page, 'topology', 'error') == 'error'
    assert 'cluster not connected' in page.locator('[data-cr-nc-for="net"]').inner_text()
    assert page.locator('[data-cr-net-tiles]').count() == 0


# --- classic and layout -------------------------------------------------------------------------

@pytest.mark.parametrize('mod', ['cve', 'costs', 'power', 'topology', 'api'])
def test_classic_corporate_keeps_the_classic_module(open_app, mod):
    app = open_app(layout='corporate')
    page = app.page
    _corp_cluster(page)
    page.locator('button', has_text=re.compile(r'^\s*Reports\s*$')).first.click()
    page.locator('.corp-tab-strip button', has_text=TAB[mod]).first.click()
    mark = {'cve': 'Scan All Nodes', 'costs': 'Cost by Node', 'power': 'Per host', 'topology': 'Click any element',
            'api': 'Top endpoints by total time'}[mod]
    page.get_by_text(mark).first.wait_for(timeout=8000)
    assert page.locator(ROOTS[mod]).count() == 0


_NO_SIDEWAYS = '() => document.scrollingElement.scrollWidth <= window.innerWidth'
_CLIPPED = """() => {
    const out = [];
    for (const th of document.querySelectorAll('.cr-md [data-cr-table] thead th[data-cr-col]')) {
        let p = th.parentElement;
        while (p && getComputedStyle(p).overflowX === 'visible') p = p.parentElement;
        if (p && th.getBoundingClientRect().right > p.getBoundingClientRect().right + 1) out.push(th.dataset.crCol);
    }
    return out;
}"""


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_the_modules_without_sideways_scroll(open_app, firefox, browser, engine, width):
    app = open_app(viewport=(width, 900), br=firefox if engine == 'firefox' else browser)
    page = _open(app, 'cve')
    page.locator('[data-cr-cve-scan]').click()
    _state(page, 'cve', 'ok')
    bad = {}
    for mod, want in (('cve', 'ok'), ('costs', 'ok'), ('power', 'ok'), ('topology', 'ok'), ('api', 'ok')):
        if mod != 'cve':
            page.locator('.corp-tab-strip button', has_text=TAB[mod]).first.click()
            page.locator(ROOTS[mod]).first.wait_for(timeout=8000)
        assert _state(page, mod, want) == want, mod
        page.wait_for_timeout(300)
        if not page.evaluate(_NO_SIDEWAYS):
            bad[mod] = 'page'
        clipped = page.evaluate(_CLIPPED)
        if clipped:
            bad[mod] = clipped
    assert bad == {}
    _no_errors(app)
