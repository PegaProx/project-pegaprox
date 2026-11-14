"""The classic drift tab says when it does not know.

- A failed read of the status or of the events drew "No open drift events. Cluster
  matches baseline.": the list starts empty and only an answer with events replaced it.
  The tab now says the read failed, with the server's reason and a retry, and drops what
  it showed before; "matches baseline" needs the whole open list read and every kind
  compared with a baseline. Until the first scan after a start nothing was compared, and
  the tab says that no scan has run yet instead of "not every kind was compared".
- A failed read of the policy checks only hid their panel; it now says they could not be
  read, and a failed refresh drops the checks it showed.
- Another cluster picked: the last one's rows, counts and checks are gone at once, and an
  answer that a newer read overtook (an earlier cluster or filter) is dropped.
- "Scan now" answers HTTP 200 with status 'skipped' when the cluster is offline, did not
  answer or is being scanned already, and the tab toasted "Scan complete". It says the scan
  was skipped and why.
- The description said "nightly"; the scanner runs every SCAN_INTERVAL (6 hours).

Runtime tests drive the built bundle in headless Chromium (and Firefox for the new box)
against the fake server of tests/test_ha_ui.py; they skip where Playwright is not installed.
NS Nov 2026
"""
import os
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, SSE_TOKEN, TOASTS_JS, VM, _App, _FakeServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEW_KEYS = ('driftScanSkipped', 'driftSkipNoAnswer', 'driftReadFailed', 'driftNoOpenUnchecked',
            'driftNoScanYet', 'driftScanRunning', 'driftPolicyReadFailed')


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _drift_tab_src():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('function DriftTab(')
    return src[start:src.index('// NS Oct 2026 - the evidence bundle', start)]


def _lang_blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{', src, re.M)]
    return {lang: src[a:(starts[i + 1][0] if i + 1 < len(starts) else len(src))]
            for i, (a, lang) in enumerate(starts)}


def _value(block, key):
    found = re.findall(rf'''^\s*{key}: (?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"),$''', block, re.M)
    return [a or b for a, b in found]


# --- source ---------------------------------------------------------------------------------

def test_every_new_word_is_in_every_language_once():
    blocks = _lang_blocks()
    assert set(LANGS) <= set(blocks)
    en = {k: _value(blocks['en'], k) for k in NEW_KEYS}
    for lang in LANGS:
        for key in NEW_KEYS:
            got = _value(blocks[lang], key)
            assert len(got) == 1 and got[0].strip(), (lang, key, got)
            if lang != 'en':
                assert got != en[key], (lang, key, 'left in English')
    for key in NEW_KEYS:
        assert f"t('{key}')" in _drift_tab_src(), key


def test_the_description_names_the_interval_the_scanner_runs_at():
    from pegaprox.api import drift
    hours = drift.SCAN_INTERVAL // 3600
    assert drift.SCAN_INTERVAL == hours * 3600
    blocks = _lang_blocks()
    for lang in LANGS:
        desc = _value(blocks[lang], 'driftDetectionDesc')
        assert len(desc) == 1, (lang, desc)
        assert str(hours) in desc[0], (lang, desc[0])
        assert 'nightly' not in desc[0].lower(), (lang, desc[0])
    assert f'every {hours} hours' in _value(blocks['en'], 'driftDetectionDesc')[0]
    tab = _drift_tab_src()
    assert f"'Snapshots cluster config every {hours} hours." in tab and 'nightly' not in tab
    assert 'Nightly' not in _read('README.md').split('Config Drift Detection**', 1)[1].split('\n', 1)[0]


def test_no_dash_in_what_this_change_added():
    tab = _drift_tab_src()
    added = [line for line in tab.splitlines() if 'NS Nov 2026' in line or 'readState' in line
             or 'policyRead' in line or 'readSeq' in line or any(k in line for k in NEW_KEYS)]
    blocks = _lang_blocks()
    for lang in LANGS:
        added += [line for line in blocks[lang].splitlines()
                  if any(f'{k}:' in line for k in NEW_KEYS + ('driftDetectionDesc',))]
    assert len(added) > 9 * 5
    for line in added:
        assert '\u2014' not in line and '\u2013' not in line, line


def test_the_bundle_was_rebuilt():
    html = _read('web', 'index.html')
    for compiled in ("t('driftReadFailed')||", "t('driftScanSkipped')||", "t('driftNoOpenUnchecked')||",
                     "t('driftNoScanYet')||", "t('driftScanRunning')||", "t('driftPolicyReadFailed')||",
                     "'Snapshots cluster config every 6 hours.", 'data-drift-read-failed',
                     'data-drift-policy-read-failed'):
        assert compiled in html, compiled
    assert 'Snapshots cluster config nightly' not in html


# --- runtime --------------------------------------------------------------------------------

KINDS = ['vm_config', 'storage', 'network', 'cluster_options', 'firewall', 'ha_rules', 'backup_jobs', 'access']
EVENT = {'id': 31, 'cluster_id': 'c1', 'kind': 'vm_config', 'scope': 'qemu/205', 'severity': 'warning',
         'summary': 'vm_config qemu/205: changed', 'detected_at': '2026-10-05T10:00:00', 'status': 'open',
         'category': 'deviation', 'diff': [{'path': 'cores', 'op': 'changed', 'before': 2, 'after': 4}]}


def _status(kinds=None, baselines=40, open_total=0, last_scan_at='2026-10-05T10:00:00', cid='c1'):
    return {'cluster_id': cid, 'open_total': open_total, 'baselines': baselines,
            'last_event_at': None, 'by_kind': {}, 'by_severity': {'critical': 0, 'warning': 0, 'info': 0},
            'by_category': {'deviation': 0, 'policy_violation': 0, 'incident': 0}, 'planned': 0,
            'kinds': kinds if kinds is not None else {k: 'checked' for k in KINDS},
            'coverage': {}, 'last_scan_at': last_scan_at}


STATUS = ('GET', '/api/clusters/c1/drift/status')
EVENTS = ('GET', '/api/clusters/c1/drift/events')
SCAN = ('POST', '/api/clusters/c1/drift/scan')
POLICY = ('GET', '/api/clusters/c1/drift/policy')
NO_CHECKS = {'checks': [], 'last_scan_at': None}
# the compliance tab, its drift sub tab, the heading of the drift view
TAB = {'en': ('Compliance', 'Config Drift Detection', 'Config Drift Detection'),
       'pl': ('Zgodność', 'Wykrywanie zmian konfiguracji', 'Wykrywanie zmian konfiguracji')}


@pytest.fixture(scope='module')
def engines():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    out = {}
    for name in ('chromium', 'firefox'):
        try:
            out[name] = getattr(pw, name).launch(headless=True)
        except Exception:
            out[name] = None
    if not out['chromium']:
        pw.stop()
        pytest.skip('no Chromium for Playwright')
    yield out
    for br in out.values():
        if br:
            br.close()
    pw.stop()


@pytest.fixture
def open_app(engines):
    apps = []

    def _open(reads, layout='modern', engine='chromium', **kw):
        if not engines.get(engine):
            pytest.skip(f'no {engine} for Playwright')
        extra = dict(SSE_TOKEN)
        # an answered policy read unless the test says otherwise
        extra[POLICY] = (200, NO_CHECKS)
        extra.update(reads)
        kw.setdefault('role', 'standalone')
        server = _FakeServer(clusters=[CLUSTER], resources=[VM], extra=extra, layout=layout, **kw)
        app = _App(engines[engine], server)
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _tab(page, language='en'):
    """The drift tab, from its heading down; the same markup before and after the change."""
    return page.locator('h2', has_text=TAB[language][2]).locator(
        'xpath=ancestor::div[contains(@class,"space-y-4")][1]')


def _settle(app, language='en', events_before=0, answered=True):
    """Until the reads came back and were drawn: the events read reached the server (unless the
    test cut the line) and the refresh button, which is disabled while they run, is free again."""
    page = app.page
    for _ in range(80):
        if not answered or app.server.calls.count(EVENTS) > events_before:
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(300)
    refresh = _tab(page, language).locator('xpath=(./div[1]//button)[last()]')
    for _ in range(80):
        if refresh.is_enabled():
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(200)


def _open_drift(app, layout='modern', language='en', answered=True):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text='Config Drift').first.click()
    else:
        compliance, drift = TAB[language][:2]
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text=re.compile(rf'^\s*{compliance}\s*$')).first.click()
        page.locator('button', has_text=re.compile(rf'^\s*{drift}\s*$')).first.click()
    page.locator('h2', has_text=TAB[language][2]).first.wait_for(timeout=8000)
    _settle(app, language, answered=answered)
    return page


def _errors(app, allow=()):
    return [e for e in app.errors if not any(a in e for a in allow)]


FAILED = {
    'events500': ({STATUS: (200, _status()), EVENTS: (500, {'error': 'internal error'})}, 'internal error'),
    'events403': ({STATUS: (200, _status()), EVENTS: (403, {'error': 'Permission denied: admin.audit'})},
                  'Permission denied: admin.audit'),
    'events404': ({STATUS: (200, _status()), EVENTS: (404, {'error': 'cluster not found'})}, 'cluster not found'),
    'status500': ({STATUS: (500, {'error': 'internal error'}), EVENTS: (200, {'events': []})}, 'internal error'),
    'both_offline': ({}, None),
}


@pytest.mark.parametrize('case', sorted(FAILED))
@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_failed_read_is_never_matches_baseline(open_app, layout, case):
    reads, reason = FAILED[case]
    app = open_app(reads, layout=layout)
    if case == 'both_offline':
        app.page.route('**/api/clusters/c1/drift/**', lambda route: route.abort())
    page = _open_drift(app, layout, answered=case != 'both_offline')
    shown = _tab(page).inner_text()
    assert 'Cluster matches baseline' not in shown and 'No open drift events' not in shown, shown
    box = page.locator('[data-drift-read-failed]')
    assert box.is_visible()
    text = box.inner_text()
    assert 'could not be read' in text and 'does not know whether the cluster matches its baseline' in text
    if reason:
        assert reason in text, text
    assert box.get_by_role('button', name='Retry').is_visible()
    assert page.locator('[data-drift-empty]').count() == 0
    if case.startswith('status'):
        # no counts without a status
        assert page.locator('[data-drift-kind]').count() == 0
    assert not _errors(app, allow=('authFetch err',)), app.errors


def test_runtime_retry_reads_again_and_a_good_answer_replaces_the_box(open_app):
    app = open_app({STATUS: (200, _status()), EVENTS: (500, {'error': 'internal error'})})
    page = _open_drift(app)
    before = app.server.calls.count(EVENTS)
    app.server.extra[EVENTS] = (200, {'events': [EVENT]})
    page.locator('[data-drift-read-failed]').get_by_role('button', name='Retry').click()
    page.get_by_text('qemu/205').first.wait_for(timeout=5000)
    assert app.server.calls.count(EVENTS) == before + 1
    assert page.locator('[data-drift-read-failed]').count() == 0
    assert not app.errors, app.errors


def test_runtime_a_failed_refresh_drops_what_was_shown(open_app):
    app = open_app({STATUS: (200, _status(open_total=1)), EVENTS: (200, {'events': [EVENT]})})
    page = _open_drift(app)
    page.get_by_text('qemu/205').first.wait_for(timeout=5000)
    assert page.locator('[data-drift-kind]').count() == 8
    app.server.extra[EVENTS] = (500, {'error': 'internal error'})
    app.server.extra[STATUS] = (500, {'error': 'internal error'})
    before = app.server.calls.count(EVENTS)
    page.locator('button', has_text='Scan now').locator('xpath=following-sibling::button[1]').click()
    _settle(app, events_before=before)
    assert page.get_by_text('qemu/205').count() == 0
    assert page.locator('[data-drift-kind]').count() == 0
    assert page.locator('[data-drift-read-failed]').is_visible()
    assert not app.errors, app.errors


NO_SCAN = 'No scan has run since this server started. Use "Scan now".'


@pytest.mark.parametrize('kinds,baselines,kind_filter,want', [
    (None, 40, '', 'No open drift events. Cluster matches baseline.'),
    ({**{k: 'checked' for k in KINDS}, 'firewall': 'not_checked'}, 40, '',
     'No open drift events, but not every kind was compared with a baseline.'),
    ({**{k: 'checked' for k in KINDS}, 'network': 'partial'}, 40, '',
     'No open drift events, but not every kind was compared with a baseline.'),
    ({**{k: 'checked' for k in KINDS}, 'access': 'no_baseline'}, 40, '',
     'No open drift events, but not every kind was compared with a baseline.'),
    ({}, 40, '', NO_SCAN),
    ({}, 0, '', NO_SCAN),
    (None, 0, '', 'No open drift events, but not every kind was compared with a baseline.'),
    (None, 40, 'storage', 'No events for this filter.'),
], ids=['all_checked', 'not_checked', 'partial', 'kind_no_baseline', 'no_scan_yet', 'no_scan_no_baseline',
        'no_baseline', 'kind_filter'])
def test_runtime_matches_baseline_only_when_everything_was_compared(open_app, kinds, baselines, kind_filter, want):
    # the kinds live in the server's memory: empty, and no last_scan_at, until it scanned
    last = None if kinds == {} else '2026-10-05T10:00:00'
    app = open_app({STATUS: (200, _status(kinds, baselines, last_scan_at=last)), EVENTS: (200, {'events': []})})
    page = _open_drift(app)
    if kind_filter:
        before = app.server.calls.count(EVENTS)
        page.locator('[data-drift-filter="kind"]').select_option(kind_filter)
        _settle(app, events_before=before)
    shown = _tab(page).inner_text()
    if want != 'No open drift events. Cluster matches baseline.':
        assert 'Cluster matches baseline' not in shown, shown
    assert want in shown, shown
    if want == NO_SCAN:
        assert 'not every kind was compared' not in shown, shown
    assert page.locator('[data-drift-read-failed]').count() == 0
    assert not app.errors, app.errors


SKIPS = {
    'offline': ({'error': 'cluster offline', 'status': 'skipped'},
                'Scan skipped, nothing was compared: Cluster unreachable', 'warning'),
    'no_answer': ({'error': 'cluster did not answer', 'status': 'skipped'},
                  'Scan skipped, nothing was compared: Cluster did not answer', 'warning'),
    'not_found': ({'error': 'cluster not found'}, 'Scan failed: cluster not found', 'error'),
    'running': ({'error': 'a scan of this cluster is already running', 'status': 'skipped'},
                'Scan skipped, nothing was compared: A scan of this cluster is already running', 'warning'),
}


@pytest.mark.parametrize('case', sorted(SKIPS))
@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_skipped_scan_is_not_scan_complete(open_app, layout, case):
    answer, want, _kind = SKIPS[case]
    app = open_app({STATUS: (200, _status()), EVENTS: (200, {'events': []}), SCAN: (200, answer)}, layout=layout)
    page = _open_drift(app, layout)
    page.locator('button', has_text='Scan now').first.click()
    for _ in range(50):
        if SCAN in app.server.calls and page.evaluate(TOASTS_JS):
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(300)
    toasts = page.evaluate(TOASTS_JS)
    assert toasts and not any('Scan complete' in x for x in toasts), toasts
    assert any(want in x for x in toasts), toasts
    assert not app.errors, app.errors


def test_runtime_a_scan_that_ran_still_says_complete(open_app):
    done = {'ok': True, 'cluster_id': 'c1', 'events_count': 2, 'seeded_baselines': 0, 'unread': [],
            'kinds': {k: 'checked' for k in KINDS}, 'events': []}
    app = open_app({STATUS: (200, _status()), EVENTS: (200, {'events': []}), SCAN: (200, done)})
    page = _open_drift(app)
    page.locator('button', has_text='Scan now').first.click()
    page.get_by_text(re.compile(r'Scan complete')).first.wait_for(timeout=5000)
    assert not any('skipped' in x for x in page.evaluate(TOASTS_JS))
    assert not app.errors, app.errors


def test_runtime_the_description_says_every_six_hours(open_app):
    app = open_app({STATUS: (200, _status()), EVENTS: (200, {'events': []})})
    page = _open_drift(app)
    shown = _tab(page).inner_text()
    assert 'nightly' not in shown
    assert 'Snapshots cluster config every 6 hours.' in shown
    assert not app.errors, app.errors


def test_runtime_the_new_words_are_translated(open_app):
    app = open_app({STATUS: (200, _status()), EVENTS: (500, {'error': 'internal error'})}, language='pl')
    page = _open_drift(app, language='pl')
    text = page.locator('[data-drift-read-failed]').inner_text()
    assert 'Nie udało się odczytać stanu ani zdarzeń zmian konfiguracji' in text, text
    assert page.locator('[data-drift-read-failed]').get_by_role('button', name='Ponów').count() == 1
    assert page.get_by_text(re.compile(r'^Co 6 godzin')).count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('width', [1280, 1600])
def test_runtime_the_box_sits_in_the_tab(open_app, engine, width):
    app = open_app({STATUS: (500, {'error': 'internal error'}), EVENTS: (500, {'error': 'internal error'}),
                    POLICY: (500, {'error': 'internal error'})},
                   layout='corporate', engine=engine)
    app.page.set_viewport_size({'width': width, 'height': 1000})
    page = _open_drift(app, 'corporate')
    geo = page.evaluate('''() => {
        const box = document.querySelector('[data-drift-read-failed]').getBoundingClientRect();
        const btn = document.querySelector('[data-drift-read-failed] button').getBoundingClientRect();
        const pol = document.querySelector('[data-drift-policy-read-failed]').getBoundingClientRect();
        const head = Array.from(document.querySelectorAll('h2')).find(h => h.innerText.includes('Config Drift Detection'));
        const tab = head.closest('.space-y-4').getBoundingClientRect();
        return {box: [box.left, box.right, box.top, box.bottom], btn: [btn.left, btn.right, btn.top, btn.bottom],
                pol: [pol.left, pol.right, pol.top, pol.bottom],
                tab: [tab.left, tab.right], sw: document.documentElement.scrollWidth, iw: window.innerWidth};
    }''')
    l, r, t, b = geo['box']
    assert geo['tab'][0] - 1 <= l and r <= geo['tab'][1] + 1, geo
    # the policy box spans the tab above the other one, without touching it
    pl, pr, pt, pb = geo['pol']
    assert geo['tab'][0] - 1 <= pl and pr <= geo['tab'][1] + 1 and pr - pl > 0.9 * (r - l), geo
    assert pt < pb <= t, geo
    bl, br, bt, bb = geo['btn']
    assert l < bl and br < r and t < bt and bb < b, geo
    assert geo['sw'] <= geo['iw'], geo
    if os.environ.get('PEGAPROX_SHOT_DIR'):
        page.screenshot(path=os.path.join(os.environ['PEGAPROX_SHOT_DIR'], f'drift-read-failed-{engine}-{width}.png'))
    assert not app.errors, app.errors


def test_runtime_no_scan_time_is_no_scan_yet_either(open_app):
    app = open_app({STATUS: (200, _status(last_scan_at=None)), EVENTS: (200, {'events': []})})
    page = _open_drift(app)
    shown = _tab(page).inner_text()
    assert NO_SCAN in shown and 'Cluster matches baseline' not in shown, shown
    assert not app.errors, app.errors


# --- the policy read ------------------------------------------------------------------------

CHECK = {'id': 'firewall_cluster_enabled', 'kind': 'firewall', 'severity': 'warning', 'violations': [],
         'enabled': True, 'status': 'pass'}
POLICY_FAILED = {
    'policy500': ((500, {'error': 'internal error'}), 'internal error'),
    'policy403': ((403, {'error': 'Permission denied: admin.audit'}), 'Permission denied: admin.audit'),
    'policy_no_checks': ((200, {'error': 'something else'}), 'something else'),
    'policy_aborted': (None, None),
}


@pytest.mark.parametrize('case', sorted(POLICY_FAILED))
@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_a_failed_policy_read_says_so(open_app, layout, case):
    answer, reason = POLICY_FAILED[case]
    reads = {STATUS: (200, _status()), EVENTS: (200, {'events': []})}
    if answer:
        reads[POLICY] = answer
    app = open_app(reads, layout=layout)
    if not answer:
        app.page.route('**/api/clusters/c1/drift/policy', lambda route: route.abort())
    page = _open_drift(app, layout)
    box = page.locator('[data-drift-policy-read-failed]')
    assert box.is_visible()
    assert 'The policy checks could not be read.' in box.inner_text()
    if reason:
        assert reason in box.inner_text()
    assert page.locator('[data-drift-policy]').count() == 0
    # the rest of the tab read fine and says so
    assert page.locator('[data-drift-read-failed]').count() == 0
    assert 'No open drift events. Cluster matches baseline.' in _tab(page).inner_text()
    assert not _errors(app, allow=('authFetch err',)), app.errors


def test_runtime_a_failed_policy_refresh_drops_the_checks_it_showed(open_app):
    app = open_app({STATUS: (200, _status()), EVENTS: (200, {'events': []}),
                    POLICY: (200, {'checks': [CHECK], 'last_scan_at': None})})
    page = _open_drift(app)
    assert page.locator('[data-drift-check="firewall_cluster_enabled"]').is_visible()
    assert page.locator('[data-drift-policy-read-failed]').count() == 0
    app.server.extra[POLICY] = (500, {'error': 'internal error'})
    before = app.server.calls.count(EVENTS)
    _tab(page).locator('xpath=(./div[1]//button)[last()]').click()
    _settle(app, events_before=before)
    assert page.locator('[data-drift-check]').count() == 0
    assert page.locator('[data-drift-policy-read-failed]').is_visible()
    assert not app.errors, app.errors


def test_runtime_the_policy_box_is_translated(open_app):
    app = open_app({STATUS: (200, _status()), EVENTS: (200, {'events': []}),
                    POLICY: (500, {'error': 'internal error'})}, language='pl')
    page = _open_drift(app, language='pl')
    assert 'Nie udało się odczytać kontroli polityki.' in page.locator('[data-drift-policy-read-failed]').inner_text()
    assert not app.errors, app.errors


# --- another cluster, an answer that was overtaken ------------------------------------------

CLUSTER2 = dict(CLUSTER, id='c2', name='Zweitcluster', display_name='Zweitcluster', host='10.0.0.2')
STATUS2 = ('GET', '/api/clusters/c2/drift/status')
EVENTS2 = ('GET', '/api/clusters/c2/drift/events')
POLICY2 = ('GET', '/api/clusters/c2/drift/policy')


class _Hold:
    """Holds back the requests `match` picks while on; release() lets the fake server answer
    them with what it holds at that moment."""

    def __init__(self, page, match):
        self.routes, self.on = [], True
        page.route(match, self._handle)

    def _handle(self, route):
        if self.on:
            self.routes.append(route)
        else:
            route.fallback()

    def release(self, server):
        self.on = False
        held, self.routes = self.routes, []
        for route in held:
            server.handle(route)


def _wait(page, test, what, tries=80):
    for _ in range(tries):
        if test():
            return
        page.wait_for_timeout(100)
    raise AssertionError(f'never: {what}')


def _pick_cluster(page, layout, cid, name):
    if layout == 'cloud':
        # the cloud shell keeps the tab mounted and hands it the new id
        page.locator('.cloud-cluster-select').select_option(cid)
    else:
        page.get_by_text(name).first.click()


@pytest.fixture
def two_clusters(engines):
    """The drift tab of c1 with a row, a check and its tiles drawn, and the next read of c1's
    and of c2's events held back. Modern and corporate mount the tab again for another
    cluster; the cloud shell keeps it mounted and hands it the new id."""
    if not engines.get('chromium'):
        pytest.skip('no Chromium for Playwright')
    made = []

    def _make(layout):
        extra = dict(SSE_TOKEN)
        extra.update({STATUS: (200, _status(open_total=1)), EVENTS: (200, {'events': [EVENT]}),
                      POLICY: (200, {'checks': [CHECK], 'last_scan_at': None}),
                      STATUS2: (200, _status(cid='c2')), EVENTS2: (200, {'events': []}),
                      POLICY2: (200, NO_CHECKS)})
        server = _FakeServer(clusters=[CLUSTER, CLUSTER2], resources=[VM], extra=extra, layout=layout,
                             role='standalone')
        app = _App(engines['chromium'], server)
        made.append(app)
        page = _open_drift(app, layout)
        page.get_by_text('qemu/205').first.wait_for(timeout=5000)
        assert page.locator('[data-drift-kind]').count() == 8
        assert page.locator('[data-drift-check]').count() == 1
        first = _Hold(page, lambda url: '/api/clusters/c1/drift/events' in url)
        second = _Hold(page, lambda url: '/api/clusters/c2/drift/events' in url)
        # a refresh of c1 that is still on its way when c2 is picked
        _tab(page).locator('xpath=(./div[1]//button)[last()]').click()
        _wait(page, lambda: first.routes, 'the refresh of c1 went out')
        _pick_cluster(page, layout, 'c2', 'Zweitcluster')
        _wait(page, lambda: second.routes, 'the read of c2 went out')
        page.wait_for_timeout(300)
        return app, page, first, second
    yield _make
    for app in made:
        app.ctx.close()


MATCHES = 'No open drift events. Cluster matches baseline.'


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_another_cluster_drops_the_last_ones_rows_at_once(two_clusters, layout):
    app, page, first, second = two_clusters(layout)
    # nothing of c1 while c2 loads
    assert page.locator('h2', has_text='Config Drift Detection').first.is_visible()
    assert page.get_by_text('qemu/205').count() == 0
    assert page.locator('[data-drift-kind]').count() == 0
    assert page.locator('[data-drift-check]').count() == 0
    assert page.locator('[data-drift-empty="loading"]').is_visible()
    second.release(app.server)
    _wait(page, lambda: page.get_by_text(MATCHES).count() == 1, 'c2 drawn')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_last_clusters_late_answer_is_not_drawn_over_the_new_one(two_clusters, layout):
    app, page, first, second = two_clusters(layout)
    second.release(app.server)
    _wait(page, lambda: page.get_by_text(MATCHES).count() == 1, 'c2 drawn')
    # c1's answer comes in after c2's
    first.release(app.server)
    page.wait_for_timeout(800)
    assert page.get_by_text('qemu/205').count() == 0
    assert page.get_by_text(MATCHES).count() == 1
    assert page.locator('[data-drift-check]').count() == 0
    assert page.locator('[data-drift-kind]').count() == 8
    assert _tab(page).locator('xpath=(./div[1]//button)[last()]').is_enabled()
    assert not app.errors, app.errors


def test_runtime_an_answer_for_an_earlier_filter_is_not_drawn_over_the_later_one(open_app):
    app = open_app({STATUS: (200, _status()), EVENTS: (200, {'events': []})})
    page = _open_drift(app)
    held = _Hold(page, lambda url: '/drift/events' in url and 'kind=storage' in url)
    page.locator('[data-drift-filter="kind"]').select_option('storage')
    _wait(page, lambda: held.routes, 'the storage read went out')
    before = app.server.calls.count(EVENTS)
    page.locator('[data-drift-filter="kind"]').select_option('')
    _settle(app, events_before=before)
    assert 'No open drift events. Cluster matches baseline.' in _tab(page).inner_text()
    # the earlier read, for storage, answers last and would bring a row
    app.server.extra[EVENTS] = (200, {'events': [EVENT]})
    held.release(app.server)
    page.wait_for_timeout(800)
    assert page.get_by_text('qemu/205').count() == 0
    assert 'No open drift events. Cluster matches baseline.' in _tab(page).inner_text()
    assert not app.errors, app.errors
