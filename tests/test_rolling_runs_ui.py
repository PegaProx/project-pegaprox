"""The rolling update a restart interrupted, in the Update Manager.

A run PegaProx did not live through comes back paused with the reason 'interrupted'
(tests/test_rolling_runs_survive_restart.py). The Update Manager opens by itself for a run
that waits, says which node was in which phase and that nothing goes on by itself, and
offers Continue and Cancel like for any other pause; a standby shows the run and neither
button. A cancel that could not undo everything lists what is left, and the last runs of
the cluster are a list that is read when it is opened. Modern, Corporate and Cloud share
the section.

The source checks read web/src and the bundle. The runtime tests drive the built bundle in
headless Chromium with the fake server of tests/test_ha_ui.py; they skip where Playwright
is not installed.

LW Oct 2026
"""
import copy
import json
import os
import re

import pytest

from test_ha_ui import BASE, LANGS, _App, _FakeServer, _blocks, _classes, browser  # noqa: F401
from test_rolling_options_ui_763_954 import CLUSTER, READS, _to_updates

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
STATUS = '/api/clusters/cluster_1/updates/status'
RESUME = '/api/clusters/cluster_1/updates/rolling/resume'
ROLLING = '/api/clusters/cluster_1/updates/rolling'
HISTORY = '/api/clusters/cluster_1/updates/rolling/history'

INTERRUPTED = {
    'run_id': 'r1', 'status': 'paused', 'paused_reason': 'interrupted', 'current_step': 'paused_interrupted',
    'current_node': 'pve1', 'current_index': 0, 'nodes': ['pve1', 'pve3'],
    'paused_details': {'node': 'pve1', 'phase': 'updating', 'message': 'PegaProx stopped while pve1 ...'},
    'resume_at': {'index': 0, 'phase': 'updating'}, 'started_at': '2026-10-10 03:00:00',
    'completed_nodes': [], 'skipped_nodes': [], 'failed_nodes': [], 'rebooting_nodes': [],
    'logs': ["[03:10:00] ⏸ INTERRUPTED - PegaProx stopped while pve1 (1/2) was in phase 'updating'."],
}
REPORT = [{'kind': 'maintenance', 'node': 'pve1'}, {'kind': 'ha_rules', 'rules': ['keep-apart']},
          {'kind': 'guests_stay', 'node': 'pve1', 'count': 2}]
RUNS = [
    {'run_id': 'r1', 'status': 'cancelled', 'started_at': '2026-10-10 03:00:00', 'started_by': 'root',
     'scheduled': False, 'nodes': 2, 'completed': 0, 'skipped': 0, 'failed': 1, 'cancel_report': REPORT[:1],
     'logs': ['[03:00:00] Rolling update started', '[03:20:00] === Rolling update cancelled ===']},
    {'run_id': 'r0', 'status': 'completed', 'started_at': '2026-10-03 03:00:00', 'started_by': 'scheduler',
     'scheduled': True, 'nodes': 2, 'completed': 2, 'skipped': 0, 'failed': 0, 'cancel_report': [],
     'logs': ['[03:00:00] Scheduled rolling update started']},
]


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _component():
    src = _read('web', 'src', 'security.js')
    start = src.index('function UpdateManagerSection(')
    return src[start:src.index('\n        function ', start + 10)]


def _new_code():
    """What this change added to the section."""
    comp = _component()
    parts = [comp[comp.index('// LW Oct 2026 - one line per item a cancel could not undo'):
                  comp.index('// NS: GitHub #40 - Resume a paused rolling update')],
             comp[comp.index('{/* LW Oct 2026 - what a cancel could not undo */}'):
                  comp.index('{/* Rolling Update Progress */}')],
             comp[comp.index('data-testid="rolling-paused"'):comp.index('{/* Header with cancel button */}')],
             comp[comp.index('{/* LW Oct 2026 - the last rolling updates'):comp.index('{/* Confirm Modal */}')]]
    return parts


def _used_keys():
    return sorted(set(re.findall(r"'(rollRun\w+)'", _component())))


# -- source ------------------------------------------------------------------------------------

def test_the_new_strings_are_their_own_keys():
    assert len(_used_keys()) == 24, _used_keys()


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_exists_once_per_language(lang):
    block = _blocks()[lang]
    for key in _used_keys():
        n = len(re.findall(r'^ +%s: ' % key, block, re.M))
        assert n == 1, f'{key} appears {n} times in {lang}'


def test_no_key_is_defined_that_nothing_uses():
    used = set(_used_keys())
    for lang, block in _blocks().items():
        assert set(re.findall(r'^ +(rollRun\w+): ', block, re.M)) == used, lang


def test_the_keys_sit_with_the_other_rolling_update_strings():
    for lang, block in _blocks().items():
        at = block.index('rollingUpdateCancelled:')
        assert 0 < block.index('rollRunPausedTitle:') - at < 200, lang


def test_placeholders_survive_translation():
    blocks = _blocks()
    for key in _used_keys():
        en = re.search(r'^ +%s: (.*),$' % key, blocks['en'], re.M).group(1)
        for lang, block in blocks.items():
            value = re.search(r'^ +%s: (.*),$' % key, block, re.M).group(1)
            assert sorted(re.findall(r'\{\w+\}', value)) == sorted(re.findall(r'\{\w+\}', en)), (lang, key)


def test_the_austrian_flag_stays_on_german():
    assert "{ code: 'de', flag: '\U0001F1E6\U0001F1F9'," in _read('web', 'src', 'contexts.js')


def test_no_em_dash_in_the_new_code_and_strings():
    lines = [line for block in _blocks().values() for line in block.splitlines() if 'rollRun' in line]
    for text in _new_code() + lines:
        assert '\u2014' not in text and '\u2013' not in text


def test_every_class_is_in_the_static_tailwind_build():
    css = _read('static', 'css', 'tailwind.min.css') + _read('web', 'index.html.original')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    names = set()
    for part in _new_code():
        names |= _classes(part)
    missing = sorted(n for n in names if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_no_icon_is_used_that_does_not_exist():
    icons = set(re.findall(r'^            ([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set()
    for part in _new_code():
        used |= set(re.findall(r'Icons\.([A-Z][A-Za-z0-9]*)', part))
    assert used <= icons, sorted(used - icons)


def test_the_history_is_read_when_opened_and_never_polled():
    comp = _component()
    assert comp.count('/updates/rolling/history') == 1
    poll = comp[comp.index('const getRollingStatus = async'):comp.index('// start rolling update')]
    assert 'history' not in poll
    assert 'if (open) loadRollHistory();' in comp


def test_continue_and_cancel_need_the_permission_and_an_instance_that_acts():
    banner = _component()
    banner = banner[banner.index('data-testid="rolling-paused"'):banner.index('{/* Header with cancel button */}')]
    assert ") : hasPerm('node.update') && (" in banner
    assert "{rollingUpdate.status === 'running' && hasPerm('node.update') && (" in _component()


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('rolling-interrupted', 'rolling-cancel-report', 'rolling-history', '/updates/rolling/history'):
        assert needle in bundle, needle
    for key in _used_keys():
        assert key in bundle, key


# -- runtime -----------------------------------------------------------------------------------

class _Server(_FakeServer):
    """The fake server with a rolling update that changes with Continue and Cancel."""

    def __init__(self, run=None, history=None, cancel_report=None, **kw):
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [])
        kw.setdefault('role', 'standalone')
        super().__init__(extra=dict(READS), **kw)
        self.run = copy.deepcopy(run if run is not None else INTERRUPTED)
        self.history = history if history is not None else RUNS
        self.cancel_report = cancel_report if cancel_report is not None else REPORT

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if not req.url.startswith(BASE) or path not in (STATUS, RESUME, ROLLING, HISTORY) or (
                path == ROLLING and req.method == 'POST'):
            return super().handle(route)
        self.calls.append((req.method, path))

        def answer(data, status=200):
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})

        if self.role == 'standby' and req.method != 'GET':
            return answer({'error': 'This is a standby instance.', 'code': 'HA_STANDBY'}, 409)
        if path == STATUS:
            return answer({'success': True, 'rolling_update': self.run or None, 'last_check': None})
        if path == HISTORY:
            return answer({'runs': self.history})
        if path == RESUME:
            self.run.update(status='running', paused_reason=None, paused_details=None, current_step='updating')
            return answer({'success': True, 'message': 'Resumed', 'was_paused_for': 'interrupted'})
        # the cancel of a run no worker follows: wound down at once, with what it could not undo
        self.run.update(status='cancelled', cancel_report=self.cancel_report, completed_at='2026-10-10 03:20:00')
        return answer({'success': True, 'message': 'Rolling update cancelled', 'not_undone': self.cancel_report})


@pytest.fixture
def ui(browser):  # noqa: F811
    apps = []

    def _open(layout='modern', **kw):
        app = _App(browser, _Server(layout=layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _shot(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, f'{name}.png'))


def _paused_banner(app, layout):
    _to_updates(app, layout)
    banner = app.page.locator('[data-testid="rolling-paused"]')
    # the section opens by itself for a run that waits
    banner.wait_for(timeout=8000)
    return banner


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_an_interrupted_run_says_where_and_continues(ui, layout):
    app = ui(layout=layout)
    banner = _paused_banner(app, layout)
    assert banner.get_attribute('data-reason') == 'interrupted'
    text = banner.locator('[data-testid="rolling-interrupted"]').inner_text()
    assert ('PegaProx stopped while pve1 was in the phase updating (a restart, or another instance took over).'
            in text), text
    assert 'Nothing goes on by itself. Continue looks at pve1 again' in text
    assert app.page.locator('[data-testid="rolling-paused-pill"]').inner_text().strip() == 'Paused'
    assert banner.locator('[data-testid="rolling-cancel"]').inner_text().strip() == 'Cancel Update'
    banner.scroll_into_view_if_needed()
    _shot(app, f'rolling-interrupted-{layout}')

    banner.locator('[data-testid="rolling-continue"]').click()
    app.page.wait_for_timeout(1500)
    assert ('POST', RESUME) in app.server.calls
    assert app.page.locator('[data-testid="rolling-paused"]').count() == 0
    assert app.page.locator('[data-testid="rolling-paused-pill"]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_cancel_lists_what_it_could_not_undo(ui, layout):
    app = ui(layout=layout)
    banner = _paused_banner(app, layout)
    banner.locator('[data-testid="rolling-cancel"]').click()
    report = app.page.locator('[data-testid="rolling-cancel-report"]')
    report.wait_for(timeout=8000)
    text = report.inner_text()
    assert 'Not undone' in text
    assert 'pve1 is still in maintenance - take it out on its node page' in text
    assert 'Negative affinity rules still off: keep-apart - PegaProx keeps switching them back on' in text
    assert '2 guest(s) moved off pve1 stay on the nodes they were moved to' in text
    assert [k for k in report.locator('[data-kind]').evaluate_all('els => els.map(e => e.dataset.kind)')] == [
        'maintenance', 'ha_rules', 'guests_stay']
    assert ('DELETE', ROLLING) in app.server.calls
    assert 'Rolling Update Cancelled' in app.page.locator('body').inner_text()
    _shot(app, f'rolling-cancel-report-{layout}')
    assert not app.errors, app.errors


def test_runtime_the_history_is_read_when_opened(ui):
    app = ui(layout='modern', run={})
    _to_updates(app, 'modern')
    page = app.page
    head = page.get_by_text('Update Manager').last
    if not page.locator('[data-testid="rolling-history"]').count():
        head.click()
    history = page.locator('[data-testid="rolling-history"]')
    history.wait_for(timeout=8000)
    assert ('GET', HISTORY) not in app.server.calls, 'read before anyone opened it'
    history.locator('button', has_text='Recent rolling updates').click()
    rows = history.locator('details[data-run]')
    rows.first.wait_for(timeout=8000)
    assert [r.get_attribute('data-status') for r in rows.all()] == ['cancelled', 'completed']
    first = rows.nth(0).inner_text()
    assert 'Cancelled' in first and '2026-10-10 03:00:00' in first and '0 updated, 0 skipped, 1 failed' in first
    assert 'by root' in first
    second = rows.nth(1).inner_text()
    assert 'Completed' in second and 'scheduled' in second
    rows.nth(0).locator('summary').click()
    page.wait_for_timeout(300)
    assert '=== Rolling update cancelled ===' in rows.nth(0).inner_text()
    assert 'pve1 is still in maintenance' in rows.nth(0).inner_text()
    assert app.server.calls.count(('GET', HISTORY)) == 1
    _shot(app, 'rolling-history')
    assert not app.errors, app.errors


def test_runtime_a_standby_shows_the_run_without_continue_or_cancel(ui):
    app = ui(layout='modern', role='standby')
    banner = _paused_banner(app, 'modern')
    assert 'PegaProx stopped while pve1' in banner.inner_text()
    assert banner.locator('[data-testid="rolling-continue"]').count() == 0
    assert banner.locator('[data-testid="rolling-cancel"]').count() == 0
    assert not [c for c in app.server.calls if c[0] != 'GET' and c[1] in (RESUME, ROLLING)]
    assert not app.errors, app.errors


def test_runtime_a_cancel_under_way_offers_no_buttons(ui):
    app = ui(layout='modern', run=dict(INTERRUPTED, current_step='cancelling'))
    banner = _paused_banner(app, 'modern')
    assert 'Cancelling: the nodes come out of maintenance' in banner.locator('[data-testid="rolling-cancelling"]').inner_text()
    assert banner.locator('[data-testid="rolling-continue"]').count() == 0
    assert not app.errors, app.errors


def test_runtime_another_pause_still_shows_its_own_message(ui):
    run = dict(INTERRUPTED, paused_reason='node_failure', current_step='paused_failure',
               paused_details={'node': 'pve1', 'message': 'Update failed on pve1. Verify the node is healthy.'})
    app = ui(layout='modern', run=run)
    banner = _paused_banner(app, 'modern')
    assert 'Update failed on pve1. Verify the node is healthy.' in banner.inner_text()
    assert banner.locator('[data-testid="rolling-interrupted"]').count() == 0
    assert banner.locator('[data-testid="rolling-continue"]').count() == 1
    assert not app.errors, app.errors


def test_runtime_it_speaks_german(ui):
    app = ui(layout='modern', language='de')
    page = app.page
    page.get_by_text('Testi').first.click()
    page.wait_for_timeout(500)
    page.locator('button', has_text=re.compile(r'^\s*Einstellungen\s*$')).last.click()
    banner = page.locator('[data-testid="rolling-paused"]')
    banner.wait_for(timeout=8000)
    text = banner.inner_text()
    assert 'Rolling Update pausiert' in text
    assert 'PegaProx wurde angehalten, während pve1 in der Phase updating war' in text
    assert banner.locator('[data-testid="rolling-continue"]').inner_text().strip() == 'Update fortsetzen'
    assert not app.errors, app.errors
