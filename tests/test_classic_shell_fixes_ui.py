"""Classic shell: the task bar on a task that ended badly or with warnings, the Refresh of
the corporate cluster header, the affinity toggle of the topology, the task log of an
XCP-ng task, and Escape on PegaProx Settings and My Profile.

- The task list never marked a task failed (core/manager.py get_tasks asked getattr() of
  a dict), so a backup with "job errors" was green and not counted.
- Refresh called loadTabData, which only exists in the node modal: the click threw.
- The affinity toggle called authFetch, which TopologyView does not have: the click threw
  before it toggled. A refused or failed read now says so instead of drawing no edges.
- An XCP-ng task log came back as one character per line (tests/test_xcpng_task_log_lines.py).
- Escape closed neither Settings nor My Profile.

The runtime tests drive the built bundle against the fake server of tests/test_ha_ui.py
in headless Chromium, the topology and Escape in Firefox too; they skip where Playwright
or the browser is not installed.
NS Nov 2026
"""
import re

import pytest

from test_ha_ui import CLUSTER, LANGS, NODE_METRICS, SSE_TOKEN, VM, _App, _blocks, _FakeServer, _read

VM2 = dict(VM, vmid=101, name='db01')


# -- translations ----------------------------------------------------------------------------

# what t('disabled') showed before the duplicate went: the later definition, in every language
DISABLED = {'de': 'deaktiviert', 'en': 'disabled', 'zh': '已禁用', 'pl': 'wyłączone', 'fr': 'désactivé',
            'es': 'desactivado', 'pt': 'desativado', 'ko': '비활성화', 'it': 'Disabilitato', 'ru': 'выключено'}


@pytest.mark.parametrize('lang', LANGS)
def test_disabled_is_defined_once_with_the_value_it_had(lang):
    found = re.findall(r"^ +disabled: '([^']*)',$", _blocks()[lang], re.M)
    assert found == [DISABLED[lang]], (lang, found)


@pytest.mark.parametrize('lang', LANGS)
def test_the_unread_affinity_note_is_translated_next_to_the_legend(lang):
    block = _blocks()[lang]
    found = re.findall(r"^ +affinityRulesUnread: '((?:[^'\\]|\\.)+)',$", block, re.M)
    assert len(found) == 1, (lang, found)
    if lang != 'en':
        assert found[0] != re.findall(r"^ +affinityRulesUnread: '([^']+)',$", _blocks()['en'], re.M)[0], lang
    # right under the affinity legend, far from the pinned tail of the block
    lines = block.split('\n')
    at = next(i for i, ln in enumerate(lines) if ln.strip().startswith('affinityRulesUnread:'))
    assert lines[at - 1].strip().startswith('legendAff:'), lines[at - 1]
    assert at < len(lines) - 100


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html')
    for needle in ('function useEscapeToClose(', 'affinityRulesUnread', 'data-affinity-unread',
                   'The affinity rules could not be read'):
        assert needle in bundle, needle
    assert "loadTabData('overview')" not in bundle


# -- runtime ---------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def browsers():
    state = {'pw': None}
    started = {}

    def get(name):
        if name in started:
            return started[name]
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            pytest.skip('Playwright is not installed')
        if state['pw'] is None:
            try:
                state['pw'] = sync_playwright().start()
            except Exception as e:
                pytest.skip(f'Playwright does not start here: {e}')
        try:
            started[name] = getattr(state['pw'], name).launch(headless=True)
        except Exception as e:
            pytest.skip(f'no {name} for Playwright: {e}')
        return started[name]
    yield get
    for br in started.values():
        br.close()
    if state['pw'] is not None:
        state['pw'].stop()


@pytest.fixture
def open_app(browsers):
    apps = []

    def _open(engine='chromium', extra=None, **kw):
        reads = dict(SSE_TOKEN)
        reads.update(extra or {})
        kw.setdefault('role', 'standalone')
        kw.setdefault('clusters', [CLUSTER])
        kw.setdefault('resources', [VM, VM2])
        kw.setdefault('metrics', NODE_METRICS)
        app = _App(browsers(engine), _FakeServer(extra=reads, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _select(app, layout):
    page = app.page
    if layout == 'corporate':
        page.locator('.corp-tree-item', has_text='Testi').first.click()
    else:
        page.get_by_text('Testi').first.click()
    page.wait_for_timeout(600)
    return page


def _paths_since(app, n):
    return [p for _m, p in app.server.calls[n:]]


# --- the task bar ---

@pytest.fixture
def pve_tasks(monkeypatch):
    """The list the server sends for real /cluster/tasks rows (manager.get_tasks)."""
    import pegaprox.api.helpers as helpers
    from test_cluster_tasks_exit_status import _mgr, _row
    monkeypatch.setattr(helpers, 'get_task_user', lambda upid: 'admin')
    rows = [_row(1, status='job errors'), _row(2, kind='qmstart', vmid='100', status='OK'),
            _row(3, status='WARNINGS: 1'), _row(4, kind='qmigrate', vmid='100', end=False)]
    return _mgr(rows).get_tasks(limit=50)


ROWS_JS = '''() => Array.from(document.querySelectorAll('.pp-taskbar tbody tr')).map(tr => {
    const dot = tr.querySelector('td span'), chip = tr.querySelector('td:last-child span');
    return {chip: chip ? chip.innerText.trim() : '', dot: dot ? dot.className : '',
            title: chip ? (chip.getAttribute('title') || '') : ''};
})'''


def _open_bar(page):
    page.locator('.pp-taskbar').get_by_text('Tasks', exact=True).first.click()
    page.locator('.pp-taskbar tbody tr').first.wait_for(timeout=5000)
    page.wait_for_timeout(300)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_task_that_ended_badly_is_counted_and_drawn_red(open_app, pve_tasks, layout):
    app = open_app(layout=layout, extra={('GET', '/api/clusters/c1/tasks'): (200, pve_tasks)})
    page = _select(app, layout)
    bar = page.locator('.pp-taskbar')
    bar.get_by_text(re.compile(r'^\s*1 failed\s*$', re.I)).first.wait_for(timeout=8000)
    _open_bar(page)
    rows = {r['chip']: r for r in page.evaluate(ROWS_JS)}
    # the failed chip says what Proxmox said (the server status is 'failed'), like Cloud
    assert set(rows) == {'job errors', 'OK', 'WARNINGS: 1', 'running'}, rows
    assert 'bg-red-500' in rows['job errors']['dot']
    assert 'bg-green-500' in rows['OK']['dot']
    # ended with warnings: yellow, neither failed nor plain green
    assert 'bg-yellow-500' in rows['WARNINGS: 1']['dot'], rows['WARNINGS: 1']
    assert 'bg-blue-500' in rows['running']['dot']
    # and in the tooltip too, as before
    assert rows['job errors']['title'] == 'job errors'
    # the "failed tasks" filter finds it
    bar.locator('select').first.select_option('error')
    page.wait_for_timeout(200)
    assert [r['chip'] for r in page.evaluate(ROWS_JS)] == ['job errors']
    assert not app.errors, app.errors


def test_runtime_the_corporate_recent_tasks_colour_a_warning_yellow(open_app, pve_tasks):
    app = open_app(layout='corporate', extra={('GET', '/api/clusters/c1/tasks'): (200, pve_tasks)})
    page = _select(app, 'corporate')
    page.locator('.corp-tasks-item').first.wait_for(timeout=8000)
    dots = page.evaluate('''() => Array.from(document.querySelectorAll('.corp-tasks-item')).map(i =>
        [i.querySelector('.corp-tasks-desc').innerText.trim(), getComputedStyle(i.querySelector('.corp-tasks-status')).backgroundColor])''')
    colours = [c for _d, c in dots]
    # red for the failed backup, yellow for the one with warnings, green for OK, blue running
    assert sorted(colours) == sorted(['rgb(245, 79, 71)', 'rgb(247, 180, 40)', 'rgb(96, 181, 21)',
                                      'rgb(73, 175, 217)']), dots
    assert not app.errors, app.errors


def test_runtime_the_cloud_task_list_keeps_the_words_of_a_failed_task(open_app, pve_tasks):
    app = open_app(layout='cloud', extra={('GET', '/api/clusters/c1/tasks'): (200, pve_tasks)})
    page = app.page
    page.locator('.cloud-shell button', has_text=re.compile(r'^\s*Tasks\s*$')).first.click()
    page.locator('.cloud-table-row').first.wait_for(timeout=8000)
    pills = page.evaluate('''() => Array.from(document.querySelectorAll('.cloud-table-row')).map(r =>
        r.querySelector('td').innerText.trim())''')
    # the server says 'failed' now; the pill still says what Proxmox said
    assert sorted(pills) == sorted(['job errors', 'OK', 'WARNINGS: 1', 'Running']), pills
    assert not app.errors, app.errors


def test_runtime_an_xcpng_task_log_shows_its_lines(open_app, api, seed):
    """The log as the real route answers it for a real XCP-ng manager."""
    from test_xcpng_task_log_lines import CL, REF, _task, _xcpng
    x = _xcpng({REF: _task(status='failed', error='VM_BAD_POWER_STATE')})
    x.current_host = 'h1'
    api.set_manager(CL, x)
    body = api.as_user(seed.user('root', role='admin')).get(f'/api/clusters/{CL}/nodes/h1/tasks/{REF}/log').get_json()
    # served under the PVE cluster of the fake server: the task bar reads any provider the same way
    app = open_app(layout='modern', extra={('GET', '/api/clusters/c1/tasks'): (200, x.get_tasks()),
                                           ('GET', f'/api/clusters/c1/nodes/h1/tasks/{REF}/log'): (200, body)})
    page = _select(app, 'modern')
    _open_bar(page)
    page.locator('.pp-taskbar tbody tr').first.click()
    pre = page.locator('pre.whitespace-pre-wrap').first
    pre.get_by_text('Action: start').wait_for(timeout=5000)
    lines = pre.inner_text().strip().split('\n')
    assert lines == ['Action: start', 'Status: failed', 'VMID: 101', 'Started: 2026-11-01T09:00:00',
                     'Error: VM_BAD_POWER_STATE'], lines[:8]
    assert not app.errors, app.errors


# --- Refresh in the corporate cluster header ---

def test_runtime_the_cluster_header_refresh_reads_the_cluster_again(open_app):
    app = open_app(layout='corporate')
    page = _select(app, 'corporate')
    button = page.locator('.corp-content-header button', has_text='Refresh')
    button.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    before = len(app.server.calls)
    button.click()
    page.wait_for_timeout(800)
    asked = set(_paths_since(app, before))
    for path in ('/api/clusters/c1/metrics', '/api/clusters/c1/resources', '/api/clusters/c1/datastores',
                 '/api/clusters/c1/pools', '/api/clusters/c1/tasks'):
        assert path in asked, (path, sorted(asked))
    assert any(p.startswith('/api/clusters/c1/networks') for p in asked), sorted(asked)
    assert not app.errors, app.errors


# --- the affinity toggle of the topology ---

def _topology(app, layout):
    page = _select(app, layout)
    page.locator('button', has_text='Resources').first.click()
    page.locator('button:not([data-corp-tool])', has_text=re.compile(r'^\s*Topology\s*$')).first.click()
    toggle = page.locator('button', has_text=re.compile(r'^[○●] Affinity$'))
    toggle.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    return page, toggle


RULES = {('GET', '/api/clusters/c1/affinity-rules'): (200, {'rules': [
    {'id': 'r1', 'type': 'together', 'vms': [100, 101], 'enabled': True}]})}


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_affinity_toggle_draws_the_rules(open_app, engine, layout):
    app = open_app(engine=engine, layout=layout, extra=RULES)
    page, toggle = _topology(app, layout)
    toggle.click()
    page.locator('svg line[stroke="#60b515"]').first.wait_for(state='attached', timeout=5000)
    assert toggle.inner_text().startswith('●')
    assert ('GET', '/api/clusters/c1/affinity-rules') in app.server.calls
    assert page.locator('[data-affinity-unread]').count() == 0
    toggle.click()
    page.wait_for_timeout(200)
    assert toggle.inner_text().startswith('○') and page.locator('svg line[stroke="#60b515"]').count() == 0
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('answer', [(500, {'error': 'boom'}), (403, {'error': 'Access denied'}),
                                    (200, {'rules': [], 'error': 'Alert operation failed'})])
def test_runtime_an_unread_rule_list_is_not_shown_as_no_rules(open_app, engine, answer):
    app = open_app(engine=engine, layout='corporate',
                   extra={('GET', '/api/clusters/c1/affinity-rules'): answer})
    page, toggle = _topology(app, 'corporate')
    toggle.click()
    note = page.locator('[data-affinity-unread]')
    note.wait_for(timeout=5000)
    assert note.inner_text().strip() == 'The affinity rules could not be read'
    # on the toolbar line of the toggle, inside the page width
    box, tbox = note.bounding_box(), toggle.bounding_box()
    assert abs((box['y'] + box['height'] / 2) - (tbox['y'] + tbox['height'] / 2)) < 6, (box, tbox)
    assert box['x'] + box['width'] <= page.viewport_size['width']
    assert page.locator('svg line[stroke="#60b515"]').count() == 0
    # off and on again asks again; an answer now clears the note
    app.server.extra.update(RULES)
    toggle.click()
    toggle.click()
    page.locator('svg line[stroke="#60b515"]').first.wait_for(state='attached', timeout=5000)
    assert note.count() == 0
    assert not app.errors, [e for e in app.errors]


def test_runtime_a_cluster_without_rules_shows_no_note(open_app):
    app = open_app(layout='modern', extra={('GET', '/api/clusters/c1/affinity-rules'): (200, {'rules': []})})
    page, toggle = _topology(app, 'modern')
    toggle.click()
    page.wait_for_timeout(600)
    assert toggle.inner_text().startswith('●')
    assert page.locator('[data-affinity-unread]').count() == 0
    assert not app.errors, app.errors


# --- Escape on PegaProx Settings and My Profile ---

def _settings_open(page):
    return page.get_by_text('PegaProx Settings').count() > 0


def _open_profile(app):
    page = app.page
    page.locator('[data-user-menu]').first.click()
    page.locator('button', has_text='My Profile').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Appearance\s*$')).first.wait_for(timeout=5000)


def _profile_open(page):
    return page.locator('button', has_text=re.compile(r'^\s*Appearance\s*$')).count() > 0


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_escape_closes_the_settings(open_app, engine, layout):
    app = open_app(engine=engine, layout=layout)
    app.open_settings()
    app.page.keyboard.press('Escape')
    app.page.wait_for_timeout(300)
    assert not _settings_open(app.page)
    # from a text field of the dialog as well
    app.open_settings()
    app.page.locator('button', has_text=re.compile(r'^\s*Add User\s*$')).first.click()
    field = app.page.locator('form input[type="text"]').first
    field.click()
    field.fill('newbie')
    app.page.keyboard.press('Escape')
    app.page.wait_for_timeout(300)
    assert not _settings_open(app.page)
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_escape_in_an_inner_dialog_leaves_the_settings(open_app, engine):
    app = open_app(engine=engine, layout='modern')
    page = app.page
    app.open_settings()
    page.locator('button', has_text='Cluster Groups').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Add Group\s*$')).first.click()
    page.wait_for_timeout(300)
    inner = page.locator('div.fixed.inset-0.bg-black\\/50')
    assert inner.count() == 1
    page.keyboard.press('Escape')
    page.wait_for_timeout(300)
    assert _settings_open(page) and inner.count() == 1
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_escape_on_a_select_is_the_selects(open_app, engine):
    app = open_app(engine=engine, layout='modern')
    page = app.page
    app.open_settings()
    page.locator('button', has_text=re.compile(r'^\s*Add User\s*$')).first.click()
    sel = page.locator('form select').first
    sel.focus()
    page.keyboard.press('Escape')
    page.wait_for_timeout(300)
    assert _settings_open(page)
    assert not app.errors, app.errors


def test_runtime_escape_closes_only_the_dialog_on_top(open_app):
    app = open_app(layout='modern')
    page = app.page
    app.open_settings()
    page.keyboard.press('?')
    page.get_by_text('Show keyboard shortcuts').first.wait_for(timeout=3000)
    page.keyboard.press('Escape')
    page.wait_for_timeout(300)
    assert page.get_by_text('Show keyboard shortcuts').count() == 0
    assert _settings_open(page), 'the settings under the shortcuts went with them'
    page.keyboard.press('Escape')
    page.wait_for_timeout(300)
    assert not _settings_open(page)
    assert not app.errors, app.errors


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_escape_closes_my_profile(open_app, engine, layout):
    app = open_app(engine=engine, layout=layout)
    _open_profile(app)
    app.page.keyboard.press('Escape')
    app.page.wait_for_timeout(300)
    assert not _profile_open(app.page)
    assert not app.errors, app.errors
