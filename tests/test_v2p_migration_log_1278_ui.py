"""The whole log of an ESXi migration in the Tasks & Events tab of the ESXi server (#1278).

The log panel of a migration showed the last 20 lines of it. It now reads the whole log from
GET /api/vmware/migrations/<mid>/log while it is open, every 3 s while the job runs and once
for a run that ended, and has a Download log button. The list of migrations asks for a page of
the stored ones and shows Show older migrations while the server says more follow; a run cut
off by a stop of PegaProx reads as interrupted. The Migration tab of a VM lists what runs and
what ran of that VM, not the whole history.

Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Nov 2026
"""
import json
import os
import re

import pytest

from test_ha_ui import ESXI_READS, SSE_TOKEN, _App, _classes, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
KEYS = {'v2pLogDownload': 'Download log', 'v2pLogDownloadFailed': 'The log could not be downloaded',
        'v2pLogLines': '{n} lines', 'v2pLogLoading': 'Loading the log...',
        'v2pHistoryOlder': 'Show older migrations'}


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z]{2}): \{', src, re.M)]
    ends = [pos for _, pos in starts[1:]] + [len(src)]
    return {lang: src[pos:end] for (lang, pos), end in zip(starts, ends)}


def _component():
    src = _read('web', 'src', 'dashboard.js')
    at = src.index('const ESXI_LOG_BLOCK = 500;')
    return src[at:src.index('// NS: Mar 2026 - Topology View redesign', at)]


def test_every_language_has_the_new_words_once_and_in_its_own_words():
    blocks = _blocks()
    assert list(blocks) == LANGS
    for key, english in KEYS.items():
        values = {}
        for lang, block in blocks.items():
            found = re.findall(rf"^\s*{key}: '((?:[^'\\]|\\.)+)',", block, re.M)
            assert len(found) == 1, (key, lang, found)
            values[lang] = found[0]
        assert values['en'] == english, (key, values['en'])
        assert all(v != english for lang, v in values.items() if lang != 'en'), (key, values)
        if '{n}' in english:
            assert all('{n}' in v for v in values.values()), (key, values)


def test_the_markup_uses_classes_the_static_build_has():
    css = _read('static', 'css', 'tailwind.min.css')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    src = _read('web', 'src', 'dashboard.js')
    older = src[src.index('{vmwareMigrationsMore && ('):src.index('{/* Migration Log Viewer */}')]
    missing = sorted(n for n in _classes(_component() + older) if n not in have)
    assert not missing, missing
    # the interrupted chip and dot (the amber ones exist for the light Corporate theme only)
    assert "m.status === 'interrupted' ? 'bg-yellow-500/20 text-yellow-300'" in src
    assert "m.status === 'interrupted' ? 'bg-yellow-400'" in src
    assert {'bg-yellow-500/20', 'text-yellow-300', 'bg-yellow-400'} <= have


def test_the_log_panel_reads_the_log_route_and_polls_only_while_the_job_runs():
    comp = _component()
    assert '/log?offset=${next}' in comp and '/log?download=1' in comp
    # a run that ended is read once; a failed read is tried again only while the run goes on
    assert 'd.running || d.next < d.total' in comp
    assert 'setTimeout(load, d ? 3000 : 10000)' in comp
    assert 'return () => { live = false; clearTimeout(timer); };' in comp
    src = _read('web', 'src', 'dashboard.js')
    assert '<EsxiMigrationLog key={vmwareSelectedMigration} mid={vmwareSelectedMigration}' in src
    assert '`${API_URL}/vmware/migrations?limit=${vmwareHistoryLimit.current}`' in src


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    assert "v2pLogDownload:'Download log'" in bundle
    assert json.loads(_read('web', 'i18n', 'de.json'))['v2pLogDownload'] == 'Protokoll herunterladen'
    assert 'EsxiMigrationLog' in bundle and 'X-History-More' in bundle


# -- runtime ------------------------------------------------------------------------------------

def _task(mid, name, status='completed', vm_id='vm-1', vmware_id='v1', phase=None):
    return {'id': mid, 'vmware_id': vmware_id, 'vm_id': vm_id, 'vm_name': name, 'target_cluster': 'c1',
            'target_node': 'pve1', 'target_storage': 'local-lvm', 'proxmox_vmid': 100,
            'phase': phase or status, 'status': status, 'progress': 100 if status == 'completed' else 40,
            'error': None, 'wait_for_confirmation': False, 'awaiting_confirmation': False,
            'started_at': '2026-11-05T13:50:00', 'completed_at': None,
            'disk_progress': {}, 'phase_times': {}, 'total_downtime_seconds': None, 'warnings': [],
            'log': [f'[13:59:{i:02d}] tail {i}' for i in range(20)], 'config': {}}


DONE = _task('m1', 'webmig01')
CUT = _task('m2', 'cutoff01', status='interrupted', phase='pre_sync')
OTHER = _task('m3', 'elsewhere01', vm_id='vm-9')
LEFT_OUT = '... 4500 lines left out here - a migration log keeps its first 2000 and its newest lines, 20000 in all ...'
FULL = [f'[13:50:{i % 60:02d}] step {i}' for i in range(30)] + [LEFT_OUT, '[14:01:00] Phase: completed']
READS = {('GET', '/api/vmware/migrations'): (200, [DONE, CUT, OTHER]),
         ('GET', '/api/vmware/migrations/m1'): (200, DONE),
         ('GET', '/api/vmware/migrations/m2'): (200, CUT),
         ('GET', '/api/vmware/migrations/m1/log'): (200, {'id': 'm1', 'offset': 0, 'lines': FULL,
                                                          'next': 4532, 'total': 4532, 'dropped': 4500,
                                                          'status': 'completed', 'running': False}),
         ('GET', '/api/audit'): (200, [])}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(**kw):
        extra = {**ESXI_READS, **SSE_TOKEN, **READS, **kw.pop('extra', {})}
        app = _App(browser, _FakeServer(role='standalone', extra=extra, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _tasks_tab(page, tab='Tasks & Events'):
    page.get_by_text('esx01').first.click()
    page.get_by_text('legacy01').first.wait_for(timeout=8000)
    page.locator('button', has_text=tab).first.click()


def _open_run(page, name):
    page.locator('div.cursor-pointer', has_text=name).first.click()


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


def _log_lines(page):
    return page.evaluate("() => Array.from(document.querySelectorAll('[data-v2p-log] .font-mono > div'))"
                         ".map(e => e.innerText)")


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'corporate-redesigned'])
def test_runtime_an_ended_run_shows_its_whole_log_and_downloads_it(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    asked = []

    def _file(route, request):
        asked.append(request.url)
        route.fulfill(status=200, body='# ESXi migration m1\nstep 0\n', headers={
            'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="esxi-migration-legacy01-m1.log"'})
    page.route(re.compile(r'.*/api/vmware/migrations/m1/log\?download=1$'), _file)
    _tasks_tab(page)
    _open_run(page, 'webmig01')
    page.locator('[data-v2p-log]').first.wait_for(timeout=8000)
    page.get_by_text('step 29').first.wait_for(timeout=8000)
    assert _log_lines(page) == FULL
    assert page.get_by_text('4532 lines').first.is_visible()
    _shot(page, f'{layout}-log.png')
    # the line that says what was left out stands out
    color = page.get_by_text(LEFT_OUT).first.evaluate('(e) => getComputedStyle(e).color')
    rgb = [float(x) for x in re.findall(r'[\d.]+', color)[:3]]
    assert rgb[0] > rgb[2] + 60 and rgb[1] > rgb[2] + 40, color
    with page.expect_download(timeout=8000) as dl:
        page.locator('[data-v2p-log] button', has_text='Download log').click()
    assert dl.value.suggested_filename == 'esxi-migration-legacy01-m1.log'
    assert asked and asked[0].endswith('/log?download=1')
    # an ended run is read once, not polled
    page.wait_for_timeout(3500)
    assert sum(1 for m, p in app.server.calls if p == '/api/vmware/migrations/m1/log') == 1
    assert not app.errors, app.errors


def test_runtime_a_running_job_is_read_on_until_its_last_line(open_app):
    running = _task('m4', 'busy01', status='running', phase='pre_sync')
    app = open_app(layout='modern', extra={('GET', '/api/vmware/migrations'): (200, [running]),
                                           ('GET', '/api/vmware/migrations/m4'): (200, running)})
    page = app.page
    reads = []

    def _log(route, request):
        offset = int(re.search(r'offset=(\d+)', request.url).group(1))
        reads.append(offset)
        lines = [f'copy {i}' for i in range(offset, min(offset + 5, 15))]
        nxt = offset + len(lines)
        body = {'id': 'm4', 'offset': offset, 'lines': lines, 'next': nxt, 'total': nxt,
                'dropped': 0, 'status': 'running', 'running': nxt < 15}
        route.fulfill(status=200, body=json.dumps(body), headers={'Content-Type': 'application/json'})
    page.route(re.compile(r'.*/api/vmware/migrations/m4/log\?offset=\d+$'), _log)
    _tasks_tab(page)
    _open_run(page, 'busy01')
    page.get_by_text('copy 4').first.wait_for(timeout=8000)
    page.get_by_text('copy 14').first.wait_for(timeout=12000)
    assert reads[:3] == [0, 5, 10]
    assert _log_lines(page) == [f'copy {i}' for i in range(15)]
    # the job has written its last line: no more reads
    page.wait_for_timeout(4000)
    assert len(reads) == 3, reads
    assert not app.errors, app.errors


def test_runtime_closing_the_panel_stops_the_reads(open_app):
    running = _task('m5', 'busy02', status='running', phase='pre_sync')
    app = open_app(layout='modern', extra={('GET', '/api/vmware/migrations'): (200, [running]),
                                           ('GET', '/api/vmware/migrations/m5'): (200, running)})
    page = app.page
    reads = []

    def _log(route, request):
        reads.append(request.url)
        route.fulfill(status=200, body=json.dumps({'id': 'm5', 'offset': 0, 'lines': ['still copying'], 'next': 1,
                                                   'total': 1, 'dropped': 0, 'status': 'running', 'running': True}),
                      headers={'Content-Type': 'application/json'})
    page.route(re.compile(r'.*/api/vmware/migrations/m5/log\?offset=\d+$'), _log)
    _tasks_tab(page)
    _open_run(page, 'busy02')
    page.get_by_text('still copying').first.wait_for(timeout=8000)
    panel = page.locator('div.rounded-xl', has=page.locator('[data-v2p-log]')).last
    panel.locator('button', has_text=re.compile(r'^\s*Close\s*$')).first.click()
    page.wait_for_timeout(300)
    seen = len(reads)
    page.wait_for_timeout(4000)
    assert len(reads) == seen and page.locator('[data-v2p-log]').count() == 0
    assert not app.errors, app.errors


def test_runtime_without_the_log_route_the_last_lines_stay(open_app):
    app = open_app(layout='modern', extra={('GET', '/api/vmware/migrations/m1/log'): (404, {'error': 'not here'})})
    page = app.page
    _tasks_tab(page)
    _open_run(page, 'webmig01')
    page.get_by_text('tail 19').first.wait_for(timeout=8000)
    page.wait_for_timeout(500)
    assert _log_lines(page) == DONE['log']
    assert page.get_by_text('Loading the log...').count() == 0
    assert not app.errors, app.errors


def test_runtime_older_runs_come_on_request_and_a_cut_off_one_says_interrupted(open_app):
    app = open_app(layout='modern')
    page = app.page
    asked = []

    def _list(route, request):
        limit = int(re.search(r'limit=(\d+)', request.url).group(1))
        asked.append(limit)
        rows = [DONE, CUT] + ([_task('m9', 'ancient01')] if limit > 50 else [])
        route.fulfill(status=200, body=json.dumps(rows), headers={
            'Content-Type': 'application/json', 'X-History-More': '1' if limit == 50 else '0'})
    page.route(re.compile(r'.*/api/vmware/migrations\?limit=\d+$'), _list)
    _tasks_tab(page)
    chip = page.locator('span', has_text=re.compile(r'^interrupted$')).first
    chip.wait_for(timeout=8000)
    color = chip.evaluate('(e) => getComputedStyle(e).color')
    rgb = [float(x) for x in re.findall(r'[\d.]+', color)[:3]]
    assert rgb[0] > rgb[2] + 60 and rgb[1] > rgb[2] + 40, color
    older = page.locator('button[data-v2p-older]')
    older.wait_for(timeout=8000)
    assert older.inner_text().strip() == 'Show older migrations'
    assert page.get_by_text('ancient01').count() == 0
    older.click()
    page.get_by_text('ancient01').first.wait_for(timeout=8000)
    _shot(page, 'older.png')
    assert 100 in asked and page.locator('button[data-v2p-older]').count() == 0
    assert not app.errors, app.errors


def test_runtime_the_migration_tab_of_a_vm_lists_its_own_runs(open_app):
    app = open_app(layout='modern')
    page = app.page
    _tasks_tab(page)
    page.get_by_text('elsewhere01').first.wait_for(timeout=8000)
    page.locator('button', has_text='Virtual Machines').first.click()
    page.get_by_text('legacy01').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Migration\s*$')).first.click()
    page.get_by_text('Active Migrations').first.wait_for(timeout=8000)
    card = page.locator('h3', has_text='Active Migrations').locator('xpath=..')
    text = card.inner_text()
    assert 'cutoff01' in text and 'elsewhere01' not in text, text
    assert not app.errors, app.errors


def test_runtime_the_new_words_speak_german(open_app):
    app = open_app(layout='modern', language='de')
    page = app.page
    _tasks_tab(page, 'Aufgaben & Ereignisse')
    _open_run(page, 'webmig01')
    page.locator('[data-v2p-log] button', has_text='Protokoll herunterladen').wait_for(timeout=8000)
    assert page.get_by_text('4532 Zeilen').first.is_visible()
    assert not app.errors, app.errors
