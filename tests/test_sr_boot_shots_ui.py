"""The boot screenshots of a DR test failover in the Site Recovery events.

An expanded test event shows what was taken (the pictures, each with the time after the
clone's start and how long the grab took), what failed or was skipped and why, and a
button for the evidence PDF with the pictures in it. A picture the viewer may not see
(403) or one no longer kept (404) says so in its place. While a test still takes its
pictures the list is read again until they are there.

The source checks read web/src and the bundle; the runtime tests drive the built bundle
in headless Chromium against the fake server of tests/test_ha_ui.py, in Modern, Corporate
and Cloud, as an active instance and as a standby. The routes behind it are tested in
tests/test_sr_boot_shots.py.
LW Oct 2026
"""
import io
import json
import os
import re

import pytest
from PIL import Image

from test_ha_ui import CLUSTER, VM, _App, _FakeServer, _classes, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.environ.get('PEGAPROX_SHOTS', '')
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it']
KEYS = ['srShotsTitle', 'srShotsSummary', 'srShotsCapturing', 'srShotsInterrupted', 'srShotsTiming',
        'srShotsNoPermission', 'srShotsGone', 'srShotsLoadFailed', 'srTestPdfTitle', 'srTestPdfStarted',
        'srTestVmid', 'srShotsAfterStart', 'srShotsGrabTime', 'srTestPdfResults', 'srTestPdfFailed']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _block():
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index("// jsPDF's Helvetica has no glyph for these")
    parts = [dash[start:dash.index('// NS: Mar 2026 - Site Recovery tab component (#150)', start)]]
    i = dash.index("// a test's boot screenshots arrive after its event completed")
    end = '}, [shotsPending, events, selectedPlan]);'
    parts.append(dash[i:dash.index(end, i) + len(end)])
    i = dash.index('// LW Oct 2026 - the evidence of one test failover')
    parts.append(dash[i:dash.index('// add VM', i)])
    i = dash.index('data-sr-shots-badge')
    parts.append(dash[i - 200:i + 300])
    i = dash.index('<SrBootShots planId={pd.id}')
    parts.append(dash[i - 120:i + 200])
    return '\n'.join(parts)


# --- source --------------------------------------------------------------------------------

@pytest.mark.parametrize('key', KEYS)
def test_every_new_string_is_in_every_language_once(key):
    found = len(re.findall(rf'^\s*{key}:', _read('web', 'src', 'translations.js'), re.M))
    assert found == 9, f'{key} is in {found} of 9 language blocks - the UI would show the key'


def test_every_new_key_is_used_and_nothing_uses_a_missing_one():
    used = set(re.findall(r"t\('(sr(?:Shots|Test)[A-Za-z]*)'\)", _read('web', 'src', 'dashboard.js')))
    assert used == set(KEYS), (sorted(used - set(KEYS)), sorted(set(KEYS) - used))


def test_the_reused_keys_exist_everywhere():
    tr = _read('web', 'src', 'translations.js')
    for key in ('drDrillExportPdf', 'failed', 'skipped', 'vmid', 'name', 'status', 'error', 'size', 'details',
                'planName', 'sourceCluster', 'targetCluster', 'startTime', 'endTime'):
        assert len(re.findall(rf'^\s*{key}:', tr, re.M)) >= 9, key


def test_placeholders_survive_translation():
    tr = _read('web', 'src', 'translations.js')
    for key, phs in (('srShotsSummary', ('{taken}', '{failed}', '{skipped}', '{s}')),
                     ('srShotsTiming', ('{s}', '{ms}'))):
        values = re.findall(rf'^\s*{key}: ["\'](.*)["\'],$', tr, re.M)
        assert len(values) == 9 and all(all(p in v for p in phs) for v in values), (key, values)


def test_no_em_dash_in_what_this_change_added():
    assert '\u2014' not in _block() and '\u2013' not in _block()
    tr = _read('web', 'src', 'translations.js')
    for key in KEYS:
        for v in re.findall(rf'^\s*{key}: (.*),$', tr, re.M):
            assert '\u2014' not in v and '\u2013' not in v, (key, v)


def test_the_icons_exist():
    have = set(re.findall(r'^\s{12}([A-Z][A-Za-z0-9]*):', _read('web', 'src', 'icons.js'), re.M))
    used = set(re.findall(r'Icons\.([A-Za-z]+)', _block()))
    assert used and used <= have, sorted(used - have)


def test_every_class_is_in_the_static_tailwind_build():
    shell = '\n'.join(line for line in _read('web', 'index.html.original').split('\n')
                      if 'data-corp-theme="light"' not in line)
    css = _read('static', 'css', 'tailwind.min.css') + shell
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    # 'text' is the type of a PDF content block, which the scan cannot tell from a class
    missing = sorted(n for n in _classes(_block()) - {'text'} if n not in have)
    assert not missing, f'not in static/css/tailwind.min.css: {missing}'


def test_the_picture_comes_from_the_route_that_asks_vm_console():
    block = _block()
    url = '`${API_URL}/site-recovery/plans/${planId}/events/${eventId}/screenshots/${row.vmid}`'
    assert url in block
    # only reads: nothing here writes, so a standby shows it unchanged
    assert 'method:' not in block and "'POST'" not in block


def test_the_bundle_was_rebuilt():
    built = _read('web', 'index.html')
    for needle in ('function SrBootShots(', 'function SrBootShot(', 'function pdfSafeText(', 'data-sr-shots-pdf',
                   'pegaprox-dr-test-', 'srShotsCapturing'):
        assert needle in built, needle


# --- runtime -------------------------------------------------------------------------------

def _png(size=(320, 200)):
    img = Image.new('RGB', size, (20, 30, 40))
    for x in range(0, size[0], 8):
        img.putpixel((x, size[1] // 2), (200, 220, 240))
    out = io.BytesIO()
    img.save(out, format='PNG')
    return out.getvalue()


PNG = _png()
REMOTE = dict(CLUSTER, id='c2', name='Remote', display_name='Remote', host='10.0.0.2')
PLAN = {'id': 'p1', 'name': 'DR-Plan-One', 'source_cluster': 'c1', 'target_cluster': 'c2', 'status': 'testing',
        'vms': [{'id': f'v{v}', 'vmid': v, 'vm_name': n, 'boot_group': 0, 'boot_delay': 30, 'vm_type': t}
                for v, n, t in ((100, 'web01', 'qemu'), (101, 'db01', 'qemu'), (102, 'ct01', 'lxc'),
                                (103, 'win01', 'qemu'))],
        'network_mappings': {}, 'storage_mappings': {}, 'auto_failover': False}
GUESTS = [
    {'vmid': 100, 'test_vmid': 90100, 'vm_name': 'web01', 'status': 'ok', 'reason': '', 'ms': 1830,
     'after_boot_s': 75, 'bytes': len(PNG), 'captured_at': '2026-10-05T10:04:15+00:00'},
    {'vmid': 101, 'test_vmid': 90101, 'vm_name': 'db01', 'status': 'failed',
     'reason': 'blank framebuffer (display likely off)', 'ms': 20004},
    {'vmid': 102, 'test_vmid': 90102, 'vm_name': 'ct01', 'status': 'skipped',
     'reason': 'a container has no display to take'},
    {'vmid': 103, 'test_vmid': 90103, 'vm_name': 'win01', 'status': 'ok', 'reason': '', 'ms': 9120,
     'after_boot_s': 96, 'bytes': 4096, 'captured_at': '2026-10-05T10:04:40+00:00'},
]


def _event(state='done'):
    shots = {'state': state, 'cap': 20, 'guests': []}
    if state == 'done':
        shots.update(taken=2, failed=1, skipped=1, parallel=3, timeout_s=45, settle_s=60, total_ms=87000,
                     guests=GUESTS)
    return {'id': 'ev1', 'plan_id': 'p1', 'event_type': 'test', 'status': 'completed',
            'started_at': '2026-10-05T10:00:00', 'completed_at': '2026-10-05T10:03:00', 'triggered_by': 'system',
            'details': {'results': {str(g['vmid']): {'success': True, 'test_vmid': g['test_vmid']} for g in GUESTS},
                        'test_vmids': [{'vmid': g['test_vmid'], 'vm_type': 'qemu'} for g in GUESTS],
                        'counts': {'ok': 4, 'failed': 0, 'total': 4}, 'screenshots': shots}}


def _open(browser, layout='modern', role='active', language='en', events=None):
    from pegaprox.utils.rbac import get_user_permissions
    perms = sorted(get_user_permissions({'username': 'admin', 'role': 'admin'}))
    server = _FakeServer(role=role, layout=layout, language=language, clusters=[CLUSTER, REMOTE], resources=[VM],
                         permissions=perms,
                         extra={('GET', '/api/site-recovery/plans'): (200, [PLAN]),
                                ('GET', '/api/site-recovery/plans/p1'): (200, PLAN),
                                ('GET', '/api/cross-cluster-replications'): (200, []),
                                ('POST', '/api/sse/token'): (200, {})})
    app = _App(browser, server)
    app.shots = []
    app.event_reads = 0
    pending = list(events or [[_event()]])

    def on_events(route):
        app.event_reads += 1
        body = pending.pop(0) if len(pending) > 1 else pending[0]
        route.fulfill(status=200, body=json.dumps(body), headers={'Content-Type': 'application/json'})

    def on_shot(route):
        vmid = route.request.url.rstrip('/').split('/')[-1]
        app.shots.append(vmid)
        if vmid == '100':
            return route.fulfill(status=200, body=PNG, headers={'Content-Type': 'image/png'})
        if vmid == '103':
            return route.fulfill(status=403, body=json.dumps({'error': 'Permission denied: vm.console'}),
                                 headers={'Content-Type': 'application/json'})
        return route.fulfill(status=404, body='{}', headers={'Content-Type': 'application/json'})

    app.page.route(re.compile(r'.*/api/site-recovery/plans/p1/events$'), on_events)
    app.page.route(re.compile(r'.*/api/site-recovery/plans/p1/events/ev1/screenshots/\d+$'), on_shot)
    return app


@pytest.fixture
def open_app(browser):
    apps = []

    def _go(**kw):
        app = _open(browser, **kw)
        apps.append(app)
        return app
    yield _go
    for app in apps:
        app.ctx.close()


def _to_events(app, layout):
    page = app.page
    if layout == 'cloud':
        page.locator('.cloud-nav-item', has_text='Site Recovery').first.click()
    else:
        page.get_by_text('Testi').first.click()
        page.locator('button', has_text='Site Recovery').first.click()
    page.get_by_text('DR-Plan-One').first.click()
    page.locator('button', has_text=re.compile(r'Failover History|Failover-Historie')).first.click()
    page.locator('div.cursor-pointer', has_text='completed').first.wait_for(timeout=5000)


def _expand(app):
    page = app.page
    page.locator('div.cursor-pointer', has_text='completed').first.click()
    page.locator('[data-sr-shots="ev1"]').wait_for(timeout=5000)


def _snap(app, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        app.page.screenshot(path=os.path.join(SHOTS, name), full_page=False)


@pytest.mark.parametrize('layout,role', [('modern', 'active'), ('corporate', 'active'), ('cloud', 'active'),
                                         ('modern', 'standby')])
def test_runtime_an_expanded_test_event_shows_its_boot_screenshots(open_app, layout, role):
    app = open_app(layout=layout, role=role)
    page = app.page
    _to_events(app, layout)
    assert page.locator('[data-sr-shots-badge="ev1"]').inner_text() == 'Boot screenshots: 2'
    _expand(app)
    page.wait_for_function(
        '() => { const i = document.querySelector(\'[data-sr-shot="100"] img\');'
        ' return !!i && i.complete && i.naturalWidth === 320; }', timeout=5000)
    assert page.locator('[data-sr-shots-summary]').inner_text() == '2 taken, 1 failed, 1 skipped in 87s'
    first = page.locator('[data-sr-shot="100"] figcaption').inner_text()
    assert 'web01' in first and '90100' in first and '75s after start, taken in 1830 ms' in first
    # the one the viewer may not open says so where the picture would be
    why = page.locator('[data-sr-shot="103"] [data-sr-shot-why]')
    why.wait_for(timeout=5000)
    assert why.inner_text() == 'No console permission for this guest'
    assert page.locator('[data-sr-shot="103"] img').count() == 0
    missed = page.locator('[data-sr-shot-missed="101"]').inner_text()
    assert 'Failed' in missed and 'db01' in missed and 'blank framebuffer (display likely off)' in missed
    skipped = page.locator('[data-sr-shot-missed="102"]').inner_text()
    assert 'Skipped' in skipped and 'container' in skipped
    # one request per picture shown, none for what was not taken
    assert sorted(set(app.shots)) == ['100', '103']
    # the evidence PDF reads only, so a standby offers it too
    assert page.locator('[data-sr-shots-pdf]').is_visible()
    _snap(app, f'sr-boot-shots-{layout}-{role}.png')
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_the_evidence_pdf_carries_the_pictures(open_app, layout):
    app = open_app(layout=layout)
    page = app.page
    _to_events(app, layout)
    _expand(app)
    page.locator('[data-sr-shot="100"] img').wait_for(timeout=5000)
    with page.expect_download(timeout=15000) as info:
        page.locator('[data-sr-shots-pdf]').click()
    dl = info.value
    assert dl.suggested_filename == 'pegaprox-dr-test-p1-2026-10-05.pdf'
    with open(dl.path(), 'rb') as fh:
        pdf = fh.read()
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        dl.save_as(os.path.join(SHOTS, f'sr-boot-shots-{layout}.pdf'))
    assert pdf.startswith(b'%PDF')
    # the picture of 100; 103 is refused to this viewer and says so instead
    assert pdf.count(b'/Subtype /Image') == 1, pdf.count(b'/Subtype /Image')
    # a PDF string escapes its parentheses
    for needle in (b'Test Failover Evidence Report', b'Boot screenshots: 2 taken, 1 failed, 1 skipped in 87s',
                   b'blank framebuffer \\(display likely off\\)', b'a container has no display to take',
                   b'100 web01 -> 90100: 75s after start, taken in 1830 ms', b'No console permission for this guest'):
        assert needle in pdf, needle
    # the caption is drawn on the page of its picture: the page that names it also draws it
    pages = re.findall(rb'stream\n(.*?)\nendstream', pdf, re.S)
    named = [p for p in pages if b'(100 web01 -> 90100: 75s after start, taken in 1830 ms) Tj' in p]
    assert len(named) == 1 and b' Do' in named[0]
    assert not app.errors, app.errors


def test_runtime_a_test_still_taking_its_pictures_is_read_again_until_they_are_there(open_app):
    app = open_app(events=[[_event('capturing')], [_event('capturing')], [_event('done')]])
    page = app.page
    _to_events(app, 'modern')
    _expand(app)
    box = page.locator('[data-sr-shots="ev1"]')
    assert box.get_attribute('data-sr-shots-state') == 'capturing'
    assert 'Taking boot screenshots of the started test VMs...' in box.inner_text()
    assert page.locator('[data-sr-shots-pdf]').count() == 0
    page.locator('[data-sr-shots="ev1"][data-sr-shots-state="done"]').wait_for(timeout=15000)
    page.locator('[data-sr-shot="100"] img').wait_for(timeout=5000)
    reads = app.event_reads
    assert reads >= 3
    # and once they are there, the list is left alone
    page.wait_for_timeout(6000)
    assert app.event_reads == reads
    assert not app.errors, app.errors


def test_runtime_a_restart_during_the_pictures_is_said_in_german(open_app):
    app = open_app(language='de', events=[[_event('interrupted')]])
    page = app.page
    _to_events(app, 'modern')
    _expand(app)
    box = page.locator('[data-sr-shots="ev1"]')
    text = box.inner_text()
    assert 'Boot-Screenshots' in text
    assert 'PegaProx wurde neu gestartet, während die Boot-Screenshots aufgenommen wurden.' in text
    _snap(app, 'sr-boot-shots-interrupted-de.png')
    assert not app.errors, app.errors
