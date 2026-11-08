"""The evidence bundle in the UI: "Export evidence" and "Verify evidence" on the cluster timeline.

Export downloads the signed bundle for the window and the filters on screen; verify takes a
bundle file, asks the server and says valid or invalid with the reason. Both sit on the cluster
timeline in every layout it is reachable in, and not on a node or a guest. Runtime tests drive
the built bundle in headless Chromium against the fake server of tests/test_ha_ui.py.
NS Oct 2026
"""
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import pytest

from test_ha_ui import LANGS, _blocks, browser  # noqa: F401
from test_timeline_ui import (_TimelineServer, _open_cluster_timeline, _wait_for, open_app,  # noqa: F401
                              _read)

EXPORT = '/api/timeline/evidence'
VERIFY = '/api/timeline/evidence/verify'
KEYS = ['flrExport', 'flrVerify', 'flrExportTitle', 'flrExportFailed', 'flrVerifyValid', 'flrVerifyInvalid',
        'flrVerifyFailed']
BUNDLE = {'format': 'pegaprox-flight-recorder', 'version': 1, 'events': [], 'signature': {'value': 'x'}}


def _reads(app):
    return [parse_qs(urlparse(u).query) for u in app.server.urls if urlparse(u).path == EXPORT]


def _open(app, layout):
    if layout == 'cloud':
        app.page.locator('.cloud-nav').get_by_text('Timeline', exact=True).click()
        app.page.locator('[data-timeline="cluster"] [data-tl-row]').first.wait_for(timeout=5000)
        return app.page
    return _open_cluster_timeline(app)


# -- source -------------------------------------------------------------------------------------

def test_every_key_exists_once_per_language_with_a_real_text():
    en = {}
    for lang, block in _blocks().items():
        for key in KEYS:
            found = re.findall(r"^ +%s: '(.*)',$" % key, block, re.M)
            assert len(found) == 1, (lang, key)
            if lang == 'en':
                en[key] = found[0]
            elif lang != 'de' or key != 'flrExport':
                assert found[0] != en.get(key), (lang, key)
    for lang, block in _blocks().items():
        value = re.search(r"^ +flrVerifyInvalid: '(.*)',$", block, re.M).group(1)
        assert '{reason}' in value, lang


def test_no_dash_and_every_key_is_used():
    src = _read('web', 'src', 'dashboard.js')
    start = src.index('function TimelineEvidence(')
    part = src[start:src.index('// LW Oct 2026 - the flight recorder', start)]
    assert set(re.findall(r"'(flr[A-Z]\w*)'", part)) == set(KEYS)
    assert '\u2014' not in part
    for block in _blocks().values():
        for key in KEYS:
            assert '\u2014' not in re.search(r'^ +%s: .*$' % key, block, re.M).group(0)


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    for needle in ('function TimelineEvidence(', '/timeline/evidence', 'data-tl-export', 'data-tl-verify'):
        assert needle in bundle, needle


# -- runtime ------------------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_export_downloads_the_bundle_for_the_window_on_screen(open_app, layout):
    app = open_app(layout=layout, extra={('GET', EXPORT): (200, BUNDLE)})
    page = _open(app, layout)
    assert page.locator('[data-tl-export]').inner_text().strip() == 'Export evidence'
    assert page.locator('[data-tl-evidence]').get_by_text('Verify evidence').count() == 1
    page.locator('[data-tl-range]').select_option('168')
    page.locator('[data-tl-filter-severity]').select_option('critical')
    page.locator('[data-tl-filter-kind]').select_option('alert')
    page.locator('[data-tl-row]').first.wait_for(timeout=5000)
    with page.expect_download() as got:
        page.locator('[data-tl-export]').click()
    download = got.value
    assert download.suggested_filename.endswith('.json')
    with open(download.path(), encoding='utf-8') as fh:
        assert json.load(fh)['format'] == 'pegaprox-flight-recorder'
    q = _reads(app)[-1]
    assert q['clusters'] == ['c1'] and q['kinds'] == ['alert'] and q['severity'] == ['critical']
    import calendar
    import time
    since = calendar.timegm(time.strptime(q['from'][0][:19], '%Y-%m-%dT%H:%M:%S'))
    assert abs((time.time() - since) - 168 * 3600) < 300
    assert not app.errors, app.errors


@pytest.mark.parametrize('layout', ['modern', 'corporate', 'cloud'])
def test_runtime_verify_says_valid_and_invalid_with_the_reason(open_app, layout):
    app = open_app(layout=layout, extra={('POST', VERIFY): (200, {'valid': True, 'reason': 'ok'})})
    page = _open(app, layout)
    file = {'name': 'bundle.json', 'mimeType': 'application/json', 'buffer': json.dumps(BUNDLE).encode()}
    page.locator('[data-tl-verify]').set_input_files(file)
    page.locator('[data-tl-verdict="ok"]').wait_for(timeout=5000)
    assert 'Valid' in page.locator('[data-tl-verdict]').inner_text()
    assert app.server.bodies[VERIFY][-1] == BUNDLE
    app.server.extra[('POST', VERIFY)] = (200, {'valid': False, 'reason': 'the signature does not match'})
    page.locator('[data-tl-verify]').set_input_files(file)
    page.locator('[data-tl-verdict="bad"]').wait_for(timeout=5000)
    text = page.locator('[data-tl-verdict]').inner_text()
    assert text.startswith('Invalid') and 'the signature does not match' in text
    assert not app.errors, app.errors


def test_runtime_a_failed_export_and_a_failed_verify_say_so(open_app):
    app = open_app(layout='modern', extra={('GET', EXPORT): (500, {'error': 'boom'}),
                                           ('POST', VERIFY): (400, {'error': 'bad body'})})
    page = _open(app, 'modern')
    page.locator('[data-tl-export]').click()
    page.locator('[data-tl-verdict="bad"]').wait_for(timeout=5000)
    assert page.locator('[data-tl-verdict]').inner_text() == 'The bundle could not be created'
    page.locator('[data-tl-verify]').set_input_files(
        {'name': 'x.json', 'mimeType': 'application/json', 'buffer': b'not json'})
    page.wait_for_function("() => (document.querySelector('[data-tl-verdict]') || {innerText: ''}).innerText.includes('could not be checked')",
                           timeout=5000)


def test_runtime_a_node_and_a_guest_timeline_have_no_bundle(open_app):
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    child = page.locator('.corp-tree-child', has_text='pve1').first
    child.wait_for(timeout=5000)
    child.click()
    page.locator('.corp-tab-strip').last.get_by_text('Monitor').click()
    page.locator('[data-corp-node-timeline]').click()
    page.locator('[data-timeline="node"] [data-tl-row="task:u1"]').wait_for(timeout=5000)
    assert page.locator('[data-tl-export]').count() == 0 and page.locator('[data-tl-verify]').count() == 0
    page.locator('[data-timeline="node"] [data-tl-row="task:u1"] [data-tl-open-guest="100"]').click()
    page.get_by_text('Snapshots').first.wait_for(timeout=5000)
    page.locator('[data-corp-vm-timeline]').click()
    page.locator('[data-timeline="guest"] [data-tl-row="alert:a1"]').wait_for(timeout=5000)
    assert page.locator('[data-tl-export]').count() == 0 and page.locator('[data-tl-verify]').count() == 0


def test_runtime_it_speaks_german(open_app):
    app = open_app(layout='modern', language='de', extra={('POST', VERIFY): (200, {'valid': True, 'reason': 'ok'})})
    page = _open_cluster_timeline(app, name='Zeitachse')
    assert page.locator('[data-tl-export]').inner_text().strip() == 'Nachweis exportieren'
    page.locator('[data-tl-verify]').set_input_files(
        {'name': 'b.json', 'mimeType': 'application/json', 'buffer': json.dumps(BUNDLE).encode()})
    page.locator('[data-tl-verdict="ok"]').wait_for(timeout=5000)
    assert page.locator('[data-tl-verdict]').inner_text().startswith('Gültig')


def test_runtime_a_standby_shows_the_buttons(open_app):
    app = open_app(layout='corporate', role='standby')
    page = _open_cluster_timeline(app)
    assert page.locator('[data-tl-export]').count() == 1 and page.locator('[data-tl-verify]').count() == 1
