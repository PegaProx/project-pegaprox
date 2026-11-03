"""Corporate Redesigned, the ISO Sync sub tab of the Datastore view (round 11): the tiles, the files with
the nodes they are on, a file opened on its nodes, the nodes with what they hold, the activity of this
session beside the auto-sync card, the state every file and node is drawn in and the field that decides
it, and the Sync and Sync All Missing against the requests the classic sub tab sends.

Runtime tests drive the built bundle in headless Chromium against the guard fake of
tests/test_corp_redesigned_guard_ui.py with the ISO Sync reads (SYNC_READS). The counterproof runs this
file against an older bundle: PEGAPROX_CR_BUNDLE=<path to index.html>.
LW Nov 2026
"""
import copy
import os
import re
import time

import pytest

from test_corp_redesigned_guard_ui import DETERMINISTIC, SYNC_READS, _GuardApp, _GuardServer, _sync_local

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAYOUT = 'corporate-redesigned'
_BUNDLE_FILE = os.environ.get('PEGAPROX_CR_BUNDLE')
BUNDLE = open(_BUNDLE_FILE, encoding='utf-8').read() if _BUNDLE_FILE else None
SHOTS = os.environ.get('PEGAPROX_UI_SHOTS', '')
DASHES = (chr(0x2014), chr(0x2013))
STATUS = '/api/clusters/c1/iso-sync/status'
LAST = '/api/clusters/c1/iso-sync/last-result'
ONE = '/api/clusters/c1/iso-sync'
ALL = '/api/clusters/c1/iso-sync/all'
DATASTORES = '/api/clusters/c1/datastores'
GIB = 1024 ** 3

# three online nodes and one offline, as /datastores (vms.py) lists them: 'isos' on pve2 only
DS = {'shared': [{'storage': 'nfs-iso', 'type': 'nfs', 'content': 'iso,images', 'shared': True, 'active': 1, 'enabled': 1,
                  'total': 500 * GIB, 'used': 100 * GIB, 'avail': 400 * GIB, 'active_on': ['pve1', 'pve2', 'pve3'], 'inactive_on': []}],
      'local': {'pve1': [_sync_local('local')], 'pve2': [_sync_local('local'), _sync_local('isos', 'iso')],
                'pve3': [_sync_local('local')], 'pve4': [_sync_local('local', active=0, node_offline=True)]},
      'nodes': ['pve1', 'pve2', 'pve3', 'pve4'], 'offline_nodes': ['pve4']}


def _file(name, storage, size, on):
    return {'name': name, 'storage': storage, 'size': size}, (f'{storage}:{name}', {n: n in on for n in ('pve1', 'pve2', 'pve3')})


def _status(*files):
    return {'nodes': ['pve1', 'pve2', 'pve3'], 'files': [f for f, _ in files], 'matrix': dict(m for _, m in files)}


# every state from the field that decides it: on every node, missing on one, on a storage two nodes lack,
# and the file of the last result with a copy that failed
DEBIAN = _file('debian-12.iso', 'local', 600 * 1024 ** 2, ('pve1', 'pve2', 'pve3'))
UBUNTU = _file('ubuntu-24.04.iso', 'local', 3 * GIB, ('pve1', 'pve2'))
VIRTIO = _file('virtio-win.iso', 'isos', 700 * 1024 ** 2, ('pve2',))
ALPINE = _file('alpine-3.20.iso', 'local', 200 * 1024 ** 2, ('pve1', 'pve3'))
STATES = _status(DEBIAN, UBUNTU, VIRTIO, ALPINE)
LAST_ALPINE = {'timestamp': '2026-10-30T08:40:00.123456', 'filename': 'alpine-3.20.iso', 'ok': 1, 'failed': 1,
               'results': [{'node': 'pve2', 'success': False, 'error': 'scp: write failed: No space left on device'},
                           {'node': 'pve3', 'success': True, 'method': 'scp'}]}
EXPECT = {'local:debian-12.iso': 'synced', 'local:ubuntu-24.04.iso': 'missing', 'isos:virtio-win.iso': 'missing',
          'local:alpine-3.20.iso': 'failed'}


def _reads(over=None):
    r = dict(SYNC_READS)
    r[('GET', DATASTORES)] = (200, DS)
    r[('GET', STATUS)] = (200, STATES)
    r[('GET', LAST)] = (200, LAST_ALPINE)
    r[('POST', ONE)] = (200, {'success': True, 'message': 'Sync started'})
    r[('POST', ALL)] = (200, {'success': True, 'message': 'Full sync started'})
    r.update(over or {})
    return r


@pytest.fixture(scope='module')
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip('Playwright is not installed')
    try:
        pw = sync_playwright().start()
    except Exception as e:
        pytest.skip(f'Playwright does not start here: {e}')
    try:
        br = pw.chromium.launch(headless=True, args=DETERMINISTIC)
    except Exception as e:
        pw.stop()
        pytest.skip(f'no Chromium for Playwright: {e}')
    yield br
    br.close()
    pw.stop()


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(extra=None, layout=LAYOUT, theme='', viewport=(1600, 1000), storage=None, **kw):
        server = _GuardServer(bundle=BUNDLE, layout=layout, extra=_reads(extra), **kw)
        app = _GuardApp(browser, server, corp_theme=theme, viewport=viewport, storage=storage)
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


def _open_sub(app, label='ISO Sync'):
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('[data-cr-tab="datastore"]').click()
    app.mark = len(app.server.calls)
    page.locator('.corp-tab-strip button', has_text=label).first.click()
    return page


def _tab(app, rows=True):
    """The ISO Sync sub tab of Testi in the navigation of Corporate Redesigned."""
    page = _open_sub(app)
    _need(page, '[data-cr-iso]', 'the ISO Sync sub tab is the page of Corporate Redesigned')
    if rows:
        _need(page, '[data-cr-iso] [data-cr-iso-row]', 'the file table is filled')
    page.wait_for_timeout(300)
    return page


def _shot(page, name):
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f'iso-{name}.png'), full_page=True)


def _states(page):
    """file key -> the state its row is drawn in."""
    return dict(page.evaluate("""() => [...document.querySelectorAll('[data-cr-table="iso-files"] tbody tr')]
        .filter(tr => tr.querySelector('[data-cr-iso-row]'))
        .map(tr => [tr.querySelector('[data-cr-iso-row]').dataset.crIsoRow, tr.querySelector('[data-cr-iso-state]').dataset.crIsoState])"""))


def _row(page, key):
    return page.locator('[data-cr-table="iso-files"] tbody tr', has=page.locator(f'[data-cr-iso-row="{key}"]'))


def _cells(page, key):
    """node -> state of one file opened in the table."""
    if not page.locator(f'[data-cr-iso-nodes="{key}"]').count():
        _row(page, key).click()
    page.locator(f'[data-cr-iso-nodes="{key}"]').wait_for(timeout=4000)
    return dict(page.evaluate("""(k) => [...document.querySelectorAll(`[data-cr-iso-nodes="${k}"] [data-cr-iso-cell]`)]
        .map(li => [li.dataset.crIsoCell, li.dataset.state])""", key))


def _tile(page, key):
    return page.locator(f'[data-cr-stat="iso-{key}"] .cr-stat-value').inner_text().strip()


def _wait(page, pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        page.wait_for_timeout(100)
    return pred()


def _count(app, method, path):
    """The requests since the sub tab was opened."""
    return len([c for c in app.server.calls[getattr(app, 'mark', 0):] if c == (method, path)])


def _no_errors(app):
    assert [e for e in app.errors if 'not mocked' not in e] == [], app.errors


def _classic_body(open_app, path, button):
    """The body the classic sub tab sends with the same reads, in the same session."""
    app = open_app(layout='corporate')
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Datastore\s*$')).first.click()
    app.mark = len(app.server.calls)
    page.locator('.corp-tab-strip button', has_text='ISO Sync').first.click()
    page.get_by_text('virtio-win.iso', exact=True).first.wait_for(timeout=8000)
    # the classic sub tab reads the status on its button, and Corporate Redesigned changes nothing there
    assert _count(app, 'GET', STATUS) == 1
    button(page).click()
    assert _wait(page, lambda: ('POST', path) in app.server.calls)
    return app.server.bodies[path][-1]


# --- the parts and the states ------------------------------------------------------------------

def test_runtime_the_page_has_its_parts_and_keeps_the_sub_tab_strip(open_app):
    app = open_app()
    page = _tab(app)
    heads = page.locator('[data-cr-iso] h2.cr-iso-h').all_inner_texts()
    assert [h.strip().lower() for h in heads] == ['sync overview', 'activity and settings', 'files', 'nodes']
    for sec in ('iso-activity', 'iso-auto', 'iso-files', 'iso-nodes'):
        assert page.locator(f'[data-cr-nc-sec="{sec}"]').count() == 1, sec
    assert page.locator('.corp-tab-strip button.active', has_text='ISO Sync').count() == 1
    # the classic sub tab is not drawn beside it: no browser-only auto-sync checkbox
    assert page.locator('[data-cr-iso] input[type="checkbox"]').count() == 0
    assert page.get_by_text('Auto-Sync after Upload', exact=True).count() == 0
    # one read of the status for ISO images and one of the last result, nothing per file or node
    assert _count(app, 'GET', STATUS) == 1 and _count(app, 'GET', LAST) == 1
    assert [u for u in app.server.urls if '/iso-sync/status' in u][-1].endswith('content=iso')
    assert not [c for c in app.server.calls[app.mark:] if c[1].startswith('/api/clusters/c1/nodes/')]
    # the sizes through the shared byte format
    assert _row(page, 'local:ubuntu-24.04.iso').locator('td').nth(2).inner_text().strip() == '3.0 GB'
    _shot(page, 'overview')
    _no_errors(app)


def test_runtime_every_file_and_node_is_drawn_in_the_state_its_fields_decide(open_app):
    app = open_app()
    page = _tab(app)
    page.wait_for_function('() => document.querySelectorAll("[data-cr-table=iso-files] [data-cr-iso-row]").length === 4', timeout=8000)
    states = _states(page)
    assert states == EXPECT
    # the most urgent first: failed, then missing, then synchronized
    assert list(states)[0] == 'local:alpine-3.20.iso' and list(states)[-1] == 'local:debian-12.iso'
    assert [_tile(page, k) for k in ('files', 'synced', 'missing', 'pending', 'running', 'failed')] == ['4', '1', '2', '0', '0', '1']
    # four copies are missing: ubuntu on pve3, virtio on pve1 and pve3, alpine on pve2
    assert page.locator('[data-cr-stat="iso-missing"] .cr-stat-sub').inner_text().startswith('4 copies')
    # three of four nodes read, the offline one is not reported, never "missing"
    assert _tile(page, 'nodes') == '3 of 4'
    assert _cells(page, 'local:alpine-3.20.iso') == {'pve1': 'present', 'pve2': 'failed', 'pve3': 'present', 'pve4': 'offline'}
    assert 'No space left on device' in page.locator('[data-cr-iso-nodes="local:alpine-3.20.iso"] [data-cr-iso-cell="pve2"]').inner_text()
    assert _cells(page, 'local:ubuntu-24.04.iso') == {'pve1': 'present', 'pve2': 'present', 'pve3': 'missing', 'pve4': 'offline'}
    # a node without the storage cannot take a copy: said so, not just "missing"
    assert _cells(page, 'isos:virtio-win.iso') == {'pve1': 'nostore', 'pve2': 'present', 'pve3': 'nostore', 'pve4': 'offline'}
    assert 'No storage isos' in page.locator('[data-cr-iso-nodes="isos:virtio-win.iso"] [data-cr-iso-cell="pve1"]').inner_text()
    assert 'from pve2 (isos)' in page.locator('[data-cr-iso-nodes="isos:virtio-win.iso"]').inner_text()
    # the shared storage with ISO content is named as left out
    assert 'nfs-iso' in page.locator('[data-cr-iso-shared]').inner_text()
    # the last result of the server, node by node
    last = page.locator('[data-cr-iso-last="alpine-3.20.iso"]')
    assert last.locator('[data-cr-iso-result="pve2"]').get_attribute('data-state') == 'failed'
    assert 'node to node' in last.locator('[data-cr-iso-result="pve3"]').inner_text()
    assert '08:40' in last.locator('[data-cr-nc-k="at"] dd').inner_text()
    _shot(page, 'states')
    _no_errors(app)


def test_runtime_the_nodes_say_what_they_hold_and_lead_to_the_files_they_lack(open_app):
    app = open_app()
    page = _tab(app)
    table = page.locator('[data-cr-table="iso-node-table"]')
    rows = dict(page.evaluate("""() => [...document.querySelectorAll('[data-cr-table="iso-node-table"] tbody tr')]
        .filter(tr => tr.querySelector('[data-cr-iso-node]'))
        .map(tr => [tr.querySelector('[data-cr-iso-node]').dataset.crIsoNode, [...tr.querySelectorAll('td')].map(td => td.innerText.trim())])"""))
    assert rows['pve1'][2] == '3 of 4' and rows['pve3'][2] == '2 of 4'
    assert 'not reported' in rows['pve4'][2].lower()
    assert table.locator('[data-cr-iso-stores="pve2"]').inner_text().strip() == 'isos, local'
    assert 'inactive: local' in table.locator('[data-cr-iso-stores="pve4"]').inner_text()
    # the count of files missing on pve3 filters the file table to them
    table.locator('[data-cr-iso-node-lack="pve3"]').click()
    assert _wait(page, lambda: sorted(_states(page)) == ['isos:virtio-win.iso', 'local:ubuntu-24.04.iso'])
    page.locator('[data-cr-iso-node-filter="pve3"]').click()
    assert _wait(page, lambda: len(_states(page)) == 4)
    _no_errors(app)


def test_runtime_a_tile_filters_the_table_and_a_second_click_lifts_it(open_app):
    app = open_app()
    page = _tab(app)
    page.locator('[data-cr-stat="iso-missing"]').click()
    assert _wait(page, lambda: sorted(_states(page)) == ['isos:virtio-win.iso', 'local:ubuntu-24.04.iso'])
    assert page.locator('[data-cr-stat="iso-missing"]').get_attribute('aria-pressed') == 'true'
    assert page.locator('[data-cr-iso-chip="missing"]').get_attribute('aria-pressed') == 'true'
    page.locator('[data-cr-stat="iso-missing"]').click()
    assert _wait(page, lambda: len(_states(page)) == 4)
    # Needs attention: missing and failed; search by node name or storage
    page.locator('[data-cr-iso-chip="attention"]').click()
    assert _wait(page, lambda: len(_states(page)) == 3)
    page.locator('[data-cr-iso-chip="all"]').click()
    page.locator('[data-cr-table="iso-files"] input[type="search"], [data-cr-table="iso-files"] input').first.fill('isos')
    assert _wait(page, lambda: list(_states(page)) == ['isos:virtio-win.iso'])
    _no_errors(app)


# --- the writes ----------------------------------------------------------------------------------

def test_runtime_sync_of_one_file_sends_the_classic_request_and_follows_its_result(open_app):
    classic = _classic_body(open_app, ONE, lambda p: p.locator('tr', has_text='ubuntu-24.04.iso').locator('button', has_text='Sync'))
    app = open_app()
    page = _tab(app)
    _row(page, 'local:ubuntu-24.04.iso').locator('[data-cr-iso-sync]').click()
    assert _wait(page, lambda: ('POST', ONE) in app.server.calls)
    assert app.server.bodies[ONE][-1] == classic == {'source_node': 'pve1', 'storage': 'local', 'filename': 'ubuntu-24.04.iso',
                                                      'content_type': 'iso'}
    # started from this session: running until the server reports the file
    assert _wait(page, lambda: _states(page).get('local:ubuntu-24.04.iso') == 'running')
    assert _tile(page, 'running') == '1'
    assert _cells(page, 'local:ubuntu-24.04.iso')['pve3'] == 'running'
    assert page.locator('[data-cr-iso-run-state="running"]').count() == 1
    assert _row(page, 'local:ubuntu-24.04.iso').locator('[data-cr-iso-sync]').count() == 0 or \
        _row(page, 'local:ubuntu-24.04.iso').locator('[data-cr-iso-sync]').is_disabled()
    # the copy is done: a new result (its time changed), then the status is read again
    done = {'timestamp': '2026-10-30T09:05:00.000001', 'filename': 'ubuntu-24.04.iso', 'ok': 2, 'failed': 0,
            'results': [{'node': 'pve2', 'success': True, 'skipped': True}, {'node': 'pve3', 'success': True, 'method': 'sftp'}]}
    app.server.extra[('GET', LAST)] = (200, done)
    app.server.extra[('GET', STATUS)] = (200, _status(DEBIAN, _file('ubuntu-24.04.iso', 'local', 3 * GIB, ('pve1', 'pve2', 'pve3')), VIRTIO, ALPINE))
    assert _wait(page, lambda: _states(page).get('local:ubuntu-24.04.iso') == 'synced', timeout=9)
    assert _count(app, 'GET', STATUS) == 2
    assert page.get_by_text('ubuntu-24.04.iso: copied to 1 nodes, 1 had it already').count() >= 1
    assert page.locator('[data-cr-iso-run-state="done"]').count() == 1
    assert 'through PegaProx' in page.locator('[data-cr-iso-result="pve3"]').inner_text()
    # nothing is waited for any more: no further reads
    n = _count(app, 'GET', LAST)
    page.wait_for_timeout(5800)
    assert _count(app, 'GET', LAST) == n
    _no_errors(app)


def test_runtime_a_result_that_was_there_before_is_not_taken_for_the_answer(open_app):
    # the last result is of alpine already: the classic wait ends on the file name at once
    app = open_app()
    page = _tab(app)
    _row(page, 'local:alpine-3.20.iso').locator('[data-cr-iso-sync]').click()
    assert _wait(page, lambda: _states(page).get('local:alpine-3.20.iso') == 'running')
    n = _count(app, 'GET', LAST)
    page.wait_for_timeout(5800)
    # read again, the same time: still running, no toast
    assert _count(app, 'GET', LAST) > n
    assert _states(page)['local:alpine-3.20.iso'] == 'running'
    assert page.get_by_text('alpine-3.20.iso: ', exact=False).count() == 0
    _no_errors(app)


def test_runtime_sync_all_sends_the_classic_request_and_marks_the_files_pending(open_app):
    classic = _classic_body(open_app, ALL, lambda p: p.locator('button', has_text='Sync All Missing'))
    app = open_app()
    page = _tab(app)
    bulk = page.locator('[data-cr-iso-bulk]').inner_text()
    assert '3 files: 4 copies' in bulk
    page.locator('[data-cr-iso-syncall]').click()
    assert _wait(page, lambda: ('POST', ALL) in app.server.calls)
    assert app.server.bodies[ALL][-1] == classic == {'content_type': 'iso'}
    assert _wait(page, lambda: _tile(page, 'pending') == '3')
    assert _states(page) == {'local:debian-12.iso': 'synced', 'local:ubuntu-24.04.iso': 'pending',
                             'isos:virtio-win.iso': 'pending', 'local:alpine-3.20.iso': 'pending'}
    assert page.locator('[data-cr-iso-syncall]').is_disabled()
    # one file reported with a failed copy: that file is failed, the others still wait
    res = {'timestamp': '2026-10-30T09:06:00.5', 'filename': 'virtio-win.iso', 'ok': 1, 'failed': 1,
           'results': [{'node': 'pve1', 'success': False, 'error': 'Storage isos not found on pve1'},
                       {'node': 'pve3', 'success': False, 'error': 'Storage isos not found on pve3'}]}
    res['ok'], res['failed'] = 0, 2
    app.server.extra[('GET', LAST)] = (200, res)
    assert _wait(page, lambda: _states(page).get('isos:virtio-win.iso') == 'failed', timeout=9)
    assert _states(page)['local:ubuntu-24.04.iso'] == 'pending'
    assert page.get_by_text('virtio-win.iso: 2 of 2 copies failed').count() >= 1
    assert '1 of 3 files reported' in page.locator('[data-cr-table="iso-runs"]').inner_text()
    # the status shows ubuntu everywhere now (its result was overwritten before it was read): done too
    app.server.extra[('GET', STATUS)] = (200, _status(DEBIAN, _file('ubuntu-24.04.iso', 'local', 3 * GIB, ('pve1', 'pve2', 'pve3')), VIRTIO, ALPINE))
    page.locator('[data-cr-iso-refresh]').click()
    assert _wait(page, lambda: _states(page).get('local:ubuntu-24.04.iso') == 'synced')
    assert '2 of 3 files reported' in page.locator('[data-cr-table="iso-runs"]').inner_text()
    # stop watching: alpine is drawn from the reads again
    page.locator('[data-cr-iso-drop]').click()
    assert _wait(page, lambda: _states(page).get('local:alpine-3.20.iso') == 'missing')
    assert page.locator('[data-cr-iso-run-state="dropped"]').count() == 1
    assert not page.locator('[data-cr-iso-syncall]').is_disabled()
    _no_errors(app)


def test_runtime_container_templates_are_read_and_synced_as_templates(open_app):
    app = open_app()
    page = _tab(app)
    page.locator('[data-cr-iso-content="vztmpl"]').click()
    assert _wait(page, lambda: [u for u in app.server.urls if '/iso-sync/status' in u][-1].endswith('content=vztmpl'))
    assert page.locator('[data-cr-iso-content="vztmpl"]').get_attribute('aria-pressed') == 'true'
    assert page.locator('[data-cr-iso]').get_attribute('data-cr-iso-ct') == 'vztmpl'
    _need(page, '[data-cr-iso-row]', 'the template table is filled')
    _row(page, 'local:ubuntu-24.04.iso').locator('[data-cr-iso-sync]').click()
    assert _wait(page, lambda: ('POST', ONE) in app.server.calls)
    assert app.server.bodies[ONE][-1]['content_type'] == 'vztmpl'
    page.locator('[data-cr-iso-syncall]').click()
    assert _wait(page, lambda: ('POST', ALL) in app.server.calls)
    assert app.server.bodies[ALL][-1] == {'content_type': 'vztmpl'}
    _no_errors(app)


def test_runtime_a_refused_sync_marks_nothing_as_running(open_app):
    app = open_app({('POST', ONE): (403, {'error': 'Permission denied'})})
    page = _tab(app)
    _row(page, 'local:ubuntu-24.04.iso').locator('[data-cr-iso-sync]').click()
    assert _wait(page, lambda: ('POST', ONE) in app.server.calls)
    page.get_by_text('Permission denied').first.wait_for(timeout=4000)
    assert _states(page)['local:ubuntu-24.04.iso'] == 'missing'
    assert page.locator('[data-cr-iso-noruns]').count() == 1
    _no_errors(app)


# --- the other states ----------------------------------------------------------------------------

def test_runtime_a_status_without_nodes_is_not_reported_and_a_failed_read_says_why(open_app):
    app = open_app({('GET', STATUS): (200, {'nodes': [], 'files': [], 'matrix': {}})})
    page = _tab(app, rows=False)
    _need(page, '[data-cr-iso-unlisted]', 'an answer without nodes is said to be not reported')
    assert _tile(page, 'synced').lower() == 'not reported' and _tile(page, 'missing').lower() == 'not reported'
    assert 'not reported' in page.locator('[data-cr-table="iso-files"] td.cr-state').inner_text().lower()
    assert page.locator('[data-cr-iso-syncall]').is_disabled()
    app2 = open_app({('GET', STATUS): (500, {'error': 'Cluster not found'}), ('GET', LAST): (403, {'error': 'Permission denied'})})
    page2 = _tab(app2, rows=False)
    _need(page2, '[data-cr-iso-error]', 'the failed read says why')
    assert 'Cluster not found' in page2.locator('[data-cr-iso-error]').inner_text()
    assert 'Permission denied' in page2.locator('[data-cr-iso-last-error]').inner_text()
    assert _tile(page2, 'failed').lower() == 'not reported'
    # Retry reads again
    app2.server.extra[('GET', STATUS)] = (200, STATES)
    page2.locator('[data-cr-iso-error] [data-cr-nc-retry]').click()
    _need(page2, '[data-cr-iso-row]', 'the retry fills the table')
    assert page2.locator('[data-cr-stat="iso-failed"] .cr-stat-sub').inner_text().strip() == 'last result not read'
    _no_errors(app)


def test_runtime_an_empty_storage_says_so(open_app):
    app = open_app({('GET', STATUS): (200, {'nodes': ['pve1', 'pve2', 'pve3'], 'files': [], 'matrix': {}}), ('GET', LAST): (200, {})})
    page = _tab(app, rows=False)
    _need(page, '[data-cr-table="iso-files"] td.cr-state', 'the empty table says why')
    assert 'No ISO images on the storages' in page.locator('[data-cr-table="iso-files"] td.cr-state').inner_text()
    assert _tile(page, 'files') == '0'
    assert page.locator('[data-cr-iso-last="none"]').count() == 1
    assert 'nothing to copy' in page.locator('[data-cr-iso-bulk]').inner_text()
    _no_errors(app)


def test_runtime_without_storage_upload_nothing_can_be_synced(open_app):
    app = open_app(admin=False, permissions=['storage.view', 'vm.view', 'node.view', 'cluster.view'])
    page = _tab(app)
    assert page.locator('[data-cr-iso-syncall]').is_disabled()
    assert all(b.is_disabled() for b in page.locator('[data-cr-iso-sync]').all())
    assert 'storage upload permission' in page.locator('[data-cr-iso-readonly]').inner_text()
    _no_errors(app)


def test_runtime_a_standby_reads_and_writes_nothing(open_app):
    app = open_app(role='standby')
    page = _tab(app)
    _need(page, '[data-cr-iso-standby]', 'the standby says it is read only')
    assert page.locator('[data-cr-iso-syncall]').is_disabled()
    assert all(b.is_disabled() for b in page.locator('[data-cr-iso-sync]').all())
    assert ('POST', ONE) not in app.server.calls and ('POST', ALL) not in app.server.calls
    _no_errors(app)


@pytest.mark.parametrize('flag, shown', [(None, 'Off'), ('true', 'On')])
def test_runtime_auto_sync_is_said_to_be_not_available_and_the_browser_flag_is_only_shown(open_app, flag, shown):
    app = open_app(storage={'autosync-c1': flag} if flag else None)
    page = _tab(app)
    card = page.locator('[data-cr-nc-sec="iso-auto"]')
    assert 'not available' in card.locator('[data-cr-nc-k="server"] dd').inner_text()
    assert card.locator('[data-cr-nc-k="browser"] dd').inner_text().strip().startswith(shown)
    assert card.locator('input, button').count() == 0
    assert page.evaluate("() => localStorage.getItem('autosync-c1')") == flag
    _no_errors(app)


def test_runtime_in_german(open_app):
    app = open_app(language='de')
    page = _open_sub(app, 'ISO Sync')
    _need(page, '[data-cr-iso] [data-cr-iso-row]', 'the file table is filled')
    heads = page.locator('[data-cr-iso] h2.cr-iso-h').all_inner_texts()
    assert [h.strip().lower() for h in heads] == ['sync im überblick', 'aktivität und einstellungen', 'dateien', 'nodes']
    assert page.locator('[data-cr-stat="iso-synced"] .cr-stat-label').inner_text().strip().lower() == 'synchronisiert'
    assert page.locator('[data-cr-iso-syncall]').inner_text().strip() == 'Alle fehlenden syncen'
    _no_errors(app)


def test_runtime_210_nodes_two_reads_and_a_node_table_that_scrolls(open_app):
    nodes = [f'n{i:03d}' for i in range(210)]
    files, matrix = [], {}
    for j in range(40):
        name = f'image-{j:02d}.iso'
        files.append({'name': name, 'storage': 'local', 'size': (j + 1) * 100 * 1024 ** 2})
        matrix[f'local:{name}'] = {n: (i + j) % 7 != 0 for i, n in enumerate(nodes)}
    ds = {'shared': [], 'local': {n: [_sync_local('local')] for n in nodes}, 'nodes': nodes, 'offline_nodes': []}
    app = open_app({('GET', STATUS): (200, {'nodes': nodes, 'files': files, 'matrix': matrix}), ('GET', DATASTORES): (200, ds),
                    ('GET', LAST): (200, {})}, viewport=(1280, 900))
    page = _tab(app)
    assert _count(app, 'GET', STATUS) == 1 and _count(app, 'GET', LAST) == 1
    assert _tile(page, 'nodes') == '210 of 210'
    assert page.locator('[data-cr-table="iso-node-table"] tbody tr').count() < 120
    assert _tile(page, 'missing') == '40'
    cells = _cells(page, 'local:image-00.iso')
    assert len(cells) == 210 and list(cells.values()).count('missing') == 30
    over = page.evaluate("""() => document.documentElement.scrollWidth - document.documentElement.clientWidth""")
    assert over <= 0
    _no_errors(app)


@pytest.mark.parametrize('width', [1600, 1280, 1024])
def test_runtime_no_sideways_scroll(open_app, width):
    app = open_app(viewport=(width, 900))
    page = _tab(app)
    _cells(page, 'isos:virtio-win.iso')
    over = page.evaluate("""() => { const el = document.querySelector('[data-cr-iso]');
        const box = (id) => { const s = document.querySelector(`[data-cr-table="${id}"] .cr-table-scroll`);
                              return s.scrollWidth - s.clientWidth; };
        return { page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                 view: el.scrollWidth - el.clientWidth, files: box('iso-files'), nodes: box('iso-node-table') }; }""")
    assert over['page'] <= 0 and over['view'] <= 0, over
    # the Sync of a file is in view without scrolling its table sideways
    assert over['files'] <= 0 and over['nodes'] <= 0, over
    assert _row(page, 'local:ubuntu-24.04.iso').locator('[data-cr-iso-sync]').is_visible()
    _shot(page, f'w{width}')
    _no_errors(app)


# --- source ----------------------------------------------------------------------------------------

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_keys_are_in_every_language_once_and_before_the_banners():
    tr = _read('web', 'src', 'translations.js')
    used = set(re.findall(r"'(crIso[A-Za-z]+)'", _read('web', 'src', 'cr_isosync.js')))
    assert len(used) > 100
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        found = set(re.findall(r'^\s*(crIso[A-Za-z]+):', block, re.M))
        # every language carries them since the translation stage, once and before the banners
        assert found == used, (lang, sorted(used ^ found))
        for key in used:
            assert len(re.findall(rf'^\s*{key}:', block, re.M)) == 1, (lang, key)
        assert block.index('crIsoSub:') < block.index('haNoLeader:'), lang
        for v in re.findall(r'^\s*crIso[A-Za-z]+: (".*"),$', block, re.M):
            assert not any(d in v for d in DASHES), v
    assert not any(d in _read('web', 'src', 'cr_isosync.js') for d in DASHES)


def test_the_variant_is_gated_and_uses_the_classic_writes():
    storage = _read('web', 'src', 'storage.js')
    assert "{activeTab === 'sync' && isCorpRedesigned ? (" in storage
    assert storage.index('<CrIsoSync ') < storage.index("{t('autoSync') || 'Auto-Sync after Upload'}")
    assert 'onSync={triggerSync} onSyncAll={triggerSyncAll}' in storage
    # the classic buttons stay as they were: the click event never reaches the tracked mode
    assert 'onClick={triggerSyncAll} disabled={syncingFiles._all}' in storage
    assert 'onClick={() => triggerSync(sourceNode, f.storage, f.name)}' in storage
    assert storage.count('if (crTracked === true)') == 2
    src = _read('web', 'src', 'cr_isosync.js')
    # reads only: the status and the last result, no write of its own and no browser flag
    assert "method:" not in src and 'POST' not in src
    assert sorted(set(re.findall(r'/iso-sync/[a-z-]+', src))) == ['/iso-sync/last-result', '/iso-sync/status']
    assert 'localStorage.setItem' not in src
    assert 'cr_isosync.js' in _read('web', 'Dev', 'build.sh')
    assert 'function CrIsoSync(' in _read('web', 'index.html')
