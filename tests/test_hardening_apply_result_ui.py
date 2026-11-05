"""The classic Harden PVE Node tab and what an apply answers now.

The server reports success only for a control that ran to its end and passes its check
afterwards, answers the controls that change nothing (net_protocols, the VS-NfD group)
noop, and refuses apply and rollback on a cluster that is not Proxmox VE (code PVE_ONLY).
The tab ticks no noop control after a check, the toast counts only real successes and
names the noop ones apart, and a PVE_ONLY refusal is said once, with the server's words.
Which controls are noop comes from the catalog of GET /api/hardening/profiles (the old
list only for a server without that field), a Failed badge carries the server's reason as
its tooltip, and the rollback toast names the controls that came back only in part.

Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_hardening_custom_profiles_ui.py, for the modern and the corporate layout. NS Nov 2026
"""
import json
import re
import time

import pytest

from test_ha_ui import _App, _toasts, browser  # noqa: F401
from test_hardening_custom_profiles_ui import (CATALOG, HARDEN_PATH, VSNFD, _harden_tab, _no_errors,
                                               _profile_select, _ProfileServer, _read)

VSNFD_RUN = ['fs_modules', 'journald', 'debsums', 'vsnfd_secure_boot', 'vsnfd_disk_encryption']
PASSING = {'fs_modules'}
ANSWERS = {
    'journald': {'success': True, 'verified': True, 'exit_code': 0},
    'debsums': {'success': False, 'verified': False, 'exit_code': 0,
                'error': "the apply ran, but the control's check still fails"},
    'net_protocols': {'success': False, 'noop': True, 'error': 'covered by fs_modules'},
    'vsnfd_secure_boot': {'success': False, 'noop': True, 'error': 'audit only'},
    'vsnfd_disk_encryption': {'success': False, 'noop': True, 'error': 'audit only'},
}
REFUSAL = 'Hardening controls are applied on Proxmox VE nodes only. On this cluster the check runs, but nothing is changed.'
# the catalog as the server hands it out: every entry says whether its apply changes nothing
SERVER_CATALOG = [dict(c, noop=c['id'] in {'net_protocols', *VSNFD}) for c in CATALOG]
ROLLBACK_PATH = HARDEN_PATH + '/rollback'
ROLLBACK = {
    'fs_modules': {'success': True, 'files': {'/etc/modprobe.d/cis-disable-modules.conf': 'restored'}},
    'journald': {'success': False, 'partial': True,
                 'files': {'/etc/systemd/journald.conf': 'restored', '/etc/systemd/journald.conf.d/cis.conf': 'no_snapshot'},
                 'error': 'only 1 of 2 files were restored; no snapshot of /etc/systemd/journald.conf.d/cis.conf'},
    'debsums': {'success': False, 'error': 'control has no rollback snapshot (not reversible)'},
}


class _ApplyServer(_ProfileServer):
    """Answers the vs-nfd check with VS_NFD_RUN and every apply the way the server does now.
    hold: the apply of that control is answered only when the test lets it go (.release())."""

    def __init__(self, refuse=False, catalog=SERVER_CATALOG, hold=None, **kw):
        super().__init__(**kw)
        self.refuse = refuse
        self.catalog = catalog
        self.hold = hold
        self.held = None
        self.rollbacks = []

    def listing(self):
        out = super().listing()
        out['catalog'] = self.catalog
        return out

    def release(self):
        route, data = self.held
        route.fulfill(status=200, body=json.dumps(data), headers={'Content-Type': 'application/json'})

    def check(self, url):
        status, out = super().check(url)
        if 'profile=vs-nfd' in url:
            out['controls'] = {c: c in PASSING for c in VSNFD_RUN}
        return status, out

    def handle(self, route):
        req = route.request
        path = re.sub(r'^https?://[^/]+', '', req.url).split('?')[0]
        if path == HARDEN_PATH and req.method == 'POST':
            body = json.loads(req.post_data or '{}')
            self.calls.append(('POST', path))
            self.applied.append(body)
            if self.refuse:
                status, data = 400, {'error': REFUSAL, 'code': 'PVE_ONLY'}
            else:
                results = {c: ANSWERS.get(c, {'success': True, 'verified': True, 'exit_code': 0})
                           for c in body.get('controls', [])}
                status, data = 200, {'node': 'pve1', 'results': results,
                                     'applied': sum(1 for r in results.values() if r['success']),
                                     'total': len(results)}
                if self.hold in body.get('controls', []):
                    self.held = (route, data)
                    return None
            return route.fulfill(status=status, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        if path == ROLLBACK_PATH and req.method == 'POST':
            controls = json.loads(req.post_data or '{}').get('controls', [])
            self.calls.append(('POST', path))
            self.rollbacks.append(controls)
            results = {c: ROLLBACK.get(c, {'success': True}) for c in controls}
            data = {'node': 'pve1', 'results': results, 'total': len(controls),
                    'restored': sum(1 for r in results.values() if r['success'])}
            return route.fulfill(status=200, body=json.dumps(data), headers={'Content-Type': 'application/json'})
        return super().handle(route)


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(layout='modern', **kw):
        app = _App(browser, _ApplyServer(layout=layout, **kw))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _card(page, title):
    return page.locator('#harden-report-content div.bg-proxmox-card', has_text=title).first


def _ticked(page, title):
    return _card(page, title).locator('input[type="checkbox"]').first.is_checked()


def _select_only(page, *titles):
    page.locator('#harden-report-content + div button').nth(1).click()      # deselect all
    for title in titles:
        _card(page, title).locator('input[type="checkbox"]').first.check()


def _check(page, profile=''):
    if profile:
        _profile_select(page).select_option(profile)
    page.get_by_role('button', name=re.compile('Check Status')).first.click()


def _profiles_loaded(page):
    # the custom profiles of the listing are options of the profile select once it is read
    page.locator('option', has_text='Web tier').first.wait_for(state='attached', timeout=8000)


def _wait_toast(app, needle, seconds=8):
    deadline = time.time() + seconds
    while time.time() < deadline:
        hit = [t for t in _toasts(app.page) if needle in t]
        if hit:
            return hit[0]
        app.page.wait_for_timeout(100)
    raise AssertionError(f'no toast with {needle!r}: {_toasts(app.page)}')


# --- source ------------------------------------------------------------------------------------

def test_the_new_key_is_in_every_language_once_and_in_front_of_the_pinned_chain():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    blocks = {lang: src[s:e] for (s, lang), e in zip(starts, ends)}
    assert set(blocks) == {'de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it'}
    texts = set()
    for lang, block in blocks.items():
        found = re.findall(r"^ {16}hardenNoopCount: '([^'\n]*)',$", block, re.M)
        assert len(found) == 1, lang
        assert '{n}' in found[0] and '\u2014' not in found[0] and '\u2013' not in found[0], lang
        texts.add(found[0])
        lines = block.splitlines()
        at = next(i for i, l in enumerate(lines) if l.lstrip().startswith('controlsApplied:'))
        assert lines[at + 1].lstrip().startswith('hardenNoopCount:'), lang     # next to its neighbour
        banner = block.find('the banners of a group that fails over automatically')
        if banner >= 0:
            assert block.index('hardenNoopCount:') < banner, lang
    assert len(texts) == 9      # translated, not English copied into the other blocks
    assert 'hardenNoopCount' in _read('web', 'index.html')


def test_the_partial_rollback_key_is_in_every_language_next_to_its_neighbour():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^            ([a-z]{2}): \{$', src, re.M)]
    ends = [s for s, _ in starts[1:]] + [len(src)]
    texts = set()
    for (start, lang), end in zip(starts, ends):
        block = src[start:end]
        found = re.findall(r"^ {16}hardenRollbackPartialCount: '([^'\n]*)',$", block, re.M)
        assert len(found) == 1, lang
        assert '{n}' in found[0] and '\u2014' not in found[0] and '\u2013' not in found[0], lang
        texts.add(found[0])
        lines = block.splitlines()
        at = next(i for i, l in enumerate(lines) if l.lstrip().startswith('controlsRolledBack:'))
        assert lines[at + 1].lstrip().startswith('hardenRollbackPartialCount:'), lang
        banner = block.find('the banners of a group that fails over automatically')
        if banner >= 0:
            assert block.index('hardenRollbackPartialCount:') < banner, lang
    assert len(starts) == 9 and len(texts) == 9
    assert 'hardenRollbackPartialCount' in _read('web', 'index.html')


# --- runtime -----------------------------------------------------------------------------------

@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_check_ticks_no_control_that_changes_nothing(open_app, layout):
    app = open_app(layout)
    page = app.page
    _harden_tab(page, layout)
    _check(page)
    page.get_by_text('controls active').first.wait_for(timeout=8000)
    # net_protocols fails its check like the others and stays unticked, its neighbours are ticked
    assert not _ticked(page, 'Disable Unused Network Protocols')
    assert _ticked(page, 'Disable Core Dumps')
    assert not _ticked(page, 'Disable Unused Filesystem Modules')     # passes, never ticked

    _check(page, 'vs-nfd')
    page.get_by_text('1/5 controls active').first.wait_for(timeout=8000)
    assert not _ticked(page, 'UEFI Secure Boot enabled')
    assert not _ticked(page, 'Disk encryption (LUKS / ZFS native)')
    assert _ticked(page, 'Journald Hardening') and _ticked(page, 'Package Verification (debsums)')
    page.get_by_role('button', name=re.compile(r'Apply Selected \(2\)')).wait_for(timeout=3000)
    # Select all follows the same rule
    helper = page.locator('#harden-report-content + div button')
    helper.nth(1).click()       # deselect all
    page.get_by_role('button', name=re.compile(r'Apply Selected \(0\)')).wait_for(timeout=3000)
    helper.nth(0).click()       # select all
    page.get_by_role('button', name=re.compile(r'Apply Selected \(2\)')).wait_for(timeout=3000)
    assert not _ticked(page, 'UEFI Secure Boot enabled')
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_toast_counts_only_real_successes(open_app, layout):
    app = open_app(layout)
    page = app.page
    _harden_tab(page, layout)
    _check(page, 'vs-nfd')
    page.get_by_text('1/5 controls active').first.wait_for(timeout=8000)
    # one audit-only control ticked by hand next to two that run
    _select_only(page, 'Journald Hardening', 'Package Verification (debsums)', 'UEFI Secure Boot enabled')
    page.get_by_role('button', name=re.compile(r'Apply Selected \(3\)')).click()
    page.get_by_role('button', name='Apply', exact=True).click()
    toast = _wait_toast(app, 'controls applied')
    # journald applied, debsums ran but its check still fails, the VS-NfD one changes nothing
    assert toast.startswith('1/3 controls applied'), toast
    assert '1 audit only, nothing to apply' in toast, toast
    assert [b['controls'] for b in app.server.applied] == [['journald'], ['debsums'], ['vsnfd_secure_boot']]
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_cluster_that_is_not_pve_says_why_once(open_app, layout):
    app = open_app(layout, refuse=True)
    page = app.page
    _harden_tab(page, layout)
    _check(page, 'vs-nfd')
    page.get_by_text('1/5 controls active').first.wait_for(timeout=8000)
    _select_only(page, 'Journald Hardening', 'Package Verification (debsums)')
    page.get_by_role('button', name=re.compile(r'Apply Selected \(2\)')).click()
    page.get_by_role('button', name='Apply', exact=True).click()
    _wait_toast(app, 'Proxmox VE nodes only')
    page.wait_for_timeout(500)
    assert len(app.server.applied) == 1                 # stops at the first refusal
    assert not [t for t in _toasts(page) if 'controls applied' in t]
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_tab_takes_the_noop_controls_from_the_server(open_app, layout):
    # a server that marks core_dumps noop and net_protocols not: the tab follows the server
    swapped = [dict(c, noop=c['id'] == 'core_dumps') for c in CATALOG]
    app = open_app(layout, catalog=swapped)
    page = app.page
    _harden_tab(page, layout)
    _profiles_loaded(page)
    _check(page)
    page.get_by_text('controls active').first.wait_for(timeout=8000)
    assert _ticked(page, 'Disable Unused Network Protocols')
    assert not _ticked(page, 'Disable Core Dumps')
    helper = page.locator('#harden-report-content + div button')
    helper.nth(1).click()       # deselect all
    helper.nth(0).click()       # select all
    assert _ticked(page, 'Disable Unused Network Protocols') and not _ticked(page, 'Disable Core Dumps')
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_server_without_the_noop_field_gets_the_old_list(open_app, layout):
    app = open_app(layout, catalog=CATALOG)
    page = app.page
    _harden_tab(page, layout)
    _profiles_loaded(page)
    _check(page)
    page.get_by_text('controls active').first.wait_for(timeout=8000)
    assert not _ticked(page, 'Disable Unused Network Protocols') and _ticked(page, 'Disable Core Dumps')
    _check(page, 'vs-nfd')
    page.get_by_text('1/5 controls active').first.wait_for(timeout=8000)
    assert not _ticked(page, 'UEFI Secure Boot enabled')
    assert _ticked(page, 'Journald Hardening')
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_the_failed_badge_carries_the_reason(open_app, layout):
    app = open_app(layout, hold='journald')
    page = app.page
    _harden_tab(page, layout)
    _check(page, 'vs-nfd')
    page.get_by_text('1/5 controls active').first.wait_for(timeout=8000)
    _select_only(page, 'Package Verification (debsums)', 'Journald Hardening')
    page.get_by_role('button', name=re.compile(r'Apply Selected \(2\)')).click()
    page.get_by_role('button', name='Apply', exact=True).click()
    deadline = time.time() + 8
    while app.server.held is None and time.time() < deadline:
        page.wait_for_timeout(100)
    assert app.server.held is not None
    checks = len(app.server.checks)
    try:
        # debsums has its answer, journald is still running: the badge says why debsums failed
        badge = _card(page, 'Package Verification (debsums)').get_by_text('Failed', exact=True)
        badge.wait_for(timeout=5000)
        assert badge.get_attribute('title') == ANSWERS['debsums']['error']
    finally:
        app.server.release()
    toast = _wait_toast(app, 'controls applied')
    assert toast.startswith('1/2 controls applied'), toast
    deadline = time.time() + 5
    while len(app.server.checks) == checks and time.time() < deadline:
        page.wait_for_timeout(100)
    assert len(app.server.checks) == checks + 1     # the re-check after the loop stays
    _no_errors(app)


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_a_partial_rollback_is_named_in_the_toast(open_app, layout):
    app = open_app(layout)
    page = app.page
    _harden_tab(page, layout)
    _check(page, 'vs-nfd')
    page.get_by_text('1/5 controls active').first.wait_for(timeout=8000)
    _select_only(page, 'Disable Unused Filesystem Modules', 'Journald Hardening', 'Package Verification (debsums)')
    page.once('dialog', lambda d: d.accept())
    checks = len(app.server.checks)
    page.get_by_role('button', name=re.compile(r'Rollback Selected \(3\)')).click()
    toast = _wait_toast(app, 'controls rolled back')
    # fs_modules came back whole, journald only in part, debsums not at all
    assert toast.startswith('1/3 controls rolled back'), toast
    assert '1 only partly, not every file was restored' in toast, toast
    assert app.server.rollbacks == [['fs_modules', 'journald', 'debsums']]
    deadline = time.time() + 5
    while len(app.server.checks) == checks and time.time() < deadline:
        page.wait_for_timeout(100)
    assert len(app.server.checks) == checks + 1
    _no_errors(app)
