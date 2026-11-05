"""Review fixes of Corporate Redesigned, in the browser.

- The Snapshots tab of a guest: the efficient list (LVM COW) needs vm.snapshot, the plain list
  vm.view. A viewer gets 403 for the efficient one; that is a list the account is not offered,
  so no error callout (whose Retry could never succeed) and the plain snapshots are drawn. A 500
  or a lost answer is still said as failed, with Retry.
- Backup SLA: a confined account gets the stores the server could not read as a count without
  names; the page says how many, without a list of dashes.
- Copy as text of Updates takes the browser's copy of a classic check only when this account
  ran it: classic now writes who did, and the next account of the browser copies the counts of
  the overview instead of the packages of the one before.
- Auto-sync after an upload: a pending copy that goes without being made is said, when the view
  is left and when its task is not seen ending in time.

The fakes serve the shapes of pegaprox/api/vms.py (snapshots, efficient-snapshots, the 403 body
of its permission check, the upload answer with its upid), clusters.py (backup-sla with unread)
and settings.py (updates check and overview). PEGAPROX_CR_BUNDLE=<file> serves another bundle
(the counterproof). Skips without Playwright. LW Nov 2026
"""
import json
import re

import pytest

from test_corp_redesigned_vm_ui import _calls, _no_errors, _open_guest, browser, open_app, playwright  # noqa: F401
from test_corp_redesigned_automation_reads_ui import (SLA, SLA_REPORT, _UpdClear, _copied, _copy_hook, _guard, _sla,
                                                       apps)  # noqa: F401
from test_corp_redesigned_updates_ui import _need, _tab as _upd_tab, _upd

Q100 = '/api/clusters/c1/vms/pve1/qemu/100'
# GET .../snapshots as PVE lists it through vms.py: the 'current' entry plus one snapshot
SNAPS = [{'name': 'pre-upgrade', 'description': 'before the kernel update', 'snaptime': 1793000000, 'vmstate': 0},
         {'name': 'current', 'description': 'You are here!', 'parent': 'pre-upgrade'}]


def _snapshots_tab(open_app, eff):
    app = open_app()
    app.server.routes.update({('GET', f'{Q100}/snapshots'): (200, SNAPS),
                              ('GET', f'{Q100}/efficient-snapshots'): eff})
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-tabs="guest"] [data-cr-tab="snapshots"]').click()
    page.locator('.corp-snap-row', has_text='pre-upgrade').first.wait_for(timeout=8000)
    # both reads are in before the callout is judged
    for _ in range(50):
        if _calls(app, f'{Q100}/efficient-snapshots') and _calls(app, f'{Q100}/snapshots'):
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(600)
    return app, page


def test_runtime_a_viewer_without_vm_snapshot_sees_the_snapshots_without_an_error(open_app):
    app, page = _snapshots_tab(open_app, (403, {'error': 'Permission denied: vm.snapshot'}))
    assert _calls(app, f'{Q100}/efficient-snapshots'), app.server.calls[-10:]
    assert page.locator('[data-cr-vm-snaps-fail]').count() == 0, page.locator('[data-cr-vm-snaps-fail]').inner_text()
    assert page.get_by_text('could not be read').count() == 0
    assert page.locator('.corp-snap-row', has_text='pre-upgrade').count() == 1
    _no_errors(app)


@pytest.mark.parametrize('eff', [(500, {'error': 'Could not read the efficient snapshots'}), 'abort'])
def test_runtime_a_failed_efficient_read_is_still_said_with_retry(open_app, eff):
    app, page = _snapshots_tab(open_app, eff)
    note = page.locator('[data-cr-vm-snaps-fail="eff"]')
    note.wait_for(timeout=5000)
    assert 'The efficient snapshots (LVM COW) could not be read' in note.inner_text(), note.inner_text()
    assert note.locator('[data-cr-vm-snaps-retry]').count() == 1
    # the plain list is drawn under it
    assert page.locator('.corp-snap-row', has_text='pre-upgrade').count() == 1
    _no_errors(app, dropped=eff == 'abort')


# --- Backup SLA: unread stores of a confined account ----------------------------------------------------

def test_runtime_a_count_of_unread_stores_without_names_is_said_without_a_list(apps):
    # what clusters.py answers a pool or ACL confined caller: the stores without their names
    report = dict(SLA_REPORT, unread=[{'storage': None, 'node': None, 'error': 'HTTP 500'},
                                      {'storage': None, 'node': None, 'error': 'did not answer in time'}])
    app = _guard(apps, extra={('GET', SLA): (200, report)})
    page = _sla(app)
    _need(page, '[data-cr-sla-unread-stores]', 'the page says that stores could not be read')
    note = page.locator('[data-cr-sla-unread-stores]')
    text = note.inner_text()
    assert note.get_attribute('data-cr-sla-unread-stores') == '2'
    assert 'The server could not read 2 storage(s). Guests whose backups lie there may show no backup' in text, text
    assert '-, -' not in text and ': -' not in text, text
    assert app.errors == []


# --- Updates: whose browser copy is copied ------------------------------------------------------------------

CACHED = {'time': '2026-10-30T08:00:00.000Z', 'summary': {'total_updates': 3, 'nodes_failed': 0, 'total_pbs': 0},
          'nodes': {'pve1': {'success': True, 'count': 1, 'updates': [
              {'Package': 'libssl3', 'OldVersion': '3.0.15', 'Version': '3.0.17', 'Origin': 'Debian', 'Section': 'libs'}]}}}


@pytest.mark.parametrize('who', ['viewer', None], ids=['another-account', 'nobody-named'])
def test_runtime_the_browser_copy_of_another_account_is_not_copied(apps, who):
    cached = dict(CACHED, **({'user': who} if who else {}))
    app = apps(_UpdClear(layout='corporate-redesigned'), storage={'updateCheck_c1': json.dumps(cached)})
    page = _upd_tab(app)
    btn = page.locator('[data-cr-upd-copy]')
    # the counts of the server's overview, not the packages of the one before
    assert not btn.is_disabled() and btn.get_attribute('data-cr-upd-copy') == 'model', btn.get_attribute('data-cr-upd-copy')
    _copy_hook(page)
    text = _copied(page)
    assert 'libssl3' not in text and '3.0.17' not in text, text
    assert 'pve1 - 5 updates' in text, text
    assert _upd(app, 'POST', '/updates/check') == []
    assert app.errors == []


def test_runtime_a_classic_check_names_the_account_that_ran_it(apps):
    app = apps(_UpdClear(layout='corporate'))
    page = app.page
    page.locator('.corp-tree-item', has_text='Testi').first.click()
    page.locator('button', has_text=re.compile(r'^\s*Automation\s*$')).first.click()
    page.wait_for_timeout(400)
    page.locator('button', has_text=re.compile(r'^\s*Settings\s*$')).last.click()
    _need(page, '[data-update-manager] h3', 'classic Settings has its Update Manager')
    # no copy in the browser yet: the section runs its first check and keeps the answer
    page.wait_for_function("() => !!localStorage.getItem('updateCheck_c1')", timeout=10000)
    kept = json.loads(page.evaluate("() => localStorage.getItem('updateCheck_c1')"))
    assert kept.get('user') == 'admin', kept.keys()
    assert kept.get('nodes') and kept.get('summary')
    assert app.errors == []


# --- Auto-sync after an upload: a copy that goes without being made is said -----------------------------

def _upload_with_autosync(browser, tasks):
    from test_corp_redesigned_guard_ui import _GuardApp
    from test_corp_redesigned_storage_reads_ui import BUNDLE as SR_BUNDLE, _ReadServer, _browse
    server = _ReadServer(layout='corporate-redesigned', bundle=SR_BUNDLE, tasks=tasks,
                         extra={('POST', '/api/clusters/c1/iso-sync'): (200, {'success': True, 'message': 'Sync started'})})
    app = _GuardApp(browser, server, storage={'autosync-c1': 'true'}, viewport=(1600, 1000))
    page = _browse(app)
    page.locator('[data-cr-ds-row="s:local@pve1"]').click()
    page.locator('[data-cr-ds-action="upload"]').click()
    page.locator('input[type="file"]').set_input_files(files=[{'name': 'small.iso', 'mimeType': 'application/octet-stream', 'buffer': b'x' * 64}])
    page.locator('div.fixed.inset-0 button', has_text=re.compile(r'^\s*Upload\s*$')).click()
    page.wait_for_function('() => !document.querySelector("input[type=file]")', timeout=8000)
    assert server.uploads == ['local']
    page.get_by_text('Auto-sync: small.iso goes to the other nodes').first.wait_for(timeout=5000)
    return app, page


def _sr_errors(app):
    return [e for e in app.errors if 'authFetch err: TypeError: Failed to fetch' not in e]


def test_runtime_an_upload_task_not_seen_ending_in_time_is_said(browser):
    from test_corp_redesigned_guard_ui import TASKS
    app, page = _upload_with_autosync(browser, list(TASKS))
    try:
        page.wait_for_timeout(500)
        assert page.get_by_text('Auto-sync did not start').count() == 0
        # the task of the upload never shows up in the task list; a quarter of an hour later (every
        # timer that is due fires once) the wait ends and says so
        page.clock.fast_forward(15 * 60 * 1000 + 1000)
        page.get_by_text('Auto-sync did not start: the upload task of small.iso was not seen ending in time').first.wait_for(timeout=5000)
        assert ('POST', '/api/clusters/c1/iso-sync') not in app.server.calls
        assert _sr_errors(app) == []
    finally:
        app.close()


def test_runtime_a_pending_copy_left_behind_with_the_view_is_said(browser):
    from test_corp_redesigned_guard_ui import TASKS
    app, page = _upload_with_autosync(browser, list(TASKS))
    try:
        page.wait_for_timeout(500)
        assert page.get_by_text('was not copied, the view was left').count() == 0
        # another tab of the cluster: the Datastore view goes, and its pending copy with it
        page.locator('[data-cr-tab="automation"]').click()
        page.get_by_text('Auto-sync: small.iso was not copied, the view was left before Proxmox VE had stored the file').first.wait_for(timeout=5000)
        assert ('POST', '/api/clusters/c1/iso-sync') not in app.server.calls
        assert _sr_errors(app) == []
    finally:
        app.close()
