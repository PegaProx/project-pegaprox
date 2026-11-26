"""A restore over a guest the backup was not taken from can be allowed, where a restore overwrites.

Proxmox VE 9.3 writes the identity (uid) of a guest into its backups and refuses to restore one
over a guest with another uid, force or not: "backup belongs to another guest: its uid ...
differs from uid ... of the existing VM 100 - use 'allow-identity-mismatch' to overwrite the VM
anyway". The restore dialogs had no way to say that, so such a restore could only be finished
on the command line. Where a restore overwrites a guest (the guest's own VMID in its Backups
tab, the overwrite mode of the batch restore and of the PBS restore wizard) the dialog now
offers "Allow restoring a backup of another guest"; ticked, the request carries
allow_identity_mismatch: true, and only then. A refusal with PVE's words shows the box with a
hint, and a batch whose rows failed that way says how to restore them.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
Skips where Playwright is not installed.
"""
import re
import time

import pytest

from test_ha_ui import CLUSTER, LANGS, SSE_TOKEN, TOASTS_JS, VM, VM_CONFIG, _App, _FakeServer, _read, browser  # noqa: F401
from test_backup_runs_batch_restore_ui import CONTENT, NOW, RUN_ID, _batch, _body, _open_storage, _restore_reads
from test_lxc_features_passthrough_ui import _open_config, _tab

Q100 = '/api/clusters/c1/vms/pve1/qemu/100'
RESTORE = Q100 + '/backups/restore'
VOLID = 'pbs1:backup/vm/100/2026-11-20T02:00:00Z'
BACKUP = {'volid': VOLID, 'filename': 'vm/100/2026-11-20T02:00:00Z', 'ctime': 1795000000,
          'size': 2147483648, 'storage': 'pbs1', 'notes': ''}
# qemu-server through pve-guest-common GuestIdentity::prepare_restore, as the server passes it on
REFUSAL = ("backup belongs to another guest: its uid '3f2a' differs from uid '9c1d' of the existing VM 100"
           " - use 'allow-identity-mismatch' to overwrite the VM anyway")
KEYS = ['restoreAllowOtherGuest', 'restoreAllowOtherGuestHint', 'restoreOtherGuestRefused', 'restoreOtherGuestBatch']


def _toast(page, text, timeout=4):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(text in x for x in page.evaluate(TOASTS_JS)):
            return
        page.wait_for_timeout(100)
    raise AssertionError(f'no toast saying {text!r}: {page.evaluate(TOASTS_JS)}')


# -- the Backups tab of a guest ----------------------------------------------------------------

def _restore_dialog(browser):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], extra={
        **SSE_TOKEN, ('GET', f'{Q100}/config'): (200, dict(VM_CONFIG, status={'status': 'running'})),
        ('GET', f'{Q100}/backups'): (200, [BACKUP]), ('POST', RESTORE): (500, {'error': REFUSAL})}))
    page = app.page
    page.on('dialog', lambda d: d.accept())
    _open_config(app, 'web01')
    _tab(app, 'Backups').click()
    page.locator('button[title="Restore"]').first.click()
    dialog = page.locator('div.max-w-md', has_text='Selected Backup').last
    dialog.wait_for(timeout=5000)
    return app, page, dialog


def _restore(app, dialog, n):
    """Restore, and wait for the n-th request to come in."""
    dialog.locator('button', has_text=re.compile(r'^\s*Restore\s*$')).click()
    deadline = time.time() + 4
    while time.time() < deadline and len(app.server.bodies.get(RESTORE, [])) < n:
        app.page.wait_for_timeout(100)


def test_runtime_the_guest_restore_offers_it_and_sends_it_only_when_ticked(browser):  # noqa: F811
    app, page, dialog = _restore_dialog(browser)
    try:
        box = dialog.locator('[data-restore-allow-mismatch]')
        assert box.count() == 1, 'nothing offered over the guest itself'
        assert not box.is_checked()
        assert dialog.locator('[data-restore-other-guest]').get_attribute('data-restore-other-guest') == ''
        assert 'Allow restoring a backup of another guest' in dialog.inner_text()
        # unticked: the request of before
        _restore(app, dialog, 1)
        assert app.server.bodies[RESTORE] == [{'volid': VOLID, 'target_vmid': 100, 'storage': '', 'start': False}]
        _toast(page, 'backup belongs to another guest')
        # the refusal: the dialog stays, the box says what to do
        hint = dialog.locator('[data-restore-other-guest="refused"]')
        hint.wait_for(timeout=3000)
        assert 'Proxmox VE refused: this backup belongs to another guest.' in hint.inner_text()
        box.check()
        app.server.extra[('POST', RESTORE)] = (200, {'success': True, 'task': 'UPID:pve1:x', 'vmid': 100})
        _restore(app, dialog, 2)
        assert app.server.bodies[RESTORE][-1] == {'volid': VOLID, 'target_vmid': 100, 'storage': '', 'start': False,
                                                  'allow_identity_mismatch': True}
        dialog.wait_for(state='detached', timeout=3000)
        # another VMID makes a new guest: nothing to allow, nothing sent; the next dialog starts unticked
        page.locator('button[title="Restore"]').first.click()
        dialog = page.locator('div.max-w-md', has_text='Selected Backup').last
        assert not dialog.locator('[data-restore-allow-mismatch]').is_checked()
        assert dialog.locator('[data-restore-other-guest]').get_attribute('data-restore-other-guest') == ''
        dialog.locator('#restore-vmid').fill('900')
        assert dialog.locator('[data-restore-allow-mismatch]').count() == 0
        dialog.locator('#restore-vmid').fill('100')
        dialog.locator('[data-restore-allow-mismatch]').check()
        dialog.locator('#restore-vmid').fill('901')
        _restore(app, dialog, 3)
        assert app.server.bodies[RESTORE][-1] == {'volid': VOLID, 'target_vmid': 901, 'storage': '', 'start': False}
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- the batch restore -------------------------------------------------------------------------

REFUSED_ROW = {'vmid': 101, 'type': 'qemu', 'volid': CONTENT[2]['volid'], 'target_vmid': 101, 'node': 'pve1',
               'state': 'failed', 'note': REFUSAL.replace('VM 100', 'VM 101'), 'task': 'UPID:x', 'began': NOW, 'ended': NOW}


def _overwrite(browser, ticked, rows=None):  # noqa: F811
    """A batch over the original guests; ticked None leaves the box alone."""
    reads = _restore_reads()
    run = _batch(state='done', counts={'failed': 1}, rows=rows or [REFUSED_ROW], may_cancel=False, mode='overwrite')
    reads[('POST', '/api/clusters/c1/backup-restore/batch')] = (202, {'run': run})
    reads[('GET', f'/api/batch-restores/{RUN_ID}')] = (200, {'run': run})
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM], extra=reads))
    page = _open_storage(app, 'modern')
    page.locator('[data-br-open]').click()
    page.locator('[data-br-check="101"]').check()
    page.locator('[data-br-next]').click()
    assert page.locator('[data-br-options] [data-restore-allow-mismatch]').count() == 0
    page.locator('[data-br-mode="overwrite"]').click()
    page.locator('[data-br-confirm]').check()
    box = page.locator('[data-br-options] [data-restore-allow-mismatch]')
    if ticked is not None:
        assert box.count() == 1, 'nothing offered over the original guests'
        assert not box.is_checked()
    if ticked:
        box.check()
    page.locator('[data-br-start]').click()
    page.locator('[data-br-run]').wait_for(timeout=5000)
    return app, page


@pytest.mark.parametrize('ticked', [False, True])
def test_runtime_the_batch_overwrite_sends_it_only_when_ticked(browser, ticked):  # noqa: F811
    app, page = _overwrite(browser, ticked)
    try:
        (body,) = _body(app)
        assert body['mode'] == 'overwrite' and body['confirm'] is True
        assert ('allow_identity_mismatch' in body) is ticked
        if ticked:
            assert body['allow_identity_mismatch'] is True
        # the row PVE refused says how to restore it
        page.locator('[data-br-run-row="101"]').wait_for(timeout=5000)
        page.wait_for_timeout(300)
        hint = page.locator('[data-br-other-guest]')
        assert hint.count() == 1, 'the refused row says nothing about the box'
        assert '"Allow restoring a backup of another guest" ticked' in hint.inner_text()
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_batch_failed_for_another_reason_gets_no_hint(browser):  # noqa: F811
    row = dict(REFUSED_ROW, note='storage local-zfs is full')
    app, page = _overwrite(browser, None, rows=[row])
    try:
        page.locator('[data-br-run-row="101"]').wait_for(timeout=5000)
        page.wait_for_timeout(300)
        assert page.locator('[data-br-other-guest]').count() == 0
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- source ------------------------------------------------------------------------------------

def test_the_pbs_wizard_sends_it_only_in_overwrite_mode():
    """The restore wizard of the PBS view: the same box, in overwrite mode only."""
    src = _read('web', 'src', 'ui.js')
    wizard = src[src.index('function BackupRestoreWizard('):src.index('window.PegaProxBackupRestoreWizard = BackupRestoreWizard')]
    assert "if (mode === 'overwrite' && otherGuest) body.allow_identity_mismatch = true;" in wizard
    assert ("{mode === 'overwrite' && (\n                                <RestoreOtherGuestOption checked={otherGuest} "
            "onChange={setOtherGuest} refused={restoreRefusedOtherGuest(error, errorCode)} />") in wizard


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.start(), m.group(1)) for m in re.finditer(r'^ {12}([a-z]{2}): \{$', src, re.M)]
    return {lang: src[pos:(starts[i + 1][0] if i + 1 < len(starts) else len(src))] for i, (pos, lang) in enumerate(starts)}


@pytest.mark.parametrize('lang', LANGS)
def test_every_new_key_is_there_once_per_language(lang):
    block = _blocks()[lang]
    for key in KEYS:
        assert len(re.findall(r'^ {16}' + key + r': ', block, re.M)) == 1, (lang, key)
