"""A single restore Proxmox VE refused for another guest shows the hint to tick the box.

Proxmox VE 9.3 refuses a restore over a guest the backup does not belong to inside the restore
task. The server now follows such a restore for a few seconds and answers 409 with code
IDENTITY_MISMATCH and PVE's words. The Backups tab of a guest and the PBS restore wizard turn that
code into their hint "Proxmox VE refused: this backup belongs to another guest. Tick the box ...",
whatever the words, and send allow_identity_mismatch once the box is ticked.

The PBS restore wizard, opened from the PBS view, had no target node to offer: that view has no
cluster selected and the nodes came empty, so its restore never started. It reads the nodes of
its cluster itself now.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
Skips where Playwright is not installed.
"""
import re
import time

from test_ha_ui import CLUSTER, PBS, SSE_TOKEN, _App, _FakeServer, _read, browser  # noqa: F401
from test_a_restore_over_another_guest_can_be_allowed_ui import BACKUP, RESTORE, VOLID, _restore, _restore_dialog

# PVE's words without the phrase the dialogs looked for before: the code alone has to do it
WORDS = "unable to restore VM 100 - use 'allow-identity-mismatch' to overwrite the VM anyway"
REFUSED_409 = (409, {'error': WORDS, 'code': 'IDENTITY_MISMATCH', 'task': 'UPID:pve1:x', 'vmid': 100})
HINT = 'Proxmox VE refused: this backup belongs to another guest.'


# -- the Backups tab of a guest ----------------------------------------------------------------

def test_runtime_the_backups_tab_shows_the_hint_for_the_code_and_then_sends_the_option(browser):  # noqa: F811
    app, page, dialog = _restore_dialog(browser)
    try:
        app.server.extra[('POST', RESTORE)] = REFUSED_409
        _restore(app, dialog, 1)
        assert app.server.bodies[RESTORE] == [{'volid': VOLID, 'target_vmid': 100, 'storage': '', 'start': False}]
        hint = dialog.locator('[data-restore-other-guest="refused"]')
        hint.wait_for(timeout=3000)
        assert HINT in hint.inner_text()
        box = dialog.locator('[data-restore-allow-mismatch]')
        assert not box.is_checked()
        box.check()
        app.server.extra[('POST', RESTORE)] = (200, {'success': True, 'task': 'UPID:pve1:y', 'vmid': 100})
        _restore(app, dialog, 2)
        assert app.server.bodies[RESTORE][-1] == {'volid': VOLID, 'target_vmid': 100, 'storage': '', 'start': False,
                                                  'allow_identity_mismatch': True}
        dialog.wait_for(state='detached', timeout=3000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_a_refusal_for_another_reason_shows_no_hint(browser):  # noqa: F811
    app, page, dialog = _restore_dialog(browser)
    try:
        app.server.extra[('POST', RESTORE)] = (409, {'error': 'VM 100 is locked (backup)', 'code': 'VM_LOCKED'})
        _restore(app, dialog, 1)
        page.wait_for_timeout(400)
        assert dialog.locator('[data-restore-other-guest="refused"]').count() == 0
        assert dialog.locator('[data-restore-other-guest]').get_attribute('data-restore-other-guest') == ''
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- the PBS restore wizard, from the PBS view ---------------------------------------------------

PBS_RESTORE = '/api/clusters/c1/backup-restore'
SNAP = {'backup-type': 'vm', 'backup-id': '100', 'backup-time': 1795000000, 'size': 2147483648}
PBS_READS = {
    **SSE_TOKEN,
    ('GET', '/api/pbs'): (200, [dict(PBS, linked_clusters=['c1'])]),
    ('GET', '/api/pbs/p1/status'): (200, {'version': {'version': '4.0'}}),
    ('GET', '/api/pbs/p1/datastores'): (200, [{'name': 'alpha'}]),
    ('GET', '/api/pbs/p1/jobs'): (200, {'sync': [], 'verify': [], 'prune': []}),
    ('GET', '/api/pbs/p1/datastores/alpha/groups'): (200, [{'backup-type': 'vm', 'backup-id': '100', 'backup-count': 1}]),
    ('GET', '/api/pbs/p1/datastores/alpha/snapshots'): (200, [SNAP]),
    ('GET', '/api/clusters/c1/nextid'): (200, {'vmid': 900}),
    ('POST', PBS_RESTORE): REFUSED_409,
}
METRICS = {'pve2': {'status': 'online'}, 'pve1': {'status': 'online'}}


def _wizard(browser, metrics=METRICS):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], metrics=metrics,
                                    extra=PBS_READS))
    page = app.page
    page.get_by_text('backup01').first.click()
    page.get_by_role('button', name='Datastores').first.click()
    page.get_by_role('button', name=re.compile(r'^alpha\b')).click()
    page.locator('button[title="Restore Backup"]').first.click()
    wizard = page.locator('div.max-w-lg', has_text='Target node').last
    wizard.wait_for(timeout=5000)
    return app, page, wizard


def _start(app, wizard, n):
    wizard.locator('button', has_text='Start restore').click()
    deadline = time.time() + 4
    while time.time() < deadline and len(app.server.bodies.get(PBS_RESTORE, [])) < n:
        app.page.wait_for_timeout(100)
    assert len(app.server.bodies.get(PBS_RESTORE, [])) == n, app.server.bodies


def test_runtime_the_pbs_wizard_offers_the_nodes_of_its_cluster(browser):  # noqa: F811
    app, page, wizard = _wizard(browser)
    try:
        nodes = wizard.locator('select').first
        page.wait_for_function('(el) => el.options.length === 2', arg=nodes.element_handle(), timeout=3000)
        assert nodes.locator('option').all_inner_texts() == ['pve1', 'pve2']
        assert nodes.input_value() == 'pve1'
        assert not wizard.locator('button', has_text='Start restore').is_disabled()
        assert ('GET', '/api/clusters/c1/metrics') in app.server.calls
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def test_runtime_the_pbs_wizard_shows_the_hint_for_the_code_and_then_sends_the_option(browser):  # noqa: F811
    app, page, wizard = _wizard(browser)
    try:
        wizard.locator('button', has_text=re.compile(r'^\s*overwrite\s*$')).click()
        wizard.locator('input[type="number"]').fill('100')
        nodes = wizard.locator('select').first
        page.wait_for_function('(el) => el.options.length === 2', arg=nodes.element_handle(), timeout=3000)
        nodes.select_option('pve2')
        _start(app, wizard, 1)
        assert app.server.bodies[PBS_RESTORE][0] == {
            'volid': 'pbs-backup01:backup/vm/100/2026-11-18T11:06:40Z', 'target_node': 'pve2',
            'target_vmid': 100, 'mode': 'overwrite'}
        # the wizard stays, with PVE's words and the hint on its box
        hint = wizard.locator('[data-restore-other-guest="refused"]')
        hint.wait_for(timeout=3000)
        assert HINT in hint.inner_text()
        assert WORDS in wizard.inner_text()
        wizard.locator('[data-restore-allow-mismatch]').check()
        app.server.extra[('POST', PBS_RESTORE)] = (200, {'success': True, 'upid': 'OK', 'mode': 'overwrite',
                                                         'target_vmid': 100})
        _start(app, wizard, 2)
        assert app.server.bodies[PBS_RESTORE][1] == dict(app.server.bodies[PBS_RESTORE][0],
                                                         allow_identity_mismatch=True)
        wizard.wait_for(state='detached', timeout=3000)
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# -- source ------------------------------------------------------------------------------------

def test_both_dialogs_read_the_code_and_the_batch_reads_as_before():
    src = _read('web', 'src', 'ui.js')
    helper = src[src.index('const restoreRefusedOtherGuest = '):src.index('function RestoreOtherGuestOption(')]
    assert "code === 'IDENTITY_MISMATCH'" in helper and '/backup belongs to another guest/i' in helper
    wizard = src[src.index('function BackupRestoreWizard('):src.index('window.PegaProxBackupRestoreWizard = BackupRestoreWizard')]
    assert 'refused={restoreRefusedOtherGuest(error, errorCode)}' in wizard
    assert "setErrorCode(j.code || '');" in wizard
    cfg = _read('web', 'src', 'vm_config.js')
    assert 'if (restoreRefusedOtherGuest(err.error, err.code)) setRestoreIdentity(' in cfg
    # the batch keeps its own reading of rows and errors
    batch = src[src.index('function BatchRestoreModal('):]
    assert 'refused={restoreRefusedOtherGuest(error) || refused.some(r => restoreRefusedOtherGuest(r.error))}' in batch
    assert "restoreRefusedOtherGuest(r.note)" in batch


def test_the_wizard_drops_an_answer_for_the_cluster_it_left():
    """The wizard reads the nodes and the next free id of its cluster. An answer for the
    cluster before a switch that came after the new one put the old nodes back, with a node
    of the new cluster selected, or a node of the old one kept. Each read is dropped once
    its effect is gone, and a kept node must be one of the cluster's."""
    src = _read('web', 'src', 'ui.js')
    wizard = src[src.index('function BackupRestoreWizard('):src.index('const submit = async () => {')]
    nodes = wizard[wizard.index('/metrics`'):]
    nodes = nodes[:nodes.index('}, [clusterId]);')]
    assert 'if (gone || !r || !r.ok) return;' in nodes
    assert 'if (gone || !j ||' in nodes
    assert 'setTargetNode(cur => names.includes(cur) ? cur : (names[0] || \'\'));' in nodes
    assert 'return () => { gone = true; };' in nodes
    nextid = wizard[wizard.index('/nextid`'):]
    nextid = nextid[:nextid.index('}, [mode, clusterId]);')]
    assert 'if (!gone && r && r.ok) {' in nextid and 'if (!gone && j.vmid' in nextid
    assert 'return () => { gone = true; };' in nextid
