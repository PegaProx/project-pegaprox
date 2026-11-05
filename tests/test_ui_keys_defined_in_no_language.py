"""Keys the UI asks for that no language defines.

t() falls back to the language, then English, then the key itself, never to the
`|| 'Fallback'` written next to the call: the key is a non-empty string, so the fallback
never runs. Sixteen keys in the shared t() were defined in no language at all, so the UI
showed their names: "snapshotNameLetterWarning" under a snapshot name that starts with a
digit, "min", "max" and "avg" under the node temperature chart, "deleteSelected" on the
snapshot bulk bar, "hwHealthCause" before the hardware health reasons, the install type
and hint of a package or Docker install in the updater, the replication PDF toasts and
the "ago" in its last-run column. test_translation_backfill_ui.py checks that a key
defined in one language is defined in all of them, which a key defined nowhere passes.

The Cloud layout hands its pages a T that answers undefined for a missing key, so there
the fallback does run: its `cloud.*` keys are fallbacks on purpose. Five plain keys of its
pages (quorumEnabled, selfFence, loaded, unloaded, reload) are added as well, so they are
translated there instead of English. Keys built from a prefix (`driftCheck_` + id) are
not literal and are left out.

The runtime test drives the built bundle in headless Chromium with the fake server of the
Corporate Redesigned guest tests and skips where Playwright is not installed.
"""
import pytest

from test_translation_backfill_ui import LANGS, _blocks, _used
from test_corp_redesigned_vm_ui import _open_guest, browser, open_app, playwright  # noqa: F401


def _asked_for():
    return {k for k in _used() if not k.startswith('cloud.') and not k.endswith('_')}


def test_every_key_the_ui_asks_for_is_defined():
    blocks = _blocks()
    gaps = {key: [lang for lang in LANGS if key not in blocks[lang]] for key in sorted(_asked_for())}
    gaps = {key: langs for key, langs in gaps.items() if langs}
    assert not gaps, f'{len(gaps)} keys the UI asks for are missing: {gaps}'


def test_runtime_a_snapshot_name_with_a_leading_digit_is_explained(open_app):
    app = open_app()
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-objhead="vm"] .cr-objhead-actions > button', has_text='Configure').click()
    modal = page.locator('.corp-vm-modal')
    modal.wait_for(timeout=8000)
    page.locator('.corp-vm-modal-tab', has_text='Snapshots').first.click()
    page.locator('button', has_text='Create Snapshot').first.click()
    name = page.locator('input[placeholder="snapshot-name"]').first
    name.wait_for(timeout=5000)

    name.fill('1st')
    page.wait_for_timeout(200)
    body = page.locator('body').inner_text()

    assert 'snapshotNameLetterWarning' not in body, 'the warning showed its key'
    assert 'Snapshot name must start with a letter from A to Z.' in body
