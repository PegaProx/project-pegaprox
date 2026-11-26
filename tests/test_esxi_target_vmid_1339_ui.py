"""The target VMID of an ESXi migration in the UI (#1339).

The wizard has an optional Target VMID on its target step (empty = the next free one), its
review shows the VMID the server checked or the range the next free one comes from, and a
refusal of the server stays there with Start off. The bulk dialog takes a VMID per guest on
its guests step, can number the guests from one VMID, and shows each guest's on the review.

Runtime tests drive the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; they skip where Playwright is not installed.
LW Nov 2026
"""
import json
import os
import re

from test_ha_ui import _classes, browser  # noqa: F401 (browser: a fixture)
from test_esxi_mapping_verify import WIZ_DRY, _migrate_bodies, _pick_target, wizard  # noqa: F401
from test_esxi_bulk import CHECK, BULK, _bodies, _item, _pick_targets, _wait_bodies, dialog  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ['de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru']
KEYS = ['v2pTargetVmid', 'v2pTargetVmidAuto', 'v2pTargetVmidHint', 'esxiBulkVmidFrom', 'esxiBulkVmidFill']


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _blocks():
    src = _read('web', 'src', 'translations.js')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z]{2}): \{', src, re.M)]
    ends = [pos for _, pos in starts[1:]] + [len(src)]
    return {lang: src[pos:end] for (lang, pos), end in zip(starts, ends)}


def _added_markup():
    src = _read('web', 'src', 'dashboard.js')
    parts = []
    for anchor, end in (('{/* LW Nov 2026 (#1339) - the VMID the guest lands under', '{/* ESXi SSH User'),
                        ('{rv.target_vmid !== undefined && (', '</span></div>'),
                        ("<span>{t('esxiBulkVmidFrom')}</span>", '{guests.map(g => {'),
                        ("<span className=\"text-gray-500\">{t('v2pTargetVmid')}</span>", '{r && r.nics.length'),
                        ('{it.target_vmid !== undefined && (', '</span></div>')):
        at = src.index(anchor)
        parts.append(src[max(0, src.rfind('\n', 0, at - 200)):src.index(end, at)])
    return '\n'.join(parts)


def test_every_language_has_each_label_once_and_in_its_own_words():
    blocks = _blocks()
    assert list(blocks) == LANGS
    for key in KEYS:
        values = {}
        for lang, block in blocks.items():
            found = re.findall(rf"^\s*{key}: '((?:[^'\\]|\\.)+)',", block, re.M)
            assert len(found) == 1, (key, lang, found)
            values[lang] = found[0]
        assert all(v != values['en'] for lang, v in values.items() if lang != 'en'), (key, values)
        assert not any(chr(0x2014) in v for v in values.values())


def test_the_new_keys_sit_next_to_the_bulk_guest_keys_not_in_the_pinned_tail():
    for lang, block in _blocks().items():
        at = block.index('esxiBulkOwnChoices:')
        nxt = block[at:].split('\n')[1:6]
        assert [ln.strip().split(':')[0] for ln in nxt] == KEYS, (lang, nxt)
        assert block.index('v2pTargetVmid:') < block.index('// LW Oct 2026 (#625) - the banners')


def test_the_markup_uses_classes_the_static_build_has_and_text_through_t():
    css = _read('static', 'css', 'tailwind.min.css')
    have = {m.group(1).replace('\\', '') for m in re.finditer(r'\.((?:\\.|[A-Za-z0-9_-])+)', css)}
    markup = _added_markup()
    missing = sorted(n for n in _classes(markup) if n not in have and n not in ('small',))
    assert not missing, missing
    assert chr(0x2014) not in markup
    # nothing a user reads that is not a translation key (the numbers are placeholders)
    for m in re.finditer(r'placeholder="([^"]*)"', markup):
        assert m.group(1).isdigit(), m.group(0)


def test_the_wizard_field_is_on_the_target_step_and_cleared_for_the_next_run():
    src = _read('web', 'src', 'dashboard.js')
    step = src[src.index("{migrateWizardStep === 'target' && ("):src.index("{migrateWizardStep === 'hardware' && (")]
    assert 'data-v2p-target-vmid' in step and "t('v2pTargetVmidHint')" in step
    assert ("if (showVmwareMigrate) setVmwareMigrateForm(f => (f.target_vmid ? {...f, target_vmid: ''} : f));\n"
            "            }, [showVmwareMigrate, vmwareSelectedVm]);") in src


def test_the_bulk_dialog_sends_a_guests_vmid_with_its_own_choices():
    src = _read('web', 'src', 'dashboard.js')
    comp = src[src.index('function EsxiBulkMigrate('):src.index('function EsxiBulkRuns(')]
    assert 'const m = {...mapsOf(g.id), ...vmidOf(g.id)};' in comp
    assert "data-esxi-bulk-vmid={g.id}" in comp and 'data-esxi-bulk-vmid-from' in comp


def test_the_bundle_carries_it():
    bundle = _read('web', 'index.html')
    assert "v2pTargetVmid:'Target VMID'" in bundle and 'data-v2p-target-vmid' in bundle
    assert 'data-esxi-bulk-vmid' in bundle
    assert json.loads(_read('web', 'i18n', 'de.json'))['v2pTargetVmid'] == 'Ziel-VMID'


# -- runtime: the wizard -------------------------------------------------------------------------

def _review(page):
    page.locator('button', has_text='Review and start').click()


def _start_button(page):
    return page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$'))


def test_runtime_a_chosen_vmid_is_reviewed_shown_and_started_as_reviewed(wizard):
    dry = dict(WIZ_DRY, target_vmid=1300, vmid_range=None)
    app, page = wizard(dry=dry)
    _pick_target(page)
    field = page.locator('[data-v2p-target-vmid]')
    field.wait_for(timeout=3000)
    assert field.get_attribute('placeholder') == 'next free ID'
    page.get_by_text('A chosen ID is checked in the review').first.wait_for(timeout=2000)
    field.fill('1300')
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    _review(page)
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    page.locator('[data-v2p-review-vmid]').get_by_text('1300').wait_for(timeout=2000)
    review = _migrate_bodies(app)[-1]
    assert review['dry_run'] is True and review['target_vmid'] == '1300'
    page.locator('label', has_text='keep this in mind').locator('input').check()
    start = _start_button(page)
    assert start.is_enabled()
    start.click()
    for _ in range(50):
        if [b for b in _migrate_bodies(app) if not b.get('dry_run')]:
            break
        page.wait_for_timeout(100)
    sent = [b for b in _migrate_bodies(app) if not b.get('dry_run')]
    assert len(sent) == 1 and sent[0]['target_vmid'] == '1300'
    assert not app.errors, app.errors


def test_runtime_without_a_vmid_the_review_names_the_range_the_next_free_one_comes_from(wizard):
    app, page = wizard(dry=dict(WIZ_DRY, target_vmid=None, vmid_range=[2000, 2999]))
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    _review(page)
    page.locator('[data-v2p-review-vmid]').get_by_text('next free ID (2000-2999)').wait_for(timeout=5000)
    assert 'target_vmid' not in _migrate_bodies(app)[-1]
    assert not app.errors, app.errors


def test_runtime_a_vmid_the_server_refuses_shows_on_the_review_and_keeps_start_off(wizard):
    bad = dict(WIZ_DRY, ok=False, target_vmid=1200, vmid_range=None,
               errors=['VMID 1200 cannot be used on the target cluster: guest ID 1200 is already in use - '
                       'choose another one, or leave it empty for the next free one'])
    app, page = wizard(dry=bad)
    _pick_target(page)
    page.locator('[data-v2p-target-vmid]').fill('1200')
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    page.locator('label', has_text='keep this in mind').locator('input').check()
    _review(page)
    page.get_by_text('The plan does not fit the target node:').first.wait_for(timeout=5000)
    page.get_by_text('guest ID 1200 is already in use').first.wait_for(timeout=2000)
    assert _start_button(page).is_disabled()
    # a new VMID is another request: the old check no longer counts
    page.locator('button', has_text='Target').first.click()
    page.locator('[data-v2p-target-vmid]').fill('1300')
    app.server.extra[('POST', '/api/vmware/v1/vms/vm-1/migrate')] = (200, dict(WIZ_DRY, target_vmid=1300))
    page.locator('button', has_text=re.compile(r'^\W*Review\s*$')).first.click()
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    assert _migrate_bodies(app)[-1]['target_vmid'] == '1300'
    assert _start_button(page).is_enabled()
    assert not app.errors, app.errors


def test_runtime_the_vmid_does_not_carry_over_to_the_next_wizard(wizard):
    app, page = wizard()
    _pick_target(page)
    page.locator('[data-v2p-target-vmid]').fill('1300')
    page.locator('button:visible', has_text=re.compile(r'^\s*Cancel\s*$')).last.click()
    page.locator('button:visible', has_text='Start Migration Wizard').first.click()
    page.locator('option', has_text='Select cluster...').first.wait_for(state='attached', timeout=5000)
    _pick_target(page)
    assert page.locator('[data-v2p-target-vmid]').input_value() == ''
    assert not app.errors, app.errors


# -- runtime: the bulk dialog --------------------------------------------------------------------

def _open_bulk(page):
    page.locator('[data-esxi-bulk-all]').check()
    page.get_by_text('Selected: 2').first.wait_for(timeout=2000)
    page.locator('[data-esxi-bulk-bar] button', has_text='Migrate to Proxmox').click()
    dlg = page.locator('[data-esxi-bulk]')
    dlg.locator('option', has_text='Testi').first.wait_for(state='attached', timeout=5000)
    _pick_targets(page)
    dlg.locator('input[type="password"]').fill('pw-1')
    return dlg


def test_runtime_bulk_guests_numbered_from_one_vmid_and_one_changed_by_hand(dialog):
    items = [dict(_item('vm-1', 'legacy01'), target_vmid=1300), dict(_item('vm-2', 'legacy02'), target_vmid=1305)]
    app, page = dialog(check=dict(CHECK, items=items, vmid_range=None))
    dlg = _open_bulk(page)
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 1)
    assert _bodies(app)[0]['vms'] == ['vm-1', 'vm-2']
    page.locator('[data-esxi-bulk-vmid-from]').fill('1300')
    dlg.locator('button', has_text='Fill in').click()
    page.locator('[data-esxi-bulk-guest="vm-2"] button').first.click()
    vm2 = page.locator('[data-esxi-bulk-vmid="vm-2"]')
    assert vm2.input_value() == '1301'
    vm2.fill('1305')
    page.locator('[data-esxi-bulk-guest="vm-2"]').get_by_text('Target VMID: 1305').wait_for(timeout=2000)
    dlg.locator('button', has_text='Review and start').click()
    _wait_bodies(app, page, 2)
    review = _bodies(app)[-1]
    assert review['vms'] == [{'vm_id': 'vm-1', 'target_vmid': 1300}, {'vm_id': 'vm-2', 'target_vmid': 1305}]
    page.locator('[data-esxi-bulk-review="vm-2"]').get_by_text('1305').wait_for(timeout=3000)
    assert dlg.locator('[data-esxi-bulk-start]').is_enabled()
    assert not app.errors, app.errors


def test_runtime_a_bulk_vmid_refused_for_one_guest_shows_there(dialog):
    refused = _item('vm-1', 'legacy01', errors=["VMID 1300 is outside this tenant's range (2000-2999)"])
    bad = dict(CHECK, ok=False, vmid_range=[2000, 2999], items=[
        dict(refused, target_vmid=1300), dict(_item('vm-2', 'legacy02'), target_vmid=None)])
    app, page = dialog(check=bad)
    dlg = _open_bulk(page)
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 1)
    dlg.locator('button', has_text='Review and start').click()
    page.locator('[data-esxi-bulk-review="vm-1"]').get_by_text("outside this tenant's range").wait_for(timeout=3000)
    page.locator('[data-esxi-bulk-review="vm-2"]').get_by_text('next free ID (2000-2999)').wait_for(timeout=2000)
    assert dlg.locator('[data-esxi-bulk-start]').is_disabled()
    assert not app.errors, app.errors
