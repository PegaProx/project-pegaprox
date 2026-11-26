"""#1252 in the ESXi wizard and the bulk dialog: the box that lets a migration install
packages on the target node (on by default), and the review's list of what the chosen
options need there, what is missing and what could not be checked.

The source half runs everywhere. The runtime half renders the built page in headless
Chromium against the fake servers of tests/test_esxi_mapping_verify.py and
tests/test_esxi_bulk.py, and skips without Playwright.
LW Nov 2026
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8') as fh:
    TR = fh.read()
with open(os.path.join(ROOT, 'web', 'src', 'dashboard.js'), encoding='utf-8') as fh:
    DASH = fh.read()

LANGS = ('de', 'en', 'zh', 'pl', 'fr', 'es', 'pt', 'ko', 'it', 'ru')
KEYS = ('v2pAllowPackageInstall', 'v2pAllowPackageInstallDesc', 'v2pPkgTitle', 'v2pPkgCouldNotCheck',
        'v2pPkgNeeded', 'v2pPkgOptional', 'v2pPkgInstalled', 'v2pPkgMissing', 'v2pPkgWillInstall',
        'v2pPkgNotChecked', 'v2pPkgManual', 'v2pPkgOptionalHint', 'v2pPkgForSshfs', 'v2pPkgForSshpass',
        'v2pPkgForVirtio', 'v2pPkgForVirtioBuild', 'v2pPkgForRbd', 'v2pPkgForLz4')
TAIL = '// LW Oct 2026 (#625) - the banners of a group that fails over automatically, for every user'


def _blocks():
    starts = sorted((TR.index(f'            {lg}: {{'), lg) for lg in LANGS)
    out = {}
    for i, (pos, lg) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(TR)
        out[lg] = TR[pos:end]
    return out


BLOCKS = _blocks()


def _table(block):
    return dict(re.findall(r"^\s+(\w+): '((?:[^'\\]|\\.)*)',$", block, re.M))


@pytest.mark.parametrize('lang', LANGS)
def test_every_key_is_in_every_language_once_and_ahead_of_the_pinned_tail(lang):
    block = BLOCKS[lang]
    table = _table(block)
    for k in KEYS:
        assert len(re.findall(rf'^\s+{k}: ', block, re.M)) == 1, (lang, k)
        assert table[k].strip(), (lang, k)
        assert '\u2014' not in table[k], (lang, k)
        assert block.index(f'{k}: ') < block.index(TAIL), (lang, k)
    assert '{node}' in table['v2pPkgTitle'], lang


@pytest.mark.parametrize('lang', [lg for lg in LANGS if lg != 'en'])
def test_the_long_texts_are_translated(lang):
    en, tr = _table(BLOCKS['en']), _table(BLOCKS[lang])
    for k in ('v2pAllowPackageInstall', 'v2pAllowPackageInstallDesc', 'v2pPkgCouldNotCheck', 'v2pPkgOptionalHint',
              'v2pPkgWillInstall'):
        assert tr[k] != en[k], (lang, k)


def test_the_wizard_and_the_bulk_dialog_send_the_box_and_show_the_list():
    # one box each, bound to allow_package_install, on by default
    assert "allow_package_install:true," in DASH
    assert "allow_package_install: true," in DASH
    assert DASH.count("checked={vmwareMigrateForm.allow_package_install !== false}") == 1
    assert DASH.count("checked={form.allow_package_install !== false}") == 1
    # the review of each lists what the node has
    assert '<V2pNodePackages np={rv.node_packages} t={t} />' in DASH
    assert '<V2pNodePackages np={check.node_packages} t={t} />' in DASH
    # an unknown state is never shown as installed
    comp = DASH[DASH.index('function V2pNodePackages'):]
    comp = comp[:comp.index('\n        }\n')]
    assert "p.installed === true" in comp and "p.installed !== false" in comp


# --------------------------------------------------------------------------- the wizard, rendered

from test_ha_ui import browser  # noqa: E402,F401 (a fixture: headless Chromium, skips without Playwright)
from test_esxi_mapping_verify import WIZ_DRY, wizard, _pick_target, _migrate_bodies  # noqa: E402,F401

PKGS = {'node': 'pve1', 'checked': True, 'error': None, 'allow_install': True,
        'items': [{'package': 'sshfs', 'feature': 'sshfs', 'purpose': 'mounting the ESXi datastore over SSHFS',
                   'needed': True, 'installed': False},
                  {'package': 'sshpass', 'feature': 'sshpass', 'purpose': 'password logins', 'needed': False,
                   'installed': True}],
        'missing': ['sshfs'], 'missing_needed': ['sshfs'],
        'apt_command': 'apt-get install --no-install-recommends sshfs'}


def _review(page):
    page.locator('button', has_text='Review and start').click()


def test_runtime_the_review_lists_what_will_be_installed(wizard):
    app, page = wizard(dry=dict(WIZ_DRY, node_packages=PKGS))
    _pick_target(page)
    page.locator('option', has_text='dmz10 (vnet)').first.wait_for(state='attached', timeout=5000)
    box = page.locator('[data-v2p-allow-packages]')
    assert box.is_checked()
    page.get_by_text('Install missing packages on the target node').first.wait_for(timeout=2000)
    _review(page)
    page.get_by_text('The plan fits the target node.').first.wait_for(timeout=5000)
    page.locator('[data-v2p-packages]').get_by_text('Packages on pve1').wait_for(timeout=2000)
    sshfs = page.locator('[data-v2p-package="sshfs"]').inner_text()
    assert 'SSHFS mount of the ESXi datastore, needed' in sshfs and 'missing, will be installed' in sshfs
    sshpass = page.locator('[data-v2p-package="sshpass"]').inner_text()
    assert 'optional' in sshpass and sshpass.strip().endswith('installed')
    page.get_by_text('apt-get install --no-install-recommends sshfs').first.wait_for(timeout=2000)
    assert _migrate_bodies(app)[-1]['allow_package_install'] is True
    assert not app.errors, app.errors


def test_runtime_unticked_the_review_says_what_is_missing_and_start_stays_off(wizard):
    refused = dict(WIZ_DRY, ok=False, node_packages=dict(PKGS, allow_install=False),
                   errors=['Target node pve1 is missing packages this migration needs, and installing packages on it '
                           'is turned off for this migration: sshfs (mounting the ESXi datastore over SSHFS). Install '
                           'them on the node (apt-get install --no-install-recommends sshfs) or allow the installs.'])
    app, page = wizard(dry=refused)
    _pick_target(page)
    page.locator('input[placeholder="ESXi password"]').fill('pw')
    page.locator('label', has_text='keep this in mind').locator('input').check()
    page.locator('[data-v2p-allow-packages]').uncheck()
    _review(page)
    page.get_by_text('The plan does not fit the target node:').first.wait_for(timeout=5000)
    assert _migrate_bodies(app)[-1]['allow_package_install'] is False
    sshfs = page.locator('[data-v2p-package="sshfs"]').inner_text()
    assert sshfs.strip().endswith('missing') and 'will be installed' not in sshfs
    assert page.locator('button', has_text=re.compile(r'^\s*Start Migration\s*$')).is_disabled()
    assert not app.errors, app.errors


def test_runtime_a_node_that_was_not_asked_shows_not_checked(wizard):
    unknown = dict(PKGS, checked=False, error='no route to host', missing=None, missing_needed=None,
                   apt_command='', items=[dict(it, installed=None) for it in PKGS['items']])
    app, page = wizard(dry=dict(WIZ_DRY, node_packages=unknown))
    _pick_target(page)
    _review(page)
    page.get_by_text('The packages on the node could not be checked: no route to host').first.wait_for(timeout=5000)
    for name in ('sshfs', 'sshpass'):
        row = page.locator(f'[data-v2p-package="{name}"]').inner_text()
        assert row.strip().endswith('not checked') and 'installed' not in row
    assert not app.errors, app.errors


# --------------------------------------------------------------------------- the bulk dialog, rendered

from test_esxi_bulk import CHECK, dialog, _pick_targets, _bodies, _wait_bodies  # noqa: E402,F401


def test_runtime_the_bulk_dialog_sends_the_box_and_reviews_the_packages(dialog):
    app, page = dialog(check=dict(CHECK, node_packages=dict(PKGS, allow_install=False)))
    page.locator('[data-esxi-bulk-pick="vm-1"]').check()
    page.locator('[data-esxi-bulk-bar] button', has_text='Migrate to Proxmox').click()
    dlg = page.locator('[data-esxi-bulk]')
    dlg.locator('option', has_text='Testi').first.wait_for(state='attached', timeout=5000)
    _pick_targets(page)
    box = dlg.locator('[data-esxi-bulk-allow-packages]')
    assert box.is_checked()
    box.uncheck()
    dlg.locator('button', has_text='Check the guests').click()
    _wait_bodies(app, page, 1)
    assert _bodies(app)[0]['allow_package_install'] is False
    dlg.locator('button', has_text='Review and start').click()
    dlg.locator('[data-v2p-packages]').get_by_text('Packages on pve1').wait_for(timeout=5000)
    assert dlg.locator('[data-v2p-package="sshfs"]').inner_text().strip().endswith('missing')
    assert not app.errors, app.errors
