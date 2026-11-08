"""A translation key defined twice in one language says what its callers mean.

In a JavaScript object literal the last of two equal keys wins. selectCluster was
defined again in the storage cluster block of each language, so every cluster picker
of the app (pool permissions, migrations, the add dialogs) read "Select a storage
cluster", in French in all four places (#1244). vmMustBeStopped came back as "VM must be
stopped for rollback" on the disk bus button, and selectStorage as "Select a storage to
view contents" on the storage pickers. Each key is now defined once per language, and
the two headings that mean the special case have keys of their own.

The table is evaluated by node, as the browser does.
"""
import json
import os
import re
import shutil
import subprocess

import pytest

from test_ha_ui import browser, open_app  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TR = os.path.join(ROOT, 'web', 'src', 'translations.js')
KEYS = ('selectCluster', 'selectStorageCluster', 'vmMustBeStopped', 'selectStorage', 'selectStorageToView')


def _effective():
    js = ("const fs = require('fs'); const src = fs.readFileSync(process.argv[1], 'utf8');"
          "const tr = new Function(src + '; return translations;')();"
          "const out = {}; for (const [l, b] of Object.entries(tr)) {"
          f"  out[l] = {{}}; for (const k of {json.dumps(list(KEYS))}) out[l][k] = b[k]; }}"
          "process.stdout.write(JSON.stringify(out));")
    return json.loads(subprocess.run(['node', '-e', js, TR], capture_output=True, text=True, check=True).stdout)


@pytest.mark.skipif(not shutil.which('node'), reason='needs node')
def test_the_pickers_say_what_they_pick():
    en = _effective()['en']
    assert en['selectCluster'] == 'Select cluster...', en
    assert en['vmMustBeStopped'] == 'VM must be stopped', en
    assert en['selectStorage'] == 'Select storage...', en
    assert en['selectStorageCluster'] == 'Select a storage cluster'
    assert en['selectStorageToView'] == 'Select a storage to view contents'


@pytest.mark.skipif(not shutil.which('node'), reason='needs node')
def test_no_language_turns_a_cluster_picker_into_a_storage_cluster_picker():
    tr = _effective()
    assert len(tr) == 9
    for lang, keys in tr.items():
        assert all(keys[k] for k in KEYS), (lang, keys)
        assert keys['selectCluster'] != keys['selectStorageCluster'], lang
        assert keys['selectStorage'] != keys['selectStorageToView'], lang


def test_each_of_these_keys_is_defined_once_per_language():
    src = open(TR, encoding='utf-8').read()
    for key in KEYS:
        assert len(re.findall(r'^\s*%s: ' % key, src, re.M)) == 9, key


def test_the_two_headings_ask_for_the_special_case():
    storage = open(os.path.join(ROOT, 'web', 'src', 'storage.js'), encoding='utf-8').read()
    assert storage.count("t('selectStorageCluster')") == 1
    assert storage.count("t('selectStorageToView')") == 1


def test_runtime_the_pool_permissions_ask_for_a_cluster(open_app):
    """The page of #1244: Settings, Permissions, Pool Permissions."""
    app = open_app()
    app.open_settings()
    page = app.page
    page.locator('button', has_text='Permissions').first.click()
    page.locator('button', has_text='Pool Permissions').first.click()
    page.get_by_text('Select cluster...').first.wait_for(timeout=5000)
    assert page.get_by_text('storage cluster').count() == 0
    assert not app.errors, app.errors
