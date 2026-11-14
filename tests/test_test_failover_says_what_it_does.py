"""The test failover asks about a test, not about a failover.

It only clones the replicated VMs on the target as SR-TEST copies and starts them, but it asked "This will migrate all protected
VMs to the target cluster", in the same words as the real one on the next button. The clones start on the live network unless the
plan disconnects their NICs, so the question names that setting instead of promising a test mode.

Drives the built bundle in headless Chromium, with the fixtures of tests/test_sr_per_guest_failover_ui.py.
"""
import pathlib
import re

import pytest

from test_ha_ui import browser  # noqa: F401
from test_sr_per_guest_failover_ui import _to_plan, open_app  # noqa: F401

TRANSLATIONS = pathlib.Path(__file__).resolve().parent.parent / 'web' / 'src' / 'translations.js'


def test_every_language_has_it_once():
    found = re.findall(r"^ +confirmTestFailover: '([^']+)',$", TRANSLATIONS.read_text(encoding='utf-8'), re.M)
    assert len(found) == 10 and len(set(found)) == 10, found


def test_every_language_names_the_sr_test_copies_and_the_nic_setting():
    tr = TRANSLATIONS.read_text(encoding='utf-8')
    starts = [(m.group(1), m.start()) for m in re.finditer(r'^            ([a-z][a-z]): \{', tr, re.M)]
    for i, (lang, at) in enumerate(starts):
        block = tr[at:starts[i + 1][1] if i + 1 < len(starts) else len(tr)]
        text = re.search(r"^ +confirmTestFailover: '([^']+)',$", block, re.M).group(1)
        setting = re.search(r"^ +testDisconnectNics: '([^']+)',$", block, re.M).group(1)
        assert 'SR-TEST' in text and setting in text, lang
    zh = tr[dict(starts)['zh']:dict(starts)['pl']]
    assert '?' not in re.search(r"^ +confirmTestFailover: '([^']+)',$", zh, re.M).group(1)


def test_runtime_the_test_button_asks_about_a_test(open_app):  # noqa: F811
    app = open_app(layout='modern')
    page = app.page
    _to_plan(app, 'modern')
    asked = []

    def answer(dialog):
        asked.append(dialog.message)
        dialog.dismiss()
    page.on('dialog', answer)
    page.get_by_role('button', name=re.compile(r'^\s*Test Failover')).first.click()
    page.wait_for_timeout(300)
    assert len(asked) == 1, asked
    assert 'SR-TEST' in asked[0] and 'migrate all' not in asked[0], asked
    assert 'Disconnect NICs on Test Failover' in asked[0] and 'test mode' not in asked[0], asked
    assert not app.errors, app.errors
