"""The test failover asks about a test, not about a failover.

It only clones the replicated VMs on the target and starts them in test mode, but it asked "This will migrate all protected VMs
to the target cluster", in the same words as the real one on the next button.

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
    assert len(found) == 9 and len(set(found)) == 9, found


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
    assert 'test mode' in asked[0] and 'migrate all' not in asked[0], asked
    assert not app.errors, app.errors
