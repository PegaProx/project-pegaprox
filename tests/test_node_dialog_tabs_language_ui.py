"""The tabs of the Modern node dialog speak the user's language.

They were English text, so in Russian only Hardware and Timeline were translated. They use
the translations now, a new one for System in all ten languages; in English every tab reads
as before.

Drives the built bundle in headless Chromium with the fake server of the pixel guard; skips
where Playwright or the browser is not installed.
"""
import json
import os
import re

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGLISH = ['Summary', 'Performance', 'Shell', 'Network', 'System', 'Hardware', 'Disks', 'Repositories', 'Tasks',
           'Timeline', 'Subscription', 'Ceph']
KEYS = ['summary', 'performance', 'shell', 'network', 'nodeTabSystem', 'hardware', 'disks', 'repositories', 'tasks',
        'tlTab', 'subscriptionInfo']
SYSTEM = {'de': 'System', 'ru': 'Система'}


def _words(language):
    if language == 'en':
        return dict(zip(KEYS, ENGLISH), nodeConfiguration='Node Configuration')
    with open(os.path.join(ROOT, 'web', 'i18n', f'{language}.json'), encoding='utf-8') as fh:
        return dict(json.load(fh), nodeTabSystem=SYSTEM[language])


def test_the_new_label_is_in_every_language():
    with open(os.path.join(ROOT, 'web', 'src', 'translations.js'), encoding='utf-8') as fh:
        src = fh.read()
    assert len(re.findall(r'^\s*nodeTabSystem:', src, re.M)) == 10


@pytest.fixture
def modern(browser):  # noqa: F811
    apps = []

    def _open(language):
        app = _GuardApp(browser, _GuardServer(layout='modern', language=language),
                        storage={'pegaprox-language': language})
        apps.append(app)
        app.page.get_by_text('Testi').first.click()
        return app
    yield _open
    for app in apps:
        app.close()


# the row of the dialog's tabs: the one that holds its first and its last tab
TAB_LABELS = '''([first, last]) => {
  const row = [...document.querySelectorAll('button')].filter(b => b.innerText.trim() === first).map(b => b.parentElement)
    .find(p => [...p.children].some(b => b.innerText.trim() === last));
  return row ? [...row.children].map(b => b.innerText.trim()) : null;
}'''


@pytest.mark.parametrize('language', ['ru', 'de', 'en'])
def test_runtime_the_node_dialog_tabs_speak_the_language(modern, language):
    app, words = modern(language), _words(language)
    page = app.page
    page.locator(f'button[title="{words["nodeConfiguration"]}"]').first.click()
    ends = [words['summary'], 'Ceph']
    page.wait_for_function(f'() => ({TAB_LABELS})({json.dumps(ends)})', timeout=8000)
    got = page.evaluate(TAB_LABELS, ends)
    assert got == [words[k] for k in KEYS] + ['Ceph'], got
    if language == 'en':
        assert got == ENGLISH, got
    else:
        assert not set(got) & {'Summary', 'Performance', 'Network', 'Disks', 'Subscription'}, got
    assert not app.errors, app.errors
