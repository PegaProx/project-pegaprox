"""The restart badge of the guest configuration fields speaks the user's language.

The input and memory fields fell back to 'NEEDS RESTART' because none of the forms handed
them t, so the badge stayed English in every language. The fields take the language
themselves now; in English the badge reads as before.

Drives the built bundle in headless Chromium with the fake server of the pixel guard; skips
where Playwright or the browser is not installed.
"""
import json
import os

import pytest

from test_corp_redesigned_guard_ui import _exact, _GuardApp, _GuardServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EN = {'resources': 'Resources', 'searchByNameOrId': 'Search by name or ID...', 'configuration': 'Configuration',
      'hardware': 'Hardware', 'optionsTab': 'Options', 'needsRestart': 'NEEDS RESTART'}


def _words(language):
    if language == 'en':
        return EN
    with open(os.path.join(ROOT, 'web', 'i18n', f'{language}.json'), encoding='utf-8') as fh:
        return json.load(fh)


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


def _badges(page, words):
    return page.evaluate('''(labels) => [...document.querySelectorAll('span')]
        .filter(s => labels.includes(s.innerText.trim()) && s.children.length === 0).map(s => s.innerText.trim())''',
                         [words['needsRestart'], EN['needsRestart']])


@pytest.mark.parametrize('language', ['de', 'ru', 'en'])
def test_runtime_the_restart_badges_speak_the_language(modern, language):
    app, words = modern(language), _words(language)
    page = app.page
    page.locator('button', has_text=_exact(words['resources'])).first.click()
    page.get_by_placeholder(words['searchByNameOrId']).first.fill('web01')
    page.wait_for_timeout(400)
    page.locator(f'button[title="{words["configuration"]}"]').first.click()
    page.locator('input[value="web01"]').first.wait_for(timeout=8000)
    # cores, sockets and memory of a running VM, the CPU type and the rest of the hardware fields
    page.locator('button', has_text=_exact(words['hardware'])).last.click()
    page.wait_for_function('(l) => [...document.querySelectorAll("span")].some(s => s.innerText.trim() === l)',
                           arg=words['needsRestart'], timeout=8000)
    page.wait_for_timeout(300)
    hardware = _badges(page, words)
    # and the checkboxes of the options tab (KVM, ACPI), which had the language already
    page.locator('button', has_text=_exact(words['optionsTab'])).last.click()
    page.wait_for_timeout(800)
    options = _badges(page, words)
    assert len(hardware) >= 5 and set(hardware) == {words['needsRestart']}, hardware
    assert len(options) >= 2 and set(options) == {words['needsRestart']}, options
    assert not app.errors, app.errors
