"""The "Open GitHub Release" link of Settings > Updates only ever opens an https page.

The link took download_url from the update check as it came, and the value is whatever the
version manifest says. React 18 renders a javascript: href as it is, so a click on the link
would have run it in this page. Now the link is drawn for an https URL only; the update
instructions above it show either way.

Drives the bundle in headless Chromium against the fake server of the pixel guard; skips
where Playwright is not installed. LW Nov 2026
"""
import os
import re

import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOOD = 'https://github.com/PegaProx/project-pegaprox/releases/tag/v99.0.0'
STEPS = ['# Restart PegaProx to finish the update', 'sudo systemctl restart pegaprox']


def _reads(download_url):
    check = {'current_version': '1.5.0', 'current_build': '2026.11.12', 'latest_version': '99.0',
             'latest_build': '2099.01.01', 'release_date': '2099-01-01', 'changelog': ['faster'],
             'download_url': download_url, 'update_available': True, 'install_method': 'source',
             'in_app_update_supported': True, 'managed_update_hint': '', 'managed_update_command': '',
             'min_python': '3.8', 'breaking_changes': []}
    prepared = {'success': True, 'restarting': False, 'instructions': STEPS,
                'backup_path': '/opt/PegaProx/backups/before-99.0'}
    return {('GET', '/api/pegaprox/check-update'): (200, check),
            ('POST', '/api/pegaprox/update'): (200, prepared)}


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(download_url):
        app = _GuardApp(browser, _GuardServer(extra=_reads(download_url), layout='modern'))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def test_the_bundle_carries_the_scheme_check():
    for text in (_src('web', 'src', 'settings_modal.js'), _src('web', 'index.html')):
        assert re.search(r"typeof updateInfo\.download_url\s*===\s*'string'\s*&&\s*/\^https:", text)


def _prepared_update(app):
    page = app.page
    page.on('dialog', lambda d: d.accept())
    page.evaluate('() => { window.__ran = 0; }')
    app.open_settings()
    page.locator('button', has_text=re.compile(r'^\s*Updates(\s*NEW)?\s*$')).first.click()
    page.get_by_role('button', name='Install Update').click()
    page.get_by_text('Update Instructions').first.wait_for(timeout=8000)
    page.wait_for_timeout(300)
    return page.locator('div.bg-blue-500\\/10', has_text='Update Instructions').first


@pytest.mark.parametrize('value', ['javascript:window.__ran=1//', ' JavaScript:window.__ran=1//',
                                   'data:text/html,<script>alert(1)</script>', 42])
def test_runtime_no_other_scheme_becomes_the_link(open_app, value):
    app = open_app(value)
    box = _prepared_update(app)
    # the instructions are still there to follow
    text = box.inner_text()
    for line in STEPS:
        assert line in text, text
    assert '/opt/PegaProx/backups/before-99.0' in text
    # but no link, and nothing on the page carries the value as an href
    assert box.locator('a').count() == 0, box.locator('a').first.get_attribute('href')
    page = app.page
    assert not page.locator('a[href*="javascript:" i], a[href^="data:" i]').count()
    assert page.evaluate('() => window.__ran') == 0
    assert not app.errors, app.errors


def test_runtime_a_release_page_is_still_linked(open_app):
    app = open_app(GOOD)
    box = _prepared_update(app)
    link = box.locator('a', has_text='Open GitHub Release')
    assert link.count() == 1
    assert link.get_attribute('href') == GOOD
    assert link.get_attribute('target') == '_blank'
    assert not app.errors, app.errors
