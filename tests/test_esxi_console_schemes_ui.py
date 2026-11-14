"""The console button of an ESXi guest opens an https page or a vmrc:// link, nothing else.

The button opened web_url of the console answer, or followed vmrc_url, as they came. The
server builds both with a fixed scheme today; the page now checks the scheme as well, and an
answer with anything else takes the fallback the button already had: the host's web UI.

Drives the bundle in headless Chromium against the fake server of the pixel guard; skips
where Playwright is not installed. LW Nov 2026
"""
import pytest

from test_corp_redesigned_guard_ui import _GuardApp, _GuardServer, browser  # noqa: F401

ESXI = {'id': 'v1', 'name': 'esx01', 'host': '10.0.0.9', 'port': 443, 'server_type': 'esxi',
        'connected': True, 'status': 'connected', 'enabled': True}
GUEST = {'vm': 'vm-1', 'name': 'app01', 'power_state': 'POWERED_ON', 'guest_OS': 'Ubuntu Linux (64-bit)',
         'cpu': {'count': 2, 'sockets': 1, 'cores_per_socket': 2, 'hot_add_enabled': False},
         'memory': {'size_MiB': 4096, 'hot_add_enabled': False}, 'notes': '',
         'hardware': {'version': 'vmx-19'}, 'disks': {}, 'nics': []}
ROW = {'vm': 'vm-1', 'name': 'app01', 'power_state': 'POWERED_ON', 'cpu_count': 2, 'memory_size_MiB': 4096}
FALLBACK = 'https://10.0.0.9/ui/#/host/vms'
WEB = 'https://10.0.0.9:443/ui/#/console/vm-1'
VMRC = 'vmrc://clone:cst-abc@10.0.0.9:902/?moid=vm-1'
EVIL = 'javascript:window.__ran=1//'


def _reads(console):
    reads = {('GET', '/api/vmware'): (200, [ESXI]), ('GET', '/api/pbs'): (200, []),
             ('GET', '/api/vmware/v1/vms'): (200, [ROW]),
             ('GET', '/api/vmware/v1/vms/vm-1'): (200, {'data': GUEST}),
             ('POST', '/api/vmware/v1/vms/vm-1/watch'): (200, {'success': True}),
             ('DELETE', '/api/vmware/v1/vms/vm-1/watch'): (200, {'success': True}),
             ('POST', '/api/vmware/v1/vms/vm-1/console'): (200, console)}
    for what in ('hosts', 'datastores', 'networks', 'clusters'):
        reads[('GET', f'/api/vmware/v1/{what}')] = (200, [])
    return reads


@pytest.fixture
def open_app(browser):
    apps = []

    def _open(console):
        app = _GuardApp(browser, _GuardServer(extra=_reads(console), layout='modern'))
        apps.append(app)
        return app
    yield _open
    for app in apps:
        app.close()


def _click_console(app):
    page = app.page
    page.get_by_text('esx01').first.click()
    page.get_by_text('app01').first.wait_for(timeout=8000)
    page.get_by_text('app01').first.click()
    page.get_by_text('Back to VM List').first.wait_for(timeout=8000)
    # what the button opens, instead of a window
    page.evaluate('''() => { window.__ran = 0; window.__opened = [];
        window.open = (url) => { window.__opened.push(String(url)); return null; }; }''')
    page.locator('button[title="Console (VMRC)"]').click()
    for _ in range(30):
        if page.evaluate('() => window.__opened.length') or page.get_by_text('Opening VMRC...').count():
            break
        page.wait_for_timeout(100)
    page.wait_for_timeout(300)
    return page


@pytest.mark.parametrize('console', [
    {'web_url': EVIL},
    {'web_url': 'data:text/html,<script>alert(1)</script>'},
    {'web_url': ' JavaScript:window.__ran=1//', 'vmrc_url': EVIL},
    {'vmrc_url': EVIL},
    {'web_url': 42, 'vmrc_url': 'javascript:window.__ran=1//vmrc://x'},
], ids=['web-js', 'web-data', 'both-js', 'vmrc-js', 'not-a-string'])
def test_runtime_another_scheme_takes_the_host_ui(open_app, console):
    app = open_app(console)
    page = _click_console(app)
    assert page.evaluate('() => window.__ran') == 0, 'the answer ran as script'
    assert page.evaluate('() => window.__opened') == [FALLBACK]
    assert page.get_by_text('Back to VM List').count(), 'the page went somewhere else'
    assert not app.errors, app.errors


def test_runtime_the_console_page_opens_as_before(open_app):
    app = open_app({'web_url': WEB, 'vmrc_url': VMRC, 'url': 'wss://10.0.0.9:443/ticket/x'})
    page = _click_console(app)
    assert page.evaluate('() => window.__opened') == [WEB]
    assert not app.errors, app.errors


def test_runtime_the_vmrc_link_is_followed_as_before(open_app):
    app = open_app({'vmrc_url': VMRC})
    page = _click_console(app)
    assert page.evaluate('() => window.__opened') == []
    assert page.get_by_text('Opening VMRC...').count()
