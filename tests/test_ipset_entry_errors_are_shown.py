"""A refused IP set entry is said, not dropped.

The entry list of an IP set in a guest's firewall (IpsetEntries in vm_config.js) reports
a refused add or remove with addToast, but was never handed addToast: ConfigModal has it
and passed only t, authFetch and the rest. Adding a CIDR the server turned down threw
"addToast is not defined" inside the handler, its catch called addToast again and threw
once more, and the user saw nothing at all: no entry, no reason.

Drives the built bundle in headless Chromium with the fake server of the Corporate
Redesigned guest tests; skips where Playwright is not installed.
"""
from test_corp_redesigned_vm_ui import _open_guest, browser, open_app, playwright  # noqa: F401

FW = '/api/clusters/c1/vms/pve1/qemu/100/firewall'
REFUSED = 'CIDR 10.0.0.300/24 is not a valid network'


def _firewall(app):
    app.server.routes.update({
        ('GET', f'{FW}/options'): (200, {'enable': 1}),
        ('GET', f'{FW}/rules'): (200, []),
        ('GET', f'{FW}/aliases'): (200, []),
        ('GET', f'{FW}/ipset'): (200, [{'name': 'blocklist', 'comment': ''}]),
        ('GET', f'{FW}/refs'): (200, []),
        ('GET', f'{FW}/ipset/blocklist'): (200, [{'cidr': '10.0.0.0/24'}]),
        ('POST', f'{FW}/ipset/blocklist'): (400, {'error': REFUSED}),
    })


def test_runtime_a_refused_cidr_is_said(open_app):
    app = open_app()
    _firewall(app)
    page = app.page
    _open_guest(page, 'web01')
    page.locator('[data-cr-objhead="vm"] .cr-objhead-actions > button', has_text='Configure').click()
    page.locator('.corp-vm-modal').wait_for(timeout=8000)
    page.locator('.corp-vm-modal-tab', has_text='Firewall').first.click()
    page.locator('button', has_text='IP Sets').first.click()
    page.get_by_text('blocklist', exact=True).first.click()
    cidr = page.locator('input[placeholder="e.g. 10.0.0.0/24"]').first
    cidr.wait_for(timeout=5000)

    cidr.fill('10.0.0.300/24')
    cidr.press('Enter')
    page.wait_for_timeout(800)

    assert ('POST', f'{FW}/ipset/blocklist') in app.server.calls
    assert page.get_by_text(REFUSED).count() > 0, 'the refusal was not shown'
    assert not [e for e in app.errors if 'addToast' in e], app.errors
