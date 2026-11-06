"""The Cloud CVE page counts CVEs, not pending updates.

A node always has `packages` with its pending updates, and an empty list is true in JavaScript's `||` only by
being an array: `n.packages || n.cves` never reached the CVEs. A node with CVEs and nothing pending read
"0 vulnerabilities, no known vulnerabilities", and plain updates counted as vulnerabilities.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

CVE = {'cve': 'CVE-2026-1001', 'package': 'openssl', 'urgency': 'high', 'status': 'fixed', 'fixed': True}
PLAIN = {'name': 'curl', 'current': '8.14', 'available': '8.15', 'security': False, 'severity': 'low'}
SECURITY = {'name': 'libxml2', 'current': '2.9', 'available': '2.10', 'security': True, 'severity': 'critical'}


def _page(browser, node):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='cloud', clusters=[CLUSTER], resources=[VM], metrics=NODE_METRICS, extra={
        **SSE_TOKEN, ('POST', '/api/clusters/c1/reports/cve-scan'): (200, {'results': [dict({'node': 'pve1'}, **node)]})}))
    page = app.page
    page.locator('.cloud-nav-item', has_text='CVE Scanner').first.click()
    page.locator('.cloud-btn-primary').first.click()
    page.locator('.cloud-kpi-grid').first.wait_for(timeout=5000)
    return app, page


@pytest.mark.parametrize('node,shown,hidden,clean', [
    ({'packages': [], 'cves': [CVE]}, ['CVE-2026-1001', 'openssl', 'high'], [], False),
    ({'packages': [PLAIN], 'cves': [CVE]}, ['CVE-2026-1001'], ['curl'], False),
    ({'packages': [PLAIN], 'cves': []}, [], ['curl'], True),
    ({'packages': [SECURITY, PLAIN], 'cves': []}, ['libxml2', 'critical', '2.9'], ['curl'], False),
    ({'packages': [], 'cves': []}, [], [], True),
], ids=['cves-and-nothing-pending', 'cves-and-updates', 'only-plain-updates', 'no-debsecan-security-update', 'clean'])
def test_runtime_what_a_node_reports(browser, node, shown, hidden, clean):  # noqa: F811
    app, page = _page(browser, node)
    try:
        text = page.locator('.cloud-body').first.inner_text()
        for word in shown:
            assert word in text, (word, text)
        for word in hidden:
            assert word not in text, (word, text)
        assert ('No known vulnerabilities' in text) is clean, text
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
