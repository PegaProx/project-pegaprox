"""A toast says why, in the colour of what happened.

The EVPN and ESXi views call addToast(title, detail, type), and it only took (message, type). The detail became
the type and the type was dropped, so a refusal showed "Error" in the info colour and never the reason.

Drives the built bundle in headless Chromium with the fake server of tests/test_ha_ui.py.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, browser, _App, _FakeServer  # noqa: F401

REASON = 'VNI 10010 is taken on Testi'
CLUSTER2 = dict(CLUSTER, id='c2', name='Zweit')


@pytest.mark.parametrize('answer,text,colour', [
    ((400, {'error': REASON}), f'Error: {REASON}', 'text-red-400'),
])
def test_runtime_a_refusal_shows_its_reason_in_red(browser, answer, text, colour):  # noqa: F811
    app = _App(browser, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER, CLUSTER2], resources=[VM], metrics=NODE_METRICS,
                                    extra={**SSE_TOKEN, ('POST', '/api/multi-sdn/vnets/validate'): answer,
                                           ('GET', '/api/multi-sdn/vnets'): (200, [])}))
    try:
        page = app.page
        page.get_by_text('Multi-Cluster EVPN').first.click()
        page.locator('button', has_text='Create').first.click()
        for holder, value in (('evpn1', 'evpn1'), ('z1', 'z1'), ('evpnctl', 'ctl'), ('10010', '10010'), ('65000', '65000')):
            page.locator(f'input[placeholder="{holder}"]').first.fill(value)
        page.locator('.fixed.inset-0 input[type="checkbox"]').first.check()
        page.locator('.fixed.inset-0 button', has_text='Validate').first.click()
        toast = page.locator('.toast-enter', has_text=REASON).first
        toast.wait_for(timeout=5000)
        assert text in toast.inner_text()
        assert colour in toast.get_attribute('class')
        assert not app.errors, app.errors
    finally:
        app.ctx.close()
