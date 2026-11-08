"""The search box of the Modern resources list has one icon, inside the field.

A second Icons.Search stood in the box without any position: it sat on its own line above the
field, and the height it took pushed the real icon up towards the edge of the field.

Drives the built bundle in headless Chromium and Firefox with the fake server of tests/test_ha_ui.py;
skips where Playwright or the browser is not installed.
"""
import pytest

from test_ha_ui import CLUSTER, NODE_METRICS, SSE_TOKEN, VM, _App, _FakeServer


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
def test_runtime_one_icon_in_the_middle_of_the_field(engine):
    sync_api = pytest.importorskip('playwright.sync_api')
    with sync_api.sync_playwright() as pw:
        try:
            br = getattr(pw, engine).launch(headless=True)
        except Exception as e:
            pytest.skip(f'no {engine} for Playwright: {e}')
        try:
            app = _App(br, _FakeServer(role='standalone', layout='modern', clusters=[CLUSTER], resources=[VM],
                                       metrics=NODE_METRICS, extra=dict(SSE_TOKEN)))
            page = app.page
            page.get_by_text('Testi').first.click()
            page.locator('button', has_text='Resources').first.click()
            field = page.locator('input[placeholder^="Search by name"]').first
            field.wait_for(timeout=6000)
            page.wait_for_timeout(200)
            found = page.evaluate('''() => {
              const input = document.querySelector('input[placeholder^="Search by name"]');
              const box = input.getBoundingClientRect();
              const icons = [...input.parentElement.querySelectorAll('svg')].map(s => s.getBoundingClientRect());
              return {count: icons.length, offset: icons.map(r => (r.top + r.bottom) / 2 - (box.top + box.bottom) / 2)};
            }''')
            assert found['count'] == 1, found
            assert abs(found['offset'][0]) <= 1, found
            assert not app.errors, app.errors
        finally:
            br.close()
