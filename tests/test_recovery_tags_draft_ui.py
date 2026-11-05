"""Typed critical tags survive a reload of the recovery assurance panel.

The Modern panel (RecoveryAssurance in ui.js) wrote the server's critical tags into the
input on every load, and it loads again after each confirm, withdraw and report refresh.
Tags typed while such a load was on its way were replaced when it answered, and Save
then sent the old tags. The Corporate panel keeps its own draft and had no such gap.

The reload is held with page.route until the tags are typed, so the order is the same on
every run. Drives the built bundle in headless Chromium against the fake server of
tests/test_ha_ui.py; skips where Playwright is not installed.
"""
from test_recovery_assurance_ui import _assurance_reads, _open_tab, _body, open_app  # noqa: F401
from test_ha_ui import _wait_for_call, browser  # noqa: F401


def test_runtime_tags_typed_during_a_reload_are_the_tags_saved(open_app):
    app = open_app(extra=_assurance_reads(), layout='modern')
    page = _open_tab(app, 'modern')
    panel = page.locator('[data-rasr-panel="c1"]')
    panel.wait_for(timeout=8000)
    tags = panel.locator('[data-rasr-tags]')
    assert tags.input_value() == 'critical'

    held = []
    page.route('**/api/clusters/c1/recovery-assurance*', lambda route: held.append(route))
    panel.locator('[data-rasr-withdraw="102"]').click()
    assert _wait_for_call(app, ('DELETE', '/api/clusters/c1/recovery-confirmations/0123456789abcdef'))
    for _ in range(50):
        if held:
            break
        page.wait_for_timeout(100)
    assert held, 'the panel did not load again after the withdraw'

    tags.fill('critical, prod')
    page.unroute('**/api/clusters/c1/recovery-assurance*')
    held[0].fallback()
    panel.locator('[data-rasr-confirmation="102"]').wait_for(timeout=5000)
    page.wait_for_timeout(300)
    assert tags.input_value() == 'critical, prod', 'the reload replaced the typed tags'

    panel.locator('[data-rasr-save-tags]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/recovery-settings'))
    assert _body(app, '/api/clusters/c1/recovery-settings') == {'critical_tags': ['critical', 'prod']}
    assert not app.errors, app.errors


def test_runtime_saved_tags_stay_in_the_field_until_the_reload_answers(open_app):
    """Dropping the draft before the reload answered showed the old tags again for that time."""
    app = open_app(extra=_assurance_reads(), layout='modern')
    page = _open_tab(app, 'modern')
    panel = page.locator('[data-rasr-panel="c1"]')
    panel.wait_for(timeout=8000)
    tags = panel.locator('[data-rasr-tags]')
    tags.fill('critical, prod')

    held = []
    page.route('**/api/clusters/c1/recovery-assurance*', lambda route: held.append(route))
    panel.locator('[data-rasr-save-tags]').click()
    assert _wait_for_call(app, ('PUT', '/api/clusters/c1/recovery-settings'))
    for _ in range(50):
        if held:
            break
        page.wait_for_timeout(100)
    assert held, 'the panel did not load again after the save'
    assert tags.input_value() == 'critical, prod', 'the field fell back to the old tags during the reload'

    # the answer is what counts from here on: this fake server still says "critical"
    page.unroute('**/api/clusters/c1/recovery-assurance*')
    held[0].fallback()
    for _ in range(50):
        if tags.input_value() == 'critical':
            break
        page.wait_for_timeout(100)
    assert tags.input_value() == 'critical', 'the draft outlived a save that went through'
    assert not app.errors, app.errors
