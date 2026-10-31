"""The advanced OIDC claim setting loads and saves through the shared settings UI."""
import pytest

from test_ha_ui import SSE_TOKEN, _App, _FakeServer, _settings_tab, browser  # noqa: F401


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_custom_groups_claim_is_loaded_and_saved(browser, layout):
    settings = {'domain': 'pegaprox.example', 'port': 5000, 'oidc_enabled': True,
                'oidc_provider': 'okta', 'oidc_authority': 'https://idp.example',
                'oidc_client_id': 'pegaprox', 'oidc_scopes': 'openid profile email groups',
                'oidc_groups_claim': 'groups_proxmox'}
    extra = dict(SSE_TOKEN)
    extra.update({('GET', '/api/settings/server'): (200, settings),
                  ('POST', '/api/settings/server'): (200, {'success': True})})
    app = _App(browser, _FakeServer(extra=extra, role='standalone', layout=layout))
    try:
        app.open_settings()
        _settings_tab(app, 'OIDC / Entra ID')
        field = app.page.locator('input[data-oidc="groups-claim"]')
        field.locator('xpath=ancestor::details').locator('summary').click()
        assert field.input_value() == 'groups_proxmox'
        field.fill('Groups_Company')
        app.page.get_by_role('button', name='Save OIDC Settings').click()
        app.page.wait_for_timeout(600)
        sent = app.server.bodies['/api/settings/server'][-1]
        assert sent['oidc_groups_claim'] == 'Groups_Company'
        assert sent['oidc_scopes'] == settings['oidc_scopes']
        assert app.errors == []
    finally:
        app.ctx.close()
