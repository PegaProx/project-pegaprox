"""The username claim in Settings > OIDC / Entra ID, rendered (#1149).

The select shows the stored claim, offers exactly the claims the backend keeps, and the
save sends the one picked.

NS Oct 2026
"""
import pytest

from pegaprox.utils.oidc import OIDC_USERNAME_CLAIMS
from test_ha_ui import SSE_TOKEN, _App, _FakeServer, _settings_tab, browser  # noqa: F401

SETTINGS = {'domain': 'pegaprox.example', 'port': 5000, 'oidc_enabled': True,
            'oidc_provider': 'generic', 'oidc_authority': 'https://adfs.corp.example/adfs',
            'oidc_client_id': 'pegaprox', 'oidc_scopes': 'openid profile email allatclaims',
            'oidc_username_claim': 'upn'}


@pytest.fixture
def app(browser):
    extra = dict(SSE_TOKEN)
    extra.update({('GET', '/api/settings/server'): (200, SETTINGS),
                  ('POST', '/api/settings/server'): (200, {'success': True})})
    a = _App(browser, _FakeServer(extra=extra, role='standalone', layout='modern'))
    yield a
    a.ctx.close()


def test_runtime_the_stored_claim_shows_and_the_picked_one_is_saved(app):
    page = app.page
    app.open_settings()
    _settings_tab(app, 'OIDC / Entra ID')
    claim = page.locator('select[data-oidc="username-claim"]')
    claim.wait_for(timeout=5000)
    assert claim.input_value() == 'upn'
    # the same list the backend keeps, with the old order first
    assert claim.locator('option').evaluate_all('os => os.map(o => o.value)') == [''] + list(OIDC_USERNAME_CLAIMS)
    claim.select_option('email')
    page.get_by_role('button', name='Save OIDC Settings').click()
    page.wait_for_timeout(600)
    sent = app.server.bodies['/api/settings/server'][-1]
    assert sent['oidc_username_claim'] == 'email'
    assert sent['oidc_scopes'] == 'openid profile email allatclaims'
