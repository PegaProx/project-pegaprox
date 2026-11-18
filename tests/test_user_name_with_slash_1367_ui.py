"""User Management disables and deletes an account whose name has a slash in it (#1367).

The old OIDC accounts are keyed oidc_<first 12 chars of the sub>, and a sub can carry '/'
and '+'. The list put the name into the URL as it is, the server answered an HTML 404, and
the toast said only "Error deleting user". The runtime part drives web/index.html in
headless Chromium against the real app (the _RealBackend of test_forced_2fa_ui.py).
"""
import pytest

from test_ha_ui import BASE, browser  # noqa: F401  (browser is a fixture)
from test_forced_2fa_ui import _RealBackend

SLASHED = 'oidc_50g1L/K/o9+R'
ENCODED = '/api/users/oidc_50g1L%2FK%2Fo9%2BR'


def _seed(db):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password('C0rrect!horse9')
    base = {'password_salt': salt, 'password_hash': pw_hash, 'enabled': True, 'language': 'en',
            'layout_chosen': True, 'tenant_id': 'default', 'ui_layout': 'modern'}
    db.save_user('root', dict(base, role='admin', auth_source='local'))
    db.save_user(SLASHED, dict(base, role='admin', auth_source='entra', oidc_sub='50g1L/K/o9+R-rest',
                               password_salt='', password_hash=''))
    user = db.get_user('root')
    user['username'] = 'root'
    return user


@pytest.fixture
def users_tab(api, db, browser):  # noqa: F811
    backend = _RealBackend(api.app)
    backend.sid = api.as_user(_seed(db)).session_id
    ctx = browser.new_context(viewport={'width': 1600, 'height': 1000})
    ctx.add_init_script("""try {
        localStorage.setItem('pegaprox_sponsor_v2:root', String(Date.now() + 1e10));
        localStorage.setItem('pegaprox-shortcuts-hint-shown', '1');
    } catch (e) {}""")
    page = ctx.new_page()
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.route('**/*', backend.handle)
    page.goto(BASE + '/', wait_until='load')
    page.wait_for_function('() => document.querySelector("header")', timeout=30000)
    page.wait_for_timeout(500)
    page.locator('body').click(position={'x': 5, 'y': 400})
    page.keyboard.press('g')
    page.keyboard.press(',')
    page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)
    page.locator('tr', has_text=SLASHED).first.wait_for(timeout=5000)
    try:
        yield page, backend, errors
    finally:
        ctx.close()


def _sent(backend, method):
    return [c[1:3] for c in backend.calls if c[0] == method and c[1].startswith('/api/users/oidc_')]


def test_runtime_the_account_is_disabled_and_deleted(users_tab, db):
    page, backend, errors = users_tab
    row = page.locator('tr', has_text=SLASHED).first

    row.get_by_title('Disable').click()
    page.get_by_text('User updated').first.wait_for(timeout=5000)
    assert _sent(backend, 'PUT') == [(ENCODED, 200)]
    assert not db.get_user(SLASHED)['enabled']

    page.once('dialog', lambda d: d.accept())
    page.locator('tr', has_text=SLASHED).first.get_by_title('Delete User').click()
    page.get_by_text('User deleted').first.wait_for(timeout=5000)
    assert _sent(backend, 'DELETE') == [(ENCODED, 200)]
    assert db.get_user(SLASHED) is None
    page.wait_for_function(f'() => !document.body.innerText.includes({SLASHED!r})', timeout=5000)
    assert not errors, errors
