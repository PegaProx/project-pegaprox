"""User Management: the button that resets the sign-in binding of an OIDC / Entra account.

An OIDC or Entra account signs in only for the identity provider subject it is bound to
(test_oidc_subject_binding.py). While an admin edits such an account and the reset takes
it (oidc_resettable: bound, and not keyed on its subject), a small "Reset sign-in binding"
button under its name asks first, then calls DELETE /api/users/<username>/oidc-binding
(test_oidc_binding_reset_route.py) and reloads the list, after which the button is gone.
Local accounts, unbound ones and ones keyed on their subject show none. The question
also says to delete, not reset, an account named with the part before the @ only.

The runtime part drives web/index.html in headless Chromium against the real app, in
Modern and Corporate.

LW Nov 2026
"""
import hashlib
import os
import re

import pytest

from test_ha_ui import BASE, ROOT, browser  # noqa: F401  (browser is a fixture)
from test_forced_2fa_ui import _RealBackend

BOUND = 'wanda@corp.example'
UNBOUND = 'nora@corp.example'
# the account of a sign-in without a name: keyed on a hash of its sub
KEYED = 'oidc_' + hashlib.sha256(b'sub-of-a-nameless-sign-in').hexdigest()[:16]


def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


# --- the source -----------------------------------------------------------------------------

def test_the_button_is_only_there_for_a_bound_oidc_account_being_edited():
    src = _src('web', 'src', 'settings_modal.js')
    at = src.index('data-oidc-binding-reset=')
    guard = src[src.rindex('{', 0, at - 200):at]
    assert 'editingUser === user.username && user.oidc_resettable' in guard
    handler = src[src.index('const handleResetOidcBinding'):][:1200]
    assert "confirm(t('resetOidcBindingConfirm')" in handler
    assert "/oidc-binding`, {" in handler and "method: 'DELETE'" in handler
    assert 'fetchUsers()' in handler


def test_every_language_has_the_strings():
    src = _src('web', 'src', 'translations.js')
    for key in ('resetOidcBinding', 'resetOidcBindingHint', 'resetOidcBindingConfirm',
                'resetOidcBindingDone', 'resetOidcBindingFailed'):
        langs = re.findall(r'^                ' + key + r": '", src, re.M)
        assert len(langs) == 10, (key, len(langs))
    assert len(re.findall(r"resetOidcBindingConfirm: '[^\n]*\{user\}[^\n]*@", src)) == 10


# --- at runtime -----------------------------------------------------------------------------

def _seed(db):
    from pegaprox.utils.auth import hash_password
    salt, pw_hash = hash_password('C0rrect!horse9')
    base = {'password_salt': salt, 'password_hash': pw_hash, 'enabled': True, 'language': 'en',
            'layout_chosen': True, 'tenant_id': 'default'}
    db.save_user('root', dict(base, role='admin', auth_source='local'))
    db.save_user('carol', dict(base, role='user', auth_source='local'))
    db.save_user(BOUND, dict(base, role='user', auth_source='entra', oidc_sub='object-id-of-wanda',
                             password_salt='', password_hash=''))
    db.save_user(UNBOUND, dict(base, role='user', auth_source='oidc', oidc_sub='',
                               password_salt='', password_hash=''))
    db.save_user(KEYED, dict(base, role='user', auth_source='oidc', oidc_sub='sub-of-a-nameless-sign-in',
                             password_salt='', password_hash=''))
    user = db.get_user('root')
    user['username'] = 'root'
    return user


@pytest.fixture
def users_tab(api, db, browser):  # noqa: F811
    opened = []

    def _open(layout):
        root = _seed(db)
        row = db.get_user('root')
        row['ui_layout'] = layout
        db.save_user('root', row)
        backend = _RealBackend(api.app)
        backend.sid = api.as_user(root).session_id
        ctx = browser.new_context(viewport={'width': 1600, 'height': 1000})
        ctx.add_init_script("""try {
            localStorage.setItem('pegaprox_sponsor_v2:root', String(Date.now() + 1e10));
            localStorage.setItem('pegaprox-shortcuts-hint-shown', '1');
        } catch (e) {}""")
        page = ctx.new_page()
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.route('**/*', backend.handle)
        opened.append(ctx)
        page.goto(BASE + '/', wait_until='load')
        page.wait_for_function(
            '() => document.querySelector("header") || document.querySelector(".cloud-shell")',
            timeout=30000)
        page.wait_for_timeout(500)
        page.locator('body').click(position={'x': 5, 'y': 400})
        page.keyboard.press('g')
        page.keyboard.press(',')
        page.get_by_text('PegaProx Settings').first.wait_for(timeout=5000)
        page.locator('tr', has_text=BOUND).first.wait_for(timeout=5000)
        return page, backend, errors
    yield _open
    for ctx in opened:
        ctx.close()


def _edit(page, username):
    page.locator('tr', has_text=username).first.get_by_title('Edit User').click()
    page.wait_for_timeout(300)


def _resets(backend):
    return [c for c in backend.calls if c[0] == 'DELETE' and c[1].endswith('/oidc-binding')]


@pytest.mark.parametrize('layout', ['modern', 'corporate'])
def test_runtime_an_admin_resets_the_binding_of_a_bound_account(users_tab, db, layout):
    page, backend, errors = users_tab(layout)
    button = page.locator(f'[data-oidc-binding-reset="{BOUND}"]')
    assert button.count() == 0                       # not outside the edit mode

    # an unbound OIDC account, one keyed on its subject and a local one show no button
    for other in (UNBOUND, KEYED, 'carol'):
        _edit(page, other)
        assert page.locator('[data-oidc-binding-reset]').count() == 0, other
        _edit(page, other)

    _edit(page, BOUND)
    button.wait_for(timeout=3000)
    if os.environ.get('PEGAPROX_UI_SHOTS'):
        page.screenshot(path=os.path.join(os.environ['PEGAPROX_UI_SHOTS'], f'oidc-reset-{layout}-edit.png'))
    assert button.inner_text().strip() == 'Reset sign-in binding'
    assert 'identity provider subject' in button.get_attribute('title')

    # asked first: a "no" changes nothing
    asked = []
    page.once('dialog', lambda d: (asked.append(d.message), d.dismiss()))
    button.click()
    page.wait_for_timeout(500)
    assert asked and BOUND in asked[0]
    assert 'the next sign-in through the identity provider under exactly this name binds it again' in asked[0]
    assert 'delete the account instead' in asked[0]
    assert _resets(backend) == []
    assert db.get_user(BOUND)['oidc_sub'] == 'object-id-of-wanda'

    page.once('dialog', lambda d: d.accept())
    button.click()
    page.get_by_text('Sign-in binding reset').first.wait_for(timeout=5000)
    assert [c[2] for c in _resets(backend)] == [200]
    assert db.get_user(BOUND)['oidc_sub'] == ''
    assert db.get_user(UNBOUND)['oidc_sub'] == ''
    # the list is read again and the account is no longer bound: no button any more
    page.wait_for_function(f'() => !document.querySelector(\'[data-oidc-binding-reset="{BOUND}"]\')',
                           timeout=5000)
    if os.environ.get('PEGAPROX_UI_SHOTS'):
        page.screenshot(path=os.path.join(os.environ['PEGAPROX_UI_SHOTS'], f'oidc-reset-{layout}.png'))
    assert not errors, errors


def test_runtime_a_refused_reset_shows_the_server_s_answer(users_tab, db, monkeypatch):
    page, backend, errors = users_tab('modern')
    _edit(page, BOUND)
    real = backend.handle

    def refuse(route):
        if route.request.method == 'DELETE' and route.request.url.endswith('/oidc-binding'):
            backend.calls.append(('DELETE', '/oidc-binding', 403, None))
            return route.fulfill(status=403, body='{"error": "Access denied: target has privileges beyond your own"}',
                                 headers={'Content-Type': 'application/json'})
        return real(route)
    page.unroute('**/*')
    page.route('**/*', refuse)
    page.once('dialog', lambda d: d.accept())
    page.locator(f'[data-oidc-binding-reset="{BOUND}"]').click()
    page.get_by_text('Access denied: target has privileges beyond your own').first.wait_for(timeout=5000)
    assert db.get_user(BOUND)['oidc_sub'] == 'object-id-of-wanda'
    assert page.locator(f'[data-oidc-binding-reset="{BOUND}"]').count() == 1
    assert not errors, errors
