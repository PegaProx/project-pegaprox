"""The layout choice at the first login offers Cloud next to Modern and Corporate Redesigned,
and picking it sets the Cloud theme with it, as the card under My Profile does. Classic
Corporate is no longer offered, only someone already on it still sees its card.

LW Oct 2026, Nov 2026
"""
import pytest

from test_ha_ui import _App, _FakeServer, browser  # noqa: F401


class _FirstLogin(_App):
    # before a layout is chosen the app shows only the choice, no header to wait for
    def wait_for_app(self):
        self.page.get_by_text('Corporate').first.wait_for(timeout=30000)
        self.page.wait_for_timeout(300)


def _first_login(browser, layout='modern', width=1280):  # noqa: F811
    user = {'username': 'admin', 'role': 'admin', 'display_name': 'Admin', 'ui_layout': layout,
            'layout_chosen': False, 'theme': '', 'language': 'en', 'permissions': [], 'enabled': True,
            'auth_source': 'local'}
    saved = {'ui_layout': 'cloud', 'theme': 'cloud', 'layout_chosen': True}
    srv = _FakeServer(role='standalone', layout=layout, extra={
        ('GET', '/api/auth/check'): (200, {'authenticated': True, 'session_id': 'sid', 'user': user,
                                           'ha': {}, 'default_theme': 'proxmoxDark'}),
        ('PUT', '/api/user/preferences'): (200, {'success': True, 'preferences': saved}),
    })
    app = _FirstLogin(browser, srv)
    app.page.set_viewport_size({'width': width, 'height': 900})
    return app, srv


def test_runtime_cloud_is_offered_and_brings_its_theme(browser):  # noqa: F811
    app, srv = _first_login(browser)
    try:
        page = app.page
        page.get_by_text('Corporate').first.wait_for(timeout=5000)
        card = page.locator('[data-layout-pick="cloud"]')
        card.wait_for(timeout=3000)
        assert 'PREVIEW' in card.inner_text() and 'Airy card grid' in card.inner_text()
        card.click()
        page.wait_for_timeout(800)
        bodies = srv.bodies.get('/api/user/preferences', [])
        assert {'ui_layout': 'cloud', 'theme': 'cloud', 'layout_chosen': True} in bodies, bodies
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


def _cards(page):
    return page.evaluate("""() => Array.from(document.querySelectorAll('button'))
        .filter(b => /Modern|Corporate|Cloud/.test(b.innerText) && b.querySelector('.h-20'))
        .map(b => { const r = b.getBoundingClientRect();
                    return {name: b.querySelector('.text-center span').innerText.split('\\n')[0].trim(),
                            box: [r.left, r.top, r.right]}; })""")


@pytest.mark.parametrize('layout, offered', [
    ('modern', ['Modern', 'Corporate Redesigned', 'Cloud']),
    ('corporate', ['Modern', 'Corporate', 'Corporate Redesigned', 'Cloud']),
])
def test_runtime_corporate_redesigned_takes_the_place_of_classic_corporate(browser, layout, offered):  # noqa: F811
    app, _ = _first_login(browser, layout=layout)
    try:
        page = app.page
        page.locator('[data-layout-pick="corporate-redesigned"]').wait_for(timeout=5000)
        assert [c['name'] for c in _cards(page)] == offered
        assert not app.errors, app.errors
    finally:
        app.ctx.close()


# LW Nov 2026 - three cards, four for someone still on classic Corporate:
# one row from 768 px, stacked on a phone
@pytest.mark.parametrize('layout', ['modern', 'corporate'])
@pytest.mark.parametrize('width', [1280, 390])
def test_runtime_the_cards_fit_without_scrolling_sideways(browser, width, layout):  # noqa: F811
    app, _ = _first_login(browser, layout=layout, width=width)
    try:
        page = app.page
        page.locator('[data-layout-pick="cloud"]').wait_for(timeout=5000)
        over = page.evaluate('() => document.documentElement.scrollWidth - window.innerWidth')
        assert over <= 0, over
        boxes = [c['box'] for c in _cards(page)]
        assert len(boxes) == (4 if layout == 'corporate' else 3), boxes
        if width >= 768:
            assert len({round(t) for _, t, _ in boxes}) == 1, boxes   # one row
        else:
            assert len({round(t) for _, t, _ in boxes}) == len(boxes), boxes   # stacked
        assert all(r <= width for _, _, r in boxes), boxes
    finally:
        app.ctx.close()
