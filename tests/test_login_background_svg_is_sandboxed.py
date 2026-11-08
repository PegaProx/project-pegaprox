"""An SVG login background cannot run script under this origin (#1065).

An admin.settings holder may upload the login background as .svg. The login page uses it
as a CSS background, where an SVG never runs script, but /images/login_bg.svg opened as a
page of its own is a same-origin document, and the policy allows inline script. Every SVG
response now carries the CSP sandbox directive: opened directly it runs nothing and has no
origin, used as an image it looks the same as before.
"""
import pytest

import pegaprox.api.settings as settings_mod

SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
       b'<script>document.title = "ran"</script><rect width="10" height="10"/></svg>')
PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32


@pytest.fixture
def branding(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_mod, 'BRANDING_DIR', str(tmp_path))
    (tmp_path / 'login_bg.svg').write_bytes(SVG)
    (tmp_path / 'login_bg.png').write_bytes(PNG)
    return tmp_path


def _directives(resp):
    return [d.strip() for d in resp.headers.get('Content-Security-Policy', '').split(';')]


def test_an_svg_background_opened_as_a_page_is_sandboxed(api, branding):
    r = api.anon().get('/images/login_bg.svg')
    assert r.status_code == 200
    assert r.mimetype == 'image/svg+xml'
    assert r.data == SVG
    assert 'sandbox' in _directives(r), r.headers.get('Content-Security-Policy')
    assert r.headers.get('X-Content-Type-Options') == 'nosniff'


def test_other_images_and_the_app_keep_their_policy(api, branding):
    png = api.anon().get('/images/login_bg.png')
    assert png.status_code == 200 and png.data == PNG
    assert 'sandbox' not in _directives(png)
    page = api.anon().get('/')
    assert 'sandbox' not in _directives(page)
    assert "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" in _directives(page)
