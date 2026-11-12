"""The release link of an update is an https page or the repository, nothing else.

download_url of the version manifest (version.json on GitHub or the mirror) went out as it
came: in the answer of check-update, which the settings dialog turns into an "Open GitHub
Release" link, and as the href of the update mail. A javascript: or data: value would have
been a link that runs. Now only an https URL is kept, anything else becomes the repo URL.
"""
import json

import pytest
import requests

import pegaprox.api.settings as settings
import pegaprox.background.alerts as alerts
from pegaprox.constants import GITHUB_REPO_URL

GOOD = 'https://github.com/PegaProx/project-pegaprox/releases/tag/v99.0.0'
REFUSED = ['javascript:alert(document.domain)//', 'JaVaScRiPt:alert(1)', ' javascript:alert(1)',
           'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)',
           'http://github.com/PegaProx/project-pegaprox/releases', 42, None]


def _manifest(download_url):
    m = {'version': '99.0', 'build': '2099.01.01', 'release_date': '2099-01-01',
         'changelog': ['faster']}
    if download_url is not None:
        m['download_url'] = download_url
    return m


def _check(api, seed, monkeypatch, download_url):
    admin = seed.user('root', role='admin', tenant_id='default')
    monkeypatch.setattr(settings, '_detect_install_method', lambda d: 'source')

    class _Resp:
        status_code = 200

        def json(self):
            return _manifest(download_url)
    monkeypatch.setattr(settings.requests, 'get', lambda *a, **k: _Resp())
    r = api.as_user(admin).get('/api/pegaprox/check-update')
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


@pytest.mark.parametrize('value', REFUSED, ids=repr)
def test_check_update_hands_out_no_other_scheme(api, seed, monkeypatch, value):
    body = _check(api, seed, monkeypatch, value)
    assert body['update_available'] is True
    assert body['download_url'] == GITHUB_REPO_URL


def test_check_update_keeps_a_real_release_page(api, seed, monkeypatch):
    assert _check(api, seed, monkeypatch, GOOD)['download_url'] == GOOD


def _mail(monkeypatch, download_url):
    sent = []
    monkeypatch.setattr(alerts, '_last_update_check_at', 1.0)
    monkeypatch.setattr(alerts, 'load_server_settings', lambda: {
        'alert_update_available': True, 'alert_email_recipients': ['ops@example.org']})
    monkeypatch.setattr(alerts, 'save_server_settings', lambda s: None)
    monkeypatch.setattr(alerts, 'send_email', lambda *a: sent.append(a) or (True, None))

    class _Raw:
        def read(self, n, decode_content=False):
            return json.dumps(_manifest(download_url)).encode()[:n]

    class _Resp:
        status_code = 200
        raw = _Raw()
    monkeypatch.setattr(requests, 'get', lambda *a, **k: _Resp())
    alerts.check_update_available_alert()
    assert len(sent) == 1, 'no update mail went out'
    _rcpt, _subject, text, html = sent[0]
    return text, html


@pytest.mark.parametrize('value', REFUSED, ids=repr)
def test_the_update_mail_links_no_other_scheme(monkeypatch, value):
    text, html = _mail(monkeypatch, value)
    assert f'<a href="{GITHUB_REPO_URL}">Release page</a>' in html, html
    assert f'Download: {GITHUB_REPO_URL}' in text
    for word in ('javascript', 'data:', 'vbscript', 'http://'):
        assert word not in html.lower() and word not in text.lower(), (word, html)


def test_the_update_mail_keeps_a_real_release_page(monkeypatch):
    text, html = _mail(monkeypatch, GOOD)
    assert f'<a href="{GOOD}">Release page</a>' in html, html
    assert f'Download: {GOOD}' in text
