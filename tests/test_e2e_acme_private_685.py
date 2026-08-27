# E2E-through-app for #685: the acme_allow_private_ca opt-in must round-trip through the real
# settings endpoint AND actually govern the ACME SSRF guard the cert flow uses.

import pytest
import pegaprox.core.acme as acme
from pegaprox.utils.url_security import SsrfError

SETTINGS = '/api/settings/server'
PRIVATE = 'https://192.168.88.88/acme/directory'
METADATA = 'https://169.254.169.254/acme/directory'


def test_e2e_acme_private_opt_in_roundtrips_and_governs_the_guard(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')

    # default OFF -> the guard blocks a private ACME directory
    with api.app.app_context():
        assert acme._acme_allow_private() is False
        with pytest.raises(SsrfError):
            acme._guard_acme_url(PRIVATE)

    # flip it on through the real settings save endpoint
    r = api.as_user(admin).post(SETTINGS, json={'acme_allow_private_ca': True})
    assert r.status_code == 200, r.get_data(as_text=True)

    # the guard now honours the persisted setting: private allowed, metadata still blocked, http still blocked
    with api.app.app_context():
        assert acme._acme_allow_private() is True
        assert acme._guard_acme_url(PRIVATE) == PRIVATE
        with pytest.raises(SsrfError):
            acme._guard_acme_url(METADATA)
        with pytest.raises(SsrfError):
            acme._guard_acme_url('http://192.168.88.88/acme/directory')

    # and flipping it back off re-blocks the private CA
    r = api.as_user(admin).post(SETTINGS, json={'acme_allow_private_ca': False})
    assert r.status_code == 200, r.get_data(as_text=True)
    with api.app.app_context():
        assert acme._acme_allow_private() is False
        with pytest.raises(SsrfError):
            acme._guard_acme_url(PRIVATE)


def test_e2e_730_flag_travels_with_the_request_without_a_separate_save(api, seed, monkeypatch):
    # #730 (Flachdachs) — #685 only read the opt-in from SAVED settings, so ticking the checkbox
    # and hitting "Request Certificate" (which doesn't save settings) left the guard blocking the
    # private directory URL. The flag now rides in the request body and the handler persists it.
    admin = seed.user('root', role='admin', tenant_id='default')

    with api.app.app_context():
        assert acme._acme_allow_private() is False   # never saved

    # stub the real issuance so the route makes no network call
    monkeypatch.setattr(acme, 'request_certificate',
                        lambda *a, **k: {'success': True, 'expires': '2099-01-01'})

    # request a cert against an internal CA with the checkbox ON, but WITHOUT a prior settings-save
    r = api.as_user(admin).post('/api/settings/acme/request', json={
        'domain': 'host.internal.example',
        'provider': 'custom',
        'directory_url': 'https://192.168.88.88/acme/directory',
        'acme_allow_private_ca': True,
    })
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json().get('restart_required') is True   # #725 — prompt a restart to serve it

    # the handler persisted the flag from the body, so the guard now honours the internal CA
    with api.app.app_context():
        assert acme._acme_allow_private() is True
        assert acme._guard_acme_url(PRIVATE) == PRIVATE
