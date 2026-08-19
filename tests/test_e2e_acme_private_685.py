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
