# #685 — an internal ACME CA (e.g. StepCA on RFC1918) was rejected by the SSRF guard on the
# ACME directory URL. It's now allowed behind the acme_allow_private_ca opt-in (off by default),
# while cloud-metadata endpoints stay blocked regardless. Network-free: literal IPs + stubbed
# settings, mirroring the alert_webhook_allow_private / oidc_allow_private_ip pattern.

import pytest
import pegaprox.core.acme as acme
from pegaprox.utils.url_security import SsrfError

PRIVATE = 'https://192.168.88.88/acme/acme/directory'
METADATA = 'https://169.254.169.254/acme/directory'


def _settings(monkeypatch, val):
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings',
                        lambda: {'acme_allow_private_ca': val}, raising=False)


def test_private_acme_ca_blocked_by_default(monkeypatch):
    _settings(monkeypatch, False)
    with pytest.raises(SsrfError):
        acme._guard_acme_url(PRIVATE)


def test_private_acme_ca_allowed_when_opted_in(monkeypatch):
    _settings(monkeypatch, True)
    assert acme._guard_acme_url(PRIVATE) == PRIVATE  # no raise; passes through


def test_metadata_endpoint_blocked_even_with_opt_in(monkeypatch):
    _settings(monkeypatch, True)
    with pytest.raises(SsrfError):
        acme._guard_acme_url(METADATA)


def test_http_scheme_still_rejected_even_with_opt_in(monkeypatch):
    # the guard stays https-only; opt-in relaxes private-range blocking, not the scheme.
    _settings(monkeypatch, True)
    with pytest.raises(SsrfError):
        acme._guard_acme_url('http://192.168.88.88/acme/directory')
