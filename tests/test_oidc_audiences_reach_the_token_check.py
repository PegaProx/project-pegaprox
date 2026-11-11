"""The accepted audiences an admin saves reach the ID token check.

oidc_decode_id_token accepts the client_id plus the comma-separated oidc_audiences, but
get_oidc_settings never handed that setting on, so the list was always empty. A token
issued for the configured logical audience alone failed the audience check and took the
unverified fallback: no signature-checked claims for the picked username claim, and its
group claims did not count.

The tokens are signed for real and the keys come from a TLS JWKS endpoint on loopback
(the harness of test_pyjwt_oidc_verification_972).

MK Nov 2026
"""
import logging

import pytest

from pegaprox.utils import oidc
from tests.conftest import _seed_user
from tests.test_pyjwt_oidc_verification_972 import (  # noqa: F401 - idp and signer are fixtures
    FALLBACK, _claims, _token, idp, signer,
)


@pytest.fixture
def admin(api, db):
    return api.as_user(_seed_user(db, 'root', role='admin'))


def _configure(admin, audiences):
    r = admin.post('/api/settings/server', json={
        'oidc_provider': 'generic', 'oidc_authority': 'https://idp.invalid',
        'oidc_client_id': 'pegaprox', 'oidc_audiences': audiences})
    assert r.status_code == 200, r.get_data(as_text=True)


def _decode(token, caplog):
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        return oidc.oidc_decode_id_token(token, expected_nonce='n-1', config=oidc.get_oidc_settings())


def test_the_saved_audiences_are_in_the_oidc_settings(admin):
    _configure(admin, ' pegaprox-prod, pegaprox-staging ')
    assert admin.get('/api/settings/server').get_json()['oidc_audiences'] == 'pegaprox-prod, pegaprox-staging'
    assert oidc.get_oidc_settings()['oidc_audiences'] == 'pegaprox-prod, pegaprox-staging'


def test_no_audiences_saved_is_an_empty_list(admin):
    _configure(admin, '')
    assert oidc.get_oidc_settings()['oidc_audiences'] == ''


@pytest.mark.parametrize('aud', ['pegaprox-prod', ['pegaprox-staging']])
def test_a_token_for_a_saved_audience_is_verified_by_its_signature(admin, idp, signer, caplog, aud):
    _configure(admin, 'pegaprox-prod, pegaprox-staging')
    claims = dict(_claims(), aud=aud)
    got = _decode(_token(signer, claims), caplog)
    assert got == claims
    assert oidc.oidc_id_token_verified(got), caplog.text
    assert FALLBACK not in caplog.text, caplog.text


def test_a_token_for_the_client_id_still_verifies(admin, idp, signer, caplog):
    _configure(admin, 'pegaprox-prod')
    got = _decode(_token(signer, _claims()), caplog)
    assert oidc.oidc_id_token_verified(got) and FALLBACK not in caplog.text, caplog.text


def test_a_token_for_an_audience_nobody_saved_is_not_verified(admin, idp, signer, caplog):
    _configure(admin, 'pegaprox-prod')
    got = _decode(_token(signer, dict(_claims(), aud='someone-else')), caplog)
    assert not oidc.oidc_id_token_verified(got)
    assert 'InvalidAudienceError' in caplog.text, caplog.text
