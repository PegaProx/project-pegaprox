"""The ID token check of an OIDC sign-in fails closed.

Every error in the signature check used to fall back to reading the token unchecked: a
bad signature, an unknown key, another audience. The sign-in went through, and for a
generic provider the groups of that token decided the role. The issuer was never
compared. Now:

  * a token whose signature, audience (client_id or oidc_audiences), azp, issuer, nbf,
    expiry or nonce does not check out is refused, with a log line that says why
  * any asymmetric algorithm verifies (RS, PS, ES, EdDSA); HS* and none are refused
  * a token without a kid, or a key set whose keys carry none, is checked against each
    key of the type its alg takes, not taken for a key set that cannot be loaded
  * the issuer is the one discovery names (Entra: the tenant's), a trailing slash aside
  * the signature goes unchecked only when the key set cannot be loaded at all (network,
    or it does not parse) and TLS is verified - the token then came from the token
    endpoint over a checked connection (OIDC Core 3.1.3.7). Audience, issuer, expiry and
    nonce are still checked. With oidc_skip_ssl_verify on, such a token is refused.
  * oidc_skip_jwt_verification stays the admin's switch: no signature check, but
    audience, azp, nbf, expiry and nonce are checked

The tokens are signed for real and the keys come from a TLS endpoint on loopback (the
harness of test_pyjwt_oidc_verification_972). The last part signs in through the
callback against a whole IdP on loopback, TLS verified.

MK Nov 2026
"""
import json
import logging
import time
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from gevent.pywsgi import WSGIServer

from pegaprox.utils import oidc
from tests.conftest import _seed_user
from tests.test_pyjwt_oidc_verification_972 import FALLBACK, _b64, _Endpoint, _jwk, _tls_files, _token

ISSUER = 'https://idp.corp.example/realms/ops'
AUTHORITY = 'https://idp/realms/ops'     # what the admin typed: another host than the IdP's own name
CFG = {'provider': 'generic', 'authority': AUTHORITY, 'client_id': 'pegaprox'}
DEAD = 'https://127.0.0.1:1/jwks'       # nothing listens there
REFUSED = 'ID token refused'
INVALID = {'error': 'Failed to validate identity token'}
# the answer for another sign-in's token, by its start; test_pyjwt_oidc_verification_972
# pins the whole wording
NONCE = {'error': 'OIDC nonce mismatch'}


def _claims(**over):
    now = int(time.time())
    body = {'iss': ISSUER, 'sub': 'alice', 'aud': 'pegaprox', 'iat': now, 'exp': now + 300,
            'nonce': 'n-1', 'groups': ['pp-admins']}
    body.update(over)
    return body


# --- tokens with other algorithms, signed by hand like _token, so PyJWT only verifies ------

_HASHES = {'256': hashes.SHA256, '384': hashes.SHA384, '512': hashes.SHA512}
_CURVES = {'ES256': (ec.SECP256R1, 'P-256', 32), 'ES384': (ec.SECP384R1, 'P-384', 48),
           'ES512': (ec.SECP521R1, 'P-521', 66)}
OTHER_ALGS = ['RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']


def _key_for(alg):
    if alg[:2] in ('RS', 'PS'):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if alg == 'EdDSA':
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(_CURVES[alg][0]())


def _public_jwk(key, alg, kid='k1'):
    pub = key.public_key()
    if alg[:2] in ('RS', 'PS'):
        jwk = dict(_jwk(pub, kid), alg=alg)
    elif alg == 'EdDSA':
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        jwk = {'kty': 'OKP', 'crv': 'Ed25519', 'use': 'sig', 'kid': kid, 'x': _b64(raw)}
    else:
        _, crv, size = _CURVES[alg]
        nums = pub.public_numbers()
        jwk = {'kty': 'EC', 'crv': crv, 'use': 'sig', 'kid': kid,
               'x': _b64(nums.x.to_bytes(size, 'big')), 'y': _b64(nums.y.to_bytes(size, 'big'))}
    if kid is None:
        del jwk['kid']
    return jwk


def _signed(key, alg, claims, kid='k1'):
    head = {'alg': alg, 'typ': 'JWT'}
    if kid is not None:
        head['kid'] = kid
    data = f"{_b64(json.dumps(head).encode())}.{_b64(json.dumps(claims).encode())}".encode()
    if alg == 'none':
        sig = b''
    elif alg == 'HS256':
        # the IdP's public key as the shared secret
        mac = hmac.HMAC(key, hashes.SHA256())
        mac.update(data)
        sig = mac.finalize()
    elif alg == 'EdDSA':
        sig = key.sign(data)
    elif alg[:2] == 'RS':
        sig = key.sign(data, padding.PKCS1v15(), _HASHES[alg[2:]]())
    elif alg[:2] == 'PS':
        digest = _HASHES[alg[2:]]()
        sig = key.sign(data, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
    else:
        size = _CURVES[alg][2]
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(_HASHES[alg[2:]]())))
        sig = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
    return f"{data.decode()}.{_b64(sig)}"


@pytest.fixture
def signer():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def stranger():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def keys(tmp_path, signer, monkeypatch):
    """The IdP's key set on a TLS endpoint the trust store knows; discovery names it."""
    tls = _tls_files(tmp_path)
    monkeypatch.setenv('SSL_CERT_FILE', tls[0])
    monkeypatch.setattr(urllib.request, '_opener', None)
    monkeypatch.setattr(oidc, '_jwks_clients', {})
    ep = _Endpoint({'keys': [_jwk(signer.public_key(), 'k1')]}, tls=tls)
    ep.endpoints = {'jwks': ep.url + '/jwks', 'issuer': ISSUER}
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: dict(ep.endpoints))
    yield ep
    ep.server.stop()


def _answer(got):
    if isinstance(got, dict) and set(got) == {'error'} and str(got['error']).startswith(NONCE['error']):
        return NONCE
    return got


def _decode(token, caplog, nonce='n-1', **cfg):
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        return oidc.oidc_decode_id_token(token, expected_nonce=nonce, config=dict(CFG, **cfg))


# --- the signature is checked ------------------------------------------------------------

def test_a_good_signature_is_verified(keys, signer, caplog):
    claims = _claims()
    got = _decode(_token(signer, claims), caplog)
    assert got == claims and oidc.oidc_id_token_verified(got), caplog.text
    assert FALLBACK not in caplog.text and REFUSED not in caplog.text


def test_a_bad_signature_is_refused(keys, stranger, caplog):
    # the key the IdP does not publish, under the kid it does
    assert _decode(_token(stranger, _claims()), caplog) == INVALID
    assert 'InvalidSignatureError' in caplog.text and REFUSED in caplog.text
    assert FALLBACK not in caplog.text


def test_an_unknown_kid_is_refused(keys, stranger, caplog):
    assert _decode(_token(stranger, _claims(), kid='k-elsewhere'), caplog) == INVALID
    assert 'k-elsewhere' in caplog.text and REFUSED in caplog.text
    assert FALLBACK not in caplog.text


@pytest.mark.parametrize('aud', ['someone-else', ['someone-else', 'pegaprox-prod']])
def test_an_audience_that_is_not_ours_is_refused(keys, signer, caplog, aud):
    assert _decode(_token(signer, _claims(aud=aud)), caplog) == INVALID
    assert 'InvalidAudienceError' in caplog.text and FALLBACK not in caplog.text


def test_a_token_without_an_audience_is_refused(keys, signer, caplog):
    claims = _claims()
    del claims['aud']
    assert _decode(_token(signer, claims), caplog) == INVALID
    assert FALLBACK not in caplog.text


@pytest.mark.parametrize('aud', ['pegaprox-prod', ['pegaprox-staging'], ['pegaprox', 'other-app']])
def test_an_audience_from_the_saved_list_is_verified(keys, signer, caplog, aud):
    got = _decode(_token(signer, _claims(aud=aud)), caplog, oidc_audiences='pegaprox-prod, pegaprox-staging')
    assert oidc.oidc_id_token_verified(got), caplog.text


def test_an_expired_token_is_refused(keys, signer, caplog):
    now = int(time.time())
    got = _decode(_token(signer, _claims(iat=now - 3600, exp=now - 900)), caplog)
    assert got == {'error': 'ID token has expired'}
    assert 'ExpiredSignatureError' in caplog.text and FALLBACK not in caplog.text


def test_a_token_within_the_clock_skew_still_verifies(keys, signer, caplog):
    got = _decode(_token(signer, _claims(exp=int(time.time()) - 60)), caplog)
    assert oidc.oidc_id_token_verified(got), caplog.text


@pytest.mark.parametrize('iss', ['https://other-idp.invalid/realms/ops', AUTHORITY,
                                 'https://idp.corp.example/realms/ops/../other', None])
def test_an_issuer_that_is_not_the_idps_is_refused(keys, signer, caplog, iss):
    claims = _claims(iss=iss)
    if iss is None:
        del claims['iss']
    assert _decode(_token(signer, claims), caplog) == INVALID
    assert 'its issuer' in caplog.text and FALLBACK not in caplog.text


@pytest.mark.parametrize('iss', [ISSUER, ISSUER + '/'])
def test_the_issuer_discovery_names_is_accepted_slash_or_not(keys, signer, caplog, iss):
    got = _decode(_token(signer, _claims(iss=iss)), caplog)
    assert oidc.oidc_id_token_verified(got), caplog.text


def test_without_discovery_the_configured_authority_is_the_issuer(keys, signer, caplog):
    del keys.endpoints['issuer']
    got = _decode(_token(signer, _claims(iss=AUTHORITY)), caplog)
    assert oidc.oidc_id_token_verified(got), caplog.text


def test_a_token_of_another_sign_in_is_refused(keys, signer, caplog):
    got = _decode(_token(signer, _claims(nonce='n-1')), caplog, nonce='n-2')
    assert _answer(got) == NONCE
    assert 'nonce' in caplog.text and FALLBACK not in caplog.text


def test_no_settings_refuse_the_token(signer, caplog):
    with caplog.at_level(logging.WARNING):
        assert oidc.oidc_decode_id_token(_token(signer, _claims()), expected_nonce='n-1') == INVALID
    assert REFUSED in caplog.text


def test_a_token_not_valid_yet_is_refused(keys, signer, caplog):
    got = _decode(_token(signer, _claims(nbf=int(time.time()) + 3600)), caplog)
    assert got == INVALID
    assert 'ImmatureSignatureError' in caplog.text and FALLBACK not in caplog.text
    # within the clock skew it is fine
    assert oidc.oidc_id_token_verified(_decode(_token(signer, _claims(nbf=int(time.time()) + 60)), caplog))


@pytest.mark.parametrize('aud', [['pegaprox', 'other-app'], 'pegaprox'])
def test_a_token_issued_to_another_client_is_refused(keys, signer, caplog, aud):
    assert _decode(_token(signer, _claims(aud=aud, azp='other-app')), caplog) == INVALID
    assert 'another client' in caplog.text and FALLBACK not in caplog.text


def test_a_token_issued_to_us_with_more_audiences_is_verified(keys, signer, caplog):
    got = _decode(_token(signer, _claims(aud=['pegaprox', 'other-app'], azp='pegaprox')), caplog)
    assert oidc.oidc_id_token_verified(got), caplog.text
    # a saved audience alone, the token still issued to our client
    got = _decode(_token(signer, _claims(aud='pegaprox-prod', azp='pegaprox')), caplog,
                  oidc_audiences='pegaprox-prod')
    assert oidc.oidc_id_token_verified(got), caplog.text


# --- algorithms, and keys without a kid ------------------------------------------------------

@pytest.mark.parametrize('alg', OTHER_ALGS)
def test_every_asymmetric_algorithm_verifies(keys, caplog, alg):
    key = _key_for(alg)
    keys.jwks = {'keys': [_public_jwk(key, alg)]}
    claims = _claims()
    got = _decode(_signed(key, alg, claims), caplog)
    assert got == claims and oidc.oidc_id_token_verified(got), caplog.text
    assert FALLBACK not in caplog.text and REFUSED not in caplog.text


@pytest.mark.parametrize('alg', OTHER_ALGS)
def test_another_algorithm_signed_by_a_stranger_is_refused(keys, caplog, alg):
    keys.jwks = {'keys': [_public_jwk(_key_for(alg), alg)]}
    assert _decode(_signed(_key_for(alg), alg, _claims()), caplog) == INVALID
    assert 'InvalidSignatureError' in caplog.text and FALLBACK not in caplog.text


@pytest.mark.parametrize('alg', ['HS256', 'none'])
def test_a_shared_secret_or_no_signature_is_refused(keys, signer, caplog, alg):
    secret = signer.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    assert _decode(_signed(secret, alg, _claims()), caplog) == INVALID
    assert 'InvalidAlgorithmError' in caplog.text and FALLBACK not in caplog.text


def test_a_kid_that_names_a_key_of_another_type_is_refused(keys, signer, caplog):
    ec_key = _key_for('ES256')
    keys.jwks = {'keys': [_jwk(signer.public_key(), 'k1'), _public_jwk(ec_key, 'ES256', 'k2')]}
    assert _decode(_signed(ec_key, 'ES256', _claims(), kid='k1'), caplog) == INVALID
    assert 'no EC signing key' in caplog.text and FALLBACK not in caplog.text
    assert oidc.oidc_id_token_verified(_decode(_signed(ec_key, 'ES256', _claims(), kid='k2'), caplog))


def test_a_token_without_a_kid_is_checked_against_each_key(keys, signer, stranger, caplog):
    keys.jwks = {'keys': [_jwk(stranger.public_key(), 'k0'), _public_jwk(_key_for('ES256'), 'ES256', 'k2'),
                          _jwk(signer.public_key(), 'k1')]}
    claims = _claims()
    got = _decode(_signed(signer, 'RS256', claims, kid=None), caplog)
    assert got == claims and oidc.oidc_id_token_verified(got), caplog.text
    assert _decode(_signed(rsa.generate_private_key(public_exponent=65537, key_size=2048), 'RS256',
                           _claims(), kid=None), caplog) == INVALID
    assert 'InvalidSignatureError' in caplog.text and FALLBACK not in caplog.text


@pytest.mark.parametrize('kid', ['k1', None])
def test_a_key_set_without_kids_is_no_outage(keys, signer, stranger, caplog, kid):
    keys.jwks = {'keys': [_public_jwk(signer, 'RS256', kid=None)]}
    got = _decode(_signed(signer, 'RS256', _claims(), kid=kid), caplog)
    assert oidc.oidc_id_token_verified(got), caplog.text
    # a stranger's token against that set is refused, not read unchecked
    assert _decode(_signed(stranger, 'RS256', _claims(), kid=kid), caplog) == INVALID
    assert 'InvalidSignatureError' in caplog.text and FALLBACK not in caplog.text


def test_a_key_rotated_in_after_the_set_was_cached_is_found(keys, signer, caplog, monkeypatch):
    claims = _claims()
    assert oidc.oidc_id_token_verified(_decode(_token(signer, claims), caplog))
    rotated = _key_for('RS256')
    keys.jwks = {'keys': [_jwk(signer.public_key(), 'k1'), _jwk(rotated.public_key(), 'k-new')]}
    for client in oidc._jwks_clients.values():
        monkeypatch.setattr(client, 'cooldown_duration', 0, raising=False)
    got = _decode(_token(rotated, claims, kid='k-new'), caplog)
    assert oidc.oidc_id_token_verified(got), caplog.text
    assert keys.hits == ['/jwks', '/jwks']


# --- the key set cannot be loaded ---------------------------------------------------------

@pytest.mark.parametrize('broken', ['unreachable', 'not-a-key-set', 'not-an-object'])
def test_without_the_keys_and_with_verified_tls_the_token_is_read_with_its_claims_checked(
        keys, stranger, caplog, broken):
    if broken == 'unreachable':
        keys.endpoints['jwks'] = DEAD
    else:
        keys.jwks = {'keys': 'nope'} if broken == 'not-a-key-set' else ['nope']
    claims = _claims()
    got = _decode(_token(stranger, claims), caplog)
    assert got == claims and not oidc.oidc_id_token_verified(got)
    assert FALLBACK in caplog.text, caplog.text


@pytest.mark.parametrize('over,nonce,error', [
    ({'aud': 'someone-else'}, 'n-1', INVALID),
    ({'iss': 'https://other-idp.invalid'}, 'n-1', INVALID),
    ({'exp': int(time.time()) - 900}, 'n-1', {'error': 'ID token has expired'}),
    ({'exp': 'tomorrow'}, 'n-1', INVALID),
    ({'nbf': int(time.time()) + 3600}, 'n-1', INVALID),
    ({'nbf': 'tomorrow'}, 'n-1', INVALID),
    ({'aud': ['pegaprox', 'other-app'], 'azp': 'other-app'}, 'n-1', INVALID),
    ({}, 'n-2', NONCE),
], ids=['aud', 'iss', 'expired', 'odd-exp', 'nbf', 'odd-nbf', 'azp', 'nonce'])
def test_without_the_keys_the_claims_are_still_checked(keys, signer, caplog, over, nonce, error):
    keys.endpoints['jwks'] = DEAD
    assert _answer(_decode(_token(signer, _claims(**over)), caplog, nonce=nonce)) == error
    assert FALLBACK in caplog.text and REFUSED in caplog.text


def test_a_token_without_an_expiry_is_refused_without_the_keys(keys, signer, caplog):
    keys.endpoints['jwks'] = DEAD
    claims = _claims()
    del claims['exp']
    assert _decode(_token(signer, claims), caplog) == INVALID


def test_without_the_keys_and_with_tls_unverified_the_token_is_refused(keys, signer, caplog):
    # oidc_skip_ssl_verify: the token answer itself could have come from anyone on the way
    keys.endpoints['jwks'] = DEAD
    assert _decode(_token(signer, _claims()), caplog, oidc_skip_ssl_verify=True,
                   oidc_allow_private_ip=True) == INVALID
    assert 'oidc_skip_ssl_verify is on' in caplog.text and FALLBACK not in caplog.text


def test_a_key_set_that_loads_but_lacks_the_key_is_no_outage(keys, signer, stranger, caplog):
    keys.jwks = {'keys': [_jwk(stranger.public_key(), 'k-other')]}
    assert _decode(_token(signer, _claims()), caplog) == INVALID
    assert FALLBACK not in caplog.text


# --- the admin's switch -------------------------------------------------------------------

def test_with_the_switch_the_signature_is_not_checked(keys, stranger, caplog):
    claims = _claims()
    got = _decode(_token(stranger, claims), caplog, oidc_skip_jwt_verification=True)
    assert got == claims and not oidc.oidc_id_token_verified(got)
    assert 'verification DISABLED' in caplog.text
    assert keys.hits == []


@pytest.mark.parametrize('over,nonce,error', [
    ({'aud': 'someone-else'}, 'n-1', INVALID),
    ({'exp': int(time.time()) - 900}, 'n-1', {'error': 'ID token has expired'}),
    ({'nbf': int(time.time()) + 3600}, 'n-1', INVALID),
    ({'aud': ['pegaprox', 'other-app'], 'azp': 'other-app'}, 'n-1', INVALID),
    ({}, 'n-2', NONCE),
], ids=['aud', 'expired', 'nbf', 'azp', 'nonce'])
def test_with_the_switch_the_claims_are_still_checked(keys, stranger, caplog, over, nonce, error):
    got = _decode(_token(stranger, _claims(**over)), caplog, nonce=nonce, oidc_skip_jwt_verification=True)
    assert _answer(got) == error
    assert REFUSED in caplog.text


# --- Entra ----------------------------------------------------------------------------------

TENANT = '72F988BF-86F1-41AF-91AB-2D7CD011DB47'
OTHER_TENANT = '0b0e0f00-1111-4222-8333-444455556666'
APP = '6731de76-14a6-49ae-97bc-6eba6914391e'


def _entra_cfg(tenant=TENANT, **over):
    cfg = {'provider': 'entra', 'tenant_id': tenant, 'client_id': APP, 'cloud_environment': 'commercial'}
    cfg.update(over)
    return cfg


def _entra_claims(tid=TENANT.lower(), iss=None, **over):
    now = int(time.time())
    body = {'ver': '2.0', 'iss': iss or f'https://login.microsoftonline.com/{tid}/v2.0', 'tid': tid,
            'aud': APP, 'sub': 'pairwise-sub', 'oid': 'object-id', 'iat': now, 'nbf': now,
            'exp': now + 300, 'nonce': 'n-1', 'preferred_username': 'wanda@corp.example'}
    body.update(over)
    return body


_REAL_ENDPOINTS = oidc.get_oidc_endpoints


def _entra_decode(monkeypatch, keys, token, caplog, cfg):
    # the real endpoints, issuer included; only the key set is served from loopback
    monkeypatch.setattr(oidc, 'get_oidc_endpoints',
                        lambda config: dict(_REAL_ENDPOINTS(config), jwks=keys.url + '/jwks'))
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        return oidc.oidc_decode_id_token(token, expected_nonce='n-1', config=cfg)


def test_entra_names_the_issuer_of_its_tenant():
    assert _REAL_ENDPOINTS(_entra_cfg())['issuer'] == \
        f'https://login.microsoftonline.com/{TENANT.lower()}/v2.0'
    assert _REAL_ENDPOINTS(_entra_cfg(cloud_environment='gcc_high'))['issuer'] == \
        f'https://login.microsoftonline.us/{TENANT.lower()}/v2.0'
    for tenant in ('common', 'organizations', 'corp.onmicrosoft.com'):
        assert _REAL_ENDPOINTS(_entra_cfg(tenant))['issuer'] == \
            'https://login.microsoftonline.com/{tenantid}/v2.0', tenant


def test_an_entra_token_of_the_tenant_is_verified(keys, signer, monkeypatch, caplog):
    claims = _entra_claims()
    got = _entra_decode(monkeypatch, keys, _token(signer, claims), caplog, _entra_cfg())
    assert got == claims and oidc.oidc_id_token_verified(got), caplog.text


def test_an_entra_token_of_another_tenant_is_refused(keys, signer, monkeypatch, caplog):
    got = _entra_decode(monkeypatch, keys, _token(signer, _entra_claims(tid=OTHER_TENANT)), caplog,
                        _entra_cfg())
    assert got == INVALID and 'its issuer' in caplog.text


def test_an_entra_token_for_another_app_is_refused(keys, signer, monkeypatch, caplog):
    got = _entra_decode(monkeypatch, keys, _token(signer, _entra_claims(aud=OTHER_TENANT)), caplog,
                        _entra_cfg())
    assert got == INVALID and 'InvalidAudienceError' in caplog.text


@pytest.mark.parametrize('tenant', ['common', 'organizations', 'corp.onmicrosoft.com'])
def test_a_multi_tenant_entra_token_fills_the_tenant_from_its_tid(keys, signer, monkeypatch, caplog, tenant):
    ok = _entra_decode(monkeypatch, keys, _token(signer, _entra_claims(tid=OTHER_TENANT)), caplog,
                       _entra_cfg(tenant))
    assert oidc.oidc_id_token_verified(ok), caplog.text
    # the tid has to be the one the iss names
    mixed = _entra_claims(tid=OTHER_TENANT, iss=f'https://login.microsoftonline.com/{TENANT.lower()}/v2.0')
    assert _entra_decode(monkeypatch, keys, _token(signer, mixed), caplog, _entra_cfg(tenant)) == INVALID
    # and a token without a tid cannot fill it
    bare = _entra_claims(tid=OTHER_TENANT)
    del bare['tid']
    assert _entra_decode(monkeypatch, keys, _token(signer, bare), caplog, _entra_cfg(tenant)) == INVALID


def test_entra_without_the_keys_reads_the_token_checked_whatever_the_tls_switch(keys, signer, monkeypatch,
                                                                                caplog):
    # the switch never reaches Entra's endpoints, its token request is always verified
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: dict(_REAL_ENDPOINTS(config), jwks=DEAD))
    for cfg in (_entra_cfg(), _entra_cfg(oidc_skip_ssl_verify=True)):
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            got = oidc.oidc_decode_id_token(_token(signer, _entra_claims()), expected_nonce='n-1', config=cfg)
        assert got.get('sub') == 'pairwise-sub', got
        assert not oidc.oidc_id_token_verified(got) and FALLBACK in caplog.text
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            other = oidc.oidc_decode_id_token(_token(signer, _entra_claims(tid=OTHER_TENANT)),
                                              expected_nonce='n-1', config=cfg)
        assert other == INVALID


# --- through the sign-in --------------------------------------------------------------------

class _IdP:
    """Discovery, token, userinfo and JWKS of a generic IdP on one TLS listener the trust
    store knows. `token_key` signs the ID token with `alg`, `token_claims` adds to it; the
    groups are in the ID token only, the way the generic provider reads them."""

    def __init__(self, tls, signer):
        import ssl
        self.signer, self.token_key, self.token_claims, self.hits = signer, signer, {}, []
        self.alg = 'RS256'
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        self.server = WSGIServer(('127.0.0.1', 0), self._app, log=None, error_log=None, ssl_context=ctx)
        self.server.start()
        self.url = f'https://127.0.0.1:{self.server.server_port}'

    def id_token(self):
        now = int(time.time())
        body = {'iss': self.url, 'sub': 'morgan-sub', 'aud': 'pegaprox', 'iat': now, 'exp': now + 300,
                'nonce': 'the-nonce', 'preferred_username': 'morgan', 'groups': ['pp-admins']}
        body.update(self.token_claims)
        return _signed(self.token_key, self.alg, body)

    def _app(self, environ, start_response):
        path = environ['PATH_INFO']
        self.hits.append(path)
        answers = {
            '/.well-known/openid-configuration': {
                'issuer': self.url, 'authorization_endpoint': self.url + '/authorize',
                'token_endpoint': self.url + '/token', 'userinfo_endpoint': self.url + '/userinfo',
                'jwks_uri': self.url + '/jwks'},
            '/token': {'access_token': 'the-access-token', 'token_type': 'Bearer', 'id_token': self.id_token()},
            '/userinfo': {'sub': 'morgan-sub', 'preferred_username': 'morgan'},
            '/jwks': {'keys': [_public_jwk(self.signer, self.alg)]},
        }
        if environ['REQUEST_METHOD'] == 'POST':
            environ['wsgi.input'].read()
        if path not in answers:
            start_response('404 Not Found', [('Content-Length', '0')])
            return [b'']
        out = json.dumps(answers[path]).encode()
        start_response('200 OK', [('Content-Type', 'application/json'), ('Content-Length', str(len(out)))])
        return [out]


@pytest.fixture
def full_idp(tmp_path, signer, monkeypatch):
    tls = _tls_files(tmp_path)
    for var in ('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE'):
        monkeypatch.setenv(var, tls[0])
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)
    monkeypatch.setattr(urllib.request, '_opener', None)
    monkeypatch.setattr(oidc, '_jwks_clients', {})
    monkeypatch.setattr(oidc, '_oidc_discovery_cache', {})
    ep = _IdP(tls, signer)
    yield ep
    ep.server.stop()


def _sign_in(api, db, idp, **settings):
    admin = api.as_user(_seed_user(db, 'root', role='admin'))
    body = {'oidc_enabled': True, 'oidc_provider': 'generic', 'oidc_authority': idp.url,
            'oidc_client_id': 'pegaprox', 'oidc_client_secret': 'the-client-secret',
            'oidc_redirect_uri': 'https://pegaprox.example/oidc/callback', 'oidc_allow_private_ip': True,
            'oidc_skip_ssl_verify': False, 'oidc_admin_group_id': 'pp-admins', 'oidc_default_role': 'viewer'}
    body.update(settings)
    r = admin.post('/api/settings/server', json=body)
    assert r.status_code == 200, r.get_data(as_text=True)
    import pegaprox.api.auth as auth_api
    for k in [k for k in auth_api.login_attempts_by_ip if str(k).startswith('oidc_cb_')]:
        auth_api.login_attempts_by_ip.pop(k, None)
    browser = api.app.test_client()
    browser.set_cookie('oidc_state', 'the-state:the-nonce:the-verifier', domain='localhost')
    return browser.post('/api/auth/oidc/callback', json={'code': 'the-code', 'state': 'the-state'},
                        headers={'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://localhost'},
                        base_url='http://localhost')


def test_a_well_signed_sign_in_gets_the_role_of_its_groups(api, db, full_idp, caplog):
    with caplog.at_level(logging.WARNING):
        r = _sign_in(api, db, full_idp)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert (r.get_json()['user'], db.get_user('morgan')['role']) == ('morgan', 'admin')
    assert FALLBACK not in caplog.text and REFUSED not in caplog.text
    assert '/jwks' in full_idp.hits


@pytest.mark.parametrize('alg', ['RS512', 'ES384', 'PS384'])
def test_a_sign_in_signed_with_another_algorithm_gets_the_role_of_its_groups(api, db, full_idp, caplog, alg):
    full_idp.signer = full_idp.token_key = _key_for(alg)
    full_idp.alg = alg
    with caplog.at_level(logging.WARNING):
        r = _sign_in(api, db, full_idp)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert db.get_user('morgan')['role'] == 'admin'
    assert FALLBACK not in caplog.text and REFUSED not in caplog.text


@pytest.mark.parametrize('case', ['bad-signature', 'audience', 'issuer', 'expired'])
def test_a_sign_in_whose_token_does_not_check_out_is_refused(api, db, full_idp, stranger, caplog, case):
    if case == 'bad-signature':
        full_idp.token_key = stranger
    elif case == 'audience':
        full_idp.token_claims = {'aud': 'someone-else'}
    elif case == 'issuer':
        full_idp.token_claims = {'iss': 'https://other-idp.invalid'}
    else:
        full_idp.token_claims = {'iat': int(time.time()) - 3600, 'exp': int(time.time()) - 900}
    with caplog.at_level(logging.WARNING):
        r = _sign_in(api, db, full_idp)
    assert r.status_code == 401, r.get_data(as_text=True)
    assert r.get_json()['error'].startswith('Authentication failed - ')
    assert 'session_id' not in r.get_json()
    assert db.get_user('morgan') is None
    assert REFUSED in caplog.text and FALLBACK not in caplog.text
