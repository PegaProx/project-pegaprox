"""The OIDC id_token is checked by PyJWT (utils/oidc.py), and requirements.txt decides
which PyJWT an install gets (#972).

Nothing else in the suite runs that check: the sign-in tests stub oidc_decode_id_token
away. These sign real RS256 tokens and serve the keys from a TLS JWKS endpoint on
loopback, the way an IdP does, and pin down:

  * requirements.txt keeps a floor, not an exact pin. update.sh and the in-app updater
    run `pip install -r` without --upgrade, so an == would take an install that already
    has a newer PyJWT back down to the pinned one.
  * a valid token is verified by its signature, not waved through the unverified
    fallback, and a wrong nonce is still refused after that.
  * a token with '=' padding on its segments still verifies. 2.14.0 refuses those
    (DecodeError "Invalid header padding"), 2.15.1 takes them again; here they would
    quietly land in the unverified fallback.
  * a JWKS endpoint that redirects is not followed. The SSRF guard approves the
    configured jwks_uri and nothing else, and up to 2.13.0 PyJWKClient went wherever
    the redirect pointed, plain http included.
  * a deeply nested token is refused and nothing escapes. The 2.15.0 advisory is about
    get_signing_key_from_jwt, which is the call we make.

MK Oct 2026 (#972)
"""
import base64
import datetime
import ipaddress
import json
import logging
import ssl
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from gevent.pywsgi import WSGIServer
from packaging.requirements import Requirement

import jwt
from pegaprox.utils import oidc

REPO = Path(__file__).resolve().parent.parent
FALLBACK = 'falling back to unverified decode'
CFG = {'provider': 'generic', 'authority': 'https://idp.invalid', 'client_id': 'pegaprox'}


def _pyjwt_requirement():
    for line in (REPO / 'requirements.txt').read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if line.lower().startswith('pyjwt'):
            return Requirement(line)
    raise AssertionError('PyJWT is missing from requirements.txt')


def test_requirements_keep_a_floor_for_pyjwt_not_a_pin():
    req = _pyjwt_requirement()
    assert 'crypto' in req.extras, 'RS256/ES256/EdDSA need the cryptography extra'
    assert not {s.operator for s in req.specifier} & {'==', '===', '~='}, str(req)
    # 2.13.0 follows JWKS redirects, 2.14.0 refuses padded segments and still has the two
    # advisories 2.15.0 closed. Anything after that has to stay installable.
    for bad in ('2.13.0', '2.14.0'):
        assert not req.specifier.contains(bad), f'{req} still lets {bad} in'
    for good in ('2.15.1', '2.15.2', '2.16.0'):
        assert req.specifier.contains(good), f'{req} keeps {good} out'


# --- an IdP on loopback ----------------------------------------------------------

def _tls_files(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'idp')])
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=False,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    cf, kf = tmp_path / 'idp-cert.pem', tmp_path / 'idp-key.pem'
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cf), str(kf)


class _Endpoint:
    """Answers GET /jwks with the key set, and any path in `redirects` with a 302."""

    def __init__(self, jwks, tls=None):
        self.jwks, self.redirects, self.hits = jwks, {}, []
        kw = {}
        if tls:
            kw['ssl_context'] = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            kw['ssl_context'].load_cert_chain(*tls)
        self.server = WSGIServer(('127.0.0.1', 0), self._app, log=None, error_log=None, **kw)
        self.server.start()
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.server.server_port}"

    def _app(self, environ, start_response):
        path = environ['PATH_INFO']
        self.hits.append(path)
        if path in self.redirects:
            start_response('302 Found', [('Location', self.redirects[path]), ('Content-Length', '0')])
            return [b'']
        body = json.dumps(self.jwks).encode()
        start_response('200 OK', [('Content-Type', 'application/json'), ('Content-Length', str(len(body)))])
        return [body]


def _b64(raw, pad=False):
    s = base64.urlsafe_b64encode(raw).decode()
    return s if pad else s.rstrip('=')


def _jwk(public_key, kid):
    nums = public_key.public_numbers()

    def enc(i):
        return _b64(i.to_bytes((i.bit_length() + 7) // 8, 'big'))
    return {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': kid, 'n': enc(nums.n), 'e': enc(nums.e)}


def _token(key, claims, kid='k1', pad=False):
    # signed by hand, not with jwt.encode, so the library under test only verifies
    head = _b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': kid}).encode(), pad)
    body = _b64(json.dumps(claims).encode(), pad)
    sig = key.sign(f'{head}.{body}'.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f'{head}.{body}.{_b64(sig, pad)}'


def _claims(nonce='n-1'):
    now = int(time.time())
    return {'iss': 'https://idp.invalid', 'sub': 'alice', 'aud': 'pegaprox',
            'iat': now, 'exp': now + 300, 'nonce': nonce}


@pytest.fixture
def signer():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def idp(tmp_path, signer, monkeypatch):
    tls = _tls_files(tmp_path)
    # urllib builds its default context from these paths; the cached global opener
    # (2.13.0 goes through urlopen) is dropped so it picks them up too
    monkeypatch.setenv('SSL_CERT_FILE', tls[0])
    monkeypatch.setattr(urllib.request, '_opener', None)
    monkeypatch.setattr(oidc, '_jwks_clients', {})
    ep = _Endpoint({'keys': [_jwk(signer.public_key(), 'k1')]}, tls=tls)
    monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: {'jwks': ep.url + '/jwks'})
    yield ep
    ep.server.stop()


def _decode(token, caplog, nonce='n-1'):
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        return oidc.oidc_decode_id_token(token, expected_nonce=nonce, config=CFG)


def test_a_valid_token_is_verified_by_its_signature(idp, signer, caplog):
    claims = _claims()
    assert _decode(_token(signer, claims), caplog) == claims
    assert FALLBACK not in caplog.text, f'PyJWT {jwt.__version__}: {caplog.text}'
    assert idp.hits == ['/jwks']


def test_a_verified_token_with_another_nonce_is_refused(idp, signer, caplog):
    result = _decode(_token(signer, _claims(nonce='n-1')), caplog, nonce='n-2')
    assert result == {'error': 'OIDC nonce mismatch - possible replay attack'}
    assert FALLBACK not in caplog.text


def test_a_token_with_padded_segments_is_still_verified(idp, signer, caplog):
    claims = _claims()
    token = _token(signer, claims, pad=True)
    assert token.rsplit('.', 1)[1].endswith('=')
    assert _decode(token, caplog) == claims
    assert FALLBACK not in caplog.text, f'PyJWT {jwt.__version__}: {caplog.text}'


def test_a_jwks_endpoint_that_redirects_is_not_followed(idp, signer, monkeypatch, caplog):
    # where the redirect points serves the very same keys, over plain http, which
    # the SSRF guard would never have let through as the jwks_uri
    elsewhere = _Endpoint(idp.jwks)
    try:
        idp.redirects['/moved'] = elsewhere.url + '/jwks'
        monkeypatch.setattr(oidc, 'get_oidc_endpoints', lambda config: {'jwks': idp.url + '/moved'})
        _decode(_token(signer, _claims()), caplog)
    finally:
        elsewhere.server.stop()
    assert idp.hits == ['/moved']
    assert elsewhere.hits == [], f'PyJWT {jwt.__version__} followed the JWKS redirect'
    assert FALLBACK in caplog.text


def test_a_deeply_nested_token_is_refused_and_nothing_escapes(idp, caplog):
    head = _b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'}).encode())
    body = _b64(b'[' * 20000 + b']' * 20000)
    token = f'{head}.{body}.{_b64(bytes(256))}'
    assert _decode(token, caplog) == {'error': 'Failed to validate identity token'}
