# What an ACME order writes into the SSL dir, and what a refused account says.
#
# Requesting and renewing both write into the dir the TLS listener loads from. The
# certificate download was taken as PEM whatever came back: a rate limit, a 5xx or a
# proxy page landed in cert.pem next to a fresh key, the pair no longer loaded,
# get_cert_info found nothing to renew any more, and the next start refused to come
# up. The pair is replaced now only when the CA answers 200 with certificates only,
# the first of them for the key of our CSR, and each file goes through a temp file
# and a rename.
#
# A refused newAccount (a contact the CA does not take, a rate limit) answered with
# "'Location'" as its reason. It says what the CA said now.
import datetime
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pegaprox import app as app_module
from pegaprox.core import acme

DOMAIN = 'pp.example.com'
FINALIZE = 'https://ca.example/finalize/1'
CERT_URL = 'https://ca.example/cert/1'

_ACCOUNT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _Resp:
    def __init__(self, status, text='', js=None, headers=None):
        self.status_code = status
        self.text = text
        self._js = js
        self.headers = headers or {}

    def json(self):
        if self._js is None:
            raise ValueError('not json')
        return self._js

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def _ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Issuing CA'),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test CA')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


_CA_KEY, _CA_CERT = _ca()


def _issue(public_key, days_left):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)]))
            .issuer_name(_CA_CERT.subject).public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=90 - days_left))
            .not_valid_after(now + datetime.timedelta(days=days_left))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), critical=False)
            .sign(_CA_KEY, hashes.SHA256()))


def _pem(*certs):
    return ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


@pytest.fixture
def served(tmp_path):
    """The pair the listener serves now: a CA certificate with 10 days left."""
    ssl_dir = tmp_path / 'ssl'
    ssl_dir.mkdir()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, keyfile = ssl_dir / 'cert.pem', ssl_dir / 'key.pem'
    cert.write_text(_pem(_issue(key.public_key(), 10), _CA_CERT))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    os.chmod(keyfile, 0o600)
    return ssl_dir


def _order(monkeypatch, ssl_dir, answer):
    """request_certificate for an order the CA validated, its certificate download
    answered by answer(csr)."""
    seen = {}

    def signed(url, payload, account_key, nonce, kid=None):
        if url == FINALIZE:
            seen['csr'] = x509.load_der_x509_csr(acme._b64url_decode(payload['csr']))
            return _Resp(200, js={'status': 'valid', 'certificate': CERT_URL})
        assert url == CERT_URL, url
        return answer(seen['csr'])

    monkeypatch.setattr(acme, '_create_order', lambda *a, **kw: {
        'success': True, 'account_key': _ACCOUNT_KEY, 'nonce': 'n1', 'kid': 'https://ca.example/acct/1',
        'order': {'finalize': FINALIZE}, 'order_url': 'https://ca.example/order/1',
        'authz_url': 'https://ca.example/authz/1',
        'authz': {'challenges': [{'type': 'http-01', 'token': 'tok', 'url': 'https://ca.example/chall/1'}]}})
    monkeypatch.setattr(acme, '_validate_challenge', lambda *a, **kw: {'success': True, 'nonce': 'n2'})
    monkeypatch.setattr(acme, '_signed_request', signed)
    return acme.request_certificate(DOMAIN, 'ops@example.com', str(ssl_dir))


def _other_key():
    return ec.generate_private_key(ec.SECP256R1()).public_key()


_KEY_BLOCK = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n'

REFUSED = {
    'a rate limit': (lambda csr: _Resp(
        429, text='{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates"}',
        js={'type': 'urn:ietf:params:acme:error:rateLimited', 'detail': 'too many certificates'}),
        'too many certificates (HTTP 429)'),
    'a gateway page': (lambda csr: _Resp(502, text='<html><body>502 Bad Gateway</body></html>'),
                       'HTTP 502'),
    'a proxy page with a 200': (lambda csr: _Resp(200, text='<html><body>Sign in to continue</body></html>'),
                                'not answer with a PEM certificate chain'),
    'a certificate for another key': (lambda csr: _Resp(200, text=_pem(_issue(_other_key(), 90), _CA_CERT)),
                                      'not for the key of this request'),
    'a key block next to the certificate': (
        lambda csr: _Resp(200, text=_pem(_issue(csr.public_key(), 90)) + _KEY_BLOCK),
        'not answer with a PEM certificate chain'),
    'a chain cut off': (
        lambda csr: _Resp(200, text=_pem(_issue(csr.public_key(), 90), _CA_CERT)[:-40]),
        'cut off'),
}


@pytest.mark.parametrize('case', list(REFUSED))
def test_a_download_that_is_no_chain_for_our_key_leaves_the_served_pair(served, monkeypatch, case):
    answer, reason = REFUSED[case]
    cert, key = served / 'cert.pem', served / 'key.pem'
    before = cert.read_bytes(), key.read_bytes()

    res = _order(monkeypatch, served, answer)

    assert (cert.read_bytes(), key.read_bytes()) == before, f'{case} replaced the served pair: {res}'
    assert res['success'] is False
    assert reason in res['message'], res['message']
    assert res['message'].startswith('Certificate download failed: ')
    # the renewal still finds the certificate it has to renew, and the next start its pair
    assert acme.get_cert_info(str(served))['days_left'] in (9, 10)
    monkeypatch.delenv('PEGAPROX_ALLOW_PLAINTEXT', raising=False)
    assert app_module._resolve_ssl_context(False, cert_file=str(cert), key_file=str(key)) == (str(cert), str(key))
    assert sorted(os.listdir(served)) == ['cert.pem', 'key.pem']


def test_an_issued_chain_replaces_the_pair(served, monkeypatch):
    issued = {}

    def answer(csr):
        issued['chain'] = _pem(_issue(csr.public_key(), 90), _CA_CERT)
        return _Resp(200, text=issued['chain'])

    res = _order(monkeypatch, served, answer)

    assert res['success'] is True, res
    cert, key = served / 'cert.pem', served / 'key.pem'
    assert cert.read_text() == issued['chain']
    assert app_module._unloadable(str(cert), str(key)) is None
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(cert).st_mode) == 0o644
    assert acme.get_cert_info(str(served))['days_left'] in (89, 90)
    assert sorted(os.listdir(served)) == ['cert.pem', 'key.pem']


def test_a_first_certificate_needs_no_pair_before_it(tmp_path, monkeypatch):
    ssl_dir = tmp_path / 'ssl'
    res = _order(monkeypatch, ssl_dir, lambda csr: _Resp(200, text=_pem(_issue(csr.public_key(), 90))))
    assert res['success'] is True, res
    assert app_module._unloadable(str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem')) is None


@pytest.mark.parametrize('status,problem', [
    (400, {'type': 'urn:ietf:params:acme:error:invalidContact',
           'detail': 'Error validating contact(s) :: invalid contact domain'}),
    (429, {'type': 'urn:ietf:params:acme:error:rateLimited',
           'detail': 'too many new registrations from this IP address'}),
])
def test_a_refused_account_says_what_the_ca_said(tmp_path, monkeypatch, status, problem):
    directory = {'newNonce': 'https://ca.example/nonce', 'newAccount': 'https://ca.example/acct',
                 'newOrder': 'https://ca.example/order'}
    sent = []

    def plain(method, url, **kw):
        return _Resp(200, js=directory) if method == 'GET' else _Resp(200, headers={'Replay-Nonce': 'n1'})

    def signed(url, payload, account_key, nonce, kid=None):
        sent.append(url)
        return _Resp(status, js=problem, headers={'Replay-Nonce': 'n2'})

    monkeypatch.setattr('pegaprox.utils.url_security.sanitize_outbound_url', lambda url, **kw: url)
    monkeypatch.setattr(acme, '_guard_acme_url', lambda url: url)
    monkeypatch.setattr(acme, '_acme_allow_private', lambda: False)
    monkeypatch.setattr(acme, '_acme_request', plain)
    monkeypatch.setattr(acme, '_signed_request', signed)

    res = acme.request_certificate(DOMAIN, 'ops@invalid', str(tmp_path), directory_url='https://ca.example/dir')

    assert res['success'] is False
    assert res['message'] == f"Account registration failed: {problem['detail']} (HTTP {status})"
    assert sent == [directory['newAccount']]
