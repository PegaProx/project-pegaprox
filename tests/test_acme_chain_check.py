# What a certificate download has to be before it replaces the served pair.
#
# The chain check counted only whole '-----BEGIN X-----' lines. A body cut inside the
# header of its second certificate ('-----BEGIN CERT') had one label and one block, so
# the leaf alone went over a full chain, followed by the stray header line, and clients
# that hold only the root failed on it while the status still said valid. The body has to
# be whole PEM certificates and nothing else now, each one issued by the next, and the
# first one for our key and the name we asked for.
import datetime
import os

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
_NOW = datetime.datetime.now(datetime.timezone.utc)


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


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_cert(subject, key, issuer=None, issuer_key=None):
    return (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer or subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - datetime.timedelta(days=1))
            .not_valid_after(_NOW + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(issuer_key or key, hashes.SHA256()))


class _Ca:
    """A root and the intermediate that issues the leaves, like a public ACME CA."""

    def __init__(self, label):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _ca_cert(_name(f'{label} Root'), self.root_key)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = _ca_cert(_name(f'{label} Intermediate'), self.int_key,
                                     self.root.subject, self.root_key)

    def leaf(self, public_key, days_left=90, name=DOMAIN, from_root=False):
        return (x509.CertificateBuilder().subject_name(x509.Name([]))
                .issuer_name((self.root if from_root else self.intermediate).subject)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(_NOW - datetime.timedelta(days=90 - days_left))
                .not_valid_after(_NOW + datetime.timedelta(days=days_left))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=True)
                .sign(self.root_key if from_root else self.int_key, hashes.SHA256()))


CA = _Ca('Test')
OTHER = _Ca('Other')


def _pem(*certs):
    return ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def _serve(ssl_dir, *chain_for_key):
    """Put a pair in ssl_dir the way the listener serves it; chain_for_key(public key)."""
    ssl_dir.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (ssl_dir / 'cert.pem').write_text(_pem(*chain_for_key[0](key.public_key())))
    (ssl_dir / 'key.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(ssl_dir / 'key.pem', 0o600)


@pytest.fixture
def served(tmp_path):
    """A pair from the public-style CA with 19 days left: the leaf and its intermediate."""
    ssl_dir = tmp_path / 'ssl'
    _serve(ssl_dir, lambda pub: (CA.leaf(pub, 19), CA.intermediate))
    return ssl_dir


def _order(monkeypatch, ssl_dir, answer):
    """request_certificate for an order the CA validated, its download answered by answer(csr)."""
    seen = {}

    def signed(url, payload, account_key, nonce, kid=None):
        if url == FINALIZE:
            seen['csr'] = x509.load_der_x509_csr(acme._b64url_decode(payload['csr']))
            return _Resp(200, js={'status': 'valid', 'certificate': CERT_URL})
        assert url == CERT_URL, url
        return _Resp(200, text=answer(seen['csr']))

    monkeypatch.setattr(acme, '_create_order', lambda *a, **kw: {
        'success': True, 'account_key': _ACCOUNT_KEY, 'nonce': 'n1', 'kid': 'https://ca.example/acct/1',
        'order': {'finalize': FINALIZE}, 'order_url': 'https://ca.example/order/1',
        'authz_url': 'https://ca.example/authz/1',
        'authz': {'challenges': [{'type': 'http-01', 'token': 'tok', 'url': 'https://ca.example/chall/1'}]}})
    monkeypatch.setattr(acme, '_validate_challenge', lambda *a, **kw: {'success': True, 'nonce': 'n2'})
    monkeypatch.setattr(acme, '_signed_request', signed)
    return acme.request_certificate(DOMAIN, 'ops@example.com', str(ssl_dir))


def _full(csr):
    return _pem(CA.leaf(csr.public_key()), CA.intermediate)


def _cut_at(marker, nth=1):
    """The full chain cut right after the nth occurrence of marker."""
    def answer(csr):
        body = _full(csr)
        at = -1
        for _ in range(nth):
            at = body.index(marker, at + 1)
        return body[:at + len(marker)]
    return answer


def _same_name_other_key(csr):
    # an intermediate that carries the right name but not the key that signed the leaf
    impostor = _ca_cert(CA.intermediate.subject, ec.generate_private_key(ec.SECP256R1()),
                        CA.root.subject, CA.root_key)
    return _pem(CA.leaf(csr.public_key()), impostor)


REFUSED = {
    # the three cuts seen against a live CA: inside the second header, after its dashes
    'cut inside the second header': (_cut_at('-----BEGIN CERTIFICATE', 2), 'cut off'),
    'cut after -----BEGIN CERT': (_cut_at('-----BEGIN CERT', 2), 'cut off'),
    'cut in the second header dashes': (_cut_at('-----BEGIN CERTIFICATE---', 2), 'cut off'),
    'cut before the last END dashes': (lambda csr: _full(csr).rstrip()[:-3], 'cut off'),
    'the intermediate of another CA': (lambda csr: _pem(CA.leaf(csr.public_key()), OTHER.intermediate),
                                       'does not link up'),
    'an intermediate with the right name and another key': (_same_name_other_key, 'does not link up'),
    'the root before the intermediate': (lambda csr: _pem(CA.leaf(csr.public_key()), CA.root, CA.intermediate),
                                         'does not link up'),
    'junk between the certificates': (
        lambda csr: _pem(CA.leaf(csr.public_key())) + 'served by edge-proxy-7\n' + _pem(CA.intermediate),
        'text outside its certificates'),
    'junk after the chain': (lambda csr: _full(csr) + '<!-- cache hit -->\n', 'text outside its certificates'),
    'a certificate for another name': (
        lambda csr: _pem(CA.leaf(csr.public_key(), name='other.example.com'), CA.intermediate),
        f'not for {DOMAIN}'),
}


@pytest.mark.parametrize('case', list(REFUSED))
def test_a_download_that_is_no_whole_chain_leaves_the_served_pair(served, monkeypatch, case):
    answer, reason = REFUSED[case]
    cert, key = served / 'cert.pem', served / 'key.pem'
    before = cert.read_bytes(), key.read_bytes(), os.stat(cert).st_ino, os.stat(key).st_ino

    res = _order(monkeypatch, served, answer)

    assert res['success'] is False, f'{case} was taken: {res}'
    assert res['message'].startswith('Certificate download failed: '), res['message']
    assert reason in res['message'], res['message']
    assert (cert.read_bytes(), key.read_bytes(), os.stat(cert).st_ino, os.stat(key).st_ino) == before
    assert sorted(os.listdir(served)) == ['cert.pem', 'key.pem']
    assert acme.get_cert_info(str(served))['days_left'] in (18, 19)
    monkeypatch.delenv('PEGAPROX_ALLOW_PLAINTEXT', raising=False)
    assert app_module._resolve_ssl_context(False, cert_file=str(cert), key_file=str(key)) == (str(cert), str(key))


TAKEN = {
    'the leaf and its intermediate': _full,
    'the full chain up to the root': lambda csr: _pem(CA.leaf(csr.public_key()), CA.intermediate, CA.root),
    'CRLF line ends and blank lines between': lambda csr: '\r\n' + _full(csr).replace('\n', '\r\n').replace(
        '-----END CERTIFICATE-----\r\n', '-----END CERTIFICATE-----\r\n\r\n'),
}


@pytest.mark.parametrize('case', list(TAKEN))
def test_a_whole_chain_replaces_the_pair(served, monkeypatch, case):
    sent = {}

    def answer(csr):
        sent['body'] = TAKEN[case](csr)
        return sent['body']

    res = _order(monkeypatch, served, answer)

    assert res['success'] is True, res
    assert (served / 'cert.pem').read_bytes() == sent['body'].encode()
    assert app_module._unloadable(str(served / 'cert.pem'), str(served / 'key.pem')) is None
    assert acme.get_cert_info(str(served))['days_left'] in (89, 90)


def test_a_private_ca_that_issues_from_its_root_keeps_working(tmp_path, monkeypatch):
    # the leaf comes alone, its issuer is the root the clients hold: on the first
    # issuance and on every renewal after it
    ssl_dir = tmp_path / 'ssl'
    for _ in range(2):
        res = _order(monkeypatch, ssl_dir, lambda csr: _pem(CA.leaf(csr.public_key(), from_root=True)))
        assert res['success'] is True, res
        assert app_module._unloadable(str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem')) is None
        assert acme.get_cert_info(str(ssl_dir))['issuer'] == 'Test Root'

