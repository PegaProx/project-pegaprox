# The certificate shown under Settings -> SSL: a certificate that names its hosts in the
# subjectAltName only (no CN, as ACME CAs issue them more and more) showed an empty
# subject. The subject is the first SAN name now, and every SAN name is listed.
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pegaprox.core.acme import get_cert_info


def _write(tmp_path, subject, sans):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Issuer'),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test CA')])
    b = (x509.CertificateBuilder().subject_name(x509.Name(subject)).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    (tmp_path / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(tmp_path)


def test_a_certificate_with_san_only_names_its_first_host(tmp_path):
    info = get_cert_info(_write(tmp_path, [], ['pegaprox.lab.example', 'pp.lab.example']))
    assert info['subject'] == 'pegaprox.lab.example'
    assert info['domains'] == ['pegaprox.lab.example', 'pp.lab.example']
    assert info['issuer'] == 'Test Issuer' and info['valid'] is True


def test_a_cn_still_wins_over_the_san(tmp_path):
    info = get_cert_info(_write(tmp_path, [x509.NameAttribute(NameOID.COMMON_NAME, 'old.example')],
                                ['new.example']))
    assert info['subject'] == 'old.example' and info['domains'] == ['new.example']


def test_a_certificate_without_san_lists_no_domains(tmp_path):
    info = get_cert_info(_write(tmp_path, [x509.NameAttribute(NameOID.COMMON_NAME, 'only.example')], []))
    assert info['subject'] == 'only.example' and info['domains'] == []
