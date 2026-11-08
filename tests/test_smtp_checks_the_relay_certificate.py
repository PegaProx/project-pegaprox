"""Mail goes out over TLS only to a relay whose certificate checks out.

smtplib without a context of its own encrypts but checks neither the certificate nor the
name of the relay, so anyone on the path could answer as the relay and read the SMTP
login and every alert. send_email now hands both SMTP_SSL and STARTTLS a context that
checks both, unless the setting smtp_verify_tls is False. A relay set up before the
setting existed reads as False until an admin turns the check on, so an upgrade does not
stop alert mail on a self-signed relay; a new setup reads as True. Once stored, the
stored value wins. The test mail takes the field from the form, or the saved value.
A real relay on loopback answers here, with TLS from the first byte or after STARTTLS.
MK Oct 2026
"""
import datetime
import ipaddress
import socket
import ssl
import threading

import pytest

from pegaprox.api.helpers import load_server_settings
from pegaprox.utils.email import send_email


def _cert(tmp_path, stem, cn, issuer=None, ca=False):
    """A cert for 127.0.0.1, without key identifiers (the way many internal CAs issue them)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_name, issuer_key = (issuer[0], issuer[1]) if issuer else (name, key)
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=2)))
    if ca:
        b = (b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, key_cert_sign=True, crl_sign=True,
                                          encipher_only=False, decipher_only=False), critical=True))
    else:
        b = b.add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
    cert = b.sign(issuer_key, hashes.SHA256())
    cf, kf = tmp_path / f'{stem}.pem', tmp_path / f'{stem}.key'
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cf), str(kf), (name, key)


class _Relay:
    """An SMTP relay on loopback that notes every command line it reads."""

    def __init__(self, cert, key, implicit):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.implicit = implicit
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.lines, self.mails = [], []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, conn):
        secure = self.implicit
        try:
            if secure:
                conn = self.ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile('rb')
            conn.sendall(b'220 relay ready\r\n')
            while True:
                line = f.readline()
                if not line:
                    return
                self.lines.append(line.decode(errors='replace').strip())
                cmd = line[:4].upper()
                if cmd == b'EHLO':
                    conn.sendall(b'250-relay\r\n' + (b'' if secure else b'250-STARTTLS\r\n')
                                 + b'250 AUTH PLAIN\r\n')
                elif cmd == b'STAR':
                    conn.sendall(b'220 go ahead\r\n')
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                    f = conn.makefile('rb')
                    secure = True
                elif cmd == b'AUTH':
                    conn.sendall(b'235 ok\r\n')
                elif cmd == b'DATA':
                    conn.sendall(b'354 go on\r\n')
                    body = b''
                    while not body.endswith(b'\r\n.\r\n'):
                        chunk = f.readline()
                        if not chunk:
                            return
                        body += chunk
                    self.mails.append(body)
                    conn.sendall(b'250 queued\r\n')
                elif cmd == b'QUIT':
                    conn.sendall(b'221 bye\r\n')
                    return
                else:
                    conn.sendall(b'250 ok\r\n')
        except (OSError, ssl.SSLError):
            return
        finally:
            conn.close()

    def saw_login(self):
        return any(ln.upper().startswith('AUTH') for ln in self.lines)

    def stop(self):
        self.sock.close()


@pytest.fixture
def self_signed(tmp_path):
    cert, key, _ = _cert(tmp_path, 'relay', 'relay')
    return cert, key


@pytest.fixture
def internal_ca(tmp_path, monkeypatch):
    """A relay cert from a CA the system trusts, both without key identifiers."""
    ca_cert, _ca_key, ca = _cert(tmp_path, 'ca', 'Internal Mail CA', ca=True)
    cert, key, _ = _cert(tmp_path, 'leaf', 'relay', issuer=ca)
    # OpenSSL reads this when the default context loads the system store
    monkeypatch.setenv('SSL_CERT_FILE', ca_cert)
    return cert, key


def _relay(request, cert, key, implicit):
    r = _Relay(cert, key, implicit)
    request.addfinalizer(r.stop)
    return r


def _smtp(relay, host='127.0.0.1', **extra):
    s = {'smtp_host': host, 'smtp_port': relay.port, 'smtp_user': 'alerts',
         'smtp_password': 'relay-pass', 'smtp_from_email': 'pp@corp.example',
         'smtp_tls': not relay.implicit, 'smtp_ssl': relay.implicit}
    s.update(extra)
    return s


@pytest.mark.parametrize('implicit', [False, True], ids=['starttls', 'implicit-tls'])
def test_a_relay_nobody_vouches_for_gets_neither_the_login_nor_the_mail(request, self_signed, implicit):
    relay = _relay(request, *self_signed, implicit)
    ok, err = send_email(['ops@corp.example'], 'disk full', 'body', smtp_settings=_smtp(relay))
    assert not ok
    assert 'certificate' in err.lower(), err
    assert not relay.saw_login() and relay.mails == []
    # counterproof: with the check turned off the same relay gets it, as before
    ok, err = send_email(['ops@corp.example'], 'disk full', 'body',
                         smtp_settings=_smtp(relay, smtp_verify_tls=False))
    assert ok, err
    assert relay.saw_login() and len(relay.mails) == 1


@pytest.mark.parametrize('implicit', [False, True], ids=['starttls', 'implicit-tls'])
def test_a_relay_from_a_trusted_internal_ca_is_taken_under_its_own_name_only(
        request, internal_ca, monkeypatch, implicit):
    real = ssl.create_default_context

    def like_python_313(*a, **kw):
        ctx = real(*a, **kw)
        ctx.verify_flags |= ssl.VERIFY_X509_STRICT
        return ctx
    monkeypatch.setattr(ssl, 'create_default_context', like_python_313)
    relay = _relay(request, *internal_ca, implicit)

    # the cert really is one the strict checks of 3.13 turn down
    probe = like_python_313()
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection(('127.0.0.1', relay.port), timeout=5) as raw:
            if implicit:
                probe.wrap_socket(raw, server_hostname='127.0.0.1')
            else:
                raw.recv(64)
                raw.sendall(b'EHLO t\r\n')
                raw.recv(256)
                raw.sendall(b'STARTTLS\r\n')
                raw.recv(64)
                probe.wrap_socket(raw, server_hostname='127.0.0.1')

    ok, err = send_email(['ops@corp.example'], 'disk full', 'body', smtp_settings=_smtp(relay))
    assert ok, err
    assert len(relay.mails) == 1
    # the cert is for 127.0.0.1, so a relay reached as another name is not the one meant
    seen = len(relay.lines)
    ok, err = send_email(['ops@corp.example'], 'disk full', 'body',
                         smtp_settings=_smtp(relay, host='localhost'))
    assert not ok and 'certificate' in err.lower(), err
    assert not any(ln.upper().startswith('AUTH') for ln in relay.lines[seen:])
    assert len(relay.mails) == 1


def test_the_setting_reads_off_for_a_relay_set_up_before_it_and_on_for_a_new_one(db):
    # nothing stored at all: a new install
    assert load_server_settings()['smtp_verify_tls'] is True
    # stored settings without a relay
    db.save_server_settings({'domain': 'pp.corp.example'})
    assert load_server_settings()['smtp_verify_tls'] is True
    # a relay from before the setting existed
    db.save_server_settings({'smtp_enabled': True, 'smtp_host': 'mail.corp.example'})
    assert load_server_settings()['smtp_verify_tls'] is False
    # once stored, the stored value wins either way
    db.save_server_setting('smtp_verify_tls', True)
    assert load_server_settings()['smtp_verify_tls'] is True
    db.save_server_setting('smtp_host', '')
    db.save_server_setting('smtp_verify_tls', False)
    assert load_server_settings()['smtp_verify_tls'] is False


def test_alert_mail_from_the_stored_settings_follows_the_setting(db, request, self_signed):
    relay = _relay(request, *self_signed, False)
    db.save_server_settings({'smtp_enabled': True, 'smtp_host': '127.0.0.1', 'smtp_port': relay.port,
                             'smtp_from_email': 'pp@corp.example', 'smtp_tls': True})
    # an existing relay keeps getting the alerts after the upgrade
    ok, err = send_email(['ops@corp.example'], 'disk full', 'body')
    assert ok, err
    assert len(relay.mails) == 1
    # and once the check is on, a relay it cannot check gets nothing
    db.save_server_setting('smtp_verify_tls', True)
    ok, err = send_email(['ops@corp.example'], 'disk full', 'body')
    assert not ok and 'certificate' in err.lower(), err
    assert len(relay.mails) == 1


def _audit(db):
    return [r['action'] for r in (db.query('SELECT action FROM audit_log ORDER BY id') or [])
            if r['action'] == 'settings.smtp_verify_tls']


def test_an_admin_reads_and_turns_the_check(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    seed.db.save_server_settings({'smtp_enabled': True, 'smtp_host': 'mail.corp.example'})
    r = admin.get('/api/settings/server')
    assert r.status_code == 200, r.data
    assert r.get_json()['smtp_verify_tls'] is False

    r = admin.post('/api/settings/server', json={'smtp_verify_tls': True})
    assert r.status_code == 200, r.data
    assert seed.db.get_server_setting('smtp_verify_tls') is True
    assert admin.get('/api/settings/server').get_json()['smtp_verify_tls'] is True
    assert _audit(seed.db) == ['settings.smtp_verify_tls']

    # the SMTP form without the field leaves it as it is
    r = admin.post('/api/settings/server', json={'smtp_host': 'mail2.corp.example', 'smtp_tls': True})
    assert r.status_code == 200, r.data
    assert admin.get('/api/settings/server').get_json()['smtp_verify_tls'] is True
    r = admin.post('/api/settings/server', json={'smtp_verify_tls': False})
    assert r.status_code == 200, r.data
    assert seed.db.get_server_setting('smtp_verify_tls') is False
    assert len(_audit(seed.db)) == 2


def test_the_test_mail_takes_the_field_from_the_form_or_the_saved_value(api, seed, request, self_signed):
    admin = api.as_user(seed.user('root', role='admin'))
    relay = _relay(request, *self_signed, False)
    form = {'email': 'ops@corp.example', 'smtp_host': '127.0.0.1', 'smtp_port': relay.port,
            'smtp_user': 'alerts', 'smtp_password': 'relay-pass',
            'smtp_from_email': 'pp@corp.example', 'smtp_tls': True, 'smtp_ssl': False}

    # a new install checks, so the self-signed relay is turned down
    r = admin.post('/api/settings/smtp/test', json=form)
    assert r.status_code == 400, r.data
    assert 'certificate' in r.get_json()['error'].lower()
    assert not relay.saw_login() and relay.mails == []
    assert admin.post('/api/settings/smtp/test', json=dict(form, smtp_verify_tls=True)).status_code == 400
    assert relay.mails == []

    # counterproof: the form turns it off, or the saved value does when the form has no field
    r = admin.post('/api/settings/smtp/test', json=dict(form, smtp_verify_tls=False))
    assert r.status_code == 200, r.data
    assert len(relay.mails) == 1
    seed.db.save_server_setting('smtp_verify_tls', False)
    r = admin.post('/api/settings/smtp/test', json=form)
    assert r.status_code == 200, r.data
    assert len(relay.mails) == 2
