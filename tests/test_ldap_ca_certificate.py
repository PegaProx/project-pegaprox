"""The LDAP settings take the CA certificate of the directory.

Certificate verification for LDAP was off by default because an internal AD CA is not in
the system trust store, and there was no way to hand PegaProx that CA. With the check off,
a machine on the network path can answer the binds itself and return any memberOf it
likes. ldap_ca_cert holds the CA as PEM text: checked when it is saved (a CA that does not
load is a 400 and is not stored), and while the check is on both places that build TLS,
the login and the test button, check the directory certificate against it. Without one
the check uses the system trust store as before.

The field goes out with every settings read and every backup, so only the certificate
blocks are kept, written out again; any other text in it, a private key above all, is
turned down. A restore runs the same check and leaves a failing CA out. And ldap3 follows
a referral on a connection of its own, built without the CA: with the check on, a
referral is not followed, without it nothing changes.

A small directory on loopback answers here over LDAPS and STARTTLS, once with a
certificate from the pasted CA and once with one from another CA. MK Nov 2026
"""
import datetime
import os
import socket
import ssl
import threading

import pytest

BASE_DN = 'DC=corp,DC=example'
ADMINS = 'CN=PegaProx Admins,OU=Groups,DC=corp,DC=example'
SVC_DN = 'CN=svc-pegaprox,OU=Service,DC=corp,DC=example'


# --- a CA, a certificate for localhost, and a directory that presents it ---------------------

def _issue(tmp, cn):
    """A CA called `cn` and a certificate for localhost it issued. Returns (ca_pem, cert, key)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    usage = x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                          crl_sign=True, encipher_only=False, decipher_only=False)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(usage, critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            # ldap3 matches DNS names only, so the directory is reached as localhost
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    stem = os.path.join(str(tmp), cn.replace(' ', '_'))
    with open(stem + '.crt', 'wb') as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
    with open(stem + '.key', 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode(), stem + '.crt', stem + '.key'


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _str(s):
    return _tlv(0x04, s.encode())


def _result(tag, code=0, extra=b''):
    return _tlv(tag, _tlv(0x0a, bytes([code])) + _str('') + _str('') + extra)


def _message(msgid, op):
    return _tlv(0x30, _tlv(0x02, msgid) + op)


def _read(f):
    tag = f.read(1)
    if not tag:
        return None, None
    first = f.read(1)[0]
    length = int.from_bytes(f.read(first & 0x7f), 'big') if first & 0x80 else first
    return tag[0], f.read(length)


class FakeDirectory:
    """Just enough of an LDAP server on loopback: binds, STARTTLS, a search for one user.

    TLS from the first byte (LDAPS) or after STARTTLS. Every bind request it reads is kept,
    password included, so a test can tell whether one reached it at all. With `refer` it
    answers every search with a referral to that URL instead."""

    def __init__(self, cert, key, ldaps, user='jdoe', groups=(ADMINS,), refer=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ldaps, self.user, self.groups, self.refer = ldaps, user, groups, refer
        self.binds = []
        self.plain_binds = []
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.sock.close()

    def _accept(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, conn):
        secure = self.ldaps
        try:
            if secure:
                conn = self.ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile('rb')
            while True:
                tag, body = _read(f)
                if tag is None:
                    return
                n = body[1]
                msgid, rest = body[2:2 + n], body[2 + n:]
                op = rest[0]
                if op == 0x60:          # bind
                    self.binds.append(rest)
                    if not secure:
                        self.plain_binds.append(rest)
                    conn.sendall(_message(msgid, _result(0x61)))
                elif op == 0x77:        # extended: STARTTLS is the only one asked for
                    conn.sendall(_message(msgid, _result(0x78, extra=_tlv(0x8a, b'1.3.6.1.4.1.1466.20037'))))
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                    f = conn.makefile('rb')
                    secure = True
                elif op == 0x63:        # search
                    if self.refer:
                        conn.sendall(_message(msgid, _result(0x65, code=10, extra=_tlv(0xa3, _str(self.refer)))))
                        continue
                    if BASE_DN.lower().encode() in rest.lower() and self.user.encode() in rest:
                        attrs = _tlv(0x30, _str('memberOf') + _tlv(0x31, b''.join(_str(g) for g in self.groups)))
                        dn = f'CN={self.user},OU=Users,{BASE_DN}'
                        conn.sendall(_message(msgid, _tlv(0x64, _str(dn) + _tlv(0x30, attrs))))
                    conn.sendall(_message(msgid, _result(0x65)))
                elif op == 0x42:        # unbind
                    return
                else:
                    conn.sendall(_message(msgid, _result(0x65, code=53)))
        except (OSError, ssl.SSLError, IndexError):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


@pytest.fixture
def pki(tmp_path):
    """The CA of the directory, and another one an impostor's certificate comes from."""
    ours = _issue(tmp_path, 'Corp Root CA')
    theirs = _issue(tmp_path, 'Other CA')
    return {'ca': ours[0], 'cert': ours[1:], 'other_ca': theirs[0], 'other_cert': theirs[1:]}


@pytest.fixture
def system_store(monkeypatch, tmp_path, pki):
    """The CA of the directory in the system trust store, as OpenSSL finds it (SSL_CERT_FILE)."""
    path = tmp_path / 'system-store.pem'
    path.write_text(pki['ca'])
    monkeypatch.setenv('SSL_CERT_FILE', str(path))
    return str(path)


@pytest.fixture
def directory(request, pki):
    """directory(ldaps, impostor=False, **kw) -> a running FakeDirectory, closed after the test."""
    made = []

    def _make(ldaps, impostor=False, **kw):
        cert = pki['other_cert'] if impostor else pki['cert']
        d = FakeDirectory(*cert, ldaps=ldaps, **kw)
        made.append(d)
        return d
    yield _make
    for d in made:
        d.close()


def ldap_settings(db, d, ca='', verify=True, ldaps=None, starttls=None):
    """Stored LDAP settings for directory `d`, the way the LDAP tab saves them."""
    ldaps = d.ldaps if ldaps is None else ldaps
    starttls = (not d.ldaps) if starttls is None else starttls
    db.save_server_settings({
        'ldap_enabled': True, 'ldap_server': 'localhost', 'ldap_port': d.port,
        'ldap_use_ssl': ldaps, 'ldap_use_starttls': starttls, 'ldap_verify_tls': verify,
        'ldap_ca_cert': ca, 'ldap_bind_dn': SVC_DN, 'ldap_bind_password': db._encrypt('svc-pw'),
        'ldap_base_dn': BASE_DN, 'ldap_admin_group': ADMINS, 'ldap_auto_create_users': True,
    })


# --- the check on save -------------------------------------------------------------------------

def test_a_ca_that_loads_is_fine_and_so_is_none(pki):
    from pegaprox.utils.ldap import ldap_ca_cert_error
    assert ldap_ca_cert_error(pki['ca']) is None
    assert ldap_ca_cert_error(pki['ca'] + pki['other_ca']) is None   # a root and an intermediate
    assert ldap_ca_cert_error('\r\n' + pki['ca'].replace('\n', '\r\n')) is None
    for empty in ('', '   \n', None):
        assert ldap_ca_cert_error(empty) is None


@pytest.mark.parametrize('bad,says', [
    ('not a certificate', 'besides the certificates'),
    ('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', 'could not be read'),
    (['-----BEGIN CERTIFICATE-----'], 'PEM text'),
    (42, 'PEM text'),
])
def test_what_does_not_load_as_a_ca_is_named(bad, says):
    from pegaprox.utils.ldap import ldap_ca_cert_error
    err = ldap_ca_cert_error(bad)
    assert err and says in err, err


def test_a_private_key_pasted_along_is_turned_down(pki, tmp_path):
    # ssl itself would load the certificate and skip the key; stored, the key would be in
    # every settings read and every backup
    from pegaprox.utils.ldap import ldap_ca_cert_error
    key = open(pki['cert'][1]).read()
    err = ldap_ca_cert_error(pki['ca'] + key)
    assert err and 'private key' in err, err


def _key_body(pki):
    lines = open(pki['cert'][1]).read().strip().splitlines()
    return '\n'.join(lines[1:-1])


@pytest.mark.parametrize('around', ['junk before', 'junk after', 'lower-case key', 'split words',
                                    'bare key body', 'another kind of block', 'a NUL byte'])
def test_nothing_but_certificates_goes_in(pki, around):
    from pegaprox.utils.ldap import ldap_ca_cert_clean
    key = open(pki['cert'][1]).read()
    value = {'junk before': 'see the wiki\n' + pki['ca'],
             'junk after': pki['ca'] + '\nthanks, ops\n',
             'lower-case key': pki['ca'] + key.replace('PRIVATE KEY', 'private key'),
             'split words': pki['ca'] + key.replace('PRIVATE KEY', 'PRIVATE\nKEY'),
             'bare key body': pki['ca'] + _key_body(pki),
             'another kind of block': pki['ca'] + key.replace('PRIVATE KEY', 'EC KEY'),
             'a NUL byte': pki['ca'] + '\x00'}[around]
    pem, err = ldap_ca_cert_clean(value)
    assert pem == '' and err, around
    if around in ('lower-case key', 'split words'):
        assert 'private key' in err, err
    else:
        assert 'besides the certificates' in err, err


def test_a_broken_block_next_to_a_good_one_is_turned_down(pki):
    from pegaprox.utils.ldap import ldap_ca_cert_error
    broken = '-----BEGIN CERTIFICATE-----\nMIIBAAAA\n-----END CERTIFICATE-----\n'
    assert 'could not be read' in ldap_ca_cert_error(pki['ca'] + broken)
    assert 'could not be read' in ldap_ca_cert_error(broken + pki['ca'])


def test_what_is_stored_is_the_blocks_written_out_again(admin, seed, pki):
    """Indented, with Windows line ends and a blank line between: stored as two clean blocks."""
    messy = '  ' + pki['ca'].replace('\n', '\r\n') + '\r\n\r\n\t' + pki['other_ca']
    assert admin.post('/api/settings/server', json={'ldap_ca_cert': messy}).status_code == 200
    stored = seed.db.get_server_setting('ldap_ca_cert')
    assert stored == pki['ca'].strip() + '\n' + pki['other_ca'].strip()
    assert admin.get('/api/settings/server').get_json()['ldap_ca_cert'] == stored


def test_a_whole_bundle_is_too_large(pki):
    from pegaprox.utils.ldap import LDAP_CA_CERT_MAX, ldap_ca_cert_error
    big = pki['ca'] * (LDAP_CA_CERT_MAX // len(pki['ca']) + 1)
    err = ldap_ca_cert_error(big)
    assert err and 'larger than' in err, err


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def test_the_ca_is_saved_and_read_back(admin, seed, pki):
    r = admin.post('/api/settings/server', json={'ldap_server': 'dc1.corp.example',
                                                 'ldap_ca_cert': '\n' + pki['ca'] + '\n\n'})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['ca'].strip()
    got = admin.get('/api/settings/server').get_json()
    assert got['ldap_ca_cert'] == pki['ca'].strip()
    # a save of the tab without the field leaves it alone, an empty one clears it
    assert admin.post('/api/settings/server', json={'ldap_port': 636}).status_code == 200
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['ca'].strip()
    assert admin.post('/api/settings/server', json={'ldap_ca_cert': ''}).status_code == 200
    assert admin.get('/api/settings/server').get_json()['ldap_ca_cert'] == ''


@pytest.mark.parametrize('bad', ['garbage', 'PRIVATE KEY'])
def test_a_bad_ca_is_a_400_and_nothing_of_the_save_is_stored(admin, seed, pki, bad):
    seed.db.save_server_settings({'ldap_server': 'dc1.corp.example', 'ldap_ca_cert': pki['ca']})
    value = 'garbage' if bad == 'garbage' else pki['ca'] + open(pki['cert'][1]).read()
    r = admin.post('/api/settings/server', json={'ldap_server': 'dc2.corp.example', 'ldap_ca_cert': value})
    assert r.status_code == 400, r.get_data(as_text=True)
    body = r.get_json()
    assert body['code'] == 'LDAP_CA_CERT_INVALID' and 'LDAP CA certificate' in body['error']
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['ca']
    assert seed.db.get_server_setting('ldap_server') == 'dc1.corp.example'


def test_the_ca_is_not_written_to_the_log(admin, pki, caplog):
    import logging
    with caplog.at_level(logging.DEBUG):
        assert admin.post('/api/settings/server', json={'ldap_server': 'dc1.corp.example',
                                                        'ldap_ca_cert': pki['ca']}).status_code == 200
    body = pki['ca'].splitlines()[1]
    assert not [r for r in caplog.records if body in r.getMessage()]


# --- what TLS is built from it ---------------------------------------------------------------

def test_the_tls_of_each_combination(pki):
    from pegaprox.utils.ldap import ldap_tls
    assert ldap_tls(False, True, pki['ca']) is None
    off = ldap_tls(True, False, pki['ca'])
    assert off.validate == ssl.CERT_NONE and off.ca_certs_data is None
    store = ldap_tls(True, True, '')
    assert store.validate == ssl.CERT_REQUIRED and store.ca_certs_data is None
    pinned = ldap_tls(True, True, '\n' + pki['ca'])
    assert pinned.validate == ssl.CERT_REQUIRED and pinned.ca_certs_data == pki['ca'].strip()


@pytest.fixture
def wire(monkeypatch):
    """Records the Tls each Server is built with; the connection goes nowhere."""
    import ldap3
    built = []

    class Server:
        def __init__(self, host, port=None, use_ssl=False, tls=None, **kw):
            built.append(tls)
            self.info = None

    class Connection:
        def __init__(self, server, **kw):
            pass

        def open(self):
            raise ldap3.core.exceptions.LDAPSocketOpenError('no directory in this test')

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, 'Server', Server)
    monkeypatch.setattr(ldap3, 'Connection', Connection)
    return built


@pytest.mark.parametrize('ldaps', [True, False])
def test_the_login_checks_against_the_saved_ca(db, wire, pki, ldaps):
    from pegaprox.utils.ldap import ldap_authenticate
    db.save_server_settings({'ldap_enabled': True, 'ldap_server': 'dc1.corp.example',
                             'ldap_use_ssl': ldaps, 'ldap_use_starttls': not ldaps,
                             'ldap_verify_tls': True, 'ldap_ca_cert': pki['ca'],
                             'ldap_base_dn': BASE_DN})
    ldap_authenticate('jdoe', 'pw')
    assert len(wire) == 1
    assert wire[0].validate == ssl.CERT_REQUIRED and wire[0].ca_certs_data == pki['ca'].strip()


def test_the_test_button_takes_the_ca_from_the_form_or_the_saved_settings(admin, seed, wire, pki):
    seed.db.save_server_settings({'ldap_server': 'dc1.corp.example', 'ldap_use_starttls': True,
                                  'ldap_verify_tls': True, 'ldap_ca_cert': pki['ca']})
    form = {'ldap_server': 'dc1.corp.example', 'ldap_use_starttls': True, 'ldap_verify_tls': True}
    admin.post('/api/settings/ldap/test', json=form)
    assert wire[-1].ca_certs_data == pki['ca'].strip()
    admin.post('/api/settings/ldap/test', json=dict(form, ldap_ca_cert=pki['other_ca']))
    assert wire[-1].ca_certs_data == pki['other_ca'].strip()
    # emptied in the form: the system trust store, as the save of that form would do
    admin.post('/api/settings/ldap/test', json=dict(form, ldap_ca_cert=''))
    assert wire[-1].validate == ssl.CERT_REQUIRED and wire[-1].ca_certs_data is None
    r = admin.post('/api/settings/ldap/test', json=dict(form, ldap_ca_cert='garbage'))
    assert r.status_code == 400 and r.get_json()['code'] == 'LDAP_CA_CERT_INVALID'
    assert len(wire) == 3


# --- against a directory ---------------------------------------------------------------------

@pytest.mark.parametrize('ldaps', [True, False], ids=['ldaps', 'starttls'])
def test_a_directory_with_an_internal_ca_signs_in_with_the_check_on(db, directory, pki, ldaps):
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(ldaps)
    ldap_settings(db, d, ca=pki['ca'])
    res = ldap_authenticate('jdoe', 'user-pw')
    assert res.get('success'), res
    assert res['role'] == 'admin'
    assert len(d.binds) >= 2 and not d.plain_binds   # the service account and the user, both over TLS


@pytest.mark.parametrize('ldaps', [True, False], ids=['ldaps', 'starttls'])
@pytest.mark.parametrize('ca', ['pasted', 'system store'])
def test_an_impostor_gets_no_password(db, directory, pki, ldaps, ca):
    """A machine on the path that answers with a certificate of its own is turned away
    before any bind, with the pasted CA and with the system trust store alike."""
    from pegaprox.utils.ldap import ldap_authenticate
    d = directory(ldaps, impostor=True)
    ldap_settings(db, d, ca=pki['ca'] if ca == 'pasted' else '')
    res = ldap_authenticate('jdoe', 'user-pw')
    assert not res.get('success')
    assert 'TLS/certificate error' in res['error'], res
    assert d.binds == []


# --- a restore -------------------------------------------------------------------------------

def _restore(client, server_settings, mode, dry_run=False):
    import io
    import json
    import pegaprox.api.settings as settings_api
    from test_sec_low_migrations import _ADMIN_PW, _BACKUP_PW
    data = {'version': 'test', 'export_date': '2026-11-01T10:00:00', 'server_settings': server_settings}
    blob = settings_api._encrypt_backup(json.dumps(data), _BACKUP_PW)
    r = client.post('/api/config/restore', content_type='multipart/form-data',
                    data={'user_password': _ADMIN_PW, 'backup_password': _BACKUP_PW, 'mode': mode,
                          'dry_run': 'true' if dry_run else 'false',
                          'backup_file': (io.BytesIO(blob), 'x.pegabackup')})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


@pytest.fixture
def restorer(api, seed):
    from test_sec_low_migrations import _admin_with_password
    return _admin_with_password(api, seed)


def _ca_errors(res):
    return [e for e in res['errors'] if 'LDAP CA certificate was not restored' in e]


@pytest.mark.parametrize('mode', ['merge', 'overwrite'])
def test_a_restore_leaves_a_ca_that_fails_out_and_says_so(restorer, seed, pki, mode):
    """A CA that does not load would fail every TLS login, and every later save of the tab
    that sends it back. The one held stays, the rest of the settings is restored."""
    seed.db.save_server_settings({'ldap_server': 'dc1.corp.example', 'ldap_ca_cert': pki['ca'].strip()})
    key = open(pki['cert'][1]).read()
    res = _restore(restorer, {'ldap_server': 'dc2.corp.example', 'ldap_ca_cert': pki['other_ca'] + key}, mode)
    assert res['restored'].get('server_settings') is True
    errors = _ca_errors(res)
    assert len(errors) == 1 and 'private key' in errors[0], res['errors']
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['ca'].strip()
    assert seed.db.get_server_setting('ldap_server') == 'dc2.corp.example'


def test_a_dry_run_names_it_and_changes_nothing(restorer, seed, pki):
    seed.db.save_server_settings({'ldap_server': 'dc1.corp.example', 'ldap_ca_cert': pki['ca'].strip()})
    res = _restore(restorer, {'ldap_ca_cert': 'not a certificate'}, 'overwrite', dry_run=True)
    assert len(_ca_errors(res)) == 1, res['errors']
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['ca'].strip()


def test_a_good_ca_is_restored_as_the_blocks_alone(restorer, seed, pki):
    res = _restore(restorer, {'ldap_ca_cert': '\r\n' + pki['other_ca'].replace('\n', '\r\n')}, 'overwrite')
    assert not _ca_errors(res), res['errors']
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['other_ca'].strip()


# --- referrals -------------------------------------------------------------------------------

@pytest.mark.parametrize('ldaps', [True, False], ids=['ldaps', 'starttls'])
@pytest.mark.parametrize('ca', ['pasted', 'system store'])
def test_with_the_check_on_a_referral_takes_no_bind_elsewhere(request, db, directory, pki, ldaps, ca, caplog):
    """ldap3 would follow the referral on a connection built without the CA: from LDAPS to an
    ldap:// URL in plain text, after STARTTLS with a STARTTLS that checks nothing. The
    machine it points to would get the service account and the user's password, and its
    memberOf would decide the role. The same with the CA in the system trust store."""
    import logging
    from pegaprox.utils.ldap import ldap_authenticate
    if ca == 'system store':
        request.getfixturevalue('system_store')
    elsewhere = directory(False, impostor=True)
    d = directory(ldaps, groups=(), refer=f'ldap://localhost:{elsewhere.port}/{BASE_DN}')
    ldap_settings(db, d, ca=pki['ca'] if ca == 'pasted' else '')
    with caplog.at_level(logging.WARNING):
        res = ldap_authenticate('jdoe', 'user-pw')
    assert res == {'error': 'User not found in LDAP'}, res
    assert elsewhere.binds == []
    said = [r.getMessage() for r in caplog.records if 'referred to' in r.getMessage()]
    assert said and f'localhost:{elsewhere.port}' in said[0] and 'Global Catalog' in said[0]


@pytest.mark.parametrize('ldaps,starttls', [(False, True), (False, False)], ids=['starttls', 'plain'])
def test_without_the_check_a_referral_is_followed_as_before(db, directory, pki, ldaps, starttls):
    """Installs that rely on referrals (a base DN at the forest root) and do not check the
    certificate keep following them: nothing the check would protect is lost there."""
    from pegaprox.utils.ldap import ldap_authenticate
    elsewhere = directory(False)
    d = directory(ldaps, groups=(), refer=f'ldap://localhost:{elsewhere.port}/{BASE_DN}')
    ldap_settings(db, d, verify=False, starttls=starttls)
    res = ldap_authenticate('jdoe', 'user-pw')
    assert res.get('success') and res['role'] == 'admin', res
    assert elsewhere.binds


def test_the_test_button_says_why_the_user_was_not_found(admin, seed, directory, pki):
    elsewhere = directory(False, impostor=True)
    d = directory(False, groups=(), refer=f'ldap://localhost:{elsewhere.port}/{BASE_DN}')
    ldap_settings(seed.db, d, ca=pki['ca'])
    res = admin.post('/api/settings/ldap/test', json={'ldap_bind_password': '********',
                                                      'test_username': 'jdoe'}).get_json()
    steps = {s['step']: s for s in res['steps']}
    assert steps['Transport']['status'] == 'ok'
    assert steps['Base DN accessible']['status'] == 'warning'
    assert 'referred to' in steps['User search: jdoe']['detail']
    assert 'Global Catalog' in res['hint'] and '3268' in res['hint']
    assert elsewhere.binds == []
