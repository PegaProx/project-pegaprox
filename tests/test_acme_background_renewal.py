# What a renewal by the background thread leaves for an admin to see.
#
# The thread renewed and said so in two INFO lines, and a production start logs from
# WARNING up, so nothing showed, the audit log had no entry (a renewal from the settings
# page writes one) and the status read the pair on disk, which looked renewed while the
# listener served the old one. A renewal is audited now, the status says whether the
# listeners serve the pair on disk, and a renewed pair they did not take up is said at
# WARNING.
import datetime
import logging
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pegaprox import app as app_module
from pegaprox.utils import served_pair

DOMAIN = 'pp.example.com'


def _install(where, days, broken=False):
    """Write a pair for DOMAIN the way the ACME code does, the key first."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name)
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA')]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .sign(key, hashes.SHA256()))
    if broken:
        key = ec.generate_private_key(ec.SECP256R1())
    app_module._write_atomic(str(where / 'key.pem'), key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o600)
    app_module._write_atomic(str(where / 'cert.pem'), cert.public_bytes(serialization.Encoding.PEM), 0o644)


@pytest.fixture
def ssl_dir(tmp_path, monkeypatch):
    where = tmp_path / 'ssl'
    where.mkdir()
    _install(where, 19)
    monkeypatch.setattr(served_pair, '_listeners', [])
    monkeypatch.setattr(app_module, 'SSL_DIR', str(where))
    monkeypatch.setattr(app_module, 'SSL_CERT_FILE', str(where / 'cert.pem'))
    return where


@pytest.fixture
def renewal(ssl_dir, monkeypatch):
    """One round of the renewal thread against a CA that hands out a pair; returns the
    audit entries it wrote."""
    import pegaprox.api.helpers as helpers
    import pegaprox.core.acme as acme
    import pegaprox.utils.audit as audit

    audited = []
    monkeypatch.setattr(helpers, 'load_server_settings', lambda: {
        'acme_enabled': True, 'domain': DOMAIN, 'acme_email': 'ops@example.com'})
    monkeypatch.setattr(helpers, 'acme_dns_config_from_settings', lambda settings: {})
    monkeypatch.setattr(audit, 'log_audit', lambda *a, **kw: audited.append(a))

    def run(broken=False):
        def renew(domain, email, where, **kw):
            _install(pathlib.Path(where), 90, broken=broken)
            return True
        monkeypatch.setattr(acme, 'check_and_renew', renew)
        app_module._acme_renewal_check()
        return audited
    return run


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def test_a_background_renewal_is_audited_and_served(ssl_dir, renewal, caplog):
    served_pair.ServedPair(str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem'))
    caplog.set_level(logging.INFO)

    audited = renewal()

    assert [a[:2] for a in audited] == [('system', 'settings.acme_renewed')]
    assert f'Certificate renewed for {DOMAIN}, expires ' in audited[0][2]
    assert 'Not served' not in audited[0][2]
    assert _warnings(caplog) == []
    assert served_pair.serves(str(ssl_dir / 'cert.pem')) is True


def test_a_renewed_pair_the_listener_did_not_take_is_said_at_warning(ssl_dir, renewal, caplog):
    served_pair.ServedPair(str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem'))
    caplog.set_level(logging.WARNING)

    audited = renewal(broken=True)

    assert [a[:2] for a in audited] == [('system', 'settings.acme_renewed')]
    assert 'Not served yet, it does not load' in audited[0][2]
    said = [m for m in _warnings(caplog) if m.startswith('[ACME]')]
    assert len(said) == 1 and 'previous one is still served' in said[0], _warnings(caplog)


def test_a_listener_that_keeps_its_pair_asks_for_a_restart(ssl_dir, renewal, caplog, monkeypatch):
    # a listener that cannot take a pair up (the files load, it just does not follow them)
    listener = served_pair.ServedPair(str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem'))
    monkeypatch.setattr(listener, 'refresh', lambda report=False: None)
    caplog.set_level(logging.WARNING)

    audited = renewal()

    assert 'Not served yet, restart PegaProx to serve it' in audited[0][2]
    assert any('restart PegaProx to serve it' in m for m in _warnings(caplog))


def test_without_a_tls_listener_a_renewal_is_audited_quietly(ssl_dir, renewal, caplog):
    # behind a reverse proxy this process serves no TLS, nothing to take up
    caplog.set_level(logging.WARNING)
    audited = renewal()
    assert len(audited) == 1 and 'Not served' not in audited[0][2]
    assert _warnings(caplog) == []


def test_the_status_says_whether_the_pair_on_disk_is_served(api, seed, ssl_dir, monkeypatch):
    import pegaprox.api.settings as settings_mod

    monkeypatch.setattr(settings_mod, 'SSL_DIR', str(ssl_dir))
    monkeypatch.setattr(settings_mod, 'SSL_CERT_FILE', str(ssl_dir / 'cert.pem'))
    listener = served_pair.ServedPair(str(ssl_dir / 'cert.pem'), str(ssl_dir / 'key.pem'))
    admin = api.as_user(seed.user('root', role='admin', tenant_id='default'))

    def status():
        r = admin.get('/api/settings/acme/status')
        assert r.status_code == 200, r.get_data(as_text=True)
        body = r.get_json()
        return body['cert']['days_left'], body['cert_served'], body['restart_required'], body['cert_error']

    assert status() == (18, True, False, '')

    # the pair on disk does not load: the old one is served, and a restart would refuse it
    _install(ssl_dir, 60, broken=True)
    days, served, restart, error = status()
    assert (days, served, restart) == (59, False, False)
    assert error

    _install(ssl_dir, 90)
    assert status() == (89, True, False, '')

    # a listener that kept its pair although the one on disk loads needs the restart
    monkeypatch.setattr(listener, 'refresh', lambda report=False: None)
    _install(ssl_dir, 45)
    assert status() == (44, False, True, '')
