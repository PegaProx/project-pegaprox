# TLS bootstrap posture - app.py::_resolve_ssl_context().
#
# SP Jul 2026 (#633): if TLS was the intended posture and the cert could not be
# read or generated, PegaProx printed a WARNING and then bound PLAINTEXT HTTP on
# the port that was meant to be TLS. Every TLS client in front of it spoke TLS
# into a cleartext socket ("Invalid http version: '\x16\x03\x01...'") while the
# service reported itself healthy. That is a fail-open downgrade.
#
# Posture now: TLS unless behind a reverse proxy. If TLS cannot be established we
# refuse to start, unless plaintext is asked for explicitly with
# PEGAPROX_ALLOW_PLAINTEXT=1.
#
# The other half of the bug was diagnostics: both branches gated on
# os.path.exists(), which is False for a cert sitting in a directory the service
# user cannot search. So EACCES and ENOENT collapsed into one branch and the
# operator was told "No SSL certificates found" about files that were present and
# valid. Unreadable and missing must never read the same.

import logging
import os
import stat

import pytest

from pegaprox import app as app_module

pytestmark = pytest.mark.skipif(os.geteuid() == 0,
                                reason='root ignores file permissions, so no case here can fail closed')


@pytest.fixture
def certs(tmp_path):
    """A usable cert/key pair in its own directory, plus a chmod that gets undone."""
    d = tmp_path / 'ssl'
    d.mkdir()
    cert, key = d / 'cert.pem', d / 'key.pem'
    cert.write_bytes(b'-- not a real cert, nothing here parses it --\n')
    key.write_bytes(b'-- not a real key --\n')
    yield cert, key
    for p in (cert, key, d):        # so tmp_path teardown can still remove it
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass


def _resolve(cert, key, **kw):
    kw.setdefault('reverse_proxy', False)
    return app_module._resolve_ssl_context(cert_file=str(cert), key_file=str(key), **kw)


def test_reverse_proxy_means_plaintext_by_design(certs):
    # nginx/traefik terminates TLS, so plain HTTP on the bind is the intent
    cert, key = certs
    assert _resolve(cert, key, reverse_proxy=True) is None


def test_readable_pair_is_used(certs):
    cert, key = certs
    assert _resolve(cert, key) == (str(cert), str(key))


def test_unreadable_cert_refuses_to_start(certs, capsys):
    cert, key = certs
    os.chmod(cert, 0o000)
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    msg = str(e.value)
    assert 'Permission denied' in msg or 'EACCES' in msg
    assert str(cert) in msg                          # resolved path, not a relative guess
    # the certs are right there - neither the message nor the startup log may claim
    # otherwise, and generation must not have been attempted over them at all
    assert 'No SSL certificates found' not in msg
    out = capsys.readouterr().out
    assert 'No SSL certificates found' not in out
    assert 'Generating self-signed' not in out
    # and they were never truncated (stat works on a 0000 file, reading does not)
    assert os.stat(cert).st_size == len(b'-- not a real cert, nothing here parses it --\n')


def test_unreadable_key_refuses_to_start(certs):
    # cert readable, key not - still fail closed, not "missing"
    cert, key = certs
    os.chmod(key, 0o000)
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    assert str(key) in str(e.value)


def test_unsearchable_directory_refuses_to_start(certs, capsys):
    # the reported case: config/ssl is 0700 root:root, service user is not root.
    # os.path.exists() returns False here, which is what made the old code print
    # "No SSL certificates found" and then generate over a perfectly good cert.
    cert, key = certs
    os.chmod(cert.parent, 0o000)
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    assert 'No SSL certificates found' not in str(e.value)
    assert 'No SSL certificates found' not in capsys.readouterr().out


def test_error_names_the_directory_owner_and_mode(certs):
    cert, key = certs
    os.chmod(cert, 0o000)
    msg = str(pytest.raises(SystemExit, _resolve, cert, key).value)
    assert str(cert.parent) in msg
    assert 'mode=' in msg and 'owner=' in msg
    assert 'uid=' in msg                             # who we are, to compare against


def test_missing_pair_is_generated(certs):
    cert, key = certs
    cert.unlink()
    key.unlink()
    assert _resolve(cert, key, domain='pegaprox.test') == (str(cert), str(key))
    assert cert.read_bytes().startswith(b'-----BEGIN CERTIFICATE-----')
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_generation_failure_refuses_to_start(certs):
    cert, key = certs
    cert.unlink()
    key.unlink()
    os.chmod(cert.parent, 0o500)                     # readable, not writable
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    assert str(cert.parent) in str(e.value)


def test_missing_pyopenssl_refuses_to_start(certs, monkeypatch):
    cert, key = certs
    cert.unlink()
    key.unlink()
    monkeypatch.setitem(__import__('sys').modules, 'OpenSSL', None)
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    assert 'pyOpenSSL' in str(e.value)


def test_plaintext_needs_an_explicit_opt_in(certs, monkeypatch, caplog):
    # the escape hatch for anyone who really does want cleartext on that port
    cert, key = certs
    os.chmod(cert, 0o000)
    monkeypatch.setenv('PEGAPROX_ALLOW_PLAINTEXT', '1')
    with caplog.at_level(logging.ERROR):
        assert _resolve(cert, key) is None
    logged = '\n'.join(r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)
    assert 'PLAINTEXT' in logged.upper()             # ERROR level, and it says what it means
    assert 'PEGAPROX_ALLOW_PLAINTEXT' in logged


def test_config_guard_reads_the_owner(monkeypatch):
    # constants.py does its mkdir/chmod/copy at IMPORT time, so a root-run script
    # that just imports pegaprox.* used to create config/ssl as root and lock the
    # service user out of its own certs - the trigger behind #633.
    from pegaprox import constants

    class _St:
        def __init__(self, uid):
            self.st_uid = uid

    monkeypatch.setattr(constants.os, 'stat', lambda p: _St(os.geteuid()))
    assert constants._config_owned_by_us() is True

    monkeypatch.setattr(constants.os, 'stat', lambda p: _St(os.geteuid() + 1))
    assert constants._config_owned_by_us() is False

    def _gone(p):
        raise FileNotFoundError(2, 'No such file or directory')

    monkeypatch.setattr(constants.os, 'stat', _gone)
    assert constants._config_owned_by_us() is True     # fresh install, we create it


def test_migration_only_runs_when_we_own_config(tmp_path, monkeypatch):
    from pegaprox import constants
    legacy = tmp_path / 'legacy_cert.pem'
    legacy.write_bytes(b'the real cert')
    dst = tmp_path / 'config_cert.pem'
    monkeypatch.setattr(constants, 'SSL_CERT_FILE_LEGACY', str(legacy))
    monkeypatch.setattr(constants, 'SSL_CERT_FILE', str(dst))
    monkeypatch.setattr(constants, 'SSL_KEY_FILE_LEGACY', str(tmp_path / 'absent_key.pem'))
    monkeypatch.setattr(constants, 'SSL_KEY_FILE', str(tmp_path / 'absent_key_dst.pem'))
    monkeypatch.setattr(constants, 'BRANDING_DIR', str(tmp_path))

    monkeypatch.setattr(constants, 'CONFIG_OWNED_BY_US', False)
    constants._migrate_to_config()
    assert not dst.exists()                          # would have been ours, not the service's

    monkeypatch.setattr(constants, 'CONFIG_OWNED_BY_US', True)
    constants._migrate_to_config()
    assert dst.read_bytes() == b'the real cert'      # and it still migrates normally


@pytest.mark.parametrize('value', ['0', 'false', 'no', '', ' '])
def test_falsy_opt_in_still_fails_closed(certs, monkeypatch, value):
    cert, key = certs
    os.chmod(cert, 0o000)
    monkeypatch.setenv('PEGAPROX_ALLOW_PLAINTEXT', value)
    with pytest.raises(SystemExit):
        _resolve(cert, key)
