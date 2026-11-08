# TLS bootstrap posture - app.py::_resolve_ssl_context().
#
# MK Aug 2026 (#633): with TLS as the intended posture, a cert that could not be
# read or generated used to get a WARNING and then a PLAINTEXT HTTP bind on the
# TLS port - so anything speaking TLS to it hit a cleartext socket (the telltale
# "Invalid http version: '\x16\x03\x01...'") while systemd still saw the unit as
# healthy. Classic fail-open downgrade; these tests pin it shut.
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

# Only the cases that chmod a cert/dir to 0 need a non-root euid - root ignores the
# permission bits and they'd false-fail instead of proving anything. Marking just
# those (not the whole module) keeps the content/ENOENT/monkeypatched fail-closed
# cases running under a root CI container or `sudo pytest`, where they still hold.
needs_dac = pytest.mark.skipif(os.geteuid() == 0,
                               reason='root ignores file permissions, so a chmod-0 case cannot fail closed')


# A real (throwaway) self-signed pair, so the "readable pair is used" path actually
# validates a loadable cert - readable garbage used to be accepted here, which hid
# that a corrupt/mismatched cert only blew up later at load_cert_chain. CN=pegaprox.test.
_TEST_CERT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUT7Dt1U3cHt96VymjsmeaNppQ5jowDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNcGVnYXByb3gudGVzdDAeFw0yNjA3MzEyMjIzMTlaFw0z
NjA3MjgyMjIzMTlaMBgxFjAUBgNVBAMMDXBlZ2Fwcm94LnRlc3QwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQChDvA3fCDSiw6gSFtdzqXTpynhKZ9vmGpI
VSrg2uTRUxVMkzpSmcJPVlz5B+wR+Rv/CqyD6Q5X2dfOenMB74itiVOQYFUdP4pZ
z1/QuBOXp1lteESV7KyBaUmbo/sdxEG5y4Ac4DaRj0eG7TUve30Hk4cLnNAd+Sx+
eyALZBvLVBdzEgAQNYaaDpdoG2MxO5jdxPjGFIcmAIvfH2AxXBaFOWqoFxV+7+Sb
X3PvaGA7u1XwXeL9e2pdoKVJHpai8TTTWzVzp3IMe96T5qA0qIHbc9csbi8u9Z7m
mzvuoEMVLCFSQqIQxJV80Qs0o4RMdbFclPt3b/XCOBguNb7GJE9RAgMBAAGjUzBR
MB0GA1UdDgQWBBTtV3C4KqWyDPzbnFEj7QhjussJxTAfBgNVHSMEGDAWgBTtV3C4
KqWyDPzbnFEj7QhjussJxTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQCdC8crcswH66d5aOCnYqYc0/ZDa8BtHLB4RrG60G4VyJ2f6hNoEPd51Xud
yyCd116ENxdhThtrV8CzashhN/KpzCwegrJ7l8YuBp6znZ8YYwIzqdGlX5dKkySD
+BBEJhbvqeqmtzj8aqkkCoU+FErmbeOon30TMvbp5Pu0TvrXWLg+uPQWQsj5LE15
J+CbZmLPZHi7ehSYvKVVdIn29vl0tx6Y8UKZ9dRPTF7ykO88dQuApe/wpsAxXBRO
1VAsml89A0e03UDaexasO9to8A44xMtAFjFzO6PJrlpfPS0RYmmhjmWmddqQ2jWL
B6rYdKCzM/sS0ckYDCdMLQdR2VJm
-----END CERTIFICATE-----
"""
_TEST_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChDvA3fCDSiw6g
SFtdzqXTpynhKZ9vmGpIVSrg2uTRUxVMkzpSmcJPVlz5B+wR+Rv/CqyD6Q5X2dfO
enMB74itiVOQYFUdP4pZz1/QuBOXp1lteESV7KyBaUmbo/sdxEG5y4Ac4DaRj0eG
7TUve30Hk4cLnNAd+Sx+eyALZBvLVBdzEgAQNYaaDpdoG2MxO5jdxPjGFIcmAIvf
H2AxXBaFOWqoFxV+7+SbX3PvaGA7u1XwXeL9e2pdoKVJHpai8TTTWzVzp3IMe96T
5qA0qIHbc9csbi8u9Z7mmzvuoEMVLCFSQqIQxJV80Qs0o4RMdbFclPt3b/XCOBgu
Nb7GJE9RAgMBAAECggEAA5FHeY3SqEyTkVyo8XCqCasn6VM5CIlxaT1sYA4D3YMf
81Hw4R2DdABvZMYWe5DEsac0imN3gYiowsEW77xfjwB+DQelOwBKTzz3BrIydOcs
ZZlcDjoaLsT8mr73dAGsjFyumh/OoEtyg9GYnlRM67Bf4Gj5JIDSydEZCkeNug46
IF53v1a0pUXZ0BDGZTU6dfb6MNm2Mg7z+E4BFQVppWI/5qGS2m+FqtDc6/dvnTrf
7v7rFvYta3EgBlAF8mt7SF3nAyby9GW9kwdTrcZrmckZ7PD1rx0NluIj2FoNWWVi
Fk3ZNQVidTv/n1rpgXMCk65d1PvWj7eYKzWG2TvQtQKBgQDQoFkmLrpP0rGiHacc
rNh2u/Z7TwoB3FVIjZFqvd5Q5v/W0hxq7CsaHz9ABuE7QlYsbsxs+r0VOLB4G7s0
+AujzhCIZPkDDC3BexedgkFdp5W+3VoJVf6r7HbScYDgqXOc9B7Ru21lGxOPR+jL
uZPisVZhUdstQziHbzTmId2L6wKBgQDFoWp5Cl+HqwA+BSm3UyJ4voDtiSnYCTd0
l5HUO/i+8+PhZESWs/lEGyhrfQJtdCpZrBgtMyIyS1hRBDtN9LYfTWLE2tdx/y7n
pSQfAyc8nrqVCfhZzH1/Pp0GHhats5nOUCkwwrCwmJAg+9wiYNNXkfpSx/9+613f
m9iR2bXuswKBgF6Ku7uc41t3DH5915QcFABCj6EzoUJUmeVGGkb4Af5BoGC2WKBv
o9yzmlMmivzyw+Bg2YztV7B9PyM+1ehcG9JAeKeGsn2aEEYkxP/g3kRVxHt5Des7
KCy6/OHDA/dLcxQGYM0Elb+CtKtyl+FymLzbRlzV3nA1jTF6yMsdP6u/AoGAIdi7
O2+jXMDUkcqgkl0SkktOGWBcYjtx2+35c7exqkJqzLc3Z/f6wMdF7OLD/6rdde4b
VeJkAOkWfwmSfo9igYnnWH+CVmu1xMZroUQQ/DjTC6NhfT+gXqKCkgGlMKqJtOPV
qhwt1pDKXlvEH78lcuH1VSgbgckdkqZGOPRoTDECgYBX7NE52Pdf7lLmMfUCF5Nw
LqXpb7444TplGChtQ1W4l1BQ3WTbHE1/Rtw4Qz/z+wG+z4Q8ptuThhfF2FuhgHXB
0maCgXkWQxyNtXd3+CzmYuz3Hu7ZeiETt/A3hvSGxwqiSdFtMjMGIfVwxz5JTLpk
T+AMZHWbxZy/CJ9M7t7kGQ==
-----END PRIVATE KEY-----
"""


@pytest.fixture
def certs(tmp_path):
    """A usable cert/key pair in its own directory, plus a chmod that gets undone."""
    d = tmp_path / 'ssl'
    d.mkdir()
    cert, key = d / 'cert.pem', d / 'key.pem'
    cert.write_bytes(_TEST_CERT_PEM)
    key.write_bytes(_TEST_KEY_PEM)
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


def test_corrupt_cert_refuses_to_start(certs, capsys):
    # readable != loadable: a present-but-garbage cert used to sail through and then
    # crash at load_cert_chain with a raw ssl.SSLError. It must fail closed HERE, with
    # a reason, and must NOT be mistaken for a missing cert.
    cert, key = certs
    cert.write_bytes(b'-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n')
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    msg = str(e.value)
    assert 'do not load' in msg
    assert 'No SSL certificates found' not in msg
    assert 'Generating self-signed' not in capsys.readouterr().out


def test_half_present_pair_refuses_to_start(certs):
    # cert present, key genuinely missing (ENOENT): regenerating would clobber the
    # surviving cert, so refuse and name the missing half instead of generating.
    cert, key = certs
    key.unlink()
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    assert str(key) in str(e.value)


@needs_dac
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
    assert os.stat(cert).st_size == len(_TEST_CERT_PEM)


@needs_dac
def test_unreadable_key_refuses_to_start(certs):
    # cert readable, key not - still fail closed, not "missing"
    cert, key = certs
    os.chmod(key, 0o000)
    with pytest.raises(SystemExit) as e:
        _resolve(cert, key)
    assert str(key) in str(e.value)


@needs_dac
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


@needs_dac
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


@needs_dac
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


@needs_dac
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


@needs_dac
@pytest.mark.parametrize('value', ['0', 'false', 'no', '', ' '])
def test_falsy_opt_in_still_fails_closed(certs, monkeypatch, value):
    cert, key = certs
    os.chmod(cert, 0o000)
    monkeypatch.setenv('PEGAPROX_ALLOW_PLAINTEXT', value)
    with pytest.raises(SystemExit):
        _resolve(cert, key)
