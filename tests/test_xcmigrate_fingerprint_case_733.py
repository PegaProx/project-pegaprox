# #733 — cross-cluster migrate handed PVE a LOWERCASE cert fingerprint, and PVE compares the
# fingerprint it is given as a raw hash key: PVE::APIClient::LWP does `$fingerprint->{cache}->{$fp}`
# with no uc()/lc(), and the $fp it builds comes from Net::SSLeay::X509_get_fingerprint, which
# formats with "%02X:". So a lowercase fingerprint parses (pve-fingerprint-sha256 accepts
# [A-Fa-f0-9]) but never matches — remote_migrate aborts on the cert check and PVE answers with a
# bare {"data":null}/500, the real reason swallowed. Nothing in the log says "fingerprint".
#
# The invariant: whatever we put in target-endpoint's fingerprint= must be PVE's own rendering,
# i.e. colon-separated UPPERCASE hex.

import hashlib
import socket
import ssl
import types

from pegaprox.core.manager import PegaProxManager


# A stand-in DER blob — get_cluster_fingerprint only ever hashes these bytes.
CERT_DER = b'\x30\x82\x01\x0a\x02\x82\x01\x01\x00#733 not a real certificate'
EXPECTED_HEX = hashlib.sha256(CERT_DER).hexdigest()
EXPECTED_FP = ':'.join(EXPECTED_HEX[i:i + 2].upper() for i in range(0, len(EXPECTED_HEX), 2))


class _FakeTLSSocket:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeercert(self, binary_form=False):
        return CERT_DER


class _FakeContext:
    check_hostname = True
    verify_mode = None

    def wrap_socket(self, sock, server_hostname=None):
        return _FakeTLSSocket()


# RFC 5737 TEST-NET-1, reserved for documentation and guaranteed never to be a real host.
# Nothing here is dialed — the socket/ssl calls are stubbed below — but if that stubbing ever
# silently stops applying, a reserved address fails closed instead of connecting to a stranger.
DOC_HOST = '192.0.2.14'
DOC_HOST_ALT = '192.0.2.9'


def _manager(monkeypatch, host=DOC_HOST):
    """A stub self for the unbound method — it touches only these three attributes."""
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **kw: _FakeTLSSocket())
    monkeypatch.setattr(ssl, 'create_default_context', lambda *a, **kw: _FakeContext())
    return types.SimpleNamespace(
        is_connected=True,
        config=types.SimpleNamespace(host=host),
        logger=types.SimpleNamespace(error=lambda *a, **kw: None),
    )


def test_fingerprint_is_uppercase_colon_hex(monkeypatch):
    result = PegaProxManager.get_cluster_fingerprint(_manager(monkeypatch))

    assert result['success'] is True
    assert result['fingerprint'] == EXPECTED_FP


def test_fingerprint_is_not_lowercase(monkeypatch):
    # The exact #733 regression: same digest, wrong case, PVE's lookup misses.
    lowercase = ':'.join(EXPECTED_HEX[i:i + 2] for i in range(0, len(EXPECTED_HEX), 2))
    result = PegaProxManager.get_cluster_fingerprint(_manager(monkeypatch))

    assert result['fingerprint'] != lowercase
    assert result['fingerprint'].upper() == result['fingerprint']


def test_fingerprint_shape_matches_pve_format(monkeypatch):
    # pve-fingerprint-sha256: 32 colon-separated hex octets.
    fp = PegaProxManager.get_cluster_fingerprint(_manager(monkeypatch))['fingerprint']
    octets = fp.split(':')

    assert len(octets) == 32
    assert all(len(o) == 2 and set(o) <= set('0123456789ABCDEF') for o in octets)


def test_host_is_reported_alongside(monkeypatch):
    # The endpoint pairs host= with fingerprint= — the source node dials this host, so a
    # migration diagnosis needs both together (see the diag line in api/vms.py).
    result = PegaProxManager.get_cluster_fingerprint(_manager(monkeypatch, host=DOC_HOST_ALT))

    assert result['host'] == DOC_HOST_ALT
    assert result['port'] == 8006
