"""LDAP connections must use transport security.

`ldap_authenticate` previously warned about plaintext LDAP but continued. With both
SSL and STARTTLS off, three binds follow on that connection; the middle one carries
the end user's password. The application now refuses plaintext LDAP connections and
requires either LDAPS or STARTTLS to be enabled.

Certificate verification is enforced by default but can be disabled for internal CAs.

MK
"""
import logging

import pytest


def _run(monkeypatch, caplog, cfg):
    """Drive ldap_authenticate far enough to reach the transport decision."""
    import pegaprox.utils.ldap as L

    base = {'enabled': True, 'server': 'ldap.example', 'port': 389,
            'bind_dn': 'cn=svc,dc=x', 'bind_password': '****',
            'use_ssl': False, 'use_starttls': False, 'verify_tls': False,
            'base_dn': 'dc=x', 'user_filter': '(uid={username})'}
    base.update(cfg)
    monkeypatch.setattr(L, 'get_ldap_settings', lambda: base)

    with caplog.at_level(logging.WARNING, logger='root'):
        result = L.ldap_authenticate('someone', 'pw')
    return result, [r.getMessage() for r in caplog.records]


def test_a_fully_plaintext_config_is_rejected(monkeypatch, caplog):
    """Plaintext LDAP is now refused, not just warned about."""
    result, msgs = _run(monkeypatch, caplog, {'use_ssl': False, 'use_starttls': False})
    assert 'error' in result, 'plaintext LDAP should be rejected'
    assert 'transport security required' in result['error'].lower()


def test_the_error_names_the_requirement(monkeypatch, caplog):
    """The error message must tell the operator what to enable."""
    result, msgs = _run(monkeypatch, caplog, {})
    assert 'error' in result
    assert 'LDAPS' in result['error'] or 'STARTTLS' in result['error']


@pytest.mark.parametrize('cfg', [{'use_ssl': True}, {'use_starttls': True}])
def test_a_protected_transport_is_accepted(monkeypatch, caplog, cfg):
    """LDAPS or STARTTLS allows the connection to proceed."""
    result, msgs = _run(monkeypatch, caplog, cfg)
    # The connection will fail (no real server), but it should not be rejected for transport security
    assert 'transport security required' not in result.get('error', '').lower()


def test_the_certificate_warning_still_works(monkeypatch, caplog):
    """Certificate verification warnings must survive the transport security check."""
    result, msgs = _run(monkeypatch, caplog, {'use_ssl': True, 'verify_tls': False})
    assert [m for m in msgs if 'certificate verification disabled' in m.lower()]
