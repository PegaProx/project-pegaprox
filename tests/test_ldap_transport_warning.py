"""The least protected LDAP configuration was the only one that said nothing.

`ldap_authenticate` warns about a missing certificate check - but only inside the branch
that runs when SSL or STARTTLS is on. With both off there is no TLS to check and no
warning either, and both default to off. Three binds follow on that connection; the middle
one carries the end user's password.

Not refused, because installs that run LDAP on a trusted segment on purpose exist and
breaking them is a release decision. Said out loud, because a silent default is not.

MK
"""
import logging

import pytest


def _run(monkeypatch, caplog, cfg):
    """Drive ldap_authenticate far enough to reach the transport decision, no further."""
    import pegaprox.utils.ldap as L

    base = {'enabled': True, 'server': 'ldap.example', 'port': 389,
            'bind_dn': 'cn=svc,dc=x', 'bind_password': 'secret',
            'use_ssl': False, 'use_starttls': False, 'verify_tls': False,
            'base_dn': 'dc=x', 'user_filter': '(uid={username})'}
    base.update(cfg)
    monkeypatch.setattr(L, 'get_ldap_settings', lambda: base)

    with caplog.at_level(logging.WARNING, logger='root'):
        try:
            L.ldap_authenticate('someone', 'pw')
        except Exception:
            pass          # no directory here; the warning fires before any socket
    return [r.getMessage() for r in caplog.records]


def test_a_fully_plaintext_config_says_so(monkeypatch, caplog):
    msgs = _run(monkeypatch, caplog, {'use_ssl': False, 'use_starttls': False})
    hit = [m for m in msgs if 'plaintext' in m]
    assert hit, 'the one configuration with no protection at all warned about nothing'
    assert 'ldap.example' in hit[0]


def test_it_names_the_user_password_not_just_our_own(monkeypatch, caplog):
    """An operator reading 'the bind password is exposed' may shrug. The point is that
    every password checked against the directory goes the same way."""
    msgs = _run(monkeypatch, caplog, {})
    hit = [m for m in msgs if 'plaintext' in m]
    assert hit and 'user password' in hit[0]


@pytest.mark.parametrize('cfg', [{'use_ssl': True}, {'use_starttls': True}])
def test_a_protected_transport_is_not_nagged(monkeypatch, caplog, cfg):
    """The mirror. Warning on a properly configured LDAPS link trains people to ignore it."""
    msgs = _run(monkeypatch, caplog, cfg)
    assert not [m for m in msgs if 'plaintext' in m]


def test_the_certificate_warning_still_works(monkeypatch, caplog):
    """The pre-existing warning must survive the new else-branch."""
    msgs = _run(monkeypatch, caplog, {'use_ssl': True, 'verify_tls': False})
    assert [m for m in msgs if 'certificate verification disabled' in m]
