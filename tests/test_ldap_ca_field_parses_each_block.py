"""Each block of the LDAP CA field is one certificate, and reading the field takes linear time.

An empty BEGIN/END CERTIFICATE block decoded to no bytes, and ssl takes empty CA data for
none at all: the save stored it, and every TLS login then failed on the stored text. Each
block is parsed as one certificate now, so an empty block, two certificates run together
in one block or a certificate with bytes after it are turned down.

The block pattern was '(.*?)' between the markers, which tries every END from every BEGIN:
a field of BEGIN markers alone (64 KB is room for about 2400) held the gevent hub for more
than a second on each save. The body is base64 and whitespace now, so no match runs on
over the next marker. MK Nov 2026
"""
import base64
import time

import pytest

from test_ldap_ca_certificate import pki  # noqa: F401 (fixture)

EMPTY = '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----'


@pytest.fixture
def admin(api, seed):
    return api.as_user(seed.user('root', role='admin'))


def _der(pem):
    return base64.b64decode(''.join(pem.strip().splitlines()[1:-1]))


def _block(der):
    body = base64.b64encode(der).decode()
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(body[i:i + 64] for i in range(0, len(body), 64)) \
        + '\n-----END CERTIFICATE-----'


@pytest.mark.parametrize('where', ['alone', 'after a good one', 'before a good one'])
def test_an_empty_block_is_turned_down(pki, where):
    from pegaprox.utils.ldap import ldap_ca_cert_clean
    value = {'alone': EMPTY, 'after a good one': pki['ca'] + EMPTY,
             'before a good one': EMPTY + '\n' + pki['ca']}[where]
    pem, err = ldap_ca_cert_clean(value)
    assert pem == '' and 'could not be read' in err, (where, err)


def test_an_empty_block_never_reaches_the_store(admin, seed, pki):
    seed.db.save_server_settings({'ldap_server': 'dc1.corp.example', 'ldap_ca_cert': pki['ca'].strip()})
    r = admin.post('/api/settings/server', json={'ldap_ca_cert': pki['ca'] + '\n' + EMPTY})
    assert r.status_code == 400 and r.get_json()['code'] == 'LDAP_CA_CERT_INVALID'
    assert seed.db.get_server_setting('ldap_ca_cert') == pki['ca'].strip()


@pytest.mark.parametrize('what', ['two certificates in one block', 'bytes after the certificate'])
def test_a_block_is_one_certificate(pki, what):
    from pegaprox.utils.ldap import ldap_ca_cert_clean
    der = _der(pki['ca'])
    extra = _der(pki['other_ca']) if what.startswith('two') else b'\x00' * 16
    pem, err = ldap_ca_cert_clean(_block(der + extra))
    assert pem == '' and 'could not be read' in err, err
    # each on its own is fine, and is stored as it came
    assert ldap_ca_cert_clean(_block(der)) == (pki['ca'].strip(), None)


def test_a_block_with_headers_in_it_is_text_besides_the_certificates(pki):
    from pegaprox.utils.ldap import ldap_ca_cert_error
    with_header = pki['ca'].replace('-----\n', '-----\nProc-Type: 4,ENCRYPTED\n\n', 1)
    assert 'besides the certificates' in ldap_ca_cert_error(with_header)


@pytest.mark.parametrize('fill', ['BEGIN markers', 'BEGIN markers and base64', 'END markers'])
def test_a_field_full_of_markers_is_read_in_linear_time(fill):
    """No END after them: each BEGIN made the old pattern scan to the end of the field."""
    from pegaprox.utils.ldap import LDAP_CA_CERT_MAX, ldap_ca_cert_clean
    unit = {'BEGIN markers': '-----BEGIN CERTIFICATE-----',
            'BEGIN markers and base64': '-----BEGIN CERTIFICATE-----\nAAAA\n',
            'END markers': '-----END CERTIFICATE-----'}[fill]
    value = unit * (LDAP_CA_CERT_MAX // len(unit))
    assert len(value) <= LDAP_CA_CERT_MAX
    started = time.monotonic()
    pem, err = ldap_ca_cert_clean(value)
    took = time.monotonic() - started
    assert err and pem == ''
    assert took < 0.25, f'{took:.3f}s for {fill}'


def test_a_field_of_many_good_blocks_is_still_quick(pki):
    from pegaprox.utils.ldap import LDAP_CA_CERT_MAX, ldap_ca_cert_clean
    value = '\n'.join([pki['ca'].strip()] * (LDAP_CA_CERT_MAX // (len(pki['ca']) + 1)))
    started = time.monotonic()
    pem, err = ldap_ca_cert_clean(value)
    assert err is None and pem.count('BEGIN CERTIFICATE') == value.count('BEGIN CERTIFICATE')
    assert time.monotonic() - started < 1.0
