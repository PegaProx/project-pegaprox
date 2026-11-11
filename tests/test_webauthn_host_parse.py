"""WebAuthn reads a bracketed IPv6 host whole.

_effective_host() dropped the port with split(':')[0]. For 'name:port' and
'1.2.3.4:port' that is right; for '[::1]:5000' it left '[' and for
'[2001:db8::1]:5000' it left '[2001'. Neither is an IP literal, so the check that
answers "open PegaProx by its hostname" (ip_literal_host) never fired: register and
sign-in handed the browser an rpId of '[', which it refuses with a bare
SecurityError, and /api/webauthn/available called that host usable. The same cut
applied to an X-Forwarded-Host from a trusted proxy.

Both now go through urlsplit, and a value it cannot read (an unclosed bracket)
counts as no host at all.

MK
"""
import pytest

import pegaprox.api.webauthn as wa

# a client that is no proxy, so the Host header is what counts
CLIENT = {'REMOTE_ADDR': '203.0.113.9'}


def _host(api, value):
    with api.app.test_request_context('/', headers={'Host': value}, environ_base=CLIENT):
        return wa._effective_host()


def _available(api, **headers):
    r = api.anon().get('/api/webauthn/available', headers=headers)
    assert r.status_code == 200, r.status_code
    return r.get_json()


def test_the_host_is_read_without_its_port(api):
    want = {
        '[::1]:5000': '::1',
        '[::1]': '::1',
        '[2001:db8::1]:5000': '2001:db8::1',
        '[2001:db8::1]': '2001:db8::1',
        # and what worked before still does
        'pegaprox.local:5000': 'pegaprox.local',
        'PegaProx.Local': 'pegaprox.local',
        'localhost:5000': 'localhost',
        '10.0.0.1:5000': '10.0.0.1',
    }

    assert {value: _host(api, value) for value in want} == want


@pytest.mark.parametrize('host', ['[::1]:5000', '[2001:db8::1]', '[2001:db8::1]:5000'])
def test_an_ipv6_host_is_reported_as_unusable(api, host):
    body = _available(api, Host=host)

    assert body['host_usable'] is False, body
    assert body['host_reason'] == 'ip_literal'


@pytest.mark.parametrize('xfh', ['[2001:db8::1]:443', '[2001:db8::1]:443, edge.internal'])
def test_an_ipv6_host_forwarded_by_a_trusted_proxy(api, xfh):
    from pegaprox.utils.audit import _is_trusted_proxy
    assert _is_trusted_proxy('127.0.0.1'), 'the test client must count as a proxy here'

    body = _available(api, **{'Host': 'pegaprox.local', 'X-Forwarded-Host': xfh})

    assert body['host'] == '2001:db8::1', body
    assert body['host_usable'] is False


def test_registering_from_an_ipv6_host_gets_the_hostname_hint(api, seed):
    if not wa.FIDO2_AVAILABLE:
        pytest.skip('fido2 is not installed')
    user = seed.user('keyuser', role='user')

    r = api.as_user(user).post('/api/webauthn/register/begin', json={},
                               headers={'Host': '[::1]:5000', 'Origin': 'http://[::1]:5000'})

    body = r.get_json()
    assert r.status_code == 400, (r.status_code, body)
    assert body['code'] == 'ip_literal_host'
    assert body['current_host'] == '::1'


def test_an_unclosed_bracket_is_no_host(api):
    # in a request context, the test client itself cannot build a URL from this Host
    with api.app.test_request_context('/api/webauthn/available', headers={'Host': '[::1'},
                                      environ_base=CLIENT):
        body = wa.is_available().get_json()
        rp, err = wa._get_rp_or_error()

    assert body['host'] == '' and body['host_usable'] is False, body
    assert rp is None and err[1] == 400
