"""The BMC reader connects to an address it vetted, not to whatever the name says next.

_validate_host() resolved the BMC name to refuse loopback, link-local and metadata, and
requests resolved it again to connect. A name that answers a LAN address to the checks
and 127.0.0.1 to the connect carried the stored Basic-auth credential to a service on
this host. The reader now resolves once, vets every answer and connects to those
addresses, with the name kept in Host. Verified https keeps the name: the certificate
check already defeats a rebind there.

NS Oct 2026
"""
import json
import socket

import pytest

import pegaprox.core.redfish as rf

NAME = 'bmc.example'
_real_getaddrinfo = socket.getaddrinfo


def _answer(ip):
    if ':' in ip:
        return (socket.AF_INET6, socket.SOCK_STREAM, 6, '', (ip, 0, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))


@pytest.fixture
def dns(monkeypatch):
    """dns(answers) - each lookup of NAME takes the next entry (a list of IPs); the last
    entry repeats. Returns the list of what each lookup was told."""
    def install(*answers):
        told = []

        def fake(host, *a, **kw):
            if host != NAME:
                return _real_getaddrinfo(host, *a, **kw)
            ips = answers[min(len(told), len(answers) - 1)]
            told.append(ips)
            return [_answer(ip) for ip in ips]
        monkeypatch.setattr(socket, 'getaddrinfo', fake)
        return told
    return install


class _Resp:
    def __init__(self, data, status=200):
        self._data, self.status_code, self.headers = data, status, {}

    def iter_content(self, n):
        yield json.dumps(self._data).encode()

    def close(self):
        pass


def _bmc(url):
    if url.endswith('/redfish/v1/Systems'):
        return _Resp({'Members': [{'@odata.id': '/redfish/v1/Systems/1'}]})
    if url.endswith('/redfish/v1/Systems/1'):
        return _Resp({'Status': {'Health': 'OK'}, 'Model': 'R650'})
    return _Resp({})


@pytest.fixture
def wire(monkeypatch):
    """requests.get as the network sees it: a name is resolved (again) at connect time.
    Records (address connected to, url, Host header)."""
    seen = []

    def fake_get(url, **kw):
        host = rf.urlparse(url).hostname
        try:
            addr = str(rf.ipaddress.ip_address(host))
        except ValueError:
            addr = socket.getaddrinfo(host, None)[0][4][0]
        seen.append((addr, url, (kw.get('headers') or {}).get('Host')))
        return _bmc(url)
    monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)
    return seen


def test_a_rebinding_name_never_carries_the_credential_to_loopback(dns, wire):
    dns(['10.0.0.5'], ['10.0.0.5'], ['127.0.0.1'])

    rf.read_node_bmc_redfish(NAME, 'root', 'secret', verify_ssl=False)

    assert all(addr != '127.0.0.1' for addr, _u, _h in wire), wire


def test_the_request_goes_to_the_vetted_address_with_the_name_in_host(dns, wire):
    dns(['10.0.0.5'])

    res = rf.read_node_bmc_redfish(NAME, 'root', 'secret', verify_ssl=False)

    assert res['available'] is True, res
    assert wire and all(u.startswith('https://10.0.0.5/redfish/v1/') for _a, u, _h in wire), wire
    assert all(h == NAME for _a, _u, h in wire), wire


def test_a_port_and_plain_http_are_kept(dns, wire):
    dns(['10.0.0.5'])
    rf.read_node_bmc_redfish(f'http://{NAME}:8080', 'root', 'secret')
    assert wire[0][1] == 'http://10.0.0.5:8080/redfish/v1/Systems' and wire[0][2] == f'{NAME}:8080'


def test_verified_https_keeps_the_name_for_the_certificate_check(dns, wire):
    dns(['10.0.0.5'])

    res = rf.read_node_bmc_redfish(NAME, 'root', 'secret', verify_ssl=True)

    assert res['available'] is True, res
    assert wire and all(u.startswith(f'https://{NAME}/') and h is None for _a, u, h in wire), wire


def test_an_address_literal_is_used_as_given(wire):
    rf.read_node_bmc_redfish('10.0.0.7', 'root', 'secret')
    assert wire and all(u.startswith('https://10.0.0.7/') and h is None for _a, u, h in wire)


def test_a_name_with_a_loopback_answer_is_refused_before_anything_is_sent(dns, wire):
    dns(['10.0.0.5', '127.0.0.1'])
    res = rf.read_node_bmc_redfish(NAME, 'root', 'secret')
    assert res == {'available': False, 'reason': 'BMC host not permitted'} and not wire


def test_the_next_vetted_address_is_tried_and_kept(dns, monkeypatch):
    """A dual-stack name whose first answer does not route: the reader moves on, as a
    resolver-order connect would, and stays on the address that answered."""
    dns(['fd00::5', '10.0.0.5'])
    tried = []

    def fake_get(url, **kw):
        tried.append(rf.urlparse(url).hostname)
        if rf.urlparse(url).hostname == 'fd00::5':
            raise rf.requests.exceptions.ConnectionError('no route to host')
        return _bmc(url)
    monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)

    res = rf.read_node_bmc_redfish(NAME, 'root', 'secret')

    assert res['available'] is True, res
    assert tried[:2] == ['fd00::5', '10.0.0.5'] and set(tried[2:]) == {'10.0.0.5'}, tried


def test_a_connect_error_names_the_bmc_not_the_address_it_resolved_to(dns, monkeypatch):
    """The reason reaches an admin.settings holder (the test route); it named the BMC
    before the pinning and must not turn into a resolver for internal names."""
    dns(['10.0.0.5'])

    def fake_get(url, **kw):
        raise rf.requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='{rf.urlparse(url).hostname}', port=443): Max retries exceeded")
    monkeypatch.setattr('pegaprox.core.redfish.requests.get', fake_get)

    res = rf.read_node_bmc_redfish(NAME, 'root', 'secret')

    assert res['available'] is False and '10.0.0.5' not in res['reason'] and NAME in res['reason'], res
