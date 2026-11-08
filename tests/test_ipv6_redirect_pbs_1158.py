"""IPv6 literals on the http->https redirect and on a PBS server (#1158).

Two places took an IPv6 address apart at its colons:

- the port-80 redirect server split the Host header on the last ':', so a browser that
  opened http://[2001:db8::10]/ was sent to "https://[2001:db8::5000/". The redirect on the
  HTTPS port had its own, different parser. Both now read the header through
  app._host_for_location, which keeps "[addr]" whole only when addr is a real IPv6
  address and otherwise falls back to localhost, the way a malformed name always did.
- PBSManager.base_url put a bare IPv6 host into the URL ("https://2001:db8::10:8007/..."),
  which requests refuses to parse, so an IPv6-only PBS never connected.

The PBS host itself stays bare: the format check, the link-local refusal and paramiko see
the same string, only the URL text carries brackets.

Everything here runs offline: the redirect server gets a fake socket module, the PBS
session a recording adapter, paramiko a fake client.
"""
import ast
import os
import socket
import types
from urllib.parse import urlsplit

import pytest
import requests

import pegaprox.app as app_mod
from pegaprox.core import pbs as pbs_mod
from pegaprox.core.pbs import PBSManager, pbs_target_refusal

V6 = '2001:db8::10'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# -- the Host header parser ----------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    ('[2001:db8::10]', '[2001:db8::10]'),
    ('[2001:db8::10]:80', '[2001:db8::10]'),
    ('  [2001:db8::10]:8443 ', '[2001:db8::10]'),
    ('[::1]', '[::1]'),
    ('[::ffff:192.0.2.1]:80', '[::ffff:192.0.2.1]'),
    ('[2001:db8::10]:', '[2001:db8::10]'),
    # names and IPv4 exactly as before
    ('pegaprox.example', 'pegaprox.example'),
    ('pegaprox.example:80', 'pegaprox.example'),
    ('192.0.2.5:8080', '192.0.2.5'),
    ('', ''),
    (None, ''),
])
def test_the_host_part_of_a_host_header(value, expected):
    assert app_mod._host_for_location(value) == expected


@pytest.mark.parametrize('value', [
    '[evil.example]',                   # no IPv6 address inside
    '[evil.example]:80',
    '[2001:db8::10]evil.example',       # anything after the bracket but a port
    '[2001:db8::10].evil.example',
    '[2001:db8::10]:80@evil.example',
    '[2001:db8::10]:8o',
    '[2001:db8::10]:123456',
    '[2001:db8::10],[2001:db8::11]',    # a folded second Host
    '[2001:db8::10',                    # no closing bracket
    '[fe80::1%eth0]',                   # zone ids never reach the Location
    '[fe80::1%25eth0]:80',
    '[2001:db8::10]]',
    '[]',
])
def test_a_bracketed_host_that_is_no_ipv6_address_gives_nothing(value):
    assert app_mod._host_for_location(value) == ''


def test_both_redirect_handlers_read_the_host_through_the_same_parser():
    """The port-80 server and the plain-HTTP branch of the HTTPS port answered the same
    Host header differently. The second one lives inside _start_gevent_server, so the
    wiring is checked in the source; its behaviour is the parser's, tested above, and the
    non-IPv6 path runs end to end in test_redirect_head_deadline."""
    with open(os.path.join(ROOT, 'pegaprox', 'app.py'), encoding='utf-8') as fh:
        tree = ast.parse(fh.read())
    users = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                        and call.func.id == '_host_for_location'):
                    users.add(node.name)
    assert {'_start_http_redirect', '_handle_http_redirect'} <= users


# -- the port-80 redirect server, end to end on a fake socket ------------------------------

class _Stop(BaseException):
    """Ends the accept loop; BaseException so the server's own handlers let it through."""


class _Client:
    def __init__(self, raw):
        self.raw = raw
        self.sent = b''

    def settimeout(self, t):
        pass

    def recv(self, n):
        return self.raw[:n]

    def sendall(self, data):
        self.sent += data

    def close(self):
        pass


class _Listener:
    def __init__(self, clients):
        self.clients = list(clients)

    def setsockopt(self, *a):
        pass

    def bind(self, addr):
        pass

    def listen(self, n):
        pass

    def settimeout(self, t):
        pass

    def accept(self):
        if not self.clients:
            raise _Stop()
        return self.clients.pop(0), ('192.0.2.7', 40000)


def _redirect(monkeypatch, host_line, https_port=5000, domain='', path='/dashboard'):
    head = f'GET {path} HTTP/1.1\r\n'
    if host_line is not None:
        head += f'Host: {host_line}\r\n'
    client = _Client((head + 'Accept: */*\r\n\r\n').encode())
    listener = _Listener([client])
    fake = types.SimpleNamespace(
        AF_INET=socket.AF_INET, AF_INET6=socket.AF_INET6, SOCK_STREAM=socket.SOCK_STREAM,
        SOL_SOCKET=socket.SOL_SOCKET, SO_REUSEADDR=socket.SO_REUSEADDR,
        IPPROTO_IPV6=socket.IPPROTO_IPV6, IPV6_V6ONLY=socket.IPV6_V6ONLY,
        timeout=socket.timeout, socket=lambda *a, **k: listener)
    monkeypatch.setattr(app_mod, 'socket', fake)
    with pytest.raises(_Stop):
        app_mod._start_http_redirect('0.0.0.0', 8080, https_port, domain)
    text = client.sent.decode()
    assert text.startswith('HTTP/1.1 301'), text
    locations = [l for l in text.split('\r\n') if l.lower().startswith('location:')]
    assert len(locations) == 1, text
    return locations[0].split(':', 1)[1].strip()


def test_an_ipv6_host_is_redirected_to_itself(monkeypatch):
    # was https://[2001:db8::5000/dashboard
    assert _redirect(monkeypatch, f'[{V6}]') == f'https://[{V6}]:5000/dashboard'


def test_an_ipv6_host_with_a_port_is_redirected_to_itself(monkeypatch):
    assert _redirect(monkeypatch, f'[{V6}]:80') == f'https://[{V6}]:5000/dashboard'


def test_an_ipv6_host_on_443_gets_no_port(monkeypatch):
    assert _redirect(monkeypatch, f'[{V6}]', https_port=443) == f'https://[{V6}]/dashboard'


def test_the_location_names_the_same_address_the_client_asked_for(monkeypatch):
    loc = _redirect(monkeypatch, f'[{V6}]:80')
    assert urlsplit(loc).hostname == V6
    assert urlsplit(loc).port == 5000


@pytest.mark.parametrize('host_line, expected', [
    ('pegaprox.example', 'https://pegaprox.example:5000/dashboard'),
    ('pegaprox.example:80', 'https://pegaprox.example:5000/dashboard'),
    ('192.0.2.5', 'https://192.0.2.5:5000/dashboard'),
    (None, 'https://localhost:5000/dashboard'),
])
def test_names_and_ipv4_are_redirected_as_before(monkeypatch, host_line, expected):
    assert _redirect(monkeypatch, host_line) == expected


@pytest.mark.parametrize('host_line', [
    '[evil.example]:80',
    f'[{V6}]evil.example',
    f'[{V6}]:80@evil.example',
    '[fe80::1%eth0]',
    '[fe80::1%0d%0aSet-Cookie:x=1]',
])
def test_a_bracketed_host_that_is_no_ipv6_address_goes_to_localhost(monkeypatch, host_line):
    loc = _redirect(monkeypatch, host_line)
    assert loc == 'https://localhost:5000/dashboard'


def test_a_configured_domain_still_wins_over_an_ipv6_host(monkeypatch):
    assert _redirect(monkeypatch, f'[{V6}]', domain='pegaprox.example') == \
        'https://pegaprox.example:5000/dashboard'


# -- PBS ---------------------------------------------------------------------------------

class _Recorder(requests.adapters.BaseAdapter):
    """Stands in for the HTTPS adapter: records the URL of every request it is handed."""

    def __init__(self, fail=False):
        super().__init__()
        self.urls = []
        self.fail = fail

    def send(self, request, **kwargs):
        self.urls.append(request.url)
        if self.fail:
            raise requests.exceptions.ConnectionError('connection refused')
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"data": {"version": "4.0"}}'
        resp.url = request.url
        resp.request = request
        return resp

    def close(self):
        pass


def _pbs(host, **cfg):
    conf = {'name': 'pbs', 'host': host, 'user': 'root@pam!pegaprox',
            'api_token_secret': 'not-a-real-secret'}
    conf.update(cfg)
    return PBSManager('p1', conf)


def test_a_bare_ipv6_pbs_host_goes_into_the_url_in_brackets():
    assert _pbs(V6).base_url == f'https://[{V6}]:8007/api2/json'
    assert _pbs(V6, port=8443).base_url == f'https://[{V6}]:8443/api2/json'


@pytest.mark.parametrize('host', ['192.0.2.5', 'pbs.example', 'pbs-01'])
def test_a_name_or_ipv4_pbs_url_is_unchanged(host):
    assert _pbs(host).base_url == f'https://{host}:8007/api2/json'


def test_the_ipv6_pbs_url_parses_to_the_stored_address():
    """requests refused the old URL outright ("is not a valid host or port")."""
    url = requests.Request('GET', _pbs(V6).base_url + '/version').prepare().url
    assert urlsplit(url).hostname == V6
    assert urlsplit(url).port == 8007


def test_an_ipv6_pbs_connects_and_the_request_goes_to_its_address():
    m = _pbs(V6)
    rec = _Recorder()
    m._session.mount('https://', rec)
    assert m.connect(), m.last_error
    (url,) = rec.urls
    assert url == f'https://[{V6}]:8007/api2/json/version'
    # the address the refusal check and paramiko get is the one the request went to
    assert urlsplit(url).hostname == m.host == V6


def test_a_failed_ipv6_connection_names_host_and_port_readably():
    m = _pbs(V6)
    m._session.mount('https://', _Recorder(fail=True))
    assert m.connect() is False
    assert m.last_error == f'Connection failed: [{V6}]:8007'


def test_the_stored_pbs_host_has_one_spelling():
    """No second, bracketed spelling gets into the store: the format check refuses it,
    so the link-local check, the URL and SSH always start from the bare address."""
    assert pbs_target_refusal(f'[{V6}]') == 'Invalid PBS host'
    with pytest.raises(ValueError):
        _pbs(f'[{V6}]')
    assert pbs_target_refusal(V6) == ''


def test_a_link_local_ipv6_pbs_is_still_refused():
    assert 'link-local' in pbs_target_refusal('fe80::1')
    assert 'loopback' in pbs_target_refusal('::1', allow_loopback=False)


@pytest.mark.parametrize('host, why', [
    ('::', 'loopback'),                         # unspecified, Linux connects it to this host
    ('::ffff:127.0.0.1', 'loopback'),
    ('::ffff:169.254.169.254', 'link-local'),
    ('64:ff9b::a9fe:a9fe', 'link-local'),       # NAT64 of the metadata address
])
def test_ipv6_spellings_of_this_host_and_metadata_stay_refused(host, why):
    """A bare IPv6 PBS URL used to fail to parse, so no HTTP request ever left for one.
    Now it does: these spellings must still be stopped before the URL is built."""
    assert why in pbs_target_refusal(host, allow_loopback=False)
    assert pbs_mod._url_host(host) == f'[{host}]'


@pytest.mark.parametrize('host', ['not-an-address', '192.0.2.5', 'pbs.example', '2001:db8::10:8007x', ''])
def test_url_host_leaves_everything_but_an_ipv6_address_alone(host):
    assert pbs_mod._url_host(host) == host


def test_url_host_brackets_an_ipv6_address():
    assert pbs_mod._url_host(V6) == f'[{V6}]'
    assert pbs_mod._url_host('::ffff:192.0.2.5') == '[::ffff:192.0.2.5]'


def test_ssh_to_an_ipv6_pbs_dials_the_bare_address(monkeypatch):
    import paramiko
    import pegaprox.utils.ssh_security as ssh_security

    dialled = []

    class _FakeClient:
        def connect(self, hostname, **kwargs):
            dialled.append((hostname, kwargs.get('port'), kwargs.get('username')))

        def close(self):
            pass

    monkeypatch.setattr(paramiko, 'SSHClient', _FakeClient)
    monkeypatch.setattr(ssh_security, 'apply_host_key_policy', lambda client, mod: None)
    monkeypatch.setattr(ssh_security, 'persist_host_keys', lambda client: None)

    m = _pbs(V6, user='root@pam', password='pw', api_token_secret='')
    client, err = m._ssh_connect()
    assert err is None and client is not None
    assert dialled == [(V6, 22, 'root')]


def test_the_pbs_routes_build_their_urls_with_brackets_too():
    """The fingerprint probe and the storage preflight check and log in at host:port. With a
    bare IPv6 host the URL check parsed '2001' as the host, and requests refused the login URL."""
    src = open(os.path.join(ROOT, 'pegaprox', 'api', 'pbs.py'), encoding='utf-8').read()
    import re
    assert re.findall(r"https://\{(?:host|server)\}", src) == []
    assert src.count("https://{_url_host(") == 4


def test_the_url_check_now_sees_the_whole_ipv6_address():
    from pegaprox.utils.url_security import is_safe_outbound_url
    from pegaprox.core.pbs import _url_host
    url = f"https://{_url_host('2001:db8::10')}:8007/"
    assert urlsplit(url).hostname == '2001:db8::10'
    assert urlsplit(url).port == 8007
    ok, _ = is_safe_outbound_url(url, allowed_schemes=('https',), allow_private=True)
    assert ok
