"""The API token of a cluster is created on an IPv6 host.

_try_create_api_token built its URL from the raw host, so for a cluster whose host is an
IPv6 literal the request went to "https://2001:db8::10:8006/...", which requests cannot
prepare. The failure is logged at debug only, so the cluster stayed on its password login
with no token and no visible reason. The URL now goes through _bracket_ipv6, like the
login and ticket URLs next to it.

Each test drives _try_create_api_token with a fake session that records the request. The
HA gate is patched to the active side, the token name is fixed, and nothing opens a real
connection.
"""
import random
from unittest.mock import MagicMock

import pytest
import requests

import pegaprox.core.manager as mgrmod
from pegaprox.core import ha
from pegaprox.core.manager import PegaProxManager
from pegaprox.models.tasks import PegaProxConfig

TOKEN_PATH = '/api2/json/access/users/root@pam/token/pegaprox_123456'
BODY = {'privsep': '0', 'expire': '0', 'comment': 'PegaProx management token'}


class _Answer:
    def __init__(self, code, data=None):
        self.status_code = code
        self._data = data

    def json(self):
        return {'data': self._data}


class _Session:
    """Records every POST requests can prepare, and answers with the given status."""

    def __init__(self, code=200):
        self.cookies = MagicMock()
        self.code = code
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        # as a real session does: a URL requests cannot prepare raises before anything is sent
        url = requests.Request('POST', url).prepare().url
        self.calls.append((url, data, headers))
        data_back = {'full-tokenid': 'root@pam!pegaprox_123456', 'value': 'secret'}
        return _Answer(self.code, data_back if self.code == 200 else None)


def _manager(host, logger=None):
    m = PegaProxManager.__new__(PegaProxManager)
    m.id = None
    m.config = PegaProxConfig({'name': 'lab', 'host': host, 'user': 'root@pam', 'pass': 'pw'})
    m._ticket = 'ticket'
    m._csrf_token = 'csrf'
    m._api_token = None
    m._using_api_token = False
    m._token_auto_created = False
    m.logger = logger or MagicMock()
    return m


@pytest.fixture
def active(monkeypatch):
    """The active side of the HA gate, a fixed token name, and no disk or database."""
    monkeypatch.setattr(ha, 'is_active', lambda: True)
    monkeypatch.setattr(random, 'choices', lambda population, k=6: list('123456')[:k])
    monkeypatch.setattr(mgrmod, 'save_config', lambda: None)
    monkeypatch.setattr(mgrmod, 'get_db', lambda: MagicMock())


def test_the_token_request_goes_to_a_bracketed_ipv6_host(active):
    """On an IPv6-only cluster the API token is created at the bracketed address."""
    m, session = _manager('2001:db8::10'), _Session(200)

    m._try_create_api_token(session, '2001:db8::10')

    assert session.calls == [(f'https://[2001:db8::10]:8006{TOKEN_PATH}', BODY,
                              {'CSRFPreventionToken': 'csrf'})]
    assert m.config.api_token_user == 'root@pam!pegaprox_123456'


def test_a_bracketed_ipv6_host_is_not_bracketed_twice(active):
    """A host the operator typed with brackets still reaches the address once bracketed."""
    m, session = _manager('[2001:db8::10]'), _Session(200)

    m._try_create_api_token(session, '[2001:db8::10]')

    assert [url for url, _, _ in session.calls] == [f'https://[2001:db8::10]:8006{TOKEN_PATH}']


@pytest.mark.parametrize('host', ['192.0.2.10', 'pve1.lab'])
def test_an_ipv4_or_dns_host_keeps_its_url(active, host):
    """An IPv4 address or a DNS name gets the same token URL as before."""
    m, session = _manager(host), _Session(200)

    m._try_create_api_token(session, host)

    assert [url for url, _, _ in session.calls] == [f'https://{host}:8006{TOKEN_PATH}']


@pytest.mark.parametrize('code', [403, 500])
def test_a_refused_token_creation_keeps_the_password_login(active, code):
    """When Proxmox refuses the token, the cluster stays connected with its password, as before."""
    m, session = _manager('2001:db8::10'), _Session(code)

    m._try_create_api_token(session, '2001:db8::10')

    assert [url for url, _, _ in session.calls] == [f'https://[2001:db8::10]:8006{TOKEN_PATH}']
    assert not m.config.api_token_user
    assert m._using_api_token is False
