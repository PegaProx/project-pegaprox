"""mint_console_session() must log in against the REGISTERED node.

The stored @pam password is a local account on the node the cluster was
registered with. `manager.host` follows the HA fallback, so a login there
answers 401 and the console dies (#740, defect 2). The mint therefore has to
target config.host regardless of which node the manager currently talks to.
"""
import io
import json
import logging
import types
import urllib.request

import pytest

from pegaprox.core.manager import PegaProxManager


def _manager(*, host, current_host, password='s3cret'):
    mgr = PegaProxManager.__new__(PegaProxManager)
    mgr.config = types.SimpleNamespace(host=host, user='root@pam', pass_=password, api_port=8006)
    mgr.current_host = current_host
    mgr._ssl_verify = False
    mgr.logger = logging.getLogger('test-mint')
    return mgr


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def capture_login(monkeypatch):
    seen = {}

    def fake_urlopen(req, context=None, timeout=None):
        seen['url'] = req.full_url
        body = json.dumps({'data': {'ticket': 'PVE:root@pam:TICKET', 'CSRFPreventionToken': 'CSRF'}})
        return _Resp(body.encode())

    monkeypatch.setattr(urllib.request, 'urlopen', fake_urlopen)
    return seen


def test_mint_targets_registered_host_not_ha_fallback(capture_login):
    mgr = _manager(host='pve1.example', current_host='pve3.example')
    ticket, csrf = mgr.mint_console_session()
    assert ticket == 'PVE:root@pam:TICKET' and csrf == 'CSRF'
    assert capture_login['url'].startswith('https://pve1.example:8006/')
    assert 'pve3' not in capture_login['url']
    # self.host would have been the fallback node — the exact bug
    assert mgr.host == 'pve3.example'


def test_mint_brackets_ipv6_registered_host(capture_login):
    mgr = _manager(host='2001:db8::1', current_host='2001:db8::3')
    mgr.mint_console_session()
    assert capture_login['url'].startswith('https://[2001:db8::1]:8006/')


def test_mint_returns_none_pair_for_token_registered_cluster(capture_login):
    mgr = _manager(host='pve1.example', current_host=None, password='')
    assert mgr.mint_console_session() == (None, None)
    assert mgr.mint_console_auth_ticket() is None
    assert 'url' not in capture_login


def test_ticket_only_view_keeps_old_contract(capture_login):
    mgr = _manager(host='pve1.example', current_host=None)
    assert mgr.mint_console_auth_ticket() == 'PVE:root@pam:TICKET'


def test_mint_refuses_inline_token_identity(capture_login):
    # An inline-token cluster stores 'user@realm!tokenid' in config.user and the
    # token SECRET in config.pass_ — pwd is truthy, but POSTing it to
    # /access/ticket is a guaranteed 401 per console open (and bypasses the
    # connect path's failed-login circuit breaker). The mint must bail without
    # ever talking to PVE.
    mgr = _manager(host='pve1.example', current_host=None, password='tokensecret')
    mgr.config.user = 'automation@pve!provisioning'
    assert mgr.mint_console_session() == (None, None)
    assert 'url' not in capture_login
