# #740.2 — the console auth-ticket mint must target the REGISTERED node (config.host), not the
# HA-fallback host the manager may have pivoted to (current_host). @pam is node-local, so minting
# the stored cluster password on a fallback node answers 401 and the console dies on every node
# but the registered one. The returned PVE ticket is cluster-wide, so the vncproxy leg can still
# run on `host`.

import json
import types
import logging
from unittest import mock

from pegaprox.core.manager import PegaProxManager


def _mgr(config_host, current_host):
    """A PegaProxManager with just enough state for the host properties + the ticket mint,
    without running the heavy __init__/connect path."""
    m = PegaProxManager.__new__(PegaProxManager)
    m.config = types.SimpleNamespace(host=config_host, user='root@pam', pass_='clusterpw', api_port=8006)
    m.current_host = current_host   # pretend an HA fallback pivoted us off the registered node
    m._ssl_verify = False
    m.logger = logging.getLogger('test-740')
    return m


def test_auth_host_stays_on_registered_node_while_host_follows_fallback():
    m = _mgr('10.0.0.1', '10.0.0.2')
    assert m.host == '10.0.0.2'       # `host` follows current_host (the fallback)
    assert m.auth_host == '10.0.0.1'  # `auth_host` stays the registered node


def test_auth_host_falls_back_to_config_host_when_no_current_host():
    m = _mgr('10.0.0.1', None)
    assert m.auth_host == '10.0.0.1'
    assert m.host == '10.0.0.1'


def test_auth_host_brackets_ipv6():
    m = _mgr('fd00::5', 'fd00::6')
    assert m.auth_host == '[fd00::5]'


def test_mint_ticket_hits_registered_node_not_the_fallback():
    m = _mgr('10.0.0.1', '10.0.0.2')
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({'data': {'ticket': 'PVE:tkt', 'CSRFPreventionToken': 'x'}}).encode()

    def _fake_urlopen(req, *a, **k):
        captured['url'] = req.full_url
        return _Resp()

    with mock.patch('urllib.request.urlopen', _fake_urlopen):
        ticket = m.mint_console_auth_ticket()

    assert ticket == 'PVE:tkt'
    assert '10.0.0.1' in captured['url']       # registered node — the password is valid here
    assert '10.0.0.2' not in captured['url']   # never the fallback (would 401 on @pam)


def test_mint_returns_none_for_token_only_cluster():
    m = _mgr('10.0.0.1', '10.0.0.2')
    m.config.pass_ = None  # token-registered cluster: nothing to mint a session ticket with
    assert m.mint_console_auth_ticket() is None


# MK Sep 2026 — the rule above is "never PREFER the fallback", not "never reach it".
# Pinning the mint to the registered node meant that once that node actually went away,
# console and the RFB screenshot fallback died and stayed dead while every other call
# followed current_host and kept working. Measured on a live cluster: the registered host
# refused TCP outright, the three fallbacks answered in ~3s, and a screenshot request sat
# there for 52s before giving up. These two tests keep both halves honest.

def test_an_unreachable_registered_node_does_not_end_the_story():
    m = _mgr('10.0.0.1', '10.0.0.2')
    m.config.fallback_hosts = ['10.0.0.9']
    seen = []

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            return json.dumps({'data': {'ticket': 'PVE:tkt', 'CSRFPreventionToken': 'x'}}).encode()

    def _fake_urlopen(req, *a, **k):
        seen.append(req.full_url)
        if '10.0.0.1' in req.full_url:
            raise TimeoutError("registered node is down")
        return _Resp()

    with mock.patch('urllib.request.urlopen', _fake_urlopen):
        assert m.mint_console_auth_ticket() == 'PVE:tkt'

    assert '10.0.0.1' in seen[0], "the registered node must still be asked first"
    assert len(seen) > 1, "gave up instead of trying a node that was actually up"


def test_a_rejection_still_stops_at_the_registered_node():
    """The #740.2 hazard itself: if the account isn't valid, walking the cluster would just
    produce a burst of failed logins. A 401 is an answer, not a reachability problem."""
    import urllib.error
    m = _mgr('10.0.0.1', '10.0.0.2')
    m.config.fallback_hosts = ['10.0.0.9']
    seen = []

    def _fake_urlopen(req, *a, **k):
        seen.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 401, 'denied', {}, None)

    with mock.patch('urllib.request.urlopen', _fake_urlopen):
        assert m.mint_console_auth_ticket() is None

    assert len(seen) == 1, f"sprayed logins across the cluster after a 401: {seen}"
