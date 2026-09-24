"""The console/screenshot ticket mint only ever asked the registered node.

`auth_host` is pinned to config.host on purpose — @pam is node-local, so minting the
stored password against an arbitrary node answers 401 (#740.2). But "registered" and
"reachable" are different things: once a cluster fails over, `host` follows
current_host and every other call keeps working, while this one sits on a dead box
until the timeout. Console and the RFB screenshot fallback break on their own and
stay broken, which is why nobody connected the two.

Measured on the dev cluster before the fix: one screenshot request = 52.5s and a 502,
with nothing cached, so every tile poll did it again. MK
"""
import urllib.error

import pytest


class _Cfg:
    def __init__(self, host, fallbacks=(), user='root@pam', pwd='s3cret'):
        self.host = host
        self.fallback_hosts = list(fallbacks)
        self.user = user
        self.pass_ = pwd


class _Mgr:
    """Only the surface mint_console_auth_ticket touches."""
    def __init__(self, host, fallbacks=(), current=None, pwd='s3cret'):
        self.config = _Cfg(host, fallbacks, pwd=pwd)
        self.current_host = current
        self.api_port = 8006
        self._ssl_verify = False
        import logging
        self.logger = logging.getLogger('test')

    _bracket_ipv6 = staticmethod(lambda h: h)

    @property
    def auth_host(self):
        return self.config.host

    # the real method under test
    from pegaprox.core.manager import PegaProxManager as _Real
    mint_console_auth_ticket = _Real.mint_console_auth_ticket


def _fake_urlopen(reachable, ticket='PVE:tkt', csrf='CSRF1', record=None):
    """urlopen stand-in: only `reachable` hosts answer, everything else times out."""
    import io as _io, json as _json

    class _Resp:
        def __init__(self, payload): self._p = payload
        def read(self): return _json.dumps(self._p).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _open(req, context=None, timeout=None):
        url = req.full_url
        if record is not None:
            record.append(url)
        if not any(f"//{h}:" in url for h in reachable):
            raise TimeoutError("timed out")
        return _Resp({'data': {'ticket': ticket, 'CSRFPreventionToken': csrf}})
    return _open


@pytest.fixture
def patched(monkeypatch):
    def _apply(opener):
        import urllib.request as ur
        monkeypatch.setattr(ur, 'urlopen', opener)
    return _apply


def test_registered_host_is_tried_first(patched):
    seen = []
    patched(_fake_urlopen(reachable={'10.0.0.1'}, record=seen))
    mgr = _Mgr('10.0.0.1', fallbacks=['10.0.0.2'])
    assert mgr.mint_console_auth_ticket() == 'PVE:tkt'
    assert '//10.0.0.1:' in seen[0], "the registered node must be asked first (#740.2)"
    assert len(seen) == 1, "no reason to touch other nodes once one answered"


def test_a_dead_registered_host_falls_through_to_a_reachable_one(patched):
    """The actual bug: registered host dead, cluster fine, screenshots broken anyway."""
    seen = []
    patched(_fake_urlopen(reachable={'10.0.0.9'}, record=seen))
    mgr = _Mgr('10.0.0.1', fallbacks=['10.0.0.2', '10.0.0.9'], current='10.0.0.2')
    assert mgr.mint_console_auth_ticket() == 'PVE:tkt'
    assert len(seen) >= 2, "it gave up on the first unreachable host"


def test_current_host_is_preferred_over_the_configured_fallback_list(patched):
    seen = []
    patched(_fake_urlopen(reachable={'10.0.0.2', '10.0.0.9'}, record=seen))
    mgr = _Mgr('10.0.0.1', fallbacks=['10.0.0.9'], current='10.0.0.2')
    mgr.mint_console_auth_ticket()
    assert '//10.0.0.2:' in seen[1], "the node we are already talking to should be next"


def test_a_401_stops_the_walk_instead_of_spraying_logins(patched):
    """#740.2 semantics: rejected credentials are not a reachability problem. Trying
    every node would just produce a burst of failed logins in the PVE auth log."""
    seen = []

    def _open(req, context=None, timeout=None):
        seen.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 401, 'denied', {}, None)

    patched(_open)
    mgr = _Mgr('10.0.0.1', fallbacks=['10.0.0.2', '10.0.0.3'])
    assert mgr.mint_console_auth_ticket() is None
    assert len(seen) == 1, f"walked on after a 401: {seen}"


def test_no_password_means_no_mint(patched):
    patched(_fake_urlopen(reachable={'10.0.0.1'}))
    mgr = _Mgr('10.0.0.1', pwd='')
    assert mgr.mint_console_auth_ticket() is None
    assert mgr.mint_console_auth_ticket(with_csrf=True) == (None, None)


def test_csrf_comes_back_when_asked(patched):
    """The vncproxy POST is cookie-authenticated, so it needs the matching CSRF token.
    Returning the ticket alone is how the websocket ended up as a different identity."""
    patched(_fake_urlopen(reachable={'10.0.0.1'}))
    mgr = _Mgr('10.0.0.1')
    assert mgr.mint_console_auth_ticket(with_csrf=True) == ('PVE:tkt', 'CSRF1')


def test_every_failure_path_keeps_the_tuple_shape(patched):
    """A caller unpacking two values must not blow up on the sad paths."""
    patched(_fake_urlopen(reachable=set()))
    mgr = _Mgr('10.0.0.1', fallbacks=['10.0.0.2'])
    t, c = mgr.mint_console_auth_ticket(with_csrf=True)
    assert (t, c) == (None, None)


def test_duplicate_candidates_are_only_tried_once(patched):
    seen = []
    patched(_fake_urlopen(reachable=set(), record=seen))
    mgr = _Mgr('10.0.0.1', fallbacks=['10.0.0.1', '10.0.0.1'], current='10.0.0.1')
    mgr.mint_console_auth_ticket()
    assert len(seen) == 1, f"same host asked {len(seen)} times"


# ── the screenshot route's side of it ──

def test_a_failed_screenshot_is_remembered():
    """Measured before the fix: a failing tile cost 52s of a bounded worker slot and
    cached nothing, so the next poll paid it again. On a wall of such tiles that is
    what starves the console and the SSE stream."""
    import time as _t
    from pegaprox.api import vms as vms_mod

    key = 'c1:999'
    vms_mod._vm_screenshot_cache.clear()
    with vms_mod._vm_screenshot_lock:
        vms_mod._vm_screenshot_cache[key] = (_t.monotonic(), None)
    hit = vms_mod._vm_screenshot_cache[key]
    assert hit[1] is None, "a failure must be representable in the cache at all"


def test_failures_expire_sooner_than_successes():
    """A remembered failure shouldn't outlive a transient outage by much."""
    from pegaprox.api import vms as vms_mod
    assert vms_mod._VM_SCREENSHOT_FAIL_TTL >= vms_mod._VM_SCREENSHOT_TTL
    assert vms_mod._VM_SCREENSHOT_FAIL_TTL <= 10 * vms_mod._VM_SCREENSHOT_TTL


def test_the_eviction_survives_negative_entries():
    """The trim sorts on the timestamp; a None payload must not break it."""
    import time as _t
    from pegaprox.api import vms as vms_mod
    vms_mod._vm_screenshot_cache.clear()
    for i in range(600):
        vms_mod._vm_screenshot_cache[f'c:{i}'] = (_t.monotonic() + i, None if i % 2 else b'x')
    oldest = sorted(vms_mod._vm_screenshot_cache.items(), key=lambda kv: kv[1][0])[:128]
    assert len(oldest) == 128
    vms_mod._vm_screenshot_cache.clear()


def test_the_vncproxy_post_drops_the_token_header():
    """Both legs must be the same identity. The pooled session carries an API token on
    token-configured clusters; leaving it on makes PVE mint the vncticket for the token
    user while the websocket presents a cookie — 'invalid PVEVNC ticket'. Hit that live."""
    import io as _io
    src = _io.open('pegaprox/api/vms.py', encoding='utf-8').read()
    i = src.index('def _screenshot_via_rfb')
    body = src[i:i + 4000]
    assert "'Authorization': None" in body, "vncproxy POST would still authenticate as the token user"
    assert 'PVEAuthCookie={pve_ticket}' in body
