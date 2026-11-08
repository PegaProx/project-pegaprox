# CSRF Origin/Referer matcher invariants — the app.py `validate_request` gate.
#
# NS Jul 2026 (Phase 1) — every state-changing /api/* request must present a
# same-origin Origin/Referer OR an XHR marker with no foreign Origin/Referer. The
# matcher was hardened after a pentest found suffix-confusion + tab-in-scheme +
# userinfo bypasses (app.py:194-291). This drives the REAL middleware through the
# Flask test client: a POST to a non-existent /api/ path either returns the exact
# `403 CSRF validation failed` (blocked) or falls through to routing → 404
# (CSRF passed). We assert on that specific 403 body, so it doesn't matter what a
# downstream route would have done.

import pytest
from werkzeug.test import EnvironBuilder, run_wsgi_app

# The test client posts against http://localhost/ by default, so request.host is
# 'localhost' with no port. Same-origin therefore == scheme://localhost.
_BASE = 'http://localhost'
_PROBE = '/api/__csrf_probe_does_not_exist__'   # non-exempt, unrouted → 404 if CSRF passes


@pytest.fixture(scope='module')
def client(_integration_app):
    # the app conftest builds on a temp database; one of its own would start on config/
    return _integration_app.test_client()


def _csrf_blocked(resp):
    """True iff the CSRF gate itself rejected the request (not a downstream 401/404)."""
    if resp.status_code != 403:
        return False
    body = resp.get_json(silent=True) or {}
    return body.get('error') == 'CSRF validation failed'


def _post(client, headers):
    # application/json is a "sensitive" content-type → arms the CSRF check.
    return client.post(_PROBE, json={'x': 1}, headers=headers, base_url=_BASE)


# ---------------------------------------------------------------------------
# BLOCKED — no valid same-origin proof
# ---------------------------------------------------------------------------

def test_no_origin_no_xhr_is_blocked(client):
    # A bare cross-site form POST (cookie auto-attached, no Origin, no XHR) is the
    # textbook CSRF — must be blocked.
    assert _csrf_blocked(_post(client, {})) is True


@pytest.mark.parametrize('origin', [
    'http://localhost.attacker.example',   # suffix confusion (the classic startswith bug)
    'http://attacker.example',             # unrelated host
    'https://evil.example:443',            # unrelated host w/ explicit port
    'http://user:pass@localhost',          # userinfo smuggling → hostname=localhost
    'http://localhost@evil.example',       # userinfo the other way
    '//localhost',                         # protocol-relative (no http/https prefix)
    'ht\ttp://localhost',                  # tab-in-scheme (urlparse would normalise it)
    'http://localhost:9999',               # right host, wrong (non-default) port
    'null',                                # opaque origin
])
def test_foreign_origin_is_blocked_even_with_xhr(client, origin):
    # XHR marker present, but a FOREIGN Origin is also present → still blocked
    # (the XHR escape hatch only applies when there's no foreign Origin/Referer).
    headers = {'Origin': origin, 'X-Requested-With': 'XMLHttpRequest'}
    assert _csrf_blocked(_post(client, headers)) is True, origin


def test_foreign_referer_is_blocked_even_with_xhr(client):
    headers = {'Referer': 'http://attacker.example/page',
               'X-Requested-With': 'XMLHttpRequest'}
    assert _csrf_blocked(_post(client, headers)) is True


# ---------------------------------------------------------------------------
# ALLOWED — a legitimate same-origin request passes the gate (→ 404 unrouted)
# ---------------------------------------------------------------------------

def test_matching_origin_passes(client):
    resp = _post(client, {'Origin': _BASE})
    assert _csrf_blocked(resp) is False
    assert resp.status_code == 404   # CSRF let it through to routing


def test_matching_referer_passes(client):
    resp = _post(client, {'Referer': _BASE + '/dashboard'})
    assert _csrf_blocked(resp) is False


def test_xhr_only_same_origin_passes(client):
    # XHR marker, no Origin, no Referer (same-origin fetch that doesn't send Origin
    # on some browsers) → allowed, because there is no FOREIGN proof to contradict it.
    resp = _post(client, {'X-Requested-With': 'XMLHttpRequest'})
    assert _csrf_blocked(resp) is False


def test_exempt_login_path_is_not_csrf_gated(client):
    # /api/auth/login is on the exempt list (no session yet to protect); a POST with
    # no Origin/XHR must NOT be turned away by the CSRF gate.
    resp = client.post('/api/auth/login', json={'username': 'x', 'password': 'y'},
                       base_url=_BASE)
    assert _csrf_blocked(resp) is False


# ---------------------------------------------------------------------------
# IPv6 literal host (#1155) - reaching the UI by its bare IPv6 address
# ---------------------------------------------------------------------------
# The Host header is bracketed ("[2001:db8::1]"), but urlparse().hostname on the
# Origin strips the brackets. req_host used to stay bracketed, so a genuine
# same-origin request never matched and every state-changing /api/* call failed
# closed with 403 - the symptom reported on the VM image (theme save, i.e.
# PUT /api/user/preferences, 403'd and the first-run never reached the inventory).

@pytest.mark.parametrize('base', [
    'https://[2001:db8::1]:8443',   # explicit non-default port
    'https://[2001:db8::1]',        # default port omitted (Host carries no port)
    'https://[fe80::dead:beef]',    # link-local, the SLAAC shape
])
def test_ipv6_literal_same_origin_passes(client, base):
    resp = client.post(_PROBE, json={'x': 1}, headers={'Origin': base}, base_url=base)
    assert _csrf_blocked(resp) is False, base
    assert resp.status_code == 404   # CSRF let it through to routing


def test_ipv6_literal_matching_referer_passes(client):
    base = 'https://[2001:db8::1]:8443'
    resp = client.post(_PROBE, json={'x': 1},
                       headers={'Referer': base + '/dashboard'}, base_url=base)
    assert _csrf_blocked(resp) is False


def test_ipv6_literal_foreign_origin_still_blocked(client):
    # Same bracket-stripping must not over-accept: a DIFFERENT IPv6 Origin against
    # this host is a real cross-origin request and stays blocked.
    resp = client.post(_PROBE, json={'x': 1},
                       headers={'Origin': 'https://[2001:db8::2]:8443',
                                'X-Requested-With': 'XMLHttpRequest'},
                       base_url='https://[2001:db8::1]:8443')
    assert _csrf_blocked(resp) is True


def test_ipv6_literal_wrong_port_still_blocked(client):
    # Right host, wrong port is a port mismatch and must be rejected.
    resp = client.post(_PROBE, json={'x': 1},
                       headers={'Origin': 'https://[2001:db8::1]:9999',
                                'X-Requested-With': 'XMLHttpRequest'},
                       base_url='https://[2001:db8::1]:8443')
    assert _csrf_blocked(resp) is True


def _raw_post(app, host, origin):
    # The test client parses the Host before the app runs and refuses these forms, so build
    # the environ here and hand it to the app the way the WSGI server would.
    env = EnvironBuilder(path=_PROBE, method='POST', json={'x': 1},
                         base_url='https://[2001:db8::1]',
                         headers={'Origin': origin}).get_environ()
    env['HTTP_HOST'] = host
    body, status, _ = run_wsgi_app(app, env)
    return status, b''.join(body)


@pytest.mark.parametrize('host', [
    '[2001:db8::1],evil.example',        # a second Host folded in by a proxy
    '[2001:db8::1]:8443,evil.example',
    '[2001:db8::1]junk',
    '[2001:db8::1]:x',
    '[2001:db8::1]:',
])
def test_ipv6_literal_host_with_more_after_the_bracket_is_blocked(_integration_app, host):
    # Only "[addr]" or "[addr]:port" is one host. Like a folded "name,other" (#626), the
    # rest must not be dropped so that the first address matches an :80/:443 Origin.
    status, body = _raw_post(_integration_app, host, 'https://[2001:db8::1]')
    assert status.startswith('403'), (host, status)
    assert b'CSRF validation failed' in body


def test_ipv6_literal_host_alone_passes_the_raw_path(_integration_app):
    # counterproof on the same raw path: the plain bracketed host still gets through
    status, _ = _raw_post(_integration_app, '[2001:db8::1]', 'https://[2001:db8::1]')
    assert status.startswith('404'), status
