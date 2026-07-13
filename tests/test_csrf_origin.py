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

from pegaprox.app import create_app

# The test client posts against http://localhost/ by default, so request.host is
# 'localhost' with no port. Same-origin therefore == scheme://localhost.
_BASE = 'http://localhost'
_PROBE = '/api/__csrf_probe_does_not_exist__'   # non-exempt, unrouted → 404 if CSRF passes


@pytest.fixture(scope='module')
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


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
