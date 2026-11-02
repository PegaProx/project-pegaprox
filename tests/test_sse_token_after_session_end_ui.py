"""A tab that outlived its session stops asking for SSE tokens.

After a server restart the session of an open tab is gone. The tab kept the token it had,
opened the stream with it (401), asked for a new token (401) and the health check started the
backoff over every 10 s: one instance counted 1214 token and 626 stream requests from a single
browser in nine minutes, until someone signed in again. authFetch leaves /sse alone, so nothing
showed that the session had ended.

Now PegaProx's own 401 on the token ends the loop and shows the session overlay, a refused
token is dropped instead of reused, and only a token request that can work later (no answer,
5xx, 429) comes back, with the backoff. An answer without a token (a standby that polls) still
opens no stream and asks nothing more.

The runtime tests drive the built bundle against the fake server of tests/test_ha_ui.py with
Playwright's clock, so two minutes of timers pass in a few seconds. LW Nov 2026
"""
import os

import pytest

from test_ha_ui import _App, _FakeServer, browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = ('POST', '/api/sse/token')
STREAM = ('GET', '/api/sse/updates')
OURS = (401, {'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'})
FOREIGN = (401, {'error_type': 'UNAUTHENTICATED'})
BUSY = (503, {'error': 'Service unavailable'})


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as fh:
        return fh.read()


def _effect():
    dash = _read('web', 'src', 'dashboard.js')
    start = dash.index('// SSE (Server-Sent Events) connection for live updates')
    return dash[start:dash.index('}, [user, sessionId]);', start)]


@pytest.fixture
def tab(browser):
    apps = []

    def _open(first_token=(200, {'token': 't1', 'expires_in': 600})):
        # the stream itself is not mocked: it fails, the way it does while the server is away
        server = _FakeServer(role='standalone', extra={TOKEN: first_token})
        app = _App(browser, server, clock=True)
        apps.append(app)
        deadline = 50
        while deadline and server.calls.count(TOKEN) == 0:
            app.page.wait_for_timeout(100)
            deadline -= 1
        assert server.calls.count(TOKEN) > 0, 'the page never asked for a token'
        return app
    yield _open
    for app in apps:
        app.ctx.close()


def _pass(app, seconds):
    # timers by the clock, a moment of real time between steps for the answers to arrive
    for _ in range(int(seconds / 2)):
        app.page.clock.run_for(2000)
        app.page.wait_for_timeout(40)


def _errors(app):
    # the stream of these tests fails on purpose, and the page says so on the console
    return [e for e in app.errors if not e.startswith('console: SSE error')]


def _since(app, mark, call):
    return app.server.calls[mark:].count(call)


def _streams_with(app, token, mark_urls):
    return sum(1 for u in app.server.urls[mark_urls:] if '/api/sse/updates' in u and f'token={token}' in u)


# --- source --------------------------------------------------------------------------------

def test_a_refused_token_is_dropped_and_only_a_passing_failure_is_retried():
    body = _effect()
    get = body[body.index('const getSseToken = async () => {'):body.index('const scheduleRetry = () => {')]
    assert get.index('sseToken = null;') < get.index('tokenFailed = !resp || resp.status >= 500 || resp.status === 429;')
    assert 'if (PegaProxApiErrors.sessionLost(body)) {' in get and 'setSessionExpired(true);' in get
    # the error handler no longer asks for a token of its own before connectSSE asks again
    assert body.count('await getSseToken();') == 2   # connectSSE and the five minute refresh


def test_the_bundle_was_rebuilt():
    bundle = _read('web', 'index.html').replace(' ', '')
    assert 'tokenFailed=!resp||resp.status>=500||resp.status===429' in bundle
    assert 'if(tokenFailed)scheduleRetry();elseeventSource=null;' in bundle


# --- runtime -------------------------------------------------------------------------------

def test_runtime_our_401_on_the_token_ends_the_loop_with_the_session_overlay(tab):
    app = tab()
    # the server restarted: the session and the token it gave are gone
    mark, mark_urls = len(app.server.calls), len(app.server.urls)
    app.server.extra[TOKEN] = OURS
    app.server.extra[STREAM] = OURS
    _pass(app, 120)
    asked = _since(app, mark, TOKEN)
    # one effect per user and session can each ask once more, then it ends
    assert 1 <= asked <= 2, f'{asked} token requests in two minutes after the session ended'
    app.page.locator('[data-session-expired]').wait_for(timeout=5000)
    # and the token the server no longer knows does not open a stream again
    assert _streams_with(app, 't1', mark_urls) <= 1, app.server.urls[mark_urls:]
    later = len(app.server.calls)
    _pass(app, 60)
    assert _since(app, later, TOKEN) == 0 and _since(app, later, STREAM) == 0
    assert not _errors(app), _errors(app)


def test_runtime_a_busy_server_is_asked_again_with_a_growing_backoff(tab):
    app = tab()
    mark = len(app.server.calls)
    app.server.extra[TOKEN] = BUSY
    _pass(app, 120)
    asked = _since(app, mark, TOKEN)
    # 1, 2, 4, 8, 16, 30, 30 ... seconds: at most about eight in two minutes, never the 10 s restart
    assert 2 <= asked <= 9, f'{asked} token requests in two minutes'
    assert app.page.locator('[data-session-expired]').count() == 0
    # and once it answers again, the stream comes back
    app.server.extra[TOKEN] = (200, {'token': 't2', 'expires_in': 600})
    mark_urls = len(app.server.urls)
    _pass(app, 40)
    assert _streams_with(app, 't2', mark_urls) >= 1
    assert not _errors(app), _errors(app)


def test_runtime_an_answer_without_a_token_opens_no_stream_and_asks_nothing_more(tab):
    app = tab(first_token=(200, {}))
    mark = len(app.server.calls)
    _pass(app, 120)
    assert _since(app, mark, TOKEN) == 0 and _since(app, mark, STREAM) == 0
    assert app.page.locator('[data-session-expired]').count() == 0


def test_runtime_a_401_that_is_not_ours_neither_signs_off_nor_loops(tab):
    app = tab()
    mark = len(app.server.calls)
    app.server.extra[TOKEN] = FOREIGN
    app.server.extra[STREAM] = FOREIGN
    _pass(app, 120)
    assert _since(app, mark, TOKEN) <= 2
    assert app.page.locator('[data-session-expired]').count() == 0
