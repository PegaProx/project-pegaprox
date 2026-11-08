"""A capped API token must not be able to register a push endpoint or read the inbox.

Web Push subscriptions are stored per username, and _alert_handler decides what a
subscriber receives from that account's STORED record - deliberately, so that a real
administrator gets every cluster's alerts. An API token presents its owner's username.
So a token an administrator minted and capped at viewer could POST /api/push/subscribe
with an https endpoint of the attacker's choosing and have the whole estate's alert
content delivered there: cluster, node and guest names, plus the live metric values that
tripped the rule. None of it is readable through that token's own permissions.

The endpoint validation already in place (https only, no RFC1918 or metadata host) does
not help - a public attacker-controlled host passes it, which is what a push service is.

A subscription comes from a service worker in a browser and a token has no browser, so
these three routes are interactive-session only. The inbox is the same content through a
different door and goes with them. Delivery, unsubscribe and the fixed-text test push are
untouched.

Aikido ai_pentest 700487533. MK
"""
import contextlib

import pytest

import pegaprox.api.push as push


ENDPOINT = 'https://push.attacker.example/x/abc123'


@contextlib.contextmanager
def _as(api, session, body=None):
    from flask import request as _rq
    with api.app.test_request_context('/', base_url='http://localhost',
                                      json=body if body is not None else {}):
        _rq.session = session
        yield


def _handler(name):
    fn = getattr(push, name)
    while hasattr(fn, '__wrapped__'):
        fn = fn.__wrapped__
    return fn


def _token(user='taylor', role='viewer'):
    return {'user': user, 'role': role, 'api_token': True}


def _login(user='taylor', role='admin'):
    return {'user': user, 'role': role}


def _sub_body():
    return {'endpoint': ENDPOINT, 'keys': {'p256dh': 'a' * 87, 'auth': 'b' * 22}}


@pytest.fixture
def taylor(api, seed):
    seed.user('taylor', role='admin')
    push._ensure_inbox_table()
    seed.db.execute('''CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        endpoint TEXT NOT NULL UNIQUE, p256dh TEXT, auth TEXT, user_agent TEXT,
        created_at TEXT, last_used_at TEXT, failures INTEGER DEFAULT 0)''')
    return seed


def _rows(seed):
    c = seed.db.conn.cursor()
    c.execute('SELECT COUNT(*) AS n FROM push_subscriptions')
    return c.fetchone()['n']


def test_a_token_cannot_register_a_delivery_endpoint(api, taylor, monkeypatch):
    # stub the host check so this really tests the token gate: without it the suite's
    # missing DNS refuses the fake hostname and the test would pass on its own
    monkeypatch.setattr(push, '_is_internal_or_metadata_host', lambda h: False)
    with _as(api, _token(), body=_sub_body()):
        resp = _handler('subscribe')()

    assert resp[1] == 403
    assert _rows(taylor) == 0, 'the subscription was stored anyway'


def test_the_owners_own_session_can_still_subscribe(api, taylor, monkeypatch):
    """The counterweight - this is how the feature is meant to be used.

    The host check is stubbed because there is no DNS in the suite and it fails
    closed on a name it cannot resolve; a real push service resolves publicly and
    passes it, which is the point the module docstring makes."""
    monkeypatch.setattr(push, '_is_internal_or_metadata_host', lambda h: False)
    with _as(api, _login(), body=_sub_body()):
        resp = _handler('subscribe')()

    assert resp.get_json() == {'ok': True}
    assert _rows(taylor) == 1


def test_a_token_cannot_read_the_notification_inbox(api, taylor):
    with _as(api, _token()):
        resp = _handler('inbox')()

    assert resp[1] == 403


def test_a_token_cannot_clear_the_notification_inbox(api, taylor):
    with _as(api, _token()):
        resp = _handler('inbox_clear')()

    assert resp[1] == 403


def test_the_owner_still_reads_their_inbox(api, taylor):
    with _as(api, _login()):
        resp = _handler('inbox')()

    assert 'error' not in (resp.get_json() or {})


def test_the_refusal_names_the_route_and_says_what_to_use(api, taylor):
    """An operator who hits this needs to know it is the token, not their rights."""
    with _as(api, _token(), body=_sub_body()):
        msg = _handler('subscribe')()[0].get_json()['error']

    assert 'API tokens' in msg and 'interactive session' in msg


def test_unsubscribing_is_left_alone(api, taylor, monkeypatch):
    """Removing your own endpoint leaks nothing and must keep working."""
    monkeypatch.setattr(push, '_is_internal_or_metadata_host', lambda h: False)
    with _as(api, _login(), body=_sub_body()):
        _handler('subscribe')()
    with _as(api, _token(), body={'endpoint': ENDPOINT}):
        resp = _handler('unsubscribe')()

    assert resp.get_json() == {'ok': True}
