"""Exactly one party may perform the websocket handshake.

#945.3 — geventwebsocket's handler upgrades every request carrying
`Upgrade: websocket`, at the WSGI layer, before Flask routes anything. Three of
our endpoints are flask-sock, and simple_websocket handshakes them itself once
reached. The client got two 101 responses back to back, read the second as a
frame, and closed with 1002 Protocol Error - which is why the console never came
up behind a reverse proxy while direct access on :5001 was fine.

The decision is taken from the URL map (flask-sock registers websocket=True
rules), so these tests drive it with the real app and real request environments.

MK Sep 2026
"""
import pytest

from pegaprox.app import _should_bypass_gevent_upgrade


def _env(path, upgrade='websocket', method='GET'):
    e = {'PATH_INFO': path, 'REQUEST_METHOD': method}
    if upgrade is not None:
        e['HTTP_UPGRADE'] = upgrade
    return e


FLASK_SOCK = [
    '/api/clusters/c1/vms/pve1/qemu/100/vncwebsocket',
    '/api/clusters/c1/nodes/pve1/shellws',
    '/api/ws/updates',
]


@pytest.mark.parametrize('path', FLASK_SOCK)
def test_flask_sock_endpoints_are_left_to_flask_sock(api, path):
    assert _should_bypass_gevent_upgrade(api.app, _env(path)) is True, (
        f'{path} would be upgraded twice')


@pytest.mark.parametrize('path', ['/api/clusters', '/api/health', '/', '/api/auth/check'])
def test_ordinary_endpoints_are_untouched(api, path):
    assert _should_bypass_gevent_upgrade(api.app, _env(path)) is False


def test_a_request_without_an_upgrade_header_is_never_diverted(api):
    """The cheap gate. Ordinary traffic must not pay for a routing lookup, and
    must never lose its normal handling."""
    for path in FLASK_SOCK:
        assert _should_bypass_gevent_upgrade(api.app, _env(path, upgrade=None)) is False
        assert _should_bypass_gevent_upgrade(api.app, _env(path, upgrade='h2c')) is False


def test_an_unroutable_path_keeps_the_previous_behaviour(api):
    assert _should_bypass_gevent_upgrade(api.app, _env('/nope/nothing/here')) is False


def test_a_broken_app_does_not_take_the_server_down_with_it(api):
    class _NoUrlMap:
        pass
    assert _should_bypass_gevent_upgrade(_NoUrlMap(), _env(FLASK_SOCK[0])) is False


def test_the_console_path_really_is_registered_twice(api):
    """Why this is needed at all, pinned so it is not mistaken for paranoia.

    The VNC path carries two rules: a plain one and flask-sock's websocket=True
    one. A real upgrade resolves to flask-sock, which is why the gevent layer
    must keep its hands off it.
    """
    rules = [r for r in api.app.url_map.iter_rules() if str(r).endswith('vncwebsocket')]
    assert len(rules) == 2, [r.endpoint for r in rules]
    assert {r.websocket for r in rules} == {True, False}

    adapter = api.app.url_map.bind('localhost')
    endpoint = adapter.match('/api/clusters/c1/vms/pve1/qemu/100/vncwebsocket',
                             websocket=True)[0]
    assert endpoint.startswith('__flask_sock')
