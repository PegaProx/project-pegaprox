"""An alert webhook that answers with a redirect has not received the alert.

The senders post with allow_redirects=False, so nothing ever goes to the Location of a
3xx. The Slack, Discord, Teams and generic channels still counted every status below 400
as delivered: the test button said "Delivered" and the log line was the one of a success,
for an alert nobody got. The ntfy channel already stopped at 300.

Real requests: an HTTP endpoint on loopback answers the status each test asks for, and a
second one stands for the place a redirect points at. It must never see a request.
"""
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import pegaprox.utils.webhooks as wh

ALERT = {'alert_name': 'CPU high', 'severity': 'warning', 'message': 'cpu at 97 %',
         'target_type': 'node', 'target_name': 'pve1', 'metric': 'cpu', 'current_value': 97,
         'cluster_id': 'c1'}
JSON_TYPES = ['generic', 'slack', 'discord', 'teams']


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        self.server.seen.append((self.path, self.rfile.read(n) if n else b''))
        self.send_response(self.server.status)
        if self.server.location:
            self.send_header('Location', self.server.location)
        self.send_header('Content-Length', '0')
        self.end_headers()


def _serve(status=200, location=None):
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    srv.daemon_threads = True
    srv.seen, srv.status, srv.location = [], status, location
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _url(srv, path='/hook'):
    return f'http://127.0.0.1:{srv.server_address[1]}{path}'


@pytest.fixture
def net(monkeypatch):
    """Endpoints on loopback, which the operator has allowed as a webhook target."""
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings',
                        lambda: {'alert_webhook_allow_private': True}, raising=False)
    started = []

    def start(status=200, location=None):
        srv = _serve(status, location)
        started.append(srv)
        return srv

    yield start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _channel(ctype, url):
    ch = {'id': 'ch1', 'name': 'ops', 'type': ctype, 'url': url, 'enabled': True}
    if ctype == 'ntfy':
        ch['topic'] = 'alerts'
    return ch


@pytest.mark.parametrize('ctype', JSON_TYPES + ['ntfy'])
@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_a_redirect_is_a_failed_delivery_and_nothing_goes_to_its_target(net, ctype, status):
    """The test button says the delivery failed, and the Location never sees the alert."""
    elsewhere = net(200)
    hook = net(status, location=_url(elsewhere, '/moved'))

    ok, detail = wh.send_to_channel(_channel(ctype, _url(hook)), ALERT)

    assert ok is False, detail
    assert str(status) in detail and 'redirect' in detail, detail
    assert len(hook.seen) == 1
    assert elsewhere.seen == []


@pytest.mark.parametrize('ctype', JSON_TYPES + ['ntfy'])
@pytest.mark.parametrize('status', [200, 201, 202, 204])
def test_a_2xx_is_still_a_delivery(net, ctype, status):
    """An endpoint that takes the alert is reported as delivered, as before."""
    hook = net(status)

    ok, detail = wh.send_to_channel(_channel(ctype, _url(hook)), ALERT)

    assert ok is True, detail
    assert detail == f'HTTP {status}'
    assert len(hook.seen) == 1


@pytest.mark.parametrize('ctype', JSON_TYPES + ['ntfy'])
@pytest.mark.parametrize('status', [400, 401, 404, 500, 503])
def test_an_error_status_is_still_a_failed_delivery(net, ctype, status):
    """A refusal or a server error keeps its plain status, without the redirect note."""
    hook = net(status)

    ok, detail = wh.send_to_channel(_channel(ctype, _url(hook)), ALERT)

    assert ok is False
    assert detail == f'HTTP {status}'


def test_the_generic_channel_still_posts_the_alert_itself(net):
    """What reaches the endpoint is the alert, under the same keys as before."""
    hook = net(200)

    wh.send_to_channel(_channel('generic', _url(hook)), ALERT)

    path, body = hook.seen[0]
    sent = json.loads(body)
    assert path == '/hook'
    assert sent['alert'] == ALERT and sent['source'] == 'pegaprox'


def test_a_redirected_alert_is_logged_as_a_failure(net, monkeypatch, caplog):
    """The dispatcher writes a warning for the channel, not the line of a delivery."""
    hook = net(302, location='http://127.0.0.1:9/moved')
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings',
                        lambda: {'alert_webhook_allow_private': True,
                                 'alert_webhooks': [_channel('generic', _url(hook))]}, raising=False)
    caplog.set_level(logging.INFO)

    wh.send_to_channels(ALERT)

    lines = [r for r in caplog.records if '[webhooks]' in r.getMessage()]
    assert len(lines) == 1
    assert lines[0].levelno == logging.WARNING and 'FAILED' in lines[0].getMessage()
