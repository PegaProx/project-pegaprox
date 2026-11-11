"""An alert webhook that answers with a redirect is not counted as a delivery.

The senders post with allow_redirects=False, so nothing ever goes to the Location of a
3xx. The redirect is not followed, so we cannot tell whether the alert was received. The
Slack, Discord, Teams and generic channels still counted every status below 400 as
delivered: the test button said "Delivered" and the log line was the one of a success.
The ntfy channel already stopped at 300.

A failed press of the test button answers as coarsely as before and writes the reason to
the log, with the secret part of a hook url cut out.

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

    # a followed 301, 302 or 303 arrives as a GET: it counts as a request too
    do_GET = do_POST


def _serve(status=200, location=None):
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    srv.daemon_threads = True
    srv.seen, srv.status, srv.location = [], status, location
    # a short poll: shutdown() waits for one, and each case stops its endpoints
    threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True).start()
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


# --- the test button ---------------------------------------------------------------------

# the answer of a failed test names no status, so the button cannot be used to probe ports
COARSE = 'Delivery failed \u2014 check the channel URL and that the endpoint is reachable'


def _press_test(api, seed):
    return api.as_user(seed.user('root', role='admin')).post('/api/alert-channels/ch1/test')


def _webhook_lines(caplog):
    return [r for r in caplog.records if '[webhooks]' in r.getMessage()]


def test_a_failed_test_keeps_its_answer_and_logs_the_reason(api, seed, net, monkeypatch, caplog):
    """The button still says only that the delivery failed; the log names the channel and the 308."""
    hook = net(308, location='http://127.0.0.1:9/moved')
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings',
                        lambda: {'alert_webhook_allow_private': True,
                                 'alert_webhooks': [_channel('slack', _url(hook))]}, raising=False)
    caplog.set_level(logging.INFO)

    r = _press_test(api, seed)

    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json() == {'success': False, 'detail': COARSE}
    lines = _webhook_lines(caplog)
    assert len(lines) == 1, [l.getMessage() for l in lines]
    assert lines[0].levelno == logging.WARNING
    assert 'ops' in lines[0].getMessage()
    assert 'HTTP 308, redirect not followed' in lines[0].getMessage()


def test_the_logged_reason_of_a_failed_test_carries_no_hook_secret(api, seed, monkeypatch, caplog):
    """A reason that holds the webhook url is logged with the secret part of the url cut out."""
    hook = 'https://hooks.example/services/T0/B0/q7Lr2VwX9tKe4NbZ'
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings',
                        lambda: {'alert_webhooks': [_channel('slack', hook)]}, raising=False)
    monkeypatch.setattr(wh, 'send_to_channel',
                        lambda ch, alert: (False, f'Max retries exceeded with url: {hook}'))
    caplog.set_level(logging.INFO)

    r = _press_test(api, seed)

    assert r.get_json() == {'success': False, 'detail': COARSE}
    lines = _webhook_lines(caplog)
    assert len(lines) == 1 and lines[0].levelno == logging.WARNING
    assert 'q7Lr2VwX9tKe4NbZ' not in caplog.text
    assert 'q7Lr2VwX9tKe4NbZ' not in lines[0].getMessage()


def test_a_test_that_is_delivered_logs_no_warning(api, seed, monkeypatch, caplog):
    """A delivered test answers as before and writes no warning."""
    monkeypatch.setattr('pegaprox.api.helpers.load_server_settings',
                        lambda: {'alert_webhooks': [_channel('slack', 'https://hooks.example/x')]},
                        raising=False)
    monkeypatch.setattr(wh, 'send_to_channel', lambda ch, alert: (True, 'HTTP 200'))
    caplog.set_level(logging.INFO)

    r = _press_test(api, seed)

    assert r.get_json() == {'success': True, 'detail': 'Delivered'}
    assert [l for l in _webhook_lines(caplog) if l.levelno >= logging.WARNING] == []
